from time import strftime, localtime
from nxc.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout
import contextlib


class SMBSpider:
    def __init__(self, smbconnection, logger, shares, folder, pattern, regex, exclude_folders, depth, content, only_files, only_folders, spider_all):
        self.smbconnection = smbconnection
        self.logger = logger
        self.spider_all = spider_all
        self.share = ""
        self.shares = shares
        self.folder = folder
        self.pattern = pattern
        self.exclude_folders = exclude_folders
        self.depth = depth
        self.content = content
        self.onlyfiles = only_files
        self.onlyfolders = only_folders
        self.regex = regex

    def spider(self):
        if self.spider_all:
            self.logger.display("Enumerating all readable shares")
            for share in self.smbconnection.listShares():
                self.share = share["shi1_netname"][:-1]
                try:
                    self.smbconnection.listPath(self.share, "*")
                    self.logger.display(f"Spidering share: {self.share}")
                    self._spider(self.folder, self.depth)
                except SessionError:
                    self.logger.debug(f"Failed accessing share: {self.share}")
        else:
            for share in self.shares:
                self.share = share
                self.logger.display(f"Spidering share: {self.share}")
                if self.folder != "/":
                    self.logger.display(f"Spidering folder: {self.folder}")
                self._spider(self.folder, self.depth)

    def _spider(self, subfolder, depth):
        filelist = None
        if subfolder in ["", ".", "/"]:
            subfolder = "*"
        else:
            subfolder += "/*"

        try:
            filelist = self.smbconnection.listPath(self.share, subfolder)
            if depth is not None and depth <= 0:
                return
            self.dir_list(filelist, subfolder)
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                self.logger.debug(f"Failed listing files on share {self.share} in directory {subfolder}")
            elif "STATUS_BAD_NETWORK_NAME" in str(e):
                self.logger.fail(f"Failed accessing {self.share} share")
            elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                self.logger.fail(f"{self.folder} folder does not exist")
            return

        for result in filelist:
            if result.is_directory() and result.get_longname() not in [".", ".."]:
                if depth is not None:
                    depth -= 1
                if result.get_longname() not in self.exclude_folders:
                    self._spider(subfolder.replace("*", "") + result.get_longname(), depth)
        return

    def dir_list(self, files, path):
        path = path.replace("*", "")
        for result in files:
            if result.get_longname() in [".", ".."] or result.get_longname() in self.exclude_folders:
                continue
            filename = bytes(result.get_longname().lower(), "utf-8")
            if self.content:
                if not result.is_directory():
                    self.search_content(path, result)
                continue
            if self.pattern and any(bytes(pattern.lower(), "utf-8") in filename for pattern in self.pattern):
                if result.is_directory():
                    if not self.onlyfiles:
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [dir]")
                else:
                    if not self.onlyfolders:
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()}]")
            if self.regex:
                for regex in self.regex:
                    if regex.findall(filename):
                        if result.is_directory():
                            if not self.onlyfiles:
                                self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [dir]")
                        else:
                            if not self.onlyfolders:
                                self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()}]")

    def search_content(self, path, result):
        path = path.replace("*", "")
        file = path + result.get_longname()
        rfile = RemoteFile(self.smbconnection, file, self.share, access=FILE_READ_DATA)
        try:
            rfile.open_file()
        except Exception as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                return

        while True:
            contents = None
            try:
                contents = rfile.read(4096)
            except NetBIOSTimeout as e:
                self.logger.fail(f"Error retrieving {file} ({e})")

            if not contents:
                break

            if self.pattern:
                for pattern in self.pattern:
                    if contents.lower().find(bytes(pattern.lower(), "utf-8")) != -1:
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()}"
                                              f"[lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()}  pattern='{pattern}']")
            if self.regex:
                for regex in self.regex:
                    if regex.findall(contents):
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()}"
                                              f"[lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()} regex='{regex.pattern.decode('utf-8')}']")
        rfile.close()

    def get_lastm_time(self, result_obj):
        with contextlib.suppress(Exception):
            time = strftime("%Y-%m-%d %H:%M", localtime(result_obj.get_mtime_epoch()))
            if not time:
                return "n\\a"
            return time
