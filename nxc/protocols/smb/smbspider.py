from time import strftime, localtime
from nxc.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout
import contextlib, re


class SMBSpider:
    def __init__(self, smbconnection, logger, spider, spider_folder, exclude_folders, depth, content, spider_all, only_files, only_folders, pattern, regex, silent):
        self.smbconnection = smbconnection
        self.logger = logger
        self.shares = spider
        self.folder = spider_folder
        self.exclude_folders = exclude_folders if exclude_folders else []
        self.depth = depth
        self.content = content
        self.spider_all = spider_all
        self.onlyfiles = only_files
        self.onlyfolders = only_folders
        self.pattern = pattern if pattern else [""]
        self.regex = regex
        self.paths = []
        self.silent = silent

    def spider(self):
        if self.spider_all:
            self.logger.display("Enumerating all readable shares")
            for share in self.smbconnection.listShares():
                share = share["shi1_netname"][:-1]
                try:
                    self.smbconnection.listPath(share, "*")
                    self.logger.display(f"Spidering share: {share}")
                    self.crawl(share, self.folder, self.depth)
                except SessionError:
                    self.logger.debug(f"Failed accessing share: {share}")
        else:
            for share in self.shares: 
                try:
                    self.smbconnection.listPath(share, "*")
                except SessionError as e:
                    if "STATUS_ACCESS_DENIED" in str(e):
                        self.logger.fail(f"Failed accessing share: {share} (Insufficient Permissions)")
                    elif "STATUS_BAD_NETWORK_NAME" in str(e):
                        self.logger.fail(f"Failed accessing share: {share} (Does Not Exist)") 
                    continue
                self.logger.display(f"Spidering share: {share}") if not self.silent else None
                if self.folder != "/":
                    self.logger.display(f"Spidering folder: {self.folder}") if not self.silent else None
                self.crawl(share, self.folder, self.depth)

    def crawl(self, share, subfolder, depth):
        filelist = None
        if subfolder in ["", ".", "/"]:
            subfolder = "*"
        else:
            subfolder += "/*"

        try:
            filelist = self.smbconnection.listPath(share, subfolder)
            if depth is not None and depth <= 0:
                return
            self.dir_list(share, filelist, subfolder)
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                self.logger.debug(f"Failed listing files on share {share} in directory {subfolder}")
            elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                self.logger.fail(f"{self.folder} folder does not exist")
            return

        for result in filelist:
            if result.is_directory() and result.get_longname() not in [".", ".."]:
                if depth is not None:
                    depth -= 1
                if result.get_longname() not in self.exclude_folders:
                    self.crawl(share, subfolder.replace("*", "") + result.get_longname(), depth)
        return

    def dir_list(self, share, files, path):
        path = path.replace("*", "")
        for result in files:
            file = path + result.get_longname()
            if result.get_longname() in [".", ".."] or result.get_longname() in self.exclude_folders:
                continue
            filename = bytes(result.get_longname().lower(), "utf-8")
            if self.content: 
                if not result.is_directory():
                    self.search_content(share, file, result)
                continue
            if self.pattern != [""] and any(bytes(pattern.lower(), "utf-8") in filename for pattern in self.pattern):
                if result.is_directory():
                    if not self.onlyfiles:
                        self.paths.append(file)
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{share}/{file} [dir]") if not self.silent else None
                else:
                    if not self.onlyfolders:
                        self.paths.append(file)
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{share}/{file} [lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()}]") if not self.silent else None 
            if self.regex:
                for regex in self.regex:
                    if regex.findall(filename):
                        if result.is_directory():
                            if not self.onlyfiles:
                                self.paths.append(file)
                                self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{share}/{file} [dir]") if not self.silent else None
                        else:
                            if not self.onlyfolders:
                                self.paths.append(file)
                                self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{share}/{file} [lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()}]") if not self.silent else None

    def search_content(self, share, file, result):
        rfile = RemoteFile(self.smbconnection, file, share, access=FILE_READ_DATA)
        try:
            rfile.open_file()
        except Exception as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                self.logger.debug(f"Failed accessing file: {file} on the {share} share")
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
                        self.paths.append(file)
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{share}/{file}"
                                              f"[lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()}  pattern='{pattern}']") if not self.silent else None
            if self.regex:
                for regex in self.regex:
                    if regex.findall(contents):
                        self.paths.append(file)
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{share}/{file}"
                                              f"[lastm:'{self.get_lastm_time(result)}' size:{result.get_filesize()} regex='{regex.pattern.decode('utf-8')}']") if not self.silent else None
        rfile.close()

    def get_lastm_time(self, result_obj):
        with contextlib.suppress(Exception):
            time = strftime("%Y-%m-%d %H:%M", localtime(result_obj.get_mtime_epoch()))
            if not time:
                return "n\\a"
            return time
