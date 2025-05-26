from time import strftime, localtime
from nxc.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
import contextlib


class SMBSpider:
    def __init__(self, smbconnection, logger, share, folder, pattern, regex, exclude_dirs, depth, content, only_files):
        self.smbconnection = smbconnection
        self.logger = logger
        self.share = share
        self.folder = folder
        self.pattern = pattern 
        self.exclude_dirs = exclude_dirs 
        self.depth = depth
        self.content = content
        self.onlyfiles = only_files
        self.regex = regex

    def spider(self):
        if self.share == "*":
             self.logger.display("Enumerating shares for spidering")
             for share in self.smbconnection.listShares():
                 self.share = share["shi1_netname"][:-1]
                 try:
                     self.smbconnection.listPath(self.share, "*")
                     self._spider(self.folder, self.depth)
                     self.logger.display(f"Spidering share: {self.share}")
                 except SessionError:
                     self.logger.debug(f"Failed accessing share: {self.share}")
                     pass
        else:
            self._spider(self.folder, self.depth)
            self.logger.display(f"Spidering folder {self.folder}")

    def _spider(self, subfolder, depth):
        filelist = None
        if subfolder in ["", ".", "/"]:
            subfolder = "*"
        else:
            subfolder += "/*"

        try:
            filelist = self.smbconnection.listPath(self.share, subfolder)
            self.dir_list(filelist, subfolder)
            if depth == 0:
                return
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                self.logger.debug(f"Failed listing files on share {self.share} in directory {subfolder}: {e}")
            elif "STATUS_BAD_NETWORK_NAME" in str(e):
                self.logger.error(f"Failed accessing {self.share} share") 
            return

        for result in filelist:
            if result.is_directory() and result.get_longname() not in [".", ".."]:
                if depth is not None:
                    depth -= 1
                if subfolder == "*" and (result.get_longname() not in self.exclude_dirs):
                    self._spider(result.get_longname(), depth) 
                else:
                    self._spider(subfolder.replace("*", "") + result.get_longname(), depth)
        return

    def dir_list(self, files, path):
        path = path.replace("*", "")
        for result in files:
            filename = bytes(result.get_longname().lower(), "utf-8")
            if self.pattern:
                if any(bytes(pattern.lower(), "utf-8") in filename for pattern in self.pattern):
                    if not self.onlyfiles and result.is_directory():
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [dir]")
                    else:
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [lastm:\'{self.get_lastm_time(result)}\' size:{result.get_filesize()}]")
            if self.regex:
                for regex in self.regex:
                    if regex.findall(filename):
                        if not self.onlyfiles and result.is_directory():
                            self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [dir]")
                        else:
                            self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [lastm:\'{self.get_lastm_time(result)}\' size:{result.get_filesize()}]")
            if self.content and not result.is_directory():
                self.search_content(path, result)

    def search_content(self, path, result):
        path = path.replace("*", "")
        rfile = RemoteFile(self.smbconnection, path + result.get_longname(), self.share, access=FILE_READ_DATA)
        rfile.open_file()

        while True:
            contents = None
            try:
                contents = rfile.read(4096)
            except SessionError as e:
                if "STATUS_END_OF_FILE" in str(e):
                    break

            if not contents:
                break

            if self.pattern:
                for pattern in self.pattern:
                    if contents.lower().find(bytes(pattern.lower(), "utf-8")) != -1:
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()}"
                                          f"[lastm:\'{self.get_lastm_time(result)}\' size:{result.get_filesize()} offset:{rfile.tell()} pattern='{pattern}']")
            if self.regex:
                for regex in self.regex:
                    if regex.findall(contents):
                        self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()}"
                                              f"[lastm:\'{self.get_lastm_time(result)}\' size:{result.get_filesize()} offset:{rfile.tell()} regex='{regex.pattern.decode('utf-8')}']")
        rfile.close()
        return


    def get_lastm_time(self, result_obj):
        with contextlib.suppress(Exception):
            time = strftime("%Y-%m-%d %H:%M", localtime(result_obj.get_mtime_epoch()))
            if not time:
                return "n\\a"
            return time
