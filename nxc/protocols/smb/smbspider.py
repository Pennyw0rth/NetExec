from time import strftime, localtime
from nxc.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
import re
import traceback
import contextlib


class SMBSpider:
    def __init__(self, smbconnection, logger):
        self.smbconnection = smbconnection
        self.logger = logger
        self.share = None
        self.regex = []
        self.pattern = []
        self.folder = None
        self.exclude_dirs = []
        self.onlyfiles = True
        self.content = False
        self.results = []
        self.silent = False

    def spider(
        self,
        share,
        folder=".",
        pattern=None,
        regex=None,
        exclude_dirs=None,
        depth=None,
        content=False,
        onlyfiles=True,
        silent=False
    ):
        if exclude_dirs is None:
            exclude_dirs = []
        if regex is None:
            regex = []
        if pattern is None:
            pattern = []
        if regex:
            try:
                self.regex = [re.compile(bytes(rx, "utf8")) for rx in regex]
            except Exception as e:
                self.logger.fail(f"Regex compilation error: {e}")

        self.folder = folder
        self.pattern = pattern
        self.exclude_dirs = exclude_dirs
        self.content = content
        self.onlyfiles = onlyfiles
        self.silent = silent

        if share == "*":
            self.logger.display("Enumerating shares for spidering")
            try:
                for share in self.smbconnection.listShares():
                    share_name = share["shi1_netname"][:-1]
                    share["shi1_remark"][:-1]
                    try:
                        self.smbconnection.listPath(share_name, "*")
                        self.share = share_name
                        self.logger.display(f"Spidering share: {share_name}")
                        self._spider(folder, depth)
                    except SessionError:
                        pass
            except Exception as e:
                self.logger.fail(f"Error enumerating shares: {e}")
        else:
            self.share = share
            if not self.silent:
                self.logger.display(f"Spidering {folder}")
            self._spider(folder, depth)

        return self.results

    def _spider(self, subfolder, depth):
        """"""
        if subfolder in ["", "."]:
            subfolder = "*"

        elif subfolder.startswith("*/"):
            subfolder = subfolder[2:] + "/*"
        else:
            subfolder = subfolder.replace("/*/", "/") + "/*"

        filelist = None
        try:
            filelist = self.smbconnection.listPath(self.share, subfolder)
            self.dir_list(filelist, subfolder)
            if depth == 0:
                return
        except SessionError as e:
            if not filelist:
                if "STATUS_ACCESS_DENIED" not in str(e):
                    self.logger.debug(f"Failed listing files on share {self.share} in directory {subfolder}: {e}")
                return

        for result in filelist:
            # this can potentially be refactored
            if result.is_directory() and result.get_longname() not in [".", ".."]:
                if subfolder == "*":  # noqa: SIM114
                    self._spider(
                        subfolder.replace("*", "") + result.get_longname(),
                        depth - 1 if depth else None,
                    )
                elif subfolder != "*" and (subfolder[:-2].split("/")[-1] not in self.exclude_dirs):
                    self._spider(
                        subfolder.replace("*", "") + result.get_longname(),
                        depth - 1 if depth else None,
                    )
        return

    def dir_list(self, files, path):
        path = path.replace("*", "")
        for result in files:
            if self.pattern:
                for pattern in self.pattern:
                    if bytes(result.get_longname().lower(), "utf8").find(bytes(pattern.lower(), "utf8")) != -1:
                        if not self.onlyfiles and result.is_directory() and not self.silent:
                            self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [dir]")
                        elif not self.silent:
                            self.logger.highlight(
                                "//{}/{}/{}{} [lastm:'{}' size:{}]".format(
                                    self.smbconnection.getRemoteHost(),
                                    self.share,
                                    path,
                                    result.get_longname(),
                                    "n\\a" if not self.get_lastm_time(result) else self.get_lastm_time(result),
                                    result.get_filesize(),
                                )
                            )
                        self.results.append(f"{path}{result.get_longname()}")
            if self.regex:
                for regex in self.regex:
                    if regex.findall(bytes(result.get_longname(), "utf8")):
                        if not self.onlyfiles and result.is_directory() and not self.silent:
                            self.logger.highlight(f"//{self.smbconnection.getRemoteHost()}/{self.share}/{path}{result.get_longname()} [dir]")
                        elif not self.silent:
                            self.logger.highlight(
                                "//{}/{}/{}{} [lastm:'{}' size:{}]".format(
                                    self.smbconnection.getRemoteHost(),
                                    self.share,
                                    path,
                                    result.get_longname(),
                                    "n\\a" if not self.get_lastm_time(result) else self.get_lastm_time(result),
                                    result.get_filesize(),
                                )
                            )
                        self.results.append(f"{path}{result.get_longname()}")

            if self.content and not result.is_directory():
                self.search_content(path, result)

    def search_content(self, path, result):
        path = path.replace("*", "")
        try:
            rfile = RemoteFile(
                self.smbconnection,
                path + result.get_longname(),
                self.share,
                access=FILE_READ_DATA,
            )
            rfile.open_file()

            while True:
                try:
                    contents = rfile.read(4096)
                    if not contents:
                        break
                except SessionError as e:
                    if "STATUS_END_OF_FILE" in str(e):
                        break

                except Exception:
                    traceback.print_exc()
                    break
                if self.pattern:
                    for pattern in self.pattern:
                        if contents.lower().find(bytes(pattern.lower(), "utf8")) != -1:
                            if not self.silent:
                                self.logger.highlight(
                                    "//{}/{}/{}{} [lastm:'{}' size:{} offset:{} pattern:'{}']".format(
                                        self.smbconnection.getRemoteHost(),
                                        self.share,
                                        path,
                                        result.get_longname(),
                                        "n\\a" if not self.get_lastm_time(result) else self.get_lastm_time(result),
                                        result.get_filesize(),
                                        rfile.tell(),
                                        pattern,
                                    )
                                )
                            self.results.append(f"{path}{result.get_longname()}")
                if self.regex:
                    for regex in self.regex:
                        if regex.findall(contents):
                            if not self.silent:
                                self.logger.highlight(
                                    "//{}/{}/{}{} [lastm:'{}' size:{} offset:{} regex:'{}']".format(
                                        self.smbconnection.getRemoteHost(),
                                        self.share,
                                        path,
                                        result.get_longname(),
                                        "n\\a" if not self.get_lastm_time(result) else self.get_lastm_time(result),
                                        result.get_filesize(),
                                        rfile.tell(),
                                        regex.pattern,
                                    )
                                )
                            self.results.append(f"{path}{result.get_longname()}")

            rfile.close()
            return

        except SessionError as e:
            if "STATUS_SHARING_VIOLATION" in str(e):
                pass

        except Exception:
            traceback.print_exc()

    def get_lastm_time(self, result_obj):
        with contextlib.suppress(Exception):
            return strftime("%Y-%m-%d %H:%M", localtime(result_obj.get_mtime_epoch()))
