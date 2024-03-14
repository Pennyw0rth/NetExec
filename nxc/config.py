import os
from os.path import join as path_join
import configparser
from nxc.paths import NXC_PATH, DATA_PATH
from nxc.first_run import first_run_setup
from nxc.logger import nxc_logger
from ast import literal_eval

nxc_default_config = configparser.ConfigParser()
nxc_default_config.read(path_join(DATA_PATH, "nxc.conf"))

nxc_config = configparser.ConfigParser()
nxc_config.read(os.path.join(NXC_PATH, "nxc.conf"))

if "nxc" not in nxc_config.sections():
    first_run_setup()
    nxc_config.read(os.path.join(NXC_PATH, "nxc.conf"))

# Check if there are any missing options in the config file
for section in nxc_default_config.sections():
    for option in nxc_default_config.options(section):
        if not nxc_config.has_option(section, option):
            nxc_logger.display(f"Adding missing option '{option}' in config section '{section}' to nxc.conf")
            nxc_config.set(section, option, nxc_default_config.get(section, option))

            with open(path_join(NXC_PATH, "nxc.conf"), "w") as config_file:
                nxc_config.write(config_file)

# THESE OPTIONS HAVE TO EXIST IN THE DEFAULT CONFIG FILE
nxc_workspace = nxc_config.get("nxc", "workspace", fallback="default")
pwned_label = nxc_config.get("nxc", "pwn3d_label", fallback="Pwn3d!")
audit_mode = nxc_config.get("nxc", "audit_mode", fallback=False)
reveal_chars_of_pwd = int(nxc_config.get("nxc", "reveal_chars_of_pwd", fallback=0))
config_log = nxc_config.getboolean("nxc", "log_mode", fallback=False)
ignore_opsec = nxc_config.getboolean("nxc", "ignore_opsec", fallback=False)
host_info_colors = literal_eval(nxc_config.get("nxc", "host_info_colors", fallback=["green", "red", "yellow", "cyan"]))


if len(host_info_colors) != 4:
    nxc_logger.error("Config option host_info_colors must have 4 values! Using default values.")
    host_info_colors = nxc_default_config.get("nxc", "host_info_colors")


# this should probably be put somewhere else, but if it's in the config helpers, there is a circular import
def process_secret(text):
    reveal = text[:reveal_chars_of_pwd]
    return text if not audit_mode else reveal + (audit_mode if len(audit_mode) > 1 else audit_mode * 8)
