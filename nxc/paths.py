import os
import sys
import nxc

NXC_PATH = os.getenv('XDG_CONFIG_HOME', os.path.expanduser("~/.nxc"))
if os.name == "nt":
    TMP_PATH = os.getenv("LOCALAPPDATA") + "\\Temp\\nxc_hosted"
elif hasattr(sys, "getandroidapilevel"):
    TMP_PATH = os.path.join("/data", "data", "com.termux", "files", "usr", "tmp", "nxc_hosted")
else:
    TMP_PATH = os.path.join("/tmp", "nxc_hosted")

CERT_PATH = os.path.join(NXC_PATH, "nxc.pem")
CONFIG_PATH = os.path.join(NXC_PATH, "nxc.conf")
WORKSPACE_DIR = os.path.join(NXC_PATH, "workspaces")
DATA_PATH = os.getenv('XDG_DATA_HOME', os.path.join(os.path.dirname(nxc.__file__), "data"))
