import os
import sys
import nxc

if "XDG_CONFIG_HOME" in os.environ:  # noqa: SIM108
    NXC_PATH = os.path.join(os.getenv("XDG_CONFIG_HOME"), "nxc")
else:
    NXC_PATH = os.path.normpath(os.path.expanduser("~/.nxc"))
    
if os.name == "nt":
    TMP_PATH = os.getenv("LOCALAPPDATA") + "\\Temp\\nxc_hosted"
elif hasattr(sys, "getandroidapilevel"):
    TMP_PATH = os.path.join("/data", "data", "com.termux", "files", "usr", "tmp", "nxc_hosted")
else:
    TMP_PATH = os.path.join("/tmp", "nxc_hosted")

CERT_PATH = os.path.join(NXC_PATH, "nxc.pem")
CONFIG_PATH = os.path.join(NXC_PATH, "nxc.conf")
WORKSPACE_DIR = os.path.join(NXC_PATH, "workspaces")
DATA_PATH = os.path.join(os.path.dirname(nxc.__file__), "data")
