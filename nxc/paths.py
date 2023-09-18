import os
import sys
import nxc

nxc_PATH = os.path.expanduser("~/.nxc")
TMP_PATH = os.path.join("/tmp", "nxc_hosted")
if os.name == "nt":
    TMP_PATH = os.getenv("LOCALAPPDATA") + "\\Temp\\nxc_hosted"
if hasattr(sys, "getandroidapilevel"):
    TMP_PATH = os.path.join("/data", "data", "com.termux", "files", "usr", "tmp", "nxc_hosted")
WS_PATH = os.path.join(nxc_PATH, "workspaces")
CERT_PATH = os.path.join(nxc_PATH, "nxc.pem")
CONFIG_PATH = os.path.join(nxc_PATH, "nxc.conf")
WORKSPACE_DIR = os.path.join(nxc_PATH, "workspaces")
DATA_PATH = os.path.join(os.path.dirname(nxc.__file__), "data")
