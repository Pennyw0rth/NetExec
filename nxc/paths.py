from os.path import join, normpath, expanduser, dirname
from os import environ, getenv
import nxc

if "NXC_PATH" in environ:  # noqa: SIM108
    NXC_PATH = normpath(getenv("NXC_PATH"))
else:
    NXC_PATH = normpath(expanduser("~/.nxc"))

TMP_PATH = join(NXC_PATH, "tmp")
CONFIG_PATH = join(NXC_PATH, "nxc.conf")
WORKSPACE_DIR = join(NXC_PATH, "workspaces")
DATA_PATH = join(dirname(nxc.__file__), "data")
