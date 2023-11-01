import os
from nxc.paths import DATA_PATH


def get_script(path):
    with open(os.path.join(DATA_PATH, path)) as script:
        return script.read()
