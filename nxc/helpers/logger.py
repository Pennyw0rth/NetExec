import os
from termcolor import colored
from nxc.paths import NXC_PATH


def write_log(data, log_name):
    logs_dir = os.path.join(NXC_PATH, "logs")
    with open(os.path.join(logs_dir, log_name), "w") as log_output:
        log_output.write(data)


def highlight(text, color="yellow"):
    if color == "yellow":
        return f"{colored(text, 'yellow', attrs=['bold'])}"
    elif color == "red":
        return f"{colored(text, 'red', attrs=['bold'])}"
