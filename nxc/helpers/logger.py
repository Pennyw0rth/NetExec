#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from termcolor import colored


def write_log(data, log_name):
    logs_dir = os.path.join(os.path.expanduser("~/.nxc"), "logs")
    with open(os.path.join(logs_dir, log_name), "w") as log_output:
        log_output.write(data)


def highlight(text, color="yellow"):
    if color == "yellow":
        return f"{colored(text, 'yellow', attrs=['bold'], force_color=True)}"
    elif color == "red":
        return f"{colored(text, 'red', attrs=['bold'], force_color=True)}"
