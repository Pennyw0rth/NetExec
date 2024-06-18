import argparse
from os import getcwd
from os.path import dirname, abspath, join, realpath, isfile, normpath
import subprocess
from time import time
from rich.console import Console
import platform
import os
from nxc.paths import TMP_PATH
import sys
if sys.stdout.encoding == "cp1252":
    sys.stdout.reconfigure(encoding="utf-8")

script_dir = dirname(abspath(__file__))
run_dir = os.getcwd()


def get_cli_args():
    parser = argparse.ArgumentParser(description="Script for running end to end tests for nxc")
    parser.add_argument(
        "--executable",
        default="netexec"
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True
    )
    parser.add_argument(
        "-u",
        "--user",
        "--username",
        dest="username",
        required=True
    )
    parser.add_argument(
        "-p",
        "--pass",
        "--password",
        dest="password",
        required=True
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        required=False,
        help="Use kerberos authentication",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        required=False,
        help="Display full command output",
    )
    parser.add_argument(
        "-e",
        "--errors",
        action="store_true",
        required=False,
        help="Display errors from commands",
    )
    parser.add_argument(
        "--poetry",
        action="store_true",
        required=False,
        help="Use poetry to run commands",
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        default=[],
        required=False,
        help="Protocols to test",
    )
    parser.add_argument(
        "--line-nums",
        nargs="+",
        type=parse_line_nums,
        required=False,
        help="Specify line numbers or ranges to run commands from",
    )
    parser.add_argument(
        "--test-user-file",
        required=False,
        default=normpath(join(script_dir, "data", "test_users.txt")),
        help="Path to the file containing test usernames",
    )
    parser.add_argument(
        "--test-password-file",
        required=False,
        default=normpath(join(script_dir, "data", "test_passwords.txt")),
        help="Path to the file containing test passwords",
    )
    parser.add_argument(
        "--amsi-bypass-file",
        required=False,
        default=normpath(join(script_dir, "data", "test_amsi_bypass.txt")),
        help="Path to the file containing AMSI bypasses",
    )
    parser.add_argument(
        "--test-normal-file",
        required=False,
        default=normpath(join(script_dir, "data", "test_file.txt")),
        help="Path to file to upload/download"
    )
    parser.add_argument(
        "--dns-server",
        action="store",
        required=False,
        help="Specify DNS server",
    )
    return parser.parse_args()


def parse_line_nums(value):
    line_nums = []
    for item in value.split():
        if "-" in item:
            start, end = item.split("-")
            line_nums.extend(range(int(start), int(end) + 1))
        else:
            line_nums.append(int(item))
    return line_nums


def generate_commands(args):
    lines = []
    file_loc = realpath(join(getcwd(), dirname(__file__)))
    commands_file = join(file_loc, "e2e_commands.txt")

    with open(commands_file) as file:
        if args.line_nums:
            flattened_list = list({num for sublist in args.line_nums for num in sublist})
            for i, line in enumerate(file):
                if i + 1 in flattened_list:
                    if line.startswith("#"):
                        continue
                    if "#" in line:
                        line = line.split("#")[0]
                    line = line.strip()
                    if args.protocols:
                        if line.split()[1] in args.protocols:
                            lines.append(replace_command(args, line))
                    else:
                        lines.append(replace_command(args, line))
        else:
            for line in file:
                if line.startswith("#"):
                    continue
                if "#" in line:
                    line = line.split("#")[0]
                line = line.strip()
                if args.protocols:
                    if line.split()[1] in args.protocols:
                        lines.append(replace_command(args, line))
                else:
                    lines.append(replace_command(args, line))
    return lines


def replace_command(args, line):
    if isfile(join(getcwd(), args.executable)):
        args.executable = abspath(join(getcwd(), args.executable))

    kerberos = "-k " if args.kerberos else ""
    dns_server = f"--dns-server {args.dns_server}" if args.dns_server else ""

    line = line\
        .replace("netexec", args.executable)\
        .replace("TARGET_HOST", args.target)\
        .replace("LOGIN_USERNAME", f'"{args.username}"')\
        .replace("LOGIN_PASSWORD", f'"{args.password}"')\
        .replace("KERBEROS ", kerberos)\
        .replace("TEST_USER_FILE", args.test_user_file)\
        .replace("TEST_PASSWORD_FILE", args.test_password_file)\
        .replace("AMSI_BYPASS_FILE", args.amsi_bypass_file)\
        .replace("TEST_NORMAL_FILE", args.test_normal_file)\
        .replace("{DNS}", dns_server)\
        .replace("/tmp", TMP_PATH)
    if args.poetry:
        line = f"poetry run {line}"
    return line


def run_e2e_tests(args):
    console = Console()
    tasks = generate_commands(args)
    tasks_len = len(tasks)
    failures = []

    result = subprocess.Popen(
        f"{args.executable} --version",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    version = result.communicate()[0].decode().strip()

    with console.status(f"[bold green] :brain: Running {tasks_len} test commands for nxc v{version}..."):
        start_time = time()
        passed = 0
        failed = 0

        while tasks:
            task = str(tasks.pop(0))
            # replace double quotes with single quotes for Linux due to special chars/escaping
            if platform.system() == "Linux":
                task = task.replace('"', "'")

            # we print the command before running because very often things will timeout and we want the last thing ran
            console.log(f"Running command: {task}")
            result = subprocess.Popen(
                task,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=abspath(join(dirname(__file__), "..")),
            )

            # pass in a "y" for things that prompt for it (--ndts, etc)
            text = result.communicate(input=b"y")[0]
            return_code = result.returncode

            if return_code == 0 and "Traceback (most recent call last)" not in text.decode("utf-8"):
                console.log(f"└─$ {task.strip()} [bold green]:heavy_check_mark:[/]")
                passed += 1
            else:
                console.log(f"[bold red]{task.strip()} :cross_mark:[/]")
                failures.append(task.strip())
                failed += 1

            if args.errors:
                raw_text = text.decode("utf-8")
                # this is not a good way to detect errors, but it does catch a lot of things
                if "error" in raw_text.lower() or "failure" in raw_text.lower() or "Traceback (most recent call last)" in raw_text:
                    console.log("[bold red]Error Detected:")
                    console.log(f"{raw_text}")

            if args.verbose:
                # this prints sorta janky, but it does its job
                console.log(f"[*] Results:\n{text.decode('utf-8')}")

        if failures:
            console.log("[bold red]Failed Commands:")
            for failure in failures:
                console.log(f"[bold red]{failure}")
        console.log(f"Ran {tasks_len} tests in {int((time() - start_time) / 60)} mins and {int((time() - start_time) % 60)} seconds - [bold green] Passed: {passed} [bold red] Failed: {failed}")


if __name__ == "__main__":
    parsed_args = get_cli_args()
    run_e2e_tests(parsed_args)
