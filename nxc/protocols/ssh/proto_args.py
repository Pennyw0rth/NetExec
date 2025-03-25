from argparse import _StoreAction
from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    ssh_parser = parser.add_parser("ssh", help="own stuff using SSH", parents=parents, formatter_class=DisplayDefaultsNotNone)
    ssh_parser.add_argument("--key-file", type=str, help="Authenticate using the specified private key. Treats the password parameter as the key's passphrase.")
    ssh_parser.add_argument("--port", type=int, default=22, help="SSH port")
    ssh_parser.add_argument("--ssh-timeout", help="SSH connection timeout", type=int, default=15)
    sudo_check_arg = ssh_parser.add_argument("--sudo-check", action="store_true", help="Check user privilege with sudo")
    sudo_check_method_arg = ssh_parser.add_argument("--sudo-check-method", action=get_conditional_action(_StoreAction), make_required=[], choices={"sudo-stdin", "mkfifo"}, default="sudo-stdin", help="method to do with sudo check (mkfifo is non-stable, probably you need to execute once again if it failed)'")
    ssh_parser.add_argument("--get-output-tries", type=int, default=5, help="Number of times with sudo command tries to get results")
    sudo_check_method_arg.make_required.append(sudo_check_arg)

    files_group = ssh_parser.add_argument_group("Files", "Options for remote file interaction")
    files_group.add_argument("--put-file", action="append", nargs=2, metavar="FILE", help="Put a local file into remote target, ex: whoami.txt /tmp/whoami.txt")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="Get a remote file, ex: /tmp/whoami.txt whoami.txt")

    cgroup = ssh_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("--codec", default="utf-8", help="Set encoding used (codec) from the target's output. If errors are detected, run chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")

    return parser

def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop("make_required", [])
            super().__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super().__call__(parser, namespace, values, option_string)

    return ConditionalAction