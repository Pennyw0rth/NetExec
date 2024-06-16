def proto_args(parser, parents):
    wmi_parser = parser.add_parser("wmi", help="own stuff using WMI", conflict_handler="resolve", parents=parents)
    wmi_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    wmi_parser.add_argument("--port", type=int, choices={135}, default=135, help="WMI port (default: 135)")
    wmi_parser.add_argument("--rpc-timeout", help="RPC/DCOM(WMI) connection timeout, default is %(default)s seconds", type=int, default=2)

    # For domain options
    dgroup = wmi_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", default=None, type=str, help="Domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="Authenticate locally to each target")

    egroup = wmi_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
    egroup.add_argument("--wmi", metavar="QUERY", dest="wmi", type=str, help="Issues the specified WMI query")
    egroup.add_argument("--wmi-namespace", metavar="NAMESPACE", type=str, default="root\\cimv2", help="WMI Namespace (default: root\\cimv2)")

    cgroup = wmi_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", type=str, help="Creates a new cmd process and executes the specified command with output")
    cgroup.add_argument("--exec-method", choices={"wmiexec", "wmiexec-event"}, default="wmiexec", help="method to execute the command. (default: wmiexec). [wmiexec (win32_process + StdRegProv)]: get command results over registry instead of using smb connection. [wmiexec-event (T1546.003)]: this method is not very stable, highly recommend use this method in single host, using on multiple hosts may crash (just try again if it crashed).")
    cgroup.add_argument("--exec-timeout", default=5, metavar="exec_timeout", dest="exec_timeout", type=int, help="Set timeout (in seconds) when executing a command, minimum 5 seconds is recommended. Default: %(default)s")
    cgroup.add_argument("--codec", default="utf-8", help="Set encoding used (codec) from the target's output (default: utf-8). If errors are detected, run chcp.com at the target & map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec")
    return parser


def get_conditional_action(base_action):
    class ConditionalAction(base_action):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop("make_required", [])
            super().__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super().__call__(parser, namespace, values, option_string)

    return ConditionalAction
