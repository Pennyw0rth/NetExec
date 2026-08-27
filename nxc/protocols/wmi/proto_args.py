from argparse import _StoreTrueAction
from nxc.helpers.args import get_conditional_action

def proto_args(parser, parents):
    wmi_parser = parser.add_parser("wmi", help="own stuff using WMI", conflict_handler="resolve", parents=parents)
    wmi_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    wmi_parser.add_argument("--port", type=int, choices={135}, default=135, help="WMI port (default: 135)")
    wmi_parser.add_argument("--rpc-timeout", help="RPC/DCOM(WMI) connection timeout, default is %(default)s seconds", type=int, default=2)

    # For domain options
    dgroup = wmi_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", default=None, type=str, help="Domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="Authenticate locally to each target")

    cred_gathering_group = wmi_parser.add_argument_group("Credential Gathering")
    cred_gathering_group.add_argument("--list-snapshots", nargs="?", dest="list_snapshots", const="ADMIN$", help="Lists the VSS snapshots (default: %(const)s)")
    cred_gathering_group.add_argument("--sam", action="store_true", help="dump SAM hashes from target systems")
    cred_gathering_group.add_argument("--lsa", action="store_true", help="dump LSA secrets from target systems")
    cred_gathering_group.add_argument("--ntds", action="store_true", help="dump the NTDS.dit from target DCs")
    ntds_arg = cred_gathering_group.add_argument("--ntds", action="store_true", help="dump the NTDS.dit from target DCs")
    cred_gathering_group.add_argument("--history", action="store_true", help="Also retrieve password history (NTDS.dit or SAM)")
    # NTDS options
    kerb_keys_arg = cred_gathering_group.add_argument("--kerberos-keys", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Also dump Kerberos AES and DES keys from target DC (NTDS.dit)")
    exclusive = cred_gathering_group.add_mutually_exclusive_group()
    enabled_arg = exclusive.add_argument("--enabled", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Only dump enabled targets from DC (NTDS.dit)")
    kerb_keys_arg.make_required = [ntds_arg]
    enabled_arg.make_required = [ntds_arg]
    cred_gathering_group.add_argument("--user", dest="userntds", type=str, help="Dump selected user from DC (NTDS.dit)")

    egroup = wmi_parser.add_argument_group("Mapping/Enumeration")
    egroup.add_argument("--wmi-query", metavar="QUERY", dest="wmi_query", type=str, help="Issues the specified WMI query")
    egroup.add_argument("--wmi-namespace", metavar="NAMESPACE", type=str, default="root\\cimv2", help="WMI Namespace (default: %(default)s)")

    files_group = wmi_parser.add_argument_group("File Operations")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="Get a remote file, ex: \\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")
    files_group.add_argument("--append-host", action="store_true", help="append the host to the get-file filename")

    cgroup = wmi_parser.add_argument_group("Command Execution")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", type=str, help="Creates a new cmd process and executes the specified command with output")
    cgroup.add_argument("-X", metavar="COMMAND", dest="execute_psh", type=str, help="Creates a new PowerShell process and executes the specified command with output")
    cgroup.add_argument("--exec-method", choices={"wmiexec", "wmiexec-event"}, default="wmiexec", help="method to execute the command. (default: wmiexec). [wmiexec (win32_process + StdRegProv)]: get command results over registry instead of using smb connection. [wmiexec-event (T1546.003)]: this method is not very stable, highly recommend use this method in single host, using on multiple hosts may crash (just try again if it crashed).")
    cgroup.add_argument("--exec-timeout", default=2, metavar="exec_timeout", dest="exec_timeout", type=int, help="Set timeout (in seconds) when executing a command, minimum 5 seconds is recommended. Default: %(default)s")
    cgroup.add_argument("--codec", default="utf-8", help="Set encoding used (codec) from the target's output (default: utf-8). If errors are detected, run chcp.com at the target & map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec")

    return parser
