from os import path
from nxc.paths import DATA_PATH
from nxc.helpers.args import DisplayDefaultsNotNone, DefaultTrackingAction


def proto_args(parser, parents):
    mssql_parser = parser.add_parser("mssql", help="own stuff using MSSQL", parents=parents, formatter_class=DisplayDefaultsNotNone)
    mssql_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    mssql_parser.add_argument("--port", default=1433, type=int, metavar="PORT", help="MSSQL port")
    mssql_parser.add_argument("--mssql-timeout", help="SQL server connection timeout", type=int, default=5)
    mssql_parser.add_argument("-q", "--query", metavar="QUERY", type=str, help="execute the specified query against the mssql db")
    mssql_parser.add_argument("--database", nargs="?", const=True, metavar="NAME", help="list databases or list tables for NAME")

    dgroup = mssql_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, help="domain name")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    cgroup = mssql_parser.add_argument_group("Credential Gathering")
    cgroup.add_argument("--sam", action="store_true", help="dump SAM hashes from target systems")
    cgroup.add_argument("--lsa", action="store_true", help="dump LSA secrets from target systems")
    cgroup = mssql_parser.add_argument_group("Command Execution")
    cgroup.add_argument("--exec-method", choices={"mssqlexec", "oleexec", "clrexec"}, default="wmiexec", help="method to execute the command. Ignored if in MSSQL mode", action=DefaultTrackingAction)
    cgroup.add_argument("--clr-assembly", default=f"{path.join(DATA_PATH, 'mssql_clr/default_cmd_assembly.dll')}", help="Path to the .NET assembly to execute via clrexec. If not provided, uses the built-in assembly.", action=DefaultTrackingAction)
    cgroup.add_argument("--clr-classname", default="StoredProcedures", help="CLR class name in the assembly (default: StoredProcedures)")
    cgroup.add_argument("--clr-method", default="ExecuteCommand", help="CLR method name in the assembly (default: ExecuteCommand)")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    xgroup = cgroup.add_mutually_exclusive_group()
    xgroup.add_argument("-x", metavar="COMMAND", dest="execute", nargs="?", const=True, help="execute the specified command")
    xgroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", nargs="?", const=True, help="execute the specified PowerShell command")

    psgroup = mssql_parser.add_argument_group("Powershell Options")
    psgroup.add_argument("--force-ps32", action="store_true", default=False, help="Force the PowerShell command to run in a 32-bit process via a job; WARNING: depends on the job completing quickly, so you may have to increase the timeout")
    psgroup.add_argument("--obfs", action="store_true", default=False, help="Obfuscate PowerShell ran on target; WARNING: Defender will almost certainly trigger on this")
    psgroup.add_argument("--amsi-bypass", nargs=1, metavar="FILE", type=str, help="File with a custom AMSI bypass")
    psgroup.add_argument("--clear-obfscripts", action="store_true", help="Clear all cached obfuscated PowerShell scripts")
    psgroup.add_argument("--no-encode", action="store_true", default=False, help="Do not encode the PowerShell command ran on target")

    tgroup = mssql_parser.add_argument_group("File Operations")
    tgroup.add_argument("--put-file", nargs=2, metavar=("SRC_FILE", "DEST_FILE"), help="Put a local file into remote target, ex: whoami.txt C:\\\\Windows\\\\Temp\\\\whoami.txt")
    tgroup.add_argument("--get-file", nargs=2, metavar=("SRC_FILE", "DEST_FILE"), help="Get a remote file, ex: C:\\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")

    mapping_enum_group = mssql_parser.add_argument_group("Mapping/Enumeration")
    mapping_enum_group.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID", help="enumerate users by bruteforcing RIDs")
    return parser
