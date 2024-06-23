from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    mssql_parser = parser.add_parser("mssql", help="own stuff using MSSQL", parents=parents, formatter_class=DisplayDefaultsNotNone)
    mssql_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    mssql_parser.add_argument("--port", default=1433, type=int, metavar="PORT", help="MSSQL port")
    mssql_parser.add_argument("--mssql-timeout", help="SQL server connection timeout", type=int, default=5)
    mssql_parser.add_argument("-q", "--query", dest="mssql_query", metavar="QUERY", type=str, help="execute the specified query against the MSSQL DB")

    dgroup = mssql_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, help="domain name")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    cgroup = mssql_parser.add_argument_group("Command Execution", "options for executing commands")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    xgroup = cgroup.add_mutually_exclusive_group()
    xgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")
    xgroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="execute the specified PowerShell command")

    psgroup = mssql_parser.add_argument_group("Powershell Options", "Options for PowerShell execution")
    psgroup.add_argument("--force-ps32", action="store_true", default=False, help="Force the PowerShell command to run in a 32-bit process via a job; WARNING: depends on the job completing quickly, so you may have to increase the timeout")
    psgroup.add_argument("--obfs", action="store_true", default=False, help="Obfuscate PowerShell ran on target; WARNING: Defender will almost certainly trigger on this")
    psgroup.add_argument("--amsi-bypass", nargs=1, metavar="FILE", type=str, help="File with a custom AMSI bypass")
    psgroup.add_argument("--clear-obfscripts", action="store_true", help="Clear all cached obfuscated PowerShell scripts")
    psgroup.add_argument("--no-encode", action="store_true", default=False, help="Do not encode the PowerShell command ran on target")

    tgroup = mssql_parser.add_argument_group("Files", "Options for put and get remote files")
    tgroup.add_argument("--put-file", nargs=2, metavar=("SRC_FILE", "DEST_FILE"), help="Put a local file into remote target, ex: whoami.txt C:\\\\Windows\\\\Temp\\\\whoami.txt")
    tgroup.add_argument("--get-file", nargs=2, metavar=("SRC_FILE", "DEST_FILE"), help="Get a remote file, ex: C:\\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")

    return parser