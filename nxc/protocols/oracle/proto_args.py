from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    oracle_parser = parser.add_parser("oracle", help="own stuff using Oracle Database", parents=parents, formatter_class=DisplayDefaultsNotNone)
    oracle_parser.add_argument("--port", type=int, default=1521, help="Oracle TNS listener port")
    oracle_parser.add_argument("--oracle-timeout", type=int, default=5, help="Oracle connection timeout")

    tgroup = oracle_parser.add_argument_group("Target Instance")
    igroup = tgroup.add_mutually_exclusive_group()
    igroup.add_argument("--service-name", metavar="NAME", help="Oracle service name to connect to (e.g. XEPDB1, ORCL)")
    igroup.add_argument("--sid", metavar="SID", help="Oracle System Identifier (legacy SID) to connect to (e.g. XE)")

    egroup = oracle_parser.add_argument_group("Enumeration")
    egroup.add_argument("--enum-sids", action="store_true", help="probe common SIDs and service names without credentials")
    egroup.add_argument("--database", nargs="?", const=True, metavar="SCHEMA", help="list pluggable databases, or list tables for SCHEMA")
    egroup.add_argument("--users", action="store_true", help="enumerate database users/accounts")
    egroup.add_argument("--roles", action="store_true", help="show current session roles and system privileges")
    egroup.add_argument("--tablespaces", action="store_true", help="list tablespaces")
    egroup.add_argument("--dblinks", action="store_true", help="enumerate database links")
    egroup.add_argument("--dump-hashes", action="store_true", help="dump password hashes from sys.user$ (requires --sysdba)")
    egroup.add_argument("-q", "--query", metavar="QUERY", type=str, help="execute the specified SQL query")

    rgroup = oracle_parser.add_argument_group("Connection Privilege")
    privgroup = rgroup.add_mutually_exclusive_group()
    privgroup.add_argument("--sysdba", action="store_true", help="Connect with the SYSDBA administrative role")
    privgroup.add_argument("--sysoper", action="store_true", help="Connect with the SYSOPER administrative role")
    return parser
