from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    mysql_parser = parser.add_parser("mysql", help="own stuff using MySQL", parents=parents, formatter_class=DisplayDefaultsNotNone)
    mysql_parser.add_argument("--port", type=int, default=3306, help="MySQL port")

    cgroup = mysql_parser.add_argument_group("Database Operations", "Options for interacting with MySQL databases")
    cgroup.add_argument("-q", "--query", metavar="SQL_QUERY", help="Execute a custom SQL query")
    cgroup.add_argument("--databases", action="store_true", help="List all databases")
    cgroup.add_argument("--tables", metavar="DATABASE", help="List tables in specified database")
    cgroup.add_argument("--dump-database", "--dump", dest="dump_database", metavar="DATABASE", help="Dump database structure and data")
    cgroup.add_argument("--server-capabilities", "--capabilities", dest="server_capabilities", action="store_true", help="Get server capabilities")
    return parser
