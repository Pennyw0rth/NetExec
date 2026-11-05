from nxc.helpers.args import DisplayDefaultsNotNone


DEFAULT_CREDS = [
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "postgres123"),
    ("postgres", "admin"),
    ("postgres", "changeme"),
    ("admin", "admin"),
    ("admin", "password"),
    ("pgadmin", "pgadmin"),
    ("postgres", "test1234"),
]


def proto_args(parser, parents):
    pg_parser = parser.add_parser(
        "postgres",
        help="own stuff using PostgreSQL",
        parents=parents,
        formatter_class=DisplayDefaultsNotNone,
    )
    pg_parser.add_argument("--port", type=int, default=5432, help="PostgreSQL port")
    pg_parser.add_argument("--database", default="postgres", help="Target database to connect to")
    pg_parser.add_argument("--postgres-timeout", type=int, default=5, help="Connection timeout in seconds")
    pg_parser.add_argument(
        "--default-creds",
        action="store_true",
        help="Try a built-in list of common default PostgreSQL credentials instead of -u/-p",
    )

    files_group = pg_parser.add_argument_group("File Operations")
    files_group.add_argument("--put-file", action="append", nargs=2, metavar="FILE", help="Put a local file into remote target, ex: whoami.txt /tmp/whoami.txt")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="Get a remote file, ex: /tmp/whoami.txt whoami.txt")

    return parser
