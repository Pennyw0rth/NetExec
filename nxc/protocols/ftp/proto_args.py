from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    ftp_parser = parser.add_parser("ftp", help="own stuff using FTP", parents=parents, formatter_class=DisplayDefaultsNotNone)
    ftp_parser.add_argument("--port", type=int, default=21, help="FTP port")

    cgroup = ftp_parser.add_argument_group("File Operations", "Options for enumerating and interacting with files on the target")
    cgroup.add_argument("--ls", metavar="DIRECTORY", nargs="?", const=".", help="List files in the directory")
    cgroup.add_argument("--get", metavar="FILE", help="Download a file")
    cgroup.add_argument("--put", metavar=("LOCAL_FILE", "REMOTE_FILE"), nargs=2, help="Upload a file")
    return parser
