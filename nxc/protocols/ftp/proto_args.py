def proto_args(parser, std_parser, module_parser):
    ftp_parser = parser.add_parser("ftp", help="own stuff using FTP", parents=[std_parser, module_parser])
    ftp_parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")

    cgroup = ftp_parser.add_argument_group("FTP Access", "Options for enumerating your access")
    cgroup.add_argument("--ls", metavar="DIRECTORY", nargs="?", const=".", help="List files in the directory, ex: --ls or --ls Directory")
    cgroup.add_argument("--get", metavar="FILE", help="Download a file, ex: --get fileName.txt")
    cgroup.add_argument("--put", metavar=("LOCAL_FILE", "REMOTE_FILE"), nargs=2, help="Upload a file, ex: --put inputFileName.txt outputFileName.txt")
    return parser
