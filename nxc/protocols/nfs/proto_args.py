def proto_args(parser, parents):
    nfs_parser = parser.add_parser("nfs", help="own stuff using NFS", parents=parents)
    nfs_parser.add_argument("--port", type=int, default=111, help="NFS portmapper port (default: %(default)s)")
    nfs_parser.add_argument("--nfs-timeout", type=int, default=5, help="NFS connection timeout (default: %(default)ss)")

    dgroup = nfs_parser.add_argument_group("NFS Mapping/Enumeration")
    dgroup.add_argument("--share", help="Specify a share, e.g. for --ls, --get-file, --put-file")
    dgroup.add_argument("--shares", action="store_true", help="List NFS shares")
    dgroup.add_argument("--enum-shares", nargs="?", type=int, const=3, help="Authenticate and enumerate exposed shares recursively (default depth: %(const)s)")
    dgroup.add_argument("--ls", const="/", nargs="?", metavar="PATH", help="List files in the specified NFS share. Example: --ls /")
    dgroup.add_argument("--get-file", nargs=2, metavar="FILE", help="Download remote NFS file. Example: --get-file remote_file local_file")
    dgroup.add_argument("--put-file", nargs=2, metavar="FILE", help="Upload remote NFS file with chmod 777 permissions to the specified folder. Example: --put-file local_file remote_file")

    sgroup = nfs_parser.add_argument_group("Spidering")
    sgroup.add_argument("--spider", nargs="?", const="/", metavar="PATH", help="Spider NFS shares to find readable files. Uses root escape if available, otherwise requires --share. Example: --spider /home")
    sgroup.add_argument("--depth", type=int, default=None, help="Max spider recursion depth (default: unlimited)")
    sgroup.add_argument("--exclude-dirs", type=str, metavar="DIR_LIST", default="", help="Comma-separated directories to exclude from spidering")
    sgroup.add_argument("--all-items", action="store_true", dest="show_all", help="Show all files/directories, including non-readable ones (default: only readable)")
    sgroup.add_argument("--include-dirs", action="store_true", dest="show_dirs", help="Include directories in output (default: only files)")
    segroup = sgroup.add_mutually_exclusive_group()
    segroup.add_argument("--pattern", nargs="+", help="Pattern(s) to search for in filenames")
    segroup.add_argument("--regex", nargs="+", help="Regex(es) to search for in filenames")

    return parser
