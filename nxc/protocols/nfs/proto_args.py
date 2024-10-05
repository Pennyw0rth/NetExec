def proto_args(parser, parents):
    nfs_parser = parser.add_parser("nfs", help="own stuff using NFS", parents=parents)
    nfs_parser.add_argument("--port", type=int, default=111, help="NFS portmapper port (default: %(default)s)")
    nfs_parser.add_argument("--nfs-timeout", type=int, default=30, help="NFS connection timeout (default: %(default)ss)")

    dgroup = nfs_parser.add_argument_group("NFS Mapping/Enumeration", "Options for Mapping/Enumerating NFS")
    dgroup.add_argument("--shares", action="store_true", help="List NFS shares")
    dgroup.add_argument("--enum-shares", nargs="?", type=int, const=3, help="Authenticate and enumerate exposed shares recursively (default depth: %(const)s)")
    dgroup.add_argument("--get-file", nargs=2, metavar="FILE", help="Download remote NFS file. Example: --get-file remote_file local_file")
    dgroup.add_argument("--put-file", nargs=2, metavar="FILE", help="Upload remote NFS file with chmod 777 permissions to the specified folder. Example: --put-file local_file remote_file")

    return parser
