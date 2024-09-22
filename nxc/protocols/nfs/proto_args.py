def proto_args(parser, parents):
    nfs_parser = parser.add_parser("nfs", help="NFS", parents=parents)
    nfs_parser.add_argument("--port", type=int, default=111, help="NFS port (default: %(default)s)")

    dgroup = nfs_parser.add_argument_group("NFS Mapping/Enumeration", "Options for Mapping/Enumerating NFS")
    dgroup.add_argument("--shares", action="store_true", help="List NFS shares with UID 0")
    dgroup.add_argument("--enum-shares", nargs="?", type=int, const=1, help="Authenticate and enumerate exposed shares recursively (default depth: %(default)s)")
    dgroup.add_argument("--uid-brute", nargs="?", type=int, const=4000, metavar="MAX_UID", help="Enumerate shares by bruteforcing UIDs")

    return parser
