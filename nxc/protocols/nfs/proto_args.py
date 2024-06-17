def proto_args(parser, parents):
    ldap_parser = parser.add_parser("nfs", help="NFS", parents=parents)
    ldap_parser.add_argument("--port", type=int, default=111, help="NFS port (default: 111)")

    dgroup = ldap_parser.add_argument_group("NFS Mapping/Enumeration", "Options for Mapping/Enumerating NFS")
    dgroup.add_argument("--shares", action="store_true", help="Authenticate locally to each target")
    dgroup.add_argument("--shares-list", action="store_true", help="Listing enumerated shares")

    return parser
