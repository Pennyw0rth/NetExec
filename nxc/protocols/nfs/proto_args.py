def proto_args(parser, parents):
    nfs_parser = parser.add_parser("nfs", help="own stuff using NFS", parents=parents)
    nfs_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NT hash(es) to use for Kerberos authentication")
    nfs_parser.add_argument("-d", "--domain", metavar="DOMAIN", dest="domain", help="Kerberos realm/domain")
    nfs_parser.add_argument("--port", type=int, help="RPC port (default: 2049 for NFSv4, rpcbind 111 for NFSv3)")
    nfs_parser.add_argument("--nfs-version", type=int, choices=(3, 4), default=3, help="NFS protocol version (default: %(default)s)")
    nfs_parser.add_argument("--nfs-auth", choices=("none", "sys", "krb5", "krb5i", "krb5p"), default="sys", help="NFS security flavor (default: %(default)s)")
    nfs_parser.add_argument("--nfs-timeout", type=int, default=2, help="NFS connection timeout (default: %(default)ss)")

    dgroup = nfs_parser.add_argument_group("NFS Mapping/Enumeration")
    dgroup.add_argument("--share", help="Specify a share, e.g. for --ls, --get-file, --put-file")
    dgroup.add_argument("--shares", action="store_true", help="List NFS shares")
    dgroup.add_argument("--enum-shares", nargs="?", type=int, const=3, help="Authenticate and enumerate exposed shares recursively (default depth: %(const)s)")
    dgroup.add_argument("--ls", const="/", nargs="?", metavar="PATH", help="List files in the specified NFS share. Example: --ls /")
    dgroup.add_argument("--cat", metavar="FILE", help="Display the contents of an NFS file. Example: --cat /path/to/file")
    dgroup.add_argument("--get-file", nargs=2, metavar="FILE", help="Download remote NFS file. Example: --get-file remote_file local_file")
    dgroup.add_argument("--put-file", nargs=2, metavar="FILE", help="Upload remote NFS file with chmod 777 permissions to the specified folder. Example: --put-file local_file remote_file")
    dgroup.add_argument("--chmod", nargs=2, metavar=("PERMISSIONS", "FILE"), help="Change permissions of remote NFS file. Example: --chmod 777 /path/to/file")

    return parser
