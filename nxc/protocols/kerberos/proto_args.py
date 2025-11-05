from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    """Define CLI arguments for the Kerberos protocol"""
    kerberos_parser = parser.add_parser(
        "kerberos",
        help="Kerberos user enumeration (no badPwdCount increment)",
        parents=parents,
        formatter_class=DisplayDefaultsNotNone
    )

    # Basic connection arguments
    kerberos_parser.add_argument(
        "--port",
        type=int,
        default=88,
        help="Kerberos port (default: 88)"
    )

    kerberos_parser.add_argument(
        "-d",
        metavar="DOMAIN",
        dest="domain",
        type=str,
        required=True,
        help="Domain to enumerate"
    )

    kerberos_parser.add_argument(
        "--dc-ip",
        dest="kdcHost",
        metavar="DC_IP",
        help="IP address or FQDN of the Domain Controller (KDC)"
    )

    kerberos_parser.add_argument(
        "--users-export",
        help="Enumerate domain users and export them to the specified file"
    )

    return parser
