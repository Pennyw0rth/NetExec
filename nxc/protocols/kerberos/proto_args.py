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

    # Performance tuning
    perf_group = kerberos_parser.add_argument_group(
        "Performance",
        "Options to tune enumeration performance"
    )

    perf_group.add_argument(
        "--delay",
        type=float,
        default=0,
        metavar="SECONDS",
        help="Delay between requests in seconds (for stealth or rate limiting)"
    )

    return parser
