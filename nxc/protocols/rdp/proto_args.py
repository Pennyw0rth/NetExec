from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    rdp_parser = parser.add_parser("rdp", help="own stuff using RDP", parents=parents, formatter_class=DisplayDefaultsNotNone)
    rdp_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    rdp_parser.add_argument("--port", type=int, default=3389, help="RDP port")
    rdp_parser.add_argument("--rdp-timeout", type=int, default=5, help="RDP timeout on socket connection")
    rdp_parser.add_argument("--nla-screenshot", action="store_true", help="Screenshot RDP login prompt if NLA is disabled")

    dgroup = rdp_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    egroup = rdp_parser.add_argument_group("Screenshot", "Remote Desktop Screenshot")
    egroup.add_argument("--screenshot", action="store_true", help="Screenshot RDP if connection success")
    egroup.add_argument("--screentime", type=int, default=10, help="Time to wait for desktop image")
    egroup.add_argument("--res", default="1024x768", help="Resolution in WIDTHxHEIGHT format")

    return parser
