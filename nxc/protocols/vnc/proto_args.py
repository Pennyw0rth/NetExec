from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    vnc_parser = parser.add_parser("vnc", help="own stuff using VNC", parents=parents, formatter_class=DisplayDefaultsNotNone)
    vnc_parser.add_argument("--port", type=int, default=5900, help="VNC port")
    vnc_parser.add_argument("--vnc-sleep", type=int, default=5, help="VNC Sleep on socket connection to avoid rate limit")

    egroup = vnc_parser.add_argument_group("Screenshot", "VNC Server")
    egroup.add_argument("--screenshot", action="store_true", help="Screenshot VNC if connection success")
    egroup.add_argument("--screentime", type=int, default=5, help="Time to wait for desktop image")

    return parser
