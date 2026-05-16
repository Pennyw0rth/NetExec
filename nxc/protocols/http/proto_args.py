from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    http_parser = parser.add_parser("http", help="own stuff using HTTP/HTTPS", parents=parents, formatter_class=DisplayDefaultsNotNone)
    http_parser.add_argument("--port", type=int, default=80, help="HTTP(S) port")
    http_parser.add_argument("--ssl", action="store_true", help="Force HTTPS (auto-enabled for ports 443, 8443)")
    http_parser.add_argument("--no-verify", action="store_true", help="Do not verify TLS certificates")
    http_parser.add_argument("--path", default="/", help="Request path to probe for service/title")
    http_parser.add_argument("--user-agent", default=None, help="Custom User-Agent string")
    http_parser.add_argument("--http-timeout", type=int, default=10, help="HTTP request timeout in seconds")
    http_parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects when probing")
    http_parser.add_argument("--proxy", default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")

    egroup = http_parser.add_argument_group("HTTP", "HTTP Probing")
    egroup.add_argument("--auth-type", choices=["basic", "digest"], default="basic", help="HTTP authentication scheme to use when credentials are supplied")
    egroup.add_argument("--check-auth-path", default=None, help="Override the path used to validate HTTP credentials (defaults to --path)")

    return parser
