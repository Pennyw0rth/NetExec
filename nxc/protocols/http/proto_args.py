def proto_args(parser, parents):
    http_parser = parser.add_parser("http", help="HTTP Basic authentication checks", parents=parents)

    http_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP port (default: 80 or 443 with --ssl)",
    )
    http_parser.add_argument("--ssl", action="store_true", help="Use HTTPS")
    http_parser.add_argument("--path", default="/", help="Request path (default: /)")
    http_parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    http_parser.add_argument("--vhost", help="Override Host header (virtual host)")
    http_parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (useful for self-signed certs)")
    http_parser.add_argument("--ca-file", dest="ca_file", help="CA bundle / CA file to verify TLS certificates")

    return parser
