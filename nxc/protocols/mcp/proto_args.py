from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    mcp_parser = parser.add_parser(
        "mcp",
        help="own stuff using MCP",
        parents=parents,
        formatter_class=DisplayDefaultsNotNone,
    )
    mcp_parser.add_argument("--port", type=int, default=8000, help="MCP server port")
    mcp_parser.add_argument("--path", default="/mcp/", help="MCP endpoint path")
    mcp_parser.add_argument("--ssl", action="store_true", help="Use HTTPS instead of HTTP")

    group = mcp_parser.add_argument_group("MCP operations")
    group.add_argument("--list", action="store_true", help="List prompts, resources, templates and tools")
    group.add_argument("--resource", metavar="URI", help="Read a resource (e.g. resource://debug)")
    group.add_argument("--tool", metavar="NAME", help="Call a tool")
    group.add_argument("--tool-args", default="{}", help='Tool arguments as JSON (e.g. \'{"id": "1"}\')')
    group.add_argument("--prompt", metavar="NAME", help="Retrieve a prompt")
    group.add_argument("--prompt-args", default="{}", help='Prompt arguments as JSON (e.g. \'{"text": "Hello"}\')')
    return parser
