#!/usr/bin/env python3
"""NetExec protocol for MCP (Model Context Protocol) servers over Streamable HTTP."""

import asyncio
import base64
import json
import socket

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from nxc.config import process_secret
from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.logger import NXCAdapter


class mcp(connection):
    def __init__(self, args, db, host):
        self.protocol = "MCP"
        self.server_info = {}
        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "MCP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    # ------------------------------------------------------------------
    # Transport helpers
    # ------------------------------------------------------------------
    def _build_transport(self, username=None, password=None):
        scheme = "https" if self.args.ssl else "http"
        headers = {}
        if username is not None and password is not None:
            creds = f"{username}:{password}"
            headers["Authorization"] = "Basic " + base64.b64encode(creds.encode("utf-8")).decode("utf-8")
        path = self.args.path if self.args.path.startswith("/") else "/" + self.args.path
        url = f"{scheme}://{self.host}:{self.port}{path}"
        return StreamableHttpTransport(url=url, headers=headers)

    def _current_transport(self):
        """Transport with the working credentials (or anonymous if none)."""
        if self.username or self.password:
            return self._build_transport(self.username, self.password)
        return self._build_transport()

    async def _handshake(self, transport):
        """Open an MCP session and return (server_info, tools)."""
        async with Client(transport) as client:
            server_info = {}
            for attr in ("server_info", "_server_info"):
                val = getattr(client, attr, None)
                if val and not callable(val):
                    server_info = val
                    break
            tools = await client.list_tools()
            return server_info, tools

    async def _check_auth(self, transport):
        """Authentication check = can we list tools with these credentials?"""
        await self._handshake(transport)

    # ------------------------------------------------------------------
    # NetExec connection lifecycle
    # ------------------------------------------------------------------
    def create_conn_obj(self):
        # 1) TCP reachability - this is the real liveness check
        try:
            sock = socket.create_connection((self.host, self.port), timeout=5)
            sock.close()
        except OSError as e:
            self.logger.debug(f"TCP connection to {self.host}:{self.port} failed: {e}")
            return False

        # 2) Optional anonymous handshake to grab server info.
        #    A 401 just means "auth required" - the host is still alive.
        try:
            transport = self._build_transport()
            self.server_info, _ = asyncio.run(self._handshake(transport))
        except Exception as e:
            msg = str(e)
            if "401" in msg or "Unauthorized" in msg:
                self.logger.debug("MCP server requires authentication (401 on anonymous initialize)")
            else:
                self.logger.debug(f"Anonymous MCP handshake failed: {e}")
            self.server_info = {}
        return True

    def enum_host_info(self):
        pass

    def print_host_info(self):
        if isinstance(self.server_info, dict) and self.server_info:
            name = self.server_info.get("name", "unknown")
            version = self.server_info.get("version", "?")
            self.logger.display(f"MCP server: {name} (version {version})")
        elif self.server_info:
            self.logger.display(f"MCP server: {self.server_info}")
        else:
            self.logger.display("MCP server reachable (server info requires authentication)")

    def plaintext_login(self, username, password):
        # MCP has no native credential mechanism: a classic implementation of auth is HTTP Basic at transport level,
        # So "logging in" = authenticated tools/list works.
        # Other authentication mechanisms are not supported for the moment. May be improved in the future.
        transport = self._build_transport(username, password)
        try:
            asyncio.run(self._check_auth(transport))
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} ({e})")
            return False

        self.username = username
        self.password = password

        banner = json.dumps(self.server_info) if self.server_info else ""
        self.db.add_host(self.host, self.port, banner)

        cred_id = self.db.add_credential(username, password)
        host_id = self.db.get_hosts(self.host)[0].id
        self.db.add_loggedin_relation(cred_id, host_id)

        self.logger.success(f"{username}:{process_secret(password)}")

        if not self.args.continue_on_success:
            return True

    def hash_login(self, domain, username, secret):
        self.logger.fail("Hash login is not supported for MCP (HTTP Basic auth only for the moment)")
        return False

    def disconnect(self):
        pass

    # ------------------------------------------------------------------
    # Command arguments
    # connection.call_cmd_args() invokes them automatically after login
    # (or even without credentials, since proto_flow() falls through to call_cmd_args() when no username/password were supplied).
    # ------------------------------------------------------------------
    def list(self):
        asyncio.run(self._cmd_list(self._current_transport()))

    def resource(self):
        asyncio.run(self._cmd_resource(self._current_transport(), self.args.resource))

    def tool(self):
        try:
            tool_args = json.loads(self.args.tool_args)
        except json.JSONDecodeError as e:
            self.logger.fail(f"Invalid JSON in --tool-args: {e}")
            return
        asyncio.run(self._cmd_tool(self._current_transport(), self.args.tool, tool_args))

    def prompt(self):
        try:
            prompt_args = json.loads(self.args.prompt_args)
        except json.JSONDecodeError as e:
            self.logger.fail(f"Invalid JSON in --prompt-args: {e}")
            return
        asyncio.run(self._cmd_prompt(self._current_transport(), self.args.prompt, prompt_args))

    # ------------------------------------------------------------------
    # MCP operations
    # ------------------------------------------------------------------
    async def _cmd_list(self, transport):
        async with Client(transport) as client:
            prompts = await client.list_prompts()
            resources = await client.list_resources()
            templates = await client.list_resource_templates()
            tools = await client.list_tools()

        self.logger.display("TOOLS")
        if tools:
            for t in tools:
                params = list(t.input_schema.get("properties", {}).keys())
                self.logger.highlight(f"  \u2022 {t.name}({', '.join(params)})")
                if t.description:
                    self.logger.highlight(f"    {t.description.strip()}")
        else:
            self.logger.highlight("  (none)")

        self.logger.display("RESOURCES")
        for r in resources or []:
            self.logger.highlight(f"  \u2022 {r.name} - URI: {r.uri!r}")
            if r.description:
                self.logger.highlight(f"    {r.description.strip()}")

        self.logger.display("RESOURCE TEMPLATES")
        for rt in templates or []:
            self.logger.highlight(f"  \u2022 {rt.name} - URI: {rt.uri_template!r}")
            if rt.description:
                self.logger.highlight(f"    {rt.description.strip()}")

        self.logger.display("PROMPTS")
        for p in prompts or []:
            self.logger.highlight(f"  \u2022 {p.name}")
            if p.description:
                self.logger.highlight(f"    {p.description.strip()}")

    async def _cmd_resource(self, transport, uri):
        async with Client(transport) as client:
            result = await client.read_resource(uri)
        for item in result:
            self.logger.highlight(item.text if hasattr(item, "text") else str(item))

    async def _cmd_tool(self, transport, name, args_dict):
        async with Client(transport) as client:
            result = await client.call_tool(name, args_dict)
        for item in result.content:
            self.logger.highlight(item.text if hasattr(item, "text") else str(item))

    async def _cmd_prompt(self, transport, name, args_dict):
        async with Client(transport) as client:
            result = await client.get_prompt(name, args_dict)
        for msg in result.messages:
            self.logger.highlight(msg.content.text if hasattr(msg.content, "text") else str(msg.content))
