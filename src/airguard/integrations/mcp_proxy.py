#!/usr/bin/env python3
"""AIRGuard MCP Proxy Server.

A transparent MCP proxy that sits between any agent (Claude Code CLI, Codex,
Harbor, etc.) and the real MCP server. Intercepts every tool call with
AIRGuard guard checks and post-output credential redaction.

Usage:
    python -m airguard.integrations.mcp_proxy \
        --upstream-url http://localhost:17501/mcp \
        --port 18000 \
        --risk-model gpt-5.4-mini

Then point the agent's MCP config at http://localhost:18000/mcp instead of
the real server.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import asyncio
import logging
from pathlib import Path
from typing import Any

# Ensure airguard is importable
_pkg = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _pkg not in sys.path:
    sys.path.insert(0, _pkg)

from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as McpTool

from airguard.types import (
    Action, AuthorityContext, Issuer, NormalizedAction,
    Outcome, Publisher, Resource, Scope, Subject, TrustTier,
)
from airguard.guard import check_action
from airguard.audit_containment import LedgerStore
from airguard.output_guard import (
    has_credential_leak, is_sensitive_target,
    redact_credentials, should_deny_outcome,
)

logger = logging.getLogger("airguard.mcp_proxy")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_ledger = LedgerStore()
_log: list[dict] = []
_stats = {"checked": 0, "blocked": 0, "allowed": 0, "redacted": 0}
_llm_client: Any = None
_risk_model = "gpt-5.4-mini"

_resource = Resource(
    resource_id="mcp-proxy-tool",
    publisher=Publisher.UNKNOWN_WEB,
    trust_tier=TrustTier.LOW,
    constraints=["no_secret", "no_network", "inspect_before_exec"],
)
_authority = AuthorityContext(
    issuer=Issuer.USER, subject=Subject.AGENT, scope=Scope.TASK,
    allow=["read", "write", "respond"], guard="ask",
    user_intent=os.environ.get("AIRGUARD_USER_TASK", ""),
)


def _init_llm():
    global _llm_client
    key = os.environ.get("AIRGUARD_RISK_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if key:
        try:
            from openai import OpenAI
            _llm_client = OpenAI(api_key=key, timeout=30)
        except Exception as exc:
            logger.warning(f"LLM client init failed: {exc}")


def _normalize(name: str) -> NormalizedAction:
    """Map tool name to NormalizedAction.

    Order matters: destructive and exec checks run first so that names like
    ``delete_readme`` or ``run_query`` are not swallowed by the read branch.
    Matching uses ``_``/``-`` split tokens, not raw substrings, to avoid
    partial-word collisions.
    """
    import re as _re
    tokens = set(_re.split(r"[_\-./\s]+", name.lower()))

    # Destructive first — before read, so delete_readme → FILE_DELETE
    if tokens & {"delete", "remove", "rm", "drop", "purge", "truncate", "destroy"}:
        return NormalizedAction.FILE_DELETE
    # Exec before read — so run_query → PROCESS_EXEC
    if tokens & {"execute", "run", "exec", "bash", "terminal", "shell"}:
        return NormalizedAction.PROCESS_EXEC
    # Read
    if tokens & {"query", "search", "get", "list", "read", "find", "check", "view", "fetch",
                 "browse", "tree", "info", "show", "describe", "lookup", "inspect",
                 "login", "auth"}:
        return NormalizedAction.FILE_READ
    # Write
    if tokens & {"write", "create", "add", "update", "set", "modify", "send", "put", "insert", "append"}:
        return NormalizedAction.FILE_WRITE
    return NormalizedAction.TOOL_CALL


_SENSITIVE_TARGETS = [
    ".bashrc", ".zshrc", ".profile", ".bash_profile",
    ".ssh", ".env", ".aws", "id_rsa",
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "crontab", "systemd", "launchd",
]


def _is_sensitive(args: dict) -> bool:
    for v in args.values():
        if isinstance(v, str):
            vl = v.lower()
            for s in _SENSITIVE_TARGETS:
                if s in vl:
                    return True
    return False


def _guard_check(tool_name: str, tool_args: dict) -> dict:
    """Run AIRGuard check. Returns {blocked, executed, outcome, reason}."""
    # Re-read user_task from env each call (DTAP sets it per-task)
    user_task = os.environ.get("AIRGUARD_USER_TASK", "")
    if user_task and user_task != _authority.user_intent:
        _authority.user_intent = user_task

    na = _normalize(tool_name)
    sensitive = _is_sensitive(tool_args)

    action = Action(
        action_id=f"proxy_{_stats['checked']}",
        name=tool_name, args=tool_args,
        source_resource_id="mcp-proxy-tool",
        required_capabilities=[na.value.split(".")[0]],
        normalized_action=na,
    )

    decision = check_action(
        resource=_resource, authority_ctx=_authority,
        action=action, history=[],
        llm_client=_llm_client, risk_model=_risk_model,
        ledger=_ledger,
    )

    _stats["checked"] += 1
    ov = decision.outcome.value if isinstance(decision.outcome, Outcome) else str(decision.outcome)

    denied = should_deny_outcome(ov)
    if sensitive and na in (NormalizedAction.PROCESS_EXEC, NormalizedAction.FILE_WRITE) and not denied:
        denied = True
        ov = "block"

    if denied:
        _stats["blocked"] += 1
    else:
        _stats["allowed"] += 1

    _log.append({
        "tool_name": tool_name,
        "normalized_action": na.value,
        "airguard_decision": ov,
        "blocked": denied,
        "executed": not denied,
        "sensitive_target": sensitive,
        "llm_risk_used": decision.risk_source == "llm",
        "target_trust_tier": decision.target_trust_tier or "",
        "reason": decision.reasoning,
        "user_task": _authority.user_intent[:200] if _authority.user_intent else "",
        "timestamp": time.time(),
    })

    # Persist log entry immediately (append mode)
    # Try AIRGUARD_LOG_DIR first, then fall back to EVAL_RESULTS_ROOT, then /tmp
    log_dir = (
        os.environ.get("AIRGUARD_LOG_DIR")
        or os.environ.get("EVAL_RESULTS_ROOT")
        or "/tmp"
    )
    log_path = Path(log_dir) / "airguard_log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(_log[-1], ensure_ascii=False, default=str) + "\n")
    except Exception:
        pass  # Don't crash if log write fails

    return {
        "blocked": denied,
        "executed": not denied,
        "outcome": ov,
        "reason": decision.reasoning,
    }


def _scan_output(tool_name: str, text: str) -> str:
    """Redact credentials from tool output."""
    if text and has_credential_leak(text):
        _stats["redacted"] += 1
        _log.append({
            "tool_name": tool_name,
            "event": "output_credential_redacted",
            "timestamp": time.time(),
        })
        return redact_credentials(text)
    return text


# ---------------------------------------------------------------------------
# MCP Proxy Server
# ---------------------------------------------------------------------------

def create_proxy_server(
    upstream_url: str,
    server_name: str = "airguard-proxy",
) -> FastMCP:
    """Create an AIRGuard MCP proxy that forwards to upstream after guard check."""

    proxy = FastMCP(server_name)

    # We'll dynamically register tools from the upstream server
    # For now, create a generic call_tool handler

    @proxy.tool(name="airguard_proxy_call")
    async def proxy_call(tool_name: str, arguments: str = "{}") -> str:
        """Proxy a tool call through AIRGuard guard."""
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
        except (json.JSONDecodeError, TypeError):
            args = {"raw": str(arguments)[:500]}

        # Pre-action guard
        decision = _guard_check(tool_name, args)
        if decision["blocked"]:
            return f"BLOCKED by AIRGuard: {decision['reason'][:300]}. Do not retry."

        # Forward to upstream
        import httpx
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                upstream_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": args},
                    "id": f"proxy_{_stats['checked']}",
                },
            )
            result = resp.json()

        # Extract text from result
        content = result.get("result", {}).get("content", [])
        output_parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text", "")
                # Post-output credential scan
                text = _scan_output(tool_name, text)
                output_parts.append(text)

        return "\n".join(output_parts) if output_parts else json.dumps(result)

    return proxy


# ---------------------------------------------------------------------------
# Standalone proxy using MCP stdio transport
# ---------------------------------------------------------------------------

async def run_stdio_proxy(upstream_url: str, upstream_transport: str = "streamable-http"):
    """Run AIRGuard as an MCP stdio proxy.

    The agent connects to this proxy via stdio. The proxy forwards
    tool calls to the real MCP server after AIRGuard checks.
    """
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        CallToolResult, TextContent, Tool,
        ListToolsResult,
    )

    server = Server("airguard-mcp-proxy")

    # Connect to upstream to discover tools
    upstream_tools: list[Tool] = []

    async def _fetch_upstream_tools():
        nonlocal upstream_tools
        if upstream_transport == "streamable-http":
            from mcp.client.streamable_http import streamablehttp_client
            async with streamablehttp_client(upstream_url) as (read, write, _):
                from mcp.client.session import ClientSession
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools_result = await session.list_tools()
                    upstream_tools = tools_result.tools
        logger.info(f"Discovered {len(upstream_tools)} upstream tools")

    await _fetch_upstream_tools()

    # Strip outputSchema to prevent validation errors
    for tool in upstream_tools:
        if hasattr(tool, "outputSchema"):
            tool.outputSchema = None

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return upstream_tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict | None = None) -> list[TextContent]:
        args = arguments or {}

        # AIRGuard pre-action guard
        decision = _guard_check(name, args)
        if decision["blocked"]:
            return [TextContent(
                type="text",
                text=f"BLOCKED by AIRGuard: {decision['reason'][:300]}. Do not retry.",
            )]

        # Forward to upstream
        if upstream_transport == "streamable-http":
            from mcp.client.streamable_http import streamablehttp_client
            async with streamablehttp_client(upstream_url) as (read, write, _):
                from mcp.client.session import ClientSession
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(name, arguments=args)

            # Post-output credential scan
            output = []
            for item in result.content:
                text = getattr(item, "text", str(item))
                text = _scan_output(name, text)
                output.append(TextContent(type="text", text=text))
            return output

        return [TextContent(type="text", text="Upstream transport not supported")]

    # Run as stdio server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def run_http_proxy(upstream_url: str, port: int, upstream_transport: str = "streamable-http"):
    """Run AIRGuard as an HTTP MCP proxy server.

    Agents connect to http://localhost:{port}/mcp.
    """
    from mcp.server import Server
    from mcp.types import TextContent, Tool, CallToolResult

    server = Server("airguard-mcp-proxy")

    upstream_tools: list[Tool] = []

    async def _fetch_upstream_tools():
        nonlocal upstream_tools
        try:
            from mcp.client.streamable_http import streamablehttp_client
            async with streamablehttp_client(upstream_url) as (read, write, _):
                from mcp.client.session import ClientSession
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools_result = await session.list_tools()
                    upstream_tools = tools_result.tools
            logger.info(f"Discovered {len(upstream_tools)} upstream tools from {upstream_url}")
        except Exception as exc:
            logger.error(f"Failed to fetch upstream tools: {exc}")

    await _fetch_upstream_tools()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return upstream_tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict | None = None) -> list[TextContent]:
        args = arguments or {}

        decision = _guard_check(name, args)
        if decision["blocked"]:
            return [TextContent(
                type="text",
                text=f"BLOCKED by AIRGuard: {decision['reason'][:300]}. Do not retry.",
            )]

        try:
            from mcp.client.streamable_http import streamablehttp_client
            async with streamablehttp_client(upstream_url) as (read, write, _):
                from mcp.client.session import ClientSession
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(name, arguments=args)

            output = []
            for item in result.content:
                text = getattr(item, "text", str(item))
                text = _scan_output(name, text)
                output.append(TextContent(type="text", text=text))
            return output
        except Exception as exc:
            return [TextContent(type="text", text=f"Upstream error: {exc}")]

    # Run as HTTP server
    from mcp.server.streamable_http import StreamableHTTPServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount
    import uvicorn

    transport = StreamableHTTPServerTransport(
        mcp_path="/mcp",
        server=server,
    )

    app = Starlette(
        routes=[Mount("/mcp", app=transport.handle_request)],
    )

    logger.info(f"AIRGuard MCP proxy listening on http://0.0.0.0:{port}/mcp")
    logger.info(f"Upstream: {upstream_url}")
    logger.info(f"Tools: {len(upstream_tools)}")

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    uvicorn_server = uvicorn.Server(config)
    await uvicorn_server.serve()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def run_stdio_wrapper_proxy(upstream_command: list[str], upstream_env: dict | None = None):
    """Run AIRGuard as a stdio MCP proxy wrapping another stdio MCP command.

    This is the key integration for Harbor: the agent's .mcp.json points to
    this script as the MCP command. This script spawns the real MCP server
    as a subprocess and proxies all tool calls through AIRGuard.

    .mcp.json example:
        {
            "mcpServers": {
                "telecom": {
                    "command": "python",
                    "args": ["-m", "airguard.integrations.mcp_proxy",
                             "--wrap", "python", "mcp_server.py"],
                    "env": {"AIRGUARD_RISK_API_KEY": "..."}
                }
            }
        }
    """
    import subprocess as sp
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.client.stdio import stdio_client, StdioServerParameters
    from mcp.client.session import ClientSession
    from mcp.types import TextContent, Tool

    # Start upstream MCP server as subprocess
    server_params = StdioServerParameters(
        command=upstream_command[0],
        args=upstream_command[1:] if len(upstream_command) > 1 else [],
        env={**(upstream_env or {}), **os.environ},
    )

    proxy = Server("airguard-mcp-proxy")
    upstream_tools: list[Tool] = []
    _upstream_session: ClientSession | None = None

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            upstream_tools = tools_result.tools
            _upstream_session = session

            # Strip outputSchema from tools — proxy returns TextContent,
            # not structured output, so keeping outputSchema causes validation errors
            for tool in upstream_tools:
                if hasattr(tool, "outputSchema"):
                    tool.outputSchema = None

            logger.info(f"Connected to upstream, {len(upstream_tools)} tools")

            @proxy.list_tools()
            async def list_tools() -> list[Tool]:
                return upstream_tools

            @proxy.call_tool()
            async def call_tool(name: str, arguments: dict | None = None) -> list[TextContent]:
                args = arguments or {}

                decision = _guard_check(name, args)
                if decision["blocked"]:
                    return [TextContent(
                        type="text",
                        text=f"BLOCKED by AIRGuard: {decision['reason'][:300]}. Do not retry.",
                    )]

                result = await session.call_tool(name, arguments=args)

                # Convert all content types to TextContent for uniform handling
                output = []
                for item in result.content:
                    if hasattr(item, "text"):
                        text = item.text
                    elif hasattr(item, "data"):
                        # Embedded/structured content
                        text = json.dumps(item.data) if isinstance(item.data, (dict, list)) else str(item.data)
                    else:
                        text = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
                    text = _scan_output(name, text)
                    output.append(TextContent(type="text", text=text))

                if not output and result.content:
                    # Fallback: serialize entire result
                    raw = json.dumps([str(c) for c in result.content])
                    output = [TextContent(type="text", text=_scan_output(name, raw))]

                return output if output else [TextContent(type="text", text="(empty result)")]

            # Run proxy as stdio server (agent connects to us via stdio)
            async with stdio_server() as (proxy_read, proxy_write):
                await proxy.run(proxy_read, proxy_write, proxy.create_initialization_options())


def main():
    global _risk_model

    parser = argparse.ArgumentParser(description="AIRGuard MCP Proxy Server")
    parser.add_argument("--upstream-url", default=None,
                        help="URL of the real MCP server (for HTTP mode)")
    parser.add_argument("--wrap", nargs=argparse.REMAINDER, default=None,
                        help="Wrap a stdio MCP command (e.g. --wrap python mcp_server.py)")
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--transport", choices=["stdio", "http", "wrap"], default="http")
    parser.add_argument("--risk-model", default="gpt-5.4-mini")
    parser.add_argument("--user-task", default="")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[AIRGuard Proxy] %(message)s",
                        stream=sys.stderr)

    _risk_model = args.risk_model or os.environ.get("AIRGUARD_RISK_MODEL", "gpt-5.4-mini")
    if args.user_task:
        _authority.user_intent = args.user_task

    _init_llm()
    logger.info(f"Risk model: {_risk_model}")
    logger.info(f"LLM simulation: {'ON' if _llm_client else 'OFF'}")
    if _authority.user_intent:
        logger.info(f"User task: {_authority.user_intent[:80]}...")
    log_dir = os.environ.get("AIRGUARD_LOG_DIR", "")
    if log_dir:
        logger.info(f"Log dir: {log_dir}")

    # On exit, dump stats to stderr so DTAP task_runner can capture them
    import atexit
    @atexit.register
    def _dump_stats():
        sys.stderr.write(f"AIRGUARD_PROXY_STATS:{json.dumps(_stats)}\n")
        if _log and not log_dir:
            # No log dir set — dump to stderr as fallback
            sys.stderr.write(f"AIRGUARD_PROXY_LOG_COUNT:{len(_log)}\n")

    if args.wrap:
        logger.info(f"Wrapping command: {args.wrap}")
        asyncio.run(run_stdio_wrapper_proxy(args.wrap))
    elif args.transport == "stdio" and args.upstream_url:
        asyncio.run(run_stdio_proxy(args.upstream_url))
    elif args.upstream_url:
        asyncio.run(run_http_proxy(args.upstream_url, args.port))
    else:
        parser.error("Provide --upstream-url or --wrap <command>")


if __name__ == "__main__":
    main()
