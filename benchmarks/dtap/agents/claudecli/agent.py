"""Claude Code CLI agent wrapper for DTAP with optional AIRGuard MCP interception."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from dt_arena.src.types.agent import Agent, AgentConfig, AgentResult, RuntimeConfig


class ClaudeCLIAgent(Agent):
    """Run DTAP tasks through the local `claude` CLI.

    When AIRGUARD_ENABLED=1, every DTAP MCP server is wrapped through
    airguard.integrations.mcp_proxy so AIRGuard can inspect tool calls.
    """

    def __init__(
        self,
        agent_config: AgentConfig,
        runtime_config: Optional[RuntimeConfig] = None,
    ):
        super().__init__(agent_config, runtime_config)
        self.output_dir = (runtime_config.output_dir or ".") if runtime_config else "."
        self._mcp_config_path: Optional[str] = None

    def _create_mcp_server(self, server_config) -> Any:
        return None

    async def initialize(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        airguard_enabled = os.environ.get("AIRGUARD_ENABLED", "") == "1"
        airguard_pkg = os.environ.get("AIRGUARD_PKG") or os.environ.get("PYTHONPATH", "").split(":")[0]

        mcp_servers = {}
        for srv in self.config.mcp_servers:
            if srv.url and airguard_enabled:
                proxy_cmd = (
                    f"PYTHONPATH={airguard_pkg} "
                    f"AIRGUARD_LOG_DIR={self.output_dir} "
                    f"python -m airguard.integrations.mcp_proxy "
                    f"--upstream-url {srv.url} --transport stdio"
                )
                mcp_servers[srv.name] = {"type": "stdio", "command": "/bin/bash", "args": ["-c", proxy_cmd]}
            elif srv.url:
                mcp_servers[srv.name] = {"type": "http", "url": srv.url}
            elif srv.command:
                cmd_parts = [srv.command] + list(srv.args or [])
                if airguard_enabled:
                    proxy_cmd = (
                        f"PYTHONPATH={airguard_pkg} "
                        f"AIRGUARD_LOG_DIR={self.output_dir} "
                        f"python -m airguard.integrations.mcp_proxy "
                        f"--wrap {' '.join(cmd_parts)}"
                    )
                    mcp_servers[srv.name] = {"type": "stdio", "command": "/bin/bash", "args": ["-c", proxy_cmd]}
                else:
                    mcp_servers[srv.name] = {"type": "stdio", "command": cmd_parts[0], "args": cmd_parts[1:]}

        fd, self._mcp_config_path = tempfile.mkstemp(
            suffix=".json",
            prefix="claude_mcp_",
            dir=self.output_dir,
        )
        with os.fdopen(fd, "w") as f:
            json.dump({"mcpServers": mcp_servers}, f, indent=2)

    async def run(
        self,
        user_input: Union[str, List[str]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        instruction = "\n".join(user_input) if isinstance(user_input, list) else user_input
        os.environ["AIRGUARD_USER_TASK"] = instruction[:500]

        model = self.runtime_config.model if self.runtime_config else "claude-haiku-4-5-20251001"
        max_turns = self.runtime_config.max_turns if self.runtime_config else 15
        timeout = 180
        if self.runtime_config and getattr(self.runtime_config, "max_agent_timeout_sec", None):
            timeout = self.runtime_config.max_agent_timeout_sec

        cmd = [
            "claude",
            "--verbose",
            "--output-format=stream-json",
            "--permission-mode=bypassPermissions",
            "--model",
            model,
            "--max-turns",
            str(max_turns),
            "--disallowedTools",
            "Bash,Read,Edit,Write,Glob,Grep,LS",
            "--append-system-prompt",
            (
                "Call WaitForMcpServers first. Use DTAP MCP tools only. "
                "Do not use local shell or file tools."
            ),
            "--print",
        ]
        if self._mcp_config_path:
            cmd += ["--mcp-config", self._mcp_config_path, "--strict-mcp-config"]
        cmd += ["--", instruction]

        env = {**os.environ, "IS_SANDBOX": "1", "AIRGUARD_LOG_DIR": self.output_dir}
        transcript_path = Path(self.output_dir) / "claude-code.txt"
        stderr_path = Path(self.output_dir) / "claude-stderr.txt"

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            stdout, stderr = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            stdout, stderr = "", "TIMEOUT"
        duration = time.time() - start

        transcript_path.write_text(stdout)
        stderr_path.write_text(stderr or "")

        final_response = ""
        turns = 0
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "result":
                final_response = event.get("result", final_response)
            elif event.get("type") == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if block.get("type") == "tool_use":
                        turns += 1
                    elif block.get("type") == "text" and block.get("text"):
                        final_response = block["text"]

        return AgentResult(final_output=final_response, turn_count=turns, trajectory=None, duration=duration)

    async def cleanup(self) -> None:
        if self._mcp_config_path:
            try:
                os.unlink(self._mcp_config_path)
            except OSError:
                pass
