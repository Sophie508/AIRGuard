"""Codex CLI agent wrapper for DTAP with optional AIRGuard MCP interception."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from dt_arena.src.types.agent import Agent, AgentConfig, AgentResult, RuntimeConfig


class CodexCLIAgent(Agent):
    """Run DTAP tasks through `codex exec`.

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
        self._codex_home: Optional[str] = None

    def _create_mcp_server(self, server_config) -> Any:
        return None

    def _write_codex_config(self, user_task: str = "") -> None:
        if not self._codex_home:
            raise RuntimeError("Codex home is not initialized")

        airguard_enabled = os.environ.get("AIRGUARD_ENABLED", "") == "1"
        airguard_pkg = os.environ.get("AIRGUARD_PKG") or os.environ.get("PYTHONPATH", "").split(":")[0]
        mcp_required = os.environ.get("CODEX_MCP_REQUIRED", "true").lower() not in {"0", "false", "no"}

        config_lines = [
            "[features]",
            "shell_tool = false",
            "unified_exec = false",
            "shell_snapshot = false",
            "browser_use = false",
            "browser_use_external = false",
            "computer_use = false",
            "in_app_browser = false",
            "",
        ]

        for srv in self.config.mcp_servers:
            if srv.url and airguard_enabled:
                proxy_cmd = (
                    f"PYTHONPATH={shlex.quote(airguard_pkg)} "
                    f"AIRGUARD_LOG_DIR={shlex.quote(str(self.output_dir))} "
                    f"AIRGUARD_USER_TASK={shlex.quote(user_task[:500])} "
                    f"python -m airguard.integrations.mcp_proxy "
                    f"--upstream-url {shlex.quote(srv.url)} --transport stdio"
                )
                config_lines.append(f"[mcp_servers.{srv.name}]")
                config_lines.append('command = "/bin/bash"')
                config_lines.append(f'args = ["-c", {json.dumps(proxy_cmd)}]')
            elif srv.url:
                config_lines.append(f"[mcp_servers.{srv.name}]")
                config_lines.append(f'url = "{srv.url}"')
            else:
                continue
            config_lines.append("startup_timeout_sec = 120")
            config_lines.append("tool_timeout_sec = 300")
            config_lines.append(f"required = {'true' if mcp_required else 'false'}")
            config_lines.append("")

        Path(self._codex_home, "config.toml").write_text("\n".join(config_lines))

    async def initialize(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        codex_base = os.environ.get("CODEX_AIRGUARD_HOME_BASE") or os.path.expanduser("~/.codex_airguard_runs")
        os.makedirs(codex_base, exist_ok=True)
        self._codex_home = tempfile.mkdtemp(prefix="codex_airguard_", dir=codex_base)

        auth_src = Path(os.environ.get("CODEX_AUTH_JSON", os.path.expanduser("~/.codex/auth.json")))
        if auth_src.exists():
            shutil.copy2(str(auth_src), str(Path(self._codex_home) / "auth.json"))
        else:
            raise FileNotFoundError(
                f"Codex OAuth auth.json not found at {auth_src}. Run 'codex login' first or set CODEX_AUTH_JSON."
            )

        self._write_codex_config(os.environ.get("AIRGUARD_USER_TASK", ""))

    async def run(
        self,
        user_input: Union[str, List[str]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        instruction = "\n".join(user_input) if isinstance(user_input, list) else user_input
        airguard_user_task = instruction[:500]
        os.environ["AIRGUARD_USER_TASK"] = airguard_user_task
        self._write_codex_config(airguard_user_task)

        instruction = (
            "Use the available MCP tools to complete the task. Local shell and file tools are disabled.\n\n"
            + instruction
        )
        model = self.runtime_config.model if self.runtime_config else "gpt-5.4-mini"
        cmd = [
            "codex",
            "exec",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "--model",
            model.split("/")[-1],
            "--json",
            "--",
            instruction,
        ]

        timeout = 300
        if self.runtime_config and getattr(self.runtime_config, "max_agent_timeout_sec", None):
            timeout = int(self.runtime_config.max_agent_timeout_sec)
        timeout = int(os.environ.get("CODEX_EXEC_TIMEOUT", str(timeout)))

        env = {**os.environ, "CODEX_HOME": self._codex_home, "AIRGUARD_LOG_DIR": self.output_dir}
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

        Path(self.output_dir, "codex_output.jsonl").write_text(stdout)
        Path(self.output_dir, "codex_stderr.txt").write_text(stderr or "")

        final_response = ""
        turns = 0
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") != "item.completed":
                continue
            item = event.get("item") or {}
            if item.get("type") == "agent_message":
                final_response = item.get("text", final_response)
            elif item.get("type") == "mcp_tool_call":
                turns += 1

        if not final_response and stderr:
            final_response = f"[codex error] {stderr.strip()[:300]}"

        return AgentResult(final_output=final_response, turn_count=turns, trajectory=None, duration=duration)

    async def cleanup(self) -> None:
        if self._codex_home:
            shutil.rmtree(self._codex_home, ignore_errors=True)
