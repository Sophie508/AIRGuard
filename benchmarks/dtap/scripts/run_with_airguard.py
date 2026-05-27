#!/usr/bin/env python3
"""Batch runner for DTAP subset-150 + AIRGuard, native Claude Code CLI (Strategy A).

For each task in the selected-tasks JSONL it invokes
``scripts/run_dtap_airguard_native.py`` (which delegates to ``eval/task_runner.py``)
with agent-type ``claudecli``. Each case runs independently; one failure never
stops the batch. Transient API/network errors are retried with backoff.

Artifacts per case land in the DTAP structured output dir
``{run_root}/benchmark/{agent_type}/{safe_model}/{dataset_path}/``:
    - judge_result.json   (written by task_runner)
    - claude-code.txt     (stream-json trajectory, written by claudecli agent)
    - claude-stderr.txt   (written by claudecli agent)
    - airguard_log.jsonl  (written by AIRGuard mcp_proxy)
    - stdout.txt / stderr.txt / metadata.json  (written by THIS runner)

Run-level artifacts at run_root:
    progress.jsonl, summary.json, summary.csv, SUMMARY.md, failed_cases.jsonl

This does NOT use Harbor, mcp_wrapper.py, or patch_mcp_config.py. The claudecli
agent wraps each MCP server URL through airguard.integrations.mcp_proxy directly.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DTAP_ROOT = Path(os.environ.get("DTAP_ROOT", ".")).resolve()
NATIVE_WRAPPER = DTAP_ROOT / "scripts" / "run_dtap_airguard_native.py"
RELEASE_ROOT = Path(__file__).resolve().parents[3]
AIRGUARD_SRC = RELEASE_ROOT / "src"

# Transient error indicators -> retry. Case-insensitive substring/regex match
# against combined stdout+stderr (and a synthetic marker on timeout).
TRANSIENT_PATTERNS = [
    r"UND_ERR_SOCKET",
    r"Unable to connect to API",
    r"ECONNRESET",
    r"ETIMEDOUT",
    r"\b429\b",
    r"Too Many Requests",
    r"rate[_ ]?limit",
    r"\b500\b", r"\b502\b", r"\b503\b", r"\b504\b", r"\b529\b",
    r"Internal Server Error",
    r"Bad Gateway",
    r"Service Unavailable",
    r"Gateway Time-?out",
    r"overloaded",
    r"__RUNNER_TIMEOUT__",
    # claude binary swapped mid-run by self-updater -> ENOENT on the symlink.
    r"No such file or directory: 'claude'",
    r"claude: command not found",
]
TRANSIENT_RE = re.compile("|".join(TRANSIENT_PATTERNS), re.IGNORECASE)

BACKOFFS = [30, 60, 120]  # seconds before retry 1, 2, 3


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def map_task_dir(rec: Dict[str, Any]) -> str:
    """Map a JSONL record to a dataset-relative task directory."""
    domain = rec["domain"]
    typ = rec["type"]
    tid = rec["task_id"]
    rc = rec.get("risk_category")
    tm = rec.get("threat_model")
    if typ == "benign":
        if rc:
            return f"dataset/{domain}/benign/{rc}/{tid}"
        return f"dataset/{domain}/benign/{tid}"
    # malicious
    return f"dataset/{domain}/malicious/{tm}/{rc}/{tid}"


def extract_dataset_path(task_dir: str) -> str:
    """Path after 'dataset/' (mirrors utils.extract_dataset_path)."""
    parts = Path(task_dir).parts
    if "dataset" in parts:
        idx = parts.index("dataset")
        return str(Path(*parts[idx + 1:]))
    return task_dir


def output_dir_for(run_root: Path, agent_type: str, model: str, task_dir: str) -> Path:
    safe_model = model.replace("/", "_").replace(":", "_")
    dataset_path = extract_dataset_path(task_dir)
    return run_root / "benchmark" / agent_type / safe_model / dataset_path


def is_transient(stdout: str, stderr: str) -> bool:
    blob = (stdout or "") + "\n" + (stderr or "")
    return bool(TRANSIENT_RE.search(blob))


def run_one_attempt(
    task_dir: str,
    agent_type: str,
    model: str,
    max_turns: int,
    timeout: int,
    env: Dict[str, str],
) -> Tuple[int, str, str, bool]:
    """Run the native wrapper once. Returns (rc, stdout, stderr, timed_out)."""
    cmd = [
        sys.executable,
        str(NATIVE_WRAPPER),
        "--task-dir", task_dir,
        "--agent-type", agent_type,
        "--model", model,
        "--max-turns", str(max_turns),
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(DTAP_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = (e.stderr or "") + "\n__RUNNER_TIMEOUT__"
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return 124, out, err, True


def load_judge(out_dir: Path) -> Optional[Dict[str, Any]]:
    jp = out_dir / "judge_result.json"
    if jp.exists():
        try:
            return json.loads(jp.read_text())
        except Exception:
            return {"_parse_error": True}
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch DTAP-150 + AIRGuard native claudecli runner.")
    ap.add_argument("--selected-tasks", required=True, help="Path to selected-tasks JSONL.")
    ap.add_argument("--agent-type", default="claudecli")
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    ap.add_argument("--max-turns", type=int, default=15)
    ap.add_argument("--retries", type=int, default=3, help="Retries for transient errors.")
    ap.add_argument("--timeout", type=int, default=900, help="Per-attempt wall-clock seconds.")
    ap.add_argument("--output-root", default=None, help="Run root dir (default: timestamped under results/).")
    args = ap.parse_args()

    # --- Run root ---
    if args.output_root:
        run_root = Path(args.output_root).resolve()
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_root = (DTAP_ROOT / "results" / f"airguard_claudecli_haiku45_{ts}").resolve()
    run_root.mkdir(parents=True, exist_ok=True)

    progress_path = run_root / "progress.jsonl"
    failed_path = run_root / "failed_cases.jsonl"

    # Base env for child processes (Strategy A native CLI; no Harbor/wrappers).
    base_env = dict(os.environ)
    base_env["EVAL_RESULTS_ROOT"] = str(run_root)
    base_env["AIRGUARD_ENABLED"] = "1"
    base_env.setdefault("AIRGUARD_PKG", str(AIRGUARD_SRC))
    base_env["DTAP_ROOT"] = str(DTAP_ROOT)
    # Prevent the claude binary from self-updating mid-run (causes ENOENT races).
    base_env["DISABLE_AUTOUPDATER"] = "1"
    base_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    # DTAP domain-specific env (normally set by eval/evaluation.py Docker
    # orchestration; the native single-task path omits them). Inject per-case so
    # code/finance/legal/os MCP servers can resolve their containers/ports.
    # setdefault so an explicit shell export always wins.
    for k, v in {
        "TERMINAL_PROJECT_NAME": "terminal",
        "PROJECT_NAME": "terminal",
        "OS_FILESYSTEM_API_PORT": "8034",
        # Gate that os-filesystem setup.sh checks before seeding the workspace.
        # Only used as a presence flag (the seed itself talks to the API port),
        # so any non-empty value un-skips the seed.
        "OS_FILESYSTEM_PROJECT_NAME": "os-filesystem",
        "TELECOM_PORT": "17501",
        "FINANCE_WEB_PORT": "5000",
        "LEGAL_WEB_PORT": "5001",
        "GMAIL_UI_PORT": "8025",
        "GMAIL_SMTP_PORT": "1025",
        "GMAIL_AUTH_PORT": "8030",
        "GMAIL_PROXY_PORT": "8031",
        "GMAIL_FRONTEND_PORT": "8050",
        "MCP_READY_TIMEOUT": "300",
    }.items():
        base_env.setdefault(k, v)
    pp = base_env.get("PYTHONPATH", "")
    needed = [base_env["AIRGUARD_PKG"], str(DTAP_ROOT)]
    parts = [p for p in pp.split(":") if p]
    for n in needed:
        if n not in parts:
            parts.append(n)
    base_env["PYTHONPATH"] = ":".join(parts)
    # Defensive: ensure no proxy leaks into children.
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"]:
        base_env.pop(var, None)

    # --- Load tasks ---
    cases: List[Dict[str, Any]] = []
    with open(args.selected_tasks) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))

    total = len(cases)
    print(f"[BATCH] Run root: {run_root}", flush=True)
    print(f"[BATCH] Tasks: {total}  agent={args.agent_type}  model={args.model}  "
          f"max_turns={args.max_turns}  retries={args.retries}  timeout={args.timeout}s",
          flush=True)
    print(f"[BATCH] Progress: {progress_path}", flush=True)

    results: List[Dict[str, Any]] = []

    for idx, rec in enumerate(cases, start=1):
        task_dir = map_task_dir(rec)
        out_dir = output_dir_for(run_root, args.agent_type, args.model, task_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        case_id = extract_dataset_path(task_dir)
        print(f"\n[BATCH] ===== Case {idx}/{total}: {case_id} =====", flush=True)
        print(f"[BATCH] task_dir={task_dir}", flush=True)
        print(f"[BATCH] out_dir={out_dir}", flush=True)

        start_ts = time.time()
        attempts_log: List[Dict[str, Any]] = []
        status = "infra_error"
        judge: Optional[Dict[str, Any]] = None
        last_rc = None

        max_attempts = args.retries + 1
        for attempt in range(1, max_attempts + 1):
            a_start = time.time()
            print(f"[BATCH] attempt {attempt}/{max_attempts} starting at {now_iso()}", flush=True)
            rc, stdout, stderr, timed_out = run_one_attempt(
                task_dir, args.agent_type, args.model, args.max_turns, args.timeout, base_env,
            )
            a_dur = time.time() - a_start
            last_rc = rc

            # Persist stdout/stderr of this attempt (overwrite with latest attempt;
            # keep per-attempt copies too for debugging).
            (out_dir / "stdout.txt").write_text(stdout or "")
            (out_dir / "stderr.txt").write_text(stderr or "")
            if attempt > 1 or max_attempts > 1:
                (out_dir / f"stdout.attempt{attempt}.txt").write_text(stdout or "")
                (out_dir / f"stderr.attempt{attempt}.txt").write_text(stderr or "")

            judge = load_judge(out_dir)
            transient = is_transient(stdout, stderr)
            attempts_log.append({
                "attempt": attempt,
                "rc": rc,
                "timed_out": timed_out,
                "transient": transient,
                "judge_present": judge is not None,
                "duration_sec": round(a_dur, 1),
            })
            print(f"[BATCH] attempt {attempt} done rc={rc} timed_out={timed_out} "
                  f"transient={transient} judge_present={judge is not None} "
                  f"dur={a_dur:.1f}s", flush=True)

            if judge is not None and not judge.get("_parse_error"):
                # A completed run: judge produced a verdict. rc may be 1 when the
                # benign task failed or attack was blocked — that is NOT infra error.
                status = "completed"
                break

            # No judge verdict. Retry only on transient indicators.
            if transient and attempt < max_attempts:
                backoff = BACKOFFS[min(attempt - 1, len(BACKOFFS) - 1)]
                print(f"[BATCH] transient error; backing off {backoff}s then retrying", flush=True)
                time.sleep(backoff)
                continue
            else:
                status = "infra_error"
                if not transient:
                    print("[BATCH] non-transient failure with no judge result; not retrying", flush=True)
                break

        dur = time.time() - start_ts

        task_success = judge.get("task_success") if judge else None
        attack_success = judge.get("attack_success") if judge else None
        judge_error = judge.get("error") if judge else None

        # Write metadata.json
        metadata = {
            "case_index": idx,
            "case_id": case_id,
            "task_dir": task_dir,
            "domain": rec.get("domain"),
            "type": rec.get("type"),
            "task_id_field": rec.get("task_id"),
            "risk_category": rec.get("risk_category"),
            "threat_model": rec.get("threat_model"),
            "agent_type": args.agent_type,
            "model": args.model,
            "max_turns": args.max_turns,
            "status": status,
            "last_rc": last_rc,
            "task_success": task_success,
            "attack_success": attack_success,
            "judge_error": judge_error,
            "attempts": attempts_log,
            "duration_sec": round(dur, 1),
            "output_dir": str(out_dir),
            "finished_at": now_iso(),
            "raw_record": rec,
        }
        (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False))

        results.append(metadata)

        # Append to progress.jsonl after each case (durable, tail-able).
        with open(progress_path, "a") as pf:
            pf.write(json.dumps({
                "case_index": idx,
                "case_id": case_id,
                "type": rec.get("type"),
                "domain": rec.get("domain"),
                "status": status,
                "task_success": task_success,
                "attack_success": attack_success,
                "last_rc": last_rc,
                "duration_sec": round(dur, 1),
                "finished_at": now_iso(),
            }, ensure_ascii=False) + "\n")

        if status != "completed":
            with open(failed_path, "a") as ff:
                ff.write(json.dumps(metadata, ensure_ascii=False) + "\n")

        print(f"[BATCH] Case {idx}/{total} -> status={status} "
              f"task_success={task_success} attack_success={attack_success} "
              f"dur={dur:.1f}s", flush=True)

        # Write rolling summaries so partial progress is always inspectable.
        write_summaries(run_root, results, total, args)

    write_summaries(run_root, results, total, args)
    print(f"\n[BATCH] DONE. {len(results)}/{total} cases processed.", flush=True)
    print(f"[BATCH] Summaries in {run_root}", flush=True)


def write_summaries(run_root: Path, results: List[Dict[str, Any]], total: int, args) -> None:
    completed = [r for r in results if r["status"] == "completed"]
    infra = [r for r in results if r["status"] != "completed"]

    benign = [r for r in completed if r["type"] == "benign"]
    malicious = [r for r in completed if r["type"] == "malicious"]

    benign_success = [r for r in benign if r["task_success"] is True]
    # For malicious: attack_success True => attack bypassed defense (bad);
    # False => attack blocked by AIRGuard (defense worked / good).
    mal_attack_success = [r for r in malicious if r["attack_success"] is True]
    mal_attack_blocked = [r for r in malicious if r["attack_success"] is False]

    def rate(n, d):
        return round(100.0 * n / d, 1) if d else None

    summary = {
        "run_root": str(run_root),
        "generated_at": now_iso(),
        "agent_type": args.agent_type,
        "model": args.model,
        "defense": "AIRGuard MCP proxy (Strategy A native CLI)",
        "total_selected": total,
        "processed": len(results),
        "completed": len(completed),
        "infra_error": len(infra),
        "benign": {
            "count": len(benign),
            "task_success": len(benign_success),
            "task_success_rate_pct": rate(len(benign_success), len(benign)),
        },
        "malicious": {
            "count": len(malicious),
            "attack_success": len(mal_attack_success),
            "attack_success_rate_pct": rate(len(mal_attack_success), len(malicious)),
            "attack_blocked": len(mal_attack_blocked),
            "defense_rate_pct": rate(len(mal_attack_blocked), len(malicious)),
        },
        "infra_error_cases": [r["case_id"] for r in infra],
    }
    (run_root / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    # summary.csv (per-case)
    with open(run_root / "summary.csv", "w", newline="") as cf:
        w = csv.writer(cf)
        w.writerow(["case_index", "case_id", "domain", "type", "threat_model",
                    "risk_category", "status", "task_success", "attack_success",
                    "last_rc", "duration_sec"])
        for r in results:
            w.writerow([r["case_index"], r["case_id"], r["domain"], r["type"],
                        r.get("threat_model"), r.get("risk_category"), r["status"],
                        r["task_success"], r["attack_success"], r["last_rc"],
                        r["duration_sec"]])

    # SUMMARY.md
    md = []
    md.append("# DTAP-150 + AIRGuard (native claudecli) — Summary\n")
    md.append(f"- Generated: {summary['generated_at']}")
    md.append(f"- Run root: `{run_root}`")
    md.append(f"- Agent: `{args.agent_type}`  Model: `{args.model}`")
    md.append(f"- Defense: {summary['defense']}")
    md.append(f"- Progress: **{len(results)}/{total}** processed, "
              f"{len(completed)} completed, {len(infra)} infra_error\n")
    md.append("## Benign (defense should NOT break these)\n")
    md.append(f"- Count: {len(benign)}")
    md.append(f"- Task success: {len(benign_success)} "
              f"({summary['benign']['task_success_rate_pct']}%)\n")
    md.append("## Malicious (AIRGuard should block these)\n")
    md.append(f"- Count: {len(malicious)}")
    md.append(f"- Attack success (defense bypassed): {len(mal_attack_success)} "
              f"({summary['malicious']['attack_success_rate_pct']}%)")
    md.append(f"- Attack blocked (defense worked): {len(mal_attack_blocked)} "
              f"({summary['malicious']['defense_rate_pct']}%)\n")
    if infra:
        md.append("## Infra errors\n")
        for r in infra:
            md.append(f"- `{r['case_id']}` (rc={r['last_rc']})")
        md.append("")
    (run_root / "SUMMARY.md").write_text("\n".join(md))


if __name__ == "__main__":
    main()
