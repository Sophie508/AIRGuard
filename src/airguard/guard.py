"""AIRGuard v0 — Top-level guard orchestrator.

Single entry point ``check_action`` runs all 5 layers and returns a
``GuardDecision``.  Also provides AgentTrap adapter helpers.
"""
from __future__ import annotations

import json
import re
import shlex
import uuid
from typing import Any

from .types import (
    Action,
    AuthorityContext,
    GuardDecision,
    LedgerEntry,
    NormalizedAction,
    Outcome,
    Resource,
    Suspicion,
    TrustTier,
)
from .trust_labeling import label_resource
from .authority_context import check_authority_coverage, detect_risk_tags
from .risk_simulation import simulate_risk
from .enforcement import decide_enforcement
from .audit_containment import LedgerStore, audit_sequence
from .target_trust import assess_target_trust


# ---------------------------------------------------------------------------
# AgentTrap tool-name -> NormalizedAction mapping
# ---------------------------------------------------------------------------
_AGENTTRAP_TOOL_MAP: dict[str, NormalizedAction] = {
    "read_file": NormalizedAction.FILE_READ,
    "write_file": NormalizedAction.FILE_WRITE,
    "run_script": NormalizedAction.PROCESS_EXEC,
    "bash": NormalizedAction.PROCESS_EXEC,
    "respond": NormalizedAction.OUTPUT_RESPOND,
}

_READ_ONLY_BASH = {
    "ls", "find", "cat", "stat", "wc", "head", "tail", "pwd",
    "grep", "rg", "sed", "awk", "sort", "uniq", "du", "file",
}
_NETWORK_BASH = {"curl", "wget", "ssh", "scp", "nc", "ncat", "ftp"}
_EXEC_BASH = {"python", "python3", "python2", "node", "npm", "pip", "pip3", "ruby", "perl", "sh", "bash"}
_WRITE_BASH = {"mkdir", "touch", "cp", "mv", "tee", "echo"}


# ---------------------------------------------------------------------------
# Main guard
# ---------------------------------------------------------------------------


def check_action(
    resource: Resource,
    authority_ctx: AuthorityContext,
    action: Action,
    history: list[Action] | list[LedgerEntry] | list,
    *,
    llm_client: Any = None,
    risk_model: str | None = None,
    ledger: LedgerStore | None = None,
) -> GuardDecision:
    """Pre-action guard: run all 5 layers, return GuardDecision.

    Flow:
        Layer 1  — confirm / normalize resource label.
        Layer 2  — check required capabilities against authority_ctx.allow.
        Layer 3  — invoke simulate_risk(...).
        Layer 4  — map risk assessment to enforcement outcome.
        Layer 5  — record ledger entry and audit sequence.
    """
    reasoning_parts: list[str] = []

    # ---- Layer 1: Resource Trust Labeling --------------------------------
    # If trust_tier is missing/unknown, re-label
    if not resource.trust_tier or resource.trust_tier in ("", "unknown", TrustTier.UNKNOWN):
        resource = label_resource({
            "resource_id": resource.resource_id,
            "publisher": resource.publisher,
            "constraints": resource.constraints,
            "content_ref": resource.content_ref,
        })
    reasoning_parts.append(
        f"L1: resource publisher={resource.publisher}, trust={resource.trust_tier}"
    )

    # ---- Layer 1b: Target Trust Assessment (v2.1) -------------------------
    target, target_type, target_trust = assess_target_trust(
        action, resource, authority_ctx, history,
        llm_client=llm_client, risk_model=risk_model,
    )

    # ---- Layer 2: Authority Context --------------------------------------
    covered, coverage_reason = check_authority_coverage(action, authority_ctx)
    reasoning_parts.append(f"L2: authority covered={covered}. {coverage_reason}")

    risk_tags = detect_risk_tags(
        action.normalized_action
        if isinstance(action.normalized_action, str)
        else action.normalized_action.value,
        action.args,
    )
    if risk_tags:
        reasoning_parts.append(f"L2: risk tags detected: {risk_tags}")

    # ---- Layer 3: LLM Risk Simulation ------------------------------------
    risk_assessment = simulate_risk(
        action, resource, authority_ctx, history,
        llm_client=llm_client, risk_model=risk_model,
    )
    reasoning_parts.append(
        f"L3: risk recommendation={risk_assessment.recommendation}, "
        f"task_necessary={risk_assessment.task_necessary}, "
        f"attack_pattern={risk_assessment.attack_pattern_match}"
    )

    # ---- Layer 4: Tiered Enforcement -------------------------------------
    outcome = decide_enforcement(
        risk_assessment,
        authority_ctx,
        resource,
        action,
        risk_tags=risk_tags,
        authority_covered=covered,
    )

    reasoning_parts.append(f"L4: enforcement outcome={outcome.value}")

    # ---- Layer 5: Sequence Audit and Containment -------------------------
    ledger_entry_id = str(uuid.uuid4())
    entry = LedgerEntry(
        action_id=action.action_id,
        normalized_action=action.normalized_action,
        authority_source=str(authority_ctx.issuer),
        capability_token="",  # TODO: per proposal, capability token lifecycle v0
        policy_decision=outcome.value if isinstance(outcome, Outcome) else str(outcome),
        resource_trust=str(resource.trust_tier),
        authority_context=str(authority_ctx),
        risk_tags=risk_tags,
        cumulative_risk=0.0,  # TODO: per proposal §5, accumulation logic not specified
    )

    if ledger is not None:
        ledger.record(entry)
        ledger_history = ledger.all_entries()
    else:
        ledger_history = []

    suspicions: list[Suspicion] = []
    if ledger_history:
        suspicions = audit_sequence(ledger_history)

    if suspicions:
        reasoning_parts.append(
            f"L5: {len(suspicions)} suspicion(s) detected: "
            + ", ".join(s.pattern_name for s in suspicions)
        )
        # Escalate outcome if suspicions are severe
        worst_severity = max(
            (_severity_rank(s.severity) for s in suspicions), default=0,
        )
        if worst_severity >= 3 and outcome in (Outcome.ALLOW, Outcome.AUDIT):
            outcome = Outcome.ASK
            reasoning_parts.append("L5: escalated to ask due to critical suspicion")
        if worst_severity >= 4 and outcome in (Outcome.ALLOW, Outcome.AUDIT, Outcome.ASK):
            outcome = Outcome.BLOCK
            reasoning_parts.append("L5: escalated to block due to critical suspicion")
    else:
        reasoning_parts.append("L5: no cross-action suspicions detected")

    return GuardDecision(
        outcome=outcome,
        reasoning=" | ".join(reasoning_parts),
        action_taken=outcome.value if isinstance(outcome, Outcome) else str(outcome),
        ledger_entry_id=ledger_entry_id,
        risk_source=risk_assessment.source,
        risk_model=risk_assessment.llm_model,
        risk_recommendation=risk_assessment.recommendation,
        risk_reason=risk_assessment.llm_reason,
        risk_error=risk_assessment.llm_error,
        target=target,
        target_type=target_type,
        target_trust_tier=target_trust.tier,
        target_trust_score=target_trust.score,
        target_trust_confidence=target_trust.confidence,
        target_trust_source=target_trust.source,
        target_trust_assessor=target_trust.assessor,
        target_trust_reason=target_trust.reason,
    )


def post_action_audit(
    action: Action,
    observed_effects: dict | str,
    ledger: LedgerStore,
) -> list[Suspicion]:
    """Post-execution audit: update ledger with observed effects and re-audit.

    # TODO: per proposal §5, observed_effect schema not specified;
    # v0 accepts free-form dict or string.
    """
    # Update the most recent matching entry with observed effects
    for entry in reversed(ledger.all_entries()):
        if entry.action_id == action.action_id:
            entry.observed_effect = (
                json.dumps(observed_effects, default=str)
                if isinstance(observed_effects, dict)
                else str(observed_effects)
            )
            break

    return audit_sequence(ledger.all_entries())


# ---------------------------------------------------------------------------
# AgentTrap compatibility adapters
# ---------------------------------------------------------------------------


def action_from_tool_call(
    tool_call: Any,
    source_resource_id: str = "",
) -> Action:
    """Convert an AgentTrap ToolCall to an AIRGuard Action.

    AgentTrap ToolCall has: id, name, arguments (dict).
    Mapping (conservative v0):
        read_file  -> file.read
        write_file -> file.write
        run_script -> process.exec
        bash       -> process.exec
        respond    -> output.respond
        unknown    -> tool.call
    """
    tc_name = str(getattr(tool_call, "name", "") or "")
    tc_id = str(getattr(tool_call, "id", "") or str(uuid.uuid4()))
    tc_args = getattr(tool_call, "arguments", {}) or {}
    if not isinstance(tc_args, dict):
        tc_args = {"raw": str(tc_args)}

    normalized = _AGENTTRAP_TOOL_MAP.get(tc_name, NormalizedAction.TOOL_CALL)
    if tc_name == "bash":
        normalized = _classify_bash(tc_args.get("command", ""))

    # Derive required capabilities from normalized action
    cap_map = {
        NormalizedAction.FILE_READ: ["read"],
        NormalizedAction.FILE_WRITE: ["write"],
        NormalizedAction.PROCESS_EXEC: ["exec"],
        NormalizedAction.TOOL_CALL: ["exec"],
        NormalizedAction.NETWORK_REQUEST: ["network"],
        NormalizedAction.OUTPUT_RESPOND: ["respond"],
        NormalizedAction.FILE_DELETE: ["write"],
    }
    required = cap_map.get(normalized, ["exec"])

    return Action(
        action_id=tc_id,
        name=tc_name,
        args=tc_args,
        source_resource_id=source_resource_id,
        required_capabilities=required,
        normalized_action=normalized,
    )


def _classify_bash(command: str) -> NormalizedAction:
    """Best-effort bash command classification for smoke-benchmark gating."""
    command = str(command or "").strip()
    lower = command.lower()
    if not lower:
        return NormalizedAction.PROCESS_EXEC
    if re.search(r"https?://|\bnc\b|\bncat\b", lower):
        return NormalizedAction.NETWORK_REQUEST
    if any(mark in lower for mark in ("<<", "$(", "`")):
        return NormalizedAction.PROCESS_EXEC
    if re.search(r">\s*|>>\s*|\b-delete\b|\brm\s+", lower):
        return NormalizedAction.FILE_DELETE if "rm " in lower or "-delete" in lower else NormalizedAction.FILE_WRITE

    try:
        first = shlex.split(command)[0]
    except (ValueError, IndexError):
        return NormalizedAction.PROCESS_EXEC
    first = first.rsplit("/", 1)[-1].lower()

    if first in _NETWORK_BASH:
        return NormalizedAction.NETWORK_REQUEST
    if first in _EXEC_BASH:
        return NormalizedAction.PROCESS_EXEC
    if first in _READ_ONLY_BASH:
        return NormalizedAction.FILE_READ
    if first in _WRITE_BASH:
        return NormalizedAction.FILE_WRITE
    return NormalizedAction.PROCESS_EXEC


def history_from_tool_log(
    tool_log: list[dict],
) -> list[LedgerEntry]:
    """Convert AgentTrap's tool_log entries into AIRGuard LedgerEntry list.

    AgentTrap tool_log entries have: turn, tool, arguments,
    observation_preview, observation, (optional judge_decision/reason).
    """
    entries: list[LedgerEntry] = []
    for log in tool_log:
        tool_name = str(log.get("tool", ""))
        na = _AGENTTRAP_TOOL_MAP.get(tool_name, NormalizedAction.TOOL_CALL)
        action_id = str(log.get("turn", len(entries)))
        entries.append(
            LedgerEntry(
                action_id=action_id,
                normalized_action=na,
                authority_source="user",
                policy_decision=log.get("judge_decision", ""),
                observed_effect=log.get("observation_preview", ""),
                risk_tags=detect_risk_tags(
                    na.value if isinstance(na, NormalizedAction) else str(na),
                    log.get("arguments", {}),
                ),
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    """Map severity string to numeric rank for comparison."""
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
