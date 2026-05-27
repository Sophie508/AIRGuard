"""AIRGuard v2.1 — Target Trust Assessment.

Infers the target of an action and assesses its trustworthiness based on
provenance, authority context, and optionally LLM reasoning.
"""
from __future__ import annotations

import re
from typing import Any

from .types import (
    Action,
    AuthorityContext,
    NormalizedAction,
    Resource,
    TargetTrust,
    TrustTier,
)


# ---------------------------------------------------------------------------
# Target inference
# ---------------------------------------------------------------------------

def infer_action_target(action: Action) -> tuple[str, str]:
    """Infer the target and target_type from an action's args.

    Returns:
        (target, target_type) where target_type is one of:
        file_path, url, command, recipient, script, message, unknown
    """
    args = action.args or {}
    na = action.normalized_action
    na_str = na.value if isinstance(na, NormalizedAction) else str(na)

    if na_str in ("file.read", "file.write"):
        path = args.get("path", "") or args.get("file", "") or args.get("filename", "")
        return path, "file_path"

    if na_str == "process.exec":
        cmd = args.get("command", "") or args.get("script", "") or ""
        return cmd[:200], "command"

    if na_str == "output.respond":
        msg = args.get("message", "")
        return msg[:100], "message"

    if na_str == "network.request":
        url = args.get("url", "") or args.get("endpoint", "")
        return url, "url"

    if na_str == "email.send":
        to = args.get("to", "") or args.get("recipient", "")
        return to, "recipient"

    # Fallback: first string arg value
    for v in args.values():
        if isinstance(v, str) and v:
            return v[:200], "unknown"
    return "", "unknown"


# ---------------------------------------------------------------------------
# Heuristic trust
# ---------------------------------------------------------------------------

_HIGH_TRUST_SOURCES = {"user", "system", "org_policy", "verified_builtin_tool"}
_LOW_TRUST_INDICATORS = {
    "file_path": [".ssh", ".env", ".aws", "id_rsa", "/etc/shadow", "/etc/passwd"],
    "command": ["curl", "wget", "nc ", "ncat", "eval(", "exec(", "base64"],
    "url": ["pastebin", "ngrok", "webhook.site", ".onion"],
    "recipient": [],
}


_PERSISTENCE_TARGETS = [
    ".bashrc", ".zshrc", ".profile", ".bash_profile", ".bash_login",
    "/etc/crontab", "systemd", "launchd",
]


def heuristic_target_trust(
    action: Action,
    resource: Resource,
    authority_ctx: AuthorityContext,
    history: list,
) -> TargetTrust:
    """Assess target trust using heuristics (no LLM call)."""
    target, target_type = infer_action_target(action)

    # Task D: empty target → unknown, not high
    if not target:
        return TargetTrust(
            tier="unknown", score=None, confidence=0.3,
            source="empty_target", assessor="heuristic",
            reason="no target inferred from action args",
        )

    # Source-based prior
    pub = resource.publisher.value if hasattr(resource.publisher, "value") else str(resource.publisher)
    trust_tier = resource.trust_tier.value if hasattr(resource.trust_tier, "value") else str(resource.trust_tier)
    issuer = authority_ctx.issuer.value if hasattr(authority_ctx.issuer, "value") else str(authority_ctx.issuer)

    # Start with resource trust as baseline
    if issuer in _HIGH_TRUST_SOURCES or pub in ("user", "system", "org_policy"):
        score = 0.90
        source = f"issuer={issuer}"
    elif pub in ("verified_repo", "popular_package"):
        score = 0.65
        source = f"publisher={pub}"
    elif pub in ("unknown_web", "generated_code", "tool_output"):
        score = 0.30
        source = f"publisher={pub}"
    else:
        return TargetTrust(
            tier="unknown", score=None, confidence=0.3,
            source=f"publisher={pub}", assessor="heuristic",
            reason="missing provenance",
        )

    # Check for suspicious target indicators
    indicators = _LOW_TRUST_INDICATORS.get(target_type, [])
    target_lower = target.lower()
    for ind in indicators:
        if ind in target_lower:
            score = min(score, 0.20)
            source += f", suspicious_indicator={ind}"
            break

    # Task D: persistence targets → always low regardless of issuer
    for pt in _PERSISTENCE_TARGETS:
        if pt in target_lower:
            score = min(score, 0.10)
            source += f", persistence_target={pt}"
            break

    # Check if target involves credentials/secrets
    if any(k in target_lower for k in (".ssh", "password", "token", "secret", "credential", "id_rsa", ".env")):
        score = min(score, 0.10)
        source += ", credential_target"

    # Derive tier
    if score >= 0.80:
        tier = "high"
    elif score >= 0.45:
        tier = "medium"
    else:
        tier = "low"

    confidence = 0.7 if tier != "unknown" else 0.3

    return TargetTrust(
        tier=tier,
        score=round(score, 2),
        confidence=confidence,
        source=source,
        assessor="heuristic",
        reason=f"target={target_type}:{target[:80]}",
    )


# ---------------------------------------------------------------------------
# LLM trust (optional)
# ---------------------------------------------------------------------------

_TARGET_TRUST_PROMPT = """\
Assess the trustworthiness of this action's target in the context of the user's task.

User task: {user_task}
Resource: trust={trust}
Action: {action_name}
Target: {target} (type: {target_type})

Questions:
- Is this target necessary for the user_task?
- Was this target introduced by user/system/trusted workflow or by external/injected/untrusted content?
- Does it require authority unrelated to the user_task?
- Does it look like credential access, persistence, destructive write, hidden recipient, privilege escalation, exfiltration, or injected tool usage?

Return ONLY JSON:
{{"tier": "high|medium|low|unknown", "score": number|null, "confidence": number, "source": "...", "reason": "brief explanation"}}
"""


def llm_target_trust(
    action: Action,
    resource: Resource,
    authority_ctx: AuthorityContext,
    history: list,
    llm_client: Any,
    model: str,
) -> TargetTrust | None:
    """Assess target trust via LLM. Returns None on failure."""
    if llm_client is None:
        return None

    target, target_type = infer_action_target(action)
    if not target:
        return None

    trust = resource.trust_tier.value if hasattr(resource.trust_tier, "value") else str(resource.trust_tier)
    na_str = action.normalized_action.value if isinstance(action.normalized_action, NormalizedAction) else str(action.normalized_action)

    prompt = _TARGET_TRUST_PROMPT.format(
        user_task=authority_ctx.user_intent or "unknown",
        trust=trust,
        action_name=na_str,
        target=target[:500],
        target_type=target_type,
    )

    try:
        from .risk_simulation import _call_llm, _parse_json
        raw = _call_llm(llm_client, model, prompt)
        parsed = _parse_json(raw)
    except Exception:
        return None

    if not parsed:
        return None

    tier = parsed.get("tier", "unknown")
    score = parsed.get("score")
    if tier not in ("high", "medium", "low", "unknown"):
        tier = "unknown"
    if tier == "unknown":
        score = None

    return TargetTrust(
        tier=tier,
        score=score,
        confidence=parsed.get("confidence", 0.5),
        source=parsed.get("source", "llm"),
        assessor="llm",
        reason=parsed.get("reason", ""),
    )


# ---------------------------------------------------------------------------
# Combine
# ---------------------------------------------------------------------------

def combine_target_trust(prior: TargetTrust, llm: TargetTrust | None) -> TargetTrust:
    """Conservative combination of heuristic and LLM trust assessments."""
    if llm is None:
        return prior

    # If either is unknown, prefer the known one with reduced confidence
    if prior.tier == "unknown" and llm.tier != "unknown":
        return TargetTrust(
            tier=llm.tier,
            score=llm.score,
            confidence=llm.confidence * 0.8,
            source=f"llm({llm.source})",
            assessor="llm",
            reason=llm.reason,
        )
    if llm.tier == "unknown" and prior.tier != "unknown":
        return TargetTrust(
            tier=prior.tier,
            score=prior.score,
            confidence=prior.confidence * 0.8,
            source=f"heuristic({prior.source})",
            assessor="heuristic",
            reason=prior.reason + " [llm=unknown]",
        )

    # Both known: conservative = min score
    p_score = prior.score if prior.score is not None else 0.5
    l_score = llm.score if llm.score is not None else 0.5
    final_score = min(p_score, l_score)

    if final_score >= 0.80:
        tier = "high"
    elif final_score >= 0.45:
        tier = "medium"
    else:
        tier = "low"

    return TargetTrust(
        tier=tier,
        score=round(final_score, 2),
        confidence=round(min(prior.confidence, llm.confidence), 2),
        source=f"combined(heuristic={prior.source}, llm={llm.source})",
        assessor="runtime_airguard",
        reason=f"heuristic:{prior.reason[:60]} | llm:{llm.reason[:60]}",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assess_target_trust(
    action: Action,
    resource: Resource,
    authority_ctx: AuthorityContext,
    history: list,
    *,
    llm_client: Any = None,
    risk_model: str | None = None,
) -> tuple[str, str, TargetTrust]:
    """Full target trust assessment. Returns (target, target_type, trust)."""
    target, target_type = infer_action_target(action)
    prior = heuristic_target_trust(action, resource, authority_ctx, history)

    llm_trust = None
    if llm_client and target:
        llm_trust = llm_target_trust(
            action, resource, authority_ctx, history, llm_client, risk_model or "gpt-5.4-mini",
        )

    final = combine_target_trust(prior, llm_trust)
    return target, target_type, final
