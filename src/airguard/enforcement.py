"""AIRGuard v0 — Layer 4: Tiered Enforcement.

Maps RiskAssessment + AuthorityContext + Resource + Action to an enforcement
outcome.  See proposal §4 "Tiered Enforcement".

Proposal guidance (§4):
    allow:      trusted resource, task-necessary action, low-risk effect
    audit:      normal action with moderate sensitivity, record trace
    ask:        ambiguous authority, irreversible effect, broad permission
    inspect:    low-trust script or generated code before execution
    sandbox:    unknown code, broad fs/net/process access, suspicious sequence
    quarantine: generated artifact or downloaded tool — stage effects
    block:      clear exfiltration, destructive write, hidden recipient,
                unauthorized persistence, privilege escalation, or untrusted
                resource self-authorizing sensitive access

AIRGuard is a contextual risk guard, NOT a simple whitelist (proposal §"Why
This Is Not a Simple Whitelist").
"""
from __future__ import annotations

from .types import (
    Action,
    AuthorityContext,
    HighRiskTag,
    NormalizedAction,
    Outcome,
    Resource,
    RiskAssessment,
    TrustTier,
)

# Tags that should always escalate to block when trust is low
_BLOCK_TAGS = frozenset({
    HighRiskTag.SECRETS.value,
    HighRiskTag.HIDDEN_RECIPIENT.value,
    HighRiskTag.PRIVILEGE_ESCALATION.value,
})

# Tags that should escalate to sandbox/quarantine
_SANDBOX_TAGS = frozenset({
    HighRiskTag.DOWNLOAD_EXECUTE.value,
    HighRiskTag.UNAUTHORIZED_NETWORK.value,
})

# Tags that should trigger ask
_ASK_TAGS = frozenset({
    HighRiskTag.DESTRUCTIVE_WRITE.value,
    HighRiskTag.PERSISTENCE.value,
    HighRiskTag.CONFIG_POISONING.value,
})

# Actions that involve code execution
_EXEC_ACTIONS = frozenset({
    NormalizedAction.PROCESS_EXEC.value,
    NormalizedAction.PACKAGE_INSTALL.value,
})

_SAFE_NON_EXEC_ACTIONS = frozenset({
    NormalizedAction.FILE_READ.value,
    NormalizedAction.FILE_WRITE.value,
    NormalizedAction.BROWSER_EXTRACT.value,
    NormalizedAction.DATABASE_QUERY.value,
    NormalizedAction.MEMORY_WRITE.value,
    NormalizedAction.TOOL_CALL.value,
    NormalizedAction.OUTPUT_RESPOND.value,
})


def decide_enforcement(
    risk: RiskAssessment,
    authority_ctx: AuthorityContext,
    resource: Resource,
    action: Action,
    risk_tags: list[str] | None = None,
    *,
    authority_covered: bool = True,
) -> Outcome:
    """Determine enforcement outcome from risk assessment and context.

    The decision follows a priority cascade:
    1. Explicit block signals (high-risk tags + low trust)
    2. Authority mismatch
    3. LLM recommendation
    4. Resource trust + action type heuristics
    5. Default: audit or allow

    When precedence is ambiguous, v0 errs toward higher enforcement.
    """
    trust = _trust_str(resource)
    na_str = _na_str(action)
    rec = risk.recommendation
    tags = set(risk_tags or [])

    # --- Priority 0: output-channel leakage --------------------------------
    # respond with hard risk tags (credential harvesting, phishing, priv esc,
    # hidden recipient) is always blocked regardless of trust — the malicious
    # content would become the final user-visible result and cannot be
    # retracted.  This is a general mechanism, not case-specific.
    if na_str == NormalizedAction.OUTPUT_RESPOND.value and tags & _BLOCK_TAGS:
        return Outcome.BLOCK

    # --- Priority 1: hard block signals -----------------------------------
    # Block if low/unknown trust AND high-risk tags present
    if trust in ("low", "unknown") and tags & _BLOCK_TAGS:
        return Outcome.BLOCK

    # Block if risk simulation says block
    if rec == "block":
        return Outcome.BLOCK

    # If the action is covered by user authority, non-executing, and has no
    # hard tags, allow it to proceed under audit even when the fallback risk
    # simulator is conservative.
    if authority_covered and na_str in _SAFE_NON_EXEC_ACTIONS and not (tags & _BLOCK_TAGS):
        if tags & _ASK_TAGS and trust in ("low", "unknown"):
            return Outcome.SANDBOX
        return Outcome.AUDIT

    # --- Priority 1b: LLM-informed exec (authority-gated) ------------------
    # LLM risk simulation can downgrade exec from INSPECT to AUDIT, but ONLY
    # when exec authority is already covered.  LLM recommendation must never
    # grant authority that the user/system did not provide.
    if (
        authority_covered
        and risk.source == "llm"
        and rec in ("allow", "audit")
        and na_str in _EXEC_ACTIONS
        and not (tags & _BLOCK_TAGS)
    ):
        return Outcome.AUDIT

    # --- Priority 2: authority mismatch -----------------------------------
    if not authority_covered:
        # Hard risk tags without authority → always block
        if tags & _BLOCK_TAGS:
            return Outcome.BLOCK
        if trust in ("low", "unknown"):
            # Low trust exec without authority: inspect content first, don't
            # blind-block.  The integration layer runs static/LLM inspection
            # and denies if hard-risk patterns are found.
            if na_str in _EXEC_ACTIONS:
                return Outcome.INSPECT
            return Outcome.BLOCK
        return Outcome.ASK

    # --- Priority 3: LLM recommendation -----------------------------------
    # Trust the LLM recommendation unless it is more permissive than
    # what the trust tier warrants.
    # TODO: per proposal §4, exact precedence among risk recommendation,
    # resource trust, and authority is not specified; v0 uses conservative
    # override rules below.

    if rec == "quarantine":
        return Outcome.QUARANTINE
    if rec == "sandbox":
        return Outcome.SANDBOX
    if rec == "inspect":
        return Outcome.INSPECT
    if rec == "ask":
        return Outcome.ASK

    # rec is "allow" or "audit" — apply trust/tag overrides
    # --- Priority 4: resource trust + action type heuristics ---------------

    # Low-trust code execution → inspect or sandbox
    if trust in ("low", "unknown") and na_str in _EXEC_ACTIONS:
        return Outcome.INSPECT

    # Low-trust with sandbox-worthy tags → sandbox
    if trust in ("low", "unknown") and tags & _SANDBOX_TAGS:
        return Outcome.SANDBOX

    # Any ask-worthy tags with medium trust → ask
    if trust == "medium" and tags & _ASK_TAGS:
        return Outcome.ASK

    # Low trust with ask-worthy tags → sandbox
    if trust in ("low", "unknown") and tags & _ASK_TAGS:
        return Outcome.SANDBOX

    # Generated code or unknown web as source → inspect if executing
    pub = _pub_str(resource)
    if pub in ("generated_code", "unknown_web") and na_str in _EXEC_ACTIONS:
        return Outcome.INSPECT

    # --- Priority 5: default based on recommendation ----------------------

    if rec == "audit":
        return Outcome.AUDIT
    if rec == "allow":
        # Final safety net: even with "allow", low trust gets audit
        if trust in ("low", "unknown"):
            return Outcome.AUDIT
        # Task-necessary + high trust → allow
        if risk.task_necessary and trust == "high":
            return Outcome.ALLOW
        # Medium trust → audit
        return Outcome.AUDIT

    # Fallback for any unrecognized recommendation
    # TODO: per proposal §4, fallback behavior not specified; v0 defaults to ask.
    return Outcome.ASK


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _trust_str(resource: Resource) -> str:
    t = resource.trust_tier
    return t.value if hasattr(t, "value") else str(t)


def _na_str(action: Action) -> str:
    na = action.normalized_action
    return na.value if isinstance(na, NormalizedAction) else str(na)


def _pub_str(resource: Resource) -> str:
    p = resource.publisher
    return p.value if hasattr(p, "value") else str(p)
