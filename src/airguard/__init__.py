"""AIRGuard v0 — Contextual Authority-Risk Guard for LLM Agent Runtimes.

5-layer architecture matching AIRGuard/docs/airguard_proposal.md:
    Layer 1: Resource Trust Labeling     (trust_labeling.py)
    Layer 2: Minimal Authority Context   (authority_context.py)
    Layer 3: LLM-Based Risk Simulation   (risk_simulation.py)
    Layer 4: Tiered Enforcement          (enforcement.py)
    Layer 5: Sequence Audit & Containment (audit_containment.py)

Orchestrator: guard.py  (check_action, post_action_audit)
"""
from .types import (
    Action,
    AuthorityContext,
    Constraint,
    GuardDecision,
    GuardLevel,
    HighRiskTag,
    Issuer,
    LedgerEntry,
    NormalizedAction,
    Outcome,
    Publisher,
    Resource,
    RiskAssessment,
    Scope,
    ScriptRiskAssessment,
    Subject,
    Suspicion,
    SuspicionResponse,
    TrustTier,
)
from .trust_labeling import label_resource
from .authority_context import (
    compile_task_authority,
    derive_step_authority,
    detect_risk_tags,
    check_authority_coverage,
)
from .risk_simulation import simulate_risk, simulate_script_execution
from .enforcement import decide_enforcement
from .audit_containment import LedgerStore, audit_sequence
from .guard import (
    check_action,
    post_action_audit,
    action_from_tool_call,
    history_from_tool_log,
)

__all__ = [
    # Types
    "Action",
    "AuthorityContext",
    "Constraint",
    "GuardDecision",
    "GuardLevel",
    "HighRiskTag",
    "Issuer",
    "LedgerEntry",
    "NormalizedAction",
    "Outcome",
    "Publisher",
    "Resource",
    "RiskAssessment",
    "Scope",
    "ScriptRiskAssessment",
    "Subject",
    "Suspicion",
    "SuspicionResponse",
    "TrustTier",
    # Layer 1
    "label_resource",
    # Layer 2
    "compile_task_authority",
    "derive_step_authority",
    "detect_risk_tags",
    "check_authority_coverage",
    # Layer 3
    "simulate_risk",
    "simulate_script_execution",
    # Layer 4
    "decide_enforcement",
    # Layer 5
    "LedgerStore",
    "audit_sequence",
    # Guard
    "check_action",
    "post_action_audit",
    "action_from_tool_call",
    "history_from_tool_log",
]
