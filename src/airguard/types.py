"""AIRGuard v0 — shared type definitions.

Dataclasses and enums matching the 5-layer proposal in
AIRGuard/docs/airguard_proposal.md.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Publisher(str, Enum):
    """Resource publisher types (proposal §1)."""
    USER = "user"
    SYSTEM = "system"
    ORG_POLICY = "org_policy"
    VERIFIED_REPO = "verified_repo"
    POPULAR_PACKAGE = "popular_package"
    UNKNOWN_WEB = "unknown_web"
    GENERATED_CODE = "generated_code"
    TOOL_OUTPUT = "tool_output"


class TrustTier(str, Enum):
    """Resource trust tiers (proposal §1)."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Issuer(str, Enum):
    """Authority issuers (proposal §2).

    issuer = who granted authority. This is NOT the same as publisher.
    """
    USER = "user"
    SYSTEM = "system"
    ORG_POLICY = "org_policy"
    EXPLICIT_CONSENT = "explicit_consent"


class Subject(str, Enum):
    """Authority subjects (proposal §2)."""
    AGENT = "agent"
    TOOL = "tool"
    CODE_BLOCK = "code_block"


class Scope(str, Enum):
    """Authority scope (proposal §2)."""
    TASK = "task"
    STEP = "step"
    SESSION = "session"


class GuardLevel(str, Enum):
    """Guard level in authority context (proposal §2)."""
    ALLOW = "allow"
    ASK = "ask"
    SANDBOX = "sandbox"
    QUARANTINE = "quarantine"
    AUDIT = "audit"
    BLOCK = "block"


class Outcome(str, Enum):
    """Enforcement outcomes (proposal §4)."""
    ALLOW = "allow"
    AUDIT = "audit"
    ASK = "ask"
    INSPECT = "inspect"
    SANDBOX = "sandbox"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class NormalizedAction(str, Enum):
    """Normalized runtime action schema (proposal §"Normalized Runtime Actions")."""
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    PROCESS_EXEC = "process.exec"
    NETWORK_REQUEST = "network.request"
    EMAIL_SEND = "email.send"
    TOOL_CALL = "tool.call"
    BROWSER_NAVIGATE = "browser.navigate"
    BROWSER_EXTRACT = "browser.extract"
    MEMORY_WRITE = "memory.write"
    CONFIG_MODIFY = "config.modify"
    DATABASE_QUERY = "database.query"
    PACKAGE_INSTALL = "package.install"
    OUTPUT_RESPOND = "output.respond"


class HighRiskTag(str, Enum):
    """High-risk semantic tags (proposal §2)."""
    SECRETS = "secrets"
    PERSISTENCE = "persistence"
    DESTRUCTIVE_WRITE = "destructive_write"
    HIDDEN_RECIPIENT = "hidden_recipient"
    UNAUTHORIZED_NETWORK = "unauthorized_network"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DOWNLOAD_EXECUTE = "download_execute"
    CONFIG_POISONING = "config_poisoning"


class Constraint(str, Enum):
    """Resource constraints (proposal §1)."""
    LOCAL_ONLY = "local_only"
    NO_SECRET = "no_secret"
    NO_PERSIST = "no_persist"
    NO_NETWORK = "no_network"
    INSPECT_BEFORE_EXEC = "inspect_before_exec"


class SuspicionResponse(str, Enum):
    """Recommended response for detected suspicions.

    # TODO: per proposal §5, the exact response enum is not specified;
    # these are conservative v0 defaults derived from the containment
    # mechanisms the proposal describes (staged commits, COW workspaces,
    # rollback metadata, etc.).
    """
    ALERT = "alert"
    ROLLBACK = "rollback"
    KILL = "kill"
    ABORT = "abort"
    ISOLATE = "isolate"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Resource:
    """A runtime resource with trust labeling (proposal §1)."""
    resource_id: str
    publisher: Publisher | str
    trust_tier: TrustTier | str
    constraints: list[str] = field(default_factory=list)
    content_ref: str = ""


@dataclass
class AuthorityContext:
    """Compact authority context (proposal §2).

    issuer = who granted authority (user, system, org_policy, explicit_consent).
    This is NOT the same as publisher (who supplied the resource).
    Unknown or low-trust publishers may inform an action but cannot mint authority.
    """
    issuer: Issuer | str
    subject: Subject | str
    scope: Scope | str
    ttl: int | str = ""
    allow: list[str] = field(default_factory=list)
    guard: str = "ask"
    user_intent: str = ""


@dataclass
class Action:
    """A proposed agent action (proposal §"Normalized Runtime Actions")."""
    action_id: str
    name: str  # raw tool/action name
    args: dict = field(default_factory=dict)
    source_resource_id: str = ""
    required_capabilities: list[str] = field(default_factory=list)
    normalized_action: NormalizedAction | str = NormalizedAction.TOOL_CALL


@dataclass
class TargetTrust:
    """Trust assessment for an action's target (v2.1)."""
    tier: str = "unknown"  # "high" | "medium" | "low" | "unknown"
    score: float | None = None
    confidence: float = 0.4
    source: str = ""
    assessor: str = "heuristic"  # "runtime_airguard" | "offline_unified_judge" | "heuristic" | "llm"
    reason: str = ""


@dataclass
class RiskAssessment:
    """Result of LLM-based risk simulation (proposal §3)."""
    predicted_effects: list[str] = field(default_factory=list)
    task_necessary: bool = True
    attack_pattern_match: str | None = None
    authority_source: str = "unknown"
    recommendation: str = "ask"
    source: str = "fallback"  # "llm" or "fallback"
    llm_model: str = ""
    llm_reason: str = ""
    llm_error: str = ""


@dataclass
class ScriptRiskAssessment:
    """Result of script-specific risk simulation (proposal §3).

    The proposal describes a "unit test without execution": predict effects
    and flag suspicious constructs without running the script.
    """
    predicted_file_effects: list[str] = field(default_factory=list)
    predicted_network_effects: list[str] = field(default_factory=list)
    predicted_process_effects: list[str] = field(default_factory=list)
    suspicious_constructs: list[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    encoded_payloads_detected: bool = False
    download_execute_detected: bool = False
    credential_access_detected: bool = False
    persistence_detected: bool = False
    anti_sandbox_detected: bool = False
    overall_risk: str = "medium"
    recommendation: str = "inspect"


@dataclass
class Suspicion:
    """A detected cross-action suspicious pattern (proposal §5)."""
    pattern_name: str
    evidence_ids: list[str] = field(default_factory=list)
    severity: str = "medium"
    recommended_response: SuspicionResponse | str = SuspicionResponse.ALERT


@dataclass
class GuardDecision:
    """Final decision from the guard (all 5 layers combined)."""
    outcome: Outcome | str
    reasoning: str = ""
    action_taken: str = ""
    ledger_entry_id: str = ""
    risk_source: str = ""       # "llm" or "fallback"
    risk_model: str = ""        # e.g. "gpt-5.4-mini"
    risk_recommendation: str = ""
    risk_reason: str = ""
    risk_error: str = ""
    # v2.1: target trust
    target: str = ""
    target_type: str = ""
    target_trust_tier: str = ""
    target_trust_score: float | None = None
    target_trust_confidence: float = 0.0
    target_trust_source: str = ""
    target_trust_assessor: str = ""
    target_trust_reason: str = ""


@dataclass
class LedgerEntry:
    """An entry in the action ledger (proposal §5 trace format)."""
    action_id: str
    normalized_action: NormalizedAction | str = NormalizedAction.TOOL_CALL
    authority_source: str = ""
    # TODO: per proposal, capability token lifecycle not fully specified in v0
    capability_token: str = ""
    policy_decision: str = ""
    filesystem_diff: str = ""
    network_events: str = ""
    process_tree: str = ""
    secret_access_attempts: str = ""
    recovery_metadata: str = ""
    # Proposal trace fields (§5)
    resource_trust: str = ""
    authority_context: str = ""
    risk_tags: list[str] = field(default_factory=list)
    # TODO: per proposal §5, observed_effect schema not specified; v0 uses free-text
    observed_effect: str = ""
    # TODO: per proposal §5, cumulative_risk calculation not specified; v0 defaults to 0
    cumulative_risk: float = 0.0
