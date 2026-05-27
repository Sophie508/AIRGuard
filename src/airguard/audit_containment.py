"""AIRGuard v0 — Layer 5: Sequence Audit and Containment.

Maintains a rolling action ledger and detects cross-action suspicious
patterns.  See proposal §5 "Sequence-Level Audit and Containment".

Containment mechanisms (staged commits, COW workspaces, shadow filesystems,
network mocks, approval gates, rollback metadata) are represented as metadata
stubs only.  v0 does NOT implement real OS sandboxing, process killing, or
filesystem isolation.
"""
from __future__ import annotations

from .types import (
    HighRiskTag,
    LedgerEntry,
    NormalizedAction,
    Suspicion,
    SuspicionResponse,
)


# ---------------------------------------------------------------------------
# Ledger store
# ---------------------------------------------------------------------------


class LedgerStore:
    """In-memory action ledger (proposal §5 trace)."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    def record(self, entry: LedgerEntry) -> None:
        """Append an entry to the ledger."""
        self._entries.append(entry)

    def recent(self, n: int = 10) -> list[LedgerEntry]:
        """Return the *n* most recent entries."""
        return self._entries[-n:]

    def all_entries(self) -> list[LedgerEntry]:
        """Return all entries."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Pattern definitions (proposal §5)
# ---------------------------------------------------------------------------
# Each pattern is: (name, condition_fn, severity, recommended_response)
# condition_fn receives the full history and returns a list of evidence
# action_id pairs if the pattern matches, or an empty list otherwise.


def _pattern_secret_then_network(history: list[LedgerEntry]) -> list[list[str]]:
    """Secret read followed by network send."""
    matches: list[list[str]] = []
    secret_ids: list[str] = []
    for entry in history:
        if HighRiskTag.SECRETS.value in entry.risk_tags:
            secret_ids.append(entry.action_id)
        if entry.normalized_action in (
            NormalizedAction.NETWORK_REQUEST,
            NormalizedAction.NETWORK_REQUEST.value,
            NormalizedAction.EMAIL_SEND,
            NormalizedAction.EMAIL_SEND.value,
        ) and secret_ids:
            matches.append(secret_ids + [entry.action_id])
    return matches


def _pattern_generated_then_exec(history: list[LedgerEntry]) -> list[list[str]]:
    """Generated script followed by execution."""
    matches: list[list[str]] = []
    gen_ids: list[str] = []
    for entry in history:
        na = entry.normalized_action
        na_str = na.value if isinstance(na, NormalizedAction) else str(na)
        if na_str == NormalizedAction.FILE_WRITE.value:
            gen_ids.append(entry.action_id)
        if na_str in (NormalizedAction.PROCESS_EXEC.value,) and gen_ids:
            matches.append(gen_ids[-1:] + [entry.action_id])
    return matches


def _pattern_config_then_persist(history: list[LedgerEntry]) -> list[list[str]]:
    """Config mutation followed by persistence."""
    matches: list[list[str]] = []
    config_ids: list[str] = []
    for entry in history:
        if HighRiskTag.CONFIG_POISONING.value in entry.risk_tags:
            config_ids.append(entry.action_id)
        if HighRiskTag.PERSISTENCE.value in entry.risk_tags and config_ids:
            matches.append(config_ids[-1:] + [entry.action_id])
    return matches


def _pattern_hidden_recipient_then_send(history: list[LedgerEntry]) -> list[list[str]]:
    """Hidden recipient insertion followed by email send."""
    matches: list[list[str]] = []
    hidden_ids: list[str] = []
    for entry in history:
        if HighRiskTag.HIDDEN_RECIPIENT.value in entry.risk_tags:
            hidden_ids.append(entry.action_id)
        na_str = entry.normalized_action
        if isinstance(na_str, NormalizedAction):
            na_str = na_str.value
        if na_str == NormalizedAction.EMAIL_SEND.value and hidden_ids:
            matches.append(hidden_ids[-1:] + [entry.action_id])
    return matches


def _pattern_install_then_postinstall(history: list[LedgerEntry]) -> list[list[str]]:
    """Package install followed by unexpected postinstall behavior."""
    matches: list[list[str]] = []
    install_ids: list[str] = []
    for entry in history:
        na_str = entry.normalized_action
        if isinstance(na_str, NormalizedAction):
            na_str = na_str.value
        if na_str == NormalizedAction.PACKAGE_INSTALL.value:
            install_ids.append(entry.action_id)
        elif na_str == NormalizedAction.PROCESS_EXEC.value and install_ids:
            matches.append(install_ids[-1:] + [entry.action_id])
    return matches


def _pattern_browser_then_credential(history: list[LedgerEntry]) -> list[list[str]]:
    """Browser/session access followed by credential or token use."""
    matches: list[list[str]] = []
    browser_ids: list[str] = []
    for entry in history:
        na_str = entry.normalized_action
        if isinstance(na_str, NormalizedAction):
            na_str = na_str.value
        if na_str in (
            NormalizedAction.BROWSER_NAVIGATE.value,
            NormalizedAction.BROWSER_EXTRACT.value,
        ):
            browser_ids.append(entry.action_id)
        if HighRiskTag.SECRETS.value in entry.risk_tags and browser_ids:
            matches.append(browser_ids[-1:] + [entry.action_id])
    return matches


def _pattern_repeated_low_risk_escalation(
    history: list[LedgerEntry],
) -> list[list[str]]:
    """Repeated low-risk actions that combine into exfiltration or priv esc.

    v0 heuristic: if >=3 distinct actions have non-empty risk_tags within the
    last 10 entries, flag as suspicious accumulation.
    """
    # TODO: per proposal §5, the exact threshold and combination logic for
    # repeated low-risk escalation is not specified; v0 uses a simple count.
    recent = history[-10:]
    tagged = [e for e in recent if e.risk_tags]
    if len(tagged) >= 3:
        return [[e.action_id for e in tagged]]
    return []


# Pattern registry
_PATTERNS: list[tuple[str, Any, str, SuspicionResponse]] = [
    (
        "secret_read_then_network_send",
        _pattern_secret_then_network,
        "critical",
        SuspicionResponse.ABORT,
    ),
    (
        "generated_script_then_exec",
        _pattern_generated_then_exec,
        "high",
        SuspicionResponse.ISOLATE,
    ),
    (
        "config_mutation_then_persistence",
        _pattern_config_then_persist,
        "high",
        SuspicionResponse.ROLLBACK,
    ),
    (
        "hidden_recipient_then_send",
        _pattern_hidden_recipient_then_send,
        "critical",
        SuspicionResponse.ABORT,
    ),
    (
        "package_install_then_postinstall",
        _pattern_install_then_postinstall,
        "high",
        SuspicionResponse.ISOLATE,
    ),
    (
        "browser_then_credential_use",
        _pattern_browser_then_credential,
        "high",
        SuspicionResponse.ALERT,
    ),
    (
        "repeated_low_risk_escalation",
        _pattern_repeated_low_risk_escalation,
        "medium",
        SuspicionResponse.ALERT,
    ),
]

# Needed for type annotation since we use Any above
from typing import Any  # noqa: E402


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def audit_sequence(history: list[LedgerEntry]) -> list[Suspicion]:
    """Look for cross-action suspicious patterns in the ledger (proposal §5)."""
    suspicions: list[Suspicion] = []
    for name, detector, severity, response in _PATTERNS:
        for evidence_ids in detector(history):
            suspicions.append(
                Suspicion(
                    pattern_name=name,
                    evidence_ids=evidence_ids,
                    severity=severity,
                    recommended_response=response,
                )
            )
    return suspicions
