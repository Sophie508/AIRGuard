"""AIRGuard v0 — Layer 2: Minimal Authority Context.

Builds and narrows compact authority contexts.
See proposal §2 "Minimal Authority Context".

Key distinction (proposal §2):
    issuer  = who granted authority  (user, system, org_policy, explicit_consent)
    publisher = who supplied the resource (user, system, ..., unknown_web, ...)
    Unknown or low-trust publishers may inform actions but cannot mint authority.
"""
from __future__ import annotations

from .types import (
    Action,
    AuthorityContext,
    HighRiskTag,
    Issuer,
    NormalizedAction,
    Scope,
    Subject,
)

# ---------------------------------------------------------------------------
# High-risk semantic tags (proposal §2) — re-exported for convenience
# ---------------------------------------------------------------------------
HIGH_RISK_TAGS: list[str] = [t.value for t in HighRiskTag]

# ---------------------------------------------------------------------------
# Action -> base risk tag mapping (v0 heuristic)
# ---------------------------------------------------------------------------
# TODO: per proposal §2, exact mapping from actions to risk tags is not
# specified; these are conservative v0 defaults.
_ACTION_RISK_TAG_MAP: dict[str, list[str]] = {
    NormalizedAction.FILE_READ: [],
    NormalizedAction.FILE_WRITE: [],
    NormalizedAction.FILE_DELETE: [HighRiskTag.DESTRUCTIVE_WRITE],
    NormalizedAction.PROCESS_EXEC: [HighRiskTag.DOWNLOAD_EXECUTE],
    NormalizedAction.NETWORK_REQUEST: [HighRiskTag.UNAUTHORIZED_NETWORK],
    NormalizedAction.EMAIL_SEND: [HighRiskTag.HIDDEN_RECIPIENT],
    NormalizedAction.TOOL_CALL: [],
    NormalizedAction.BROWSER_NAVIGATE: [HighRiskTag.UNAUTHORIZED_NETWORK],
    NormalizedAction.BROWSER_EXTRACT: [],
    NormalizedAction.MEMORY_WRITE: [],
    NormalizedAction.CONFIG_MODIFY: [
        HighRiskTag.CONFIG_POISONING,
        HighRiskTag.PERSISTENCE,
    ],
    NormalizedAction.DATABASE_QUERY: [],
    NormalizedAction.PACKAGE_INSTALL: [HighRiskTag.DOWNLOAD_EXECUTE],
    NormalizedAction.OUTPUT_RESPOND: [],
}

_SECRET_PATH_PATTERNS: list[str] = [
    ".ssh/", ".env", ".aws/", ".config/",
    "api_key", "secret_key", "private_key", "auth_key", "encryption_key",
    "access_token", "refresh_token", "bearer_token", "auth_token",
    "_token=", "_token/", "_key=", "_key/",
    "credentials", "secrets/", "secrets.json", "secrets.yaml", "secrets.yml",
    "id_rsa", "id_ed25519", "known_hosts",
]

_SECRET_HARVEST_PATTERNS: list[str] = [
    "current password", "enter your password", "provide your password",
    "send your password", "share your password", "password reset link",
    "credential collection", "login at http", "login at https",
]

_PERSISTENCE_PATTERNS: list[str] = [
    ".bashrc", ".zshrc", ".profile", ".bash_profile",
    "crontab", "systemd", "launchd", "autostart",
    "startup", ".config/autostart",
]

_PRIV_ESC_PATTERNS: list[str] = [
    "sudo", "chmod 777", "chmod +s", "setuid",
    "administratoraccess", "arn:aws:iam", "sts:assumerole",
    "crossaccount", "cross-account", "lambda:invokefunction",
    "authorizationtype: none",
]

# ---------------------------------------------------------------------------
# Capability requirement map (v0)
# ---------------------------------------------------------------------------
# TODO: per proposal §2, the exact mapping from normalized actions to required
# capability categories is not specified; v0 uses this simple heuristic.
_CAPABILITY_MAP: dict[str, str] = {
    "file.read": "read",
    "file.write": "write",
    "file.delete": "write",
    "process.exec": "exec",
    "network.request": "network",
    "email.send": "network",
    "tool.call": "exec",
    "output.respond": "respond",
    "browser.navigate": "network",
    "browser.extract": "read",
    "memory.write": "write",
    "config.modify": "write",
    "database.query": "read",
    "package.install": "exec",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compile_task_authority(
    user_intent: str,
    system_policy: dict | None = None,
) -> AuthorityContext:
    """Build an AuthorityContext from user intent and system policy.

    The issuer is the user (they stated the intent).  The scope is task-level.

    Args:
        user_intent: natural language description of what the user asked for.
        system_policy: optional dict with keys like ``allow``, ``deny``, ``guard``.
    """
    # TODO: per proposal §2, how to parse user_intent into allow/deny sets
    # is not specified.  v0 uses a conservative default: allow read + write
    # within workspace, require ask for everything else.
    system_policy = system_policy or {}
    allow = system_policy.get("allow", ["read", "write", "respond"])
    guard = system_policy.get("guard", "ask")
    ttl = system_policy.get("ttl", "session")

    return AuthorityContext(
        issuer=Issuer.USER,
        subject=Subject.AGENT,
        scope=Scope.TASK,
        ttl=ttl,
        allow=list(allow) if isinstance(allow, (list, tuple)) else [allow],
        guard=str(guard),
        user_intent=user_intent,
    )


def derive_step_authority(
    parent: AuthorityContext,
    step_descriptor: dict,
) -> AuthorityContext:
    """Narrow an authority context for a specific step.

    Step authority can only be equal to or narrower than the parent — it
    cannot expand permissions.
    """
    step_allow = step_descriptor.get("allow", parent.allow)
    parent_allow = parent.allow if isinstance(parent.allow, list) else [parent.allow]
    if isinstance(step_allow, list):
        step_allow = [a for a in step_allow if a in parent_allow]
    step_guard = step_descriptor.get("guard", parent.guard)

    return AuthorityContext(
        issuer=parent.issuer,
        subject=step_descriptor.get("subject", parent.subject),
        scope=Scope.STEP,
        ttl=step_descriptor.get("ttl", parent.ttl),
        allow=step_allow,
        guard=str(step_guard),
        user_intent=parent.user_intent,
    )


def detect_risk_tags(action_name: str, action_args: dict) -> list[str]:
    """Detect high-risk semantic tags for a proposed action."""
    tags: list[str] = []
    na_str = action_name.value if isinstance(action_name, NormalizedAction) else str(action_name)

    # Base tags from action type
    for t in _ACTION_RISK_TAG_MAP.get(na_str, []):
        tags.append(t.value if isinstance(t, HighRiskTag) else str(t))

    args_lower = str(action_args).lower()

    # Secret access: paths and credential-harvesting language are high risk.
    # Plain policy prose mentioning "password" should not trip this by itself.
    if any(p in args_lower for p in _SECRET_PATH_PATTERNS):
        tags.append(HighRiskTag.SECRETS.value)
    if any(p in args_lower for p in _SECRET_HARVEST_PATTERNS):
        tags.append(HighRiskTag.SECRETS.value)

    # Persistence
    if any(p in args_lower for p in _PERSISTENCE_PATTERNS):
        tags.append(HighRiskTag.PERSISTENCE.value)

    # Hidden recipient
    if na_str == NormalizedAction.EMAIL_SEND.value and (
        action_args.get("bcc") or action_args.get("cc")
    ):
        tags.append(HighRiskTag.HIDDEN_RECIPIENT.value)

    # Privilege escalation
    if any(p in args_lower for p in _PRIV_ESC_PATTERNS):
        tags.append(HighRiskTag.PRIVILEGE_ESCALATION.value)

    # Final-output phishing/network redirection.
    if na_str == NormalizedAction.OUTPUT_RESPOND.value:
        if ("http://" in args_lower or "https://" in args_lower) and (
            "password" in args_lower or "credential" in args_lower or "login" in args_lower
        ):
            tags.append(HighRiskTag.UNAUTHORIZED_NETWORK.value)

    return list(dict.fromkeys(tags))  # deduplicate, preserve order


def check_authority_coverage(
    action: Action,
    authority_ctx: AuthorityContext,
) -> tuple[bool, str]:
    """Check if the action's required capabilities are within authority.

    Returns (covered, reason).
    """
    na = action.normalized_action
    na_str = na.value if isinstance(na, NormalizedAction) else str(na)
    required = _CAPABILITY_MAP.get(na_str, "exec")
    allow_list = (
        authority_ctx.allow
        if isinstance(authority_ctx.allow, list)
        else [authority_ctx.allow]
    )

    if required in allow_list:
        return True, f"Action requires '{required}', covered by authority allow set."
    return False, (
        f"Action requires '{required}', NOT in authority allow set {allow_list}."
    )
