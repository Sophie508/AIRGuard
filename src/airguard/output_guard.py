"""AIRGuard v2.1 — Output Guard.

Post-execution guards for tool output and final agent responses.
These are generic AIRGuard capabilities, not benchmark-specific.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Credential patterns
# ---------------------------------------------------------------------------

# JSON field: "password": "value"
_CREDENTIAL_JSON_RE = re.compile(
    r'"(password|passwd|secret|token|pin|api_key|private_key|credentials?|auth_token)"'
    r'\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)

# Key=value / key: value (plaintext, env vars, config files)
# Matches both bare keys (password=xxx) and prefixed env names
# (OPENAI_API_KEY=xxx, DATABASE_PASSWORD=xxx, AWS_SECRET_ACCESS_KEY=xxx)
_CREDENTIAL_KV_RE = re.compile(
    r'(\b\w*(?:password|passwd|secret|token|pin|api_key|private_key|auth_token|'
    r'credentials?|secret_key|access_key)\w*)\s*[:=]\s*(\S+)',
    re.IGNORECASE,
)

# Authorization header: Bearer xxx
_BEARER_RE = re.compile(
    r'(Bearer|Authorization[:=]\s*Bearer)\s+(\S+)',
    re.IGNORECASE,
)

# Sensitive file/path targets
SENSITIVE_TARGETS = [
    ".bashrc", ".zshrc", ".profile", ".bash_profile", ".bash_login",
    ".ssh", ".env", ".aws", "id_rsa",
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "crontab", "systemd", "launchd",
]

# Enforcement outcomes that deny execution in unattended environments
DENY_OUTCOMES = frozenset({"block", "quarantine", "sandbox", "inspect", "ask"})


# ---------------------------------------------------------------------------
# Credential redaction
# ---------------------------------------------------------------------------

def redact_credentials(text: str) -> str:
    """Redact credential values from text, keeping field names.

    Handles JSON fields, key=value pairs, env vars, and Bearer tokens.
    """
    # JSON: "password": "xxx" → "password": "[REDACTED by AIRGuard]"
    text = _CREDENTIAL_JSON_RE.sub(
        lambda m: f'"{m.group(1)}": "[REDACTED by AIRGuard]"', text,
    )
    # key=value: password=xxx → password=[REDACTED by AIRGuard]
    def _kv_replace(m: re.Match) -> str:
        key = m.group(1)
        # Preserve the separator (: or =)
        full = m.group(0)
        sep_idx = len(key)
        sep = full[sep_idx:sep_idx + 1].strip() or "="
        return f"{key}{sep}[REDACTED by AIRGuard]"
    text = _CREDENTIAL_KV_RE.sub(_kv_replace, text)
    # Bearer token
    text = _BEARER_RE.sub(
        lambda m: f'{m.group(1)} [REDACTED by AIRGuard]', text,
    )
    return text


def has_credential_leak(text: str) -> bool:
    """Check if text contains any credential value (JSON, key=value, or Bearer)."""
    if not text:
        return False
    return bool(
        _CREDENTIAL_JSON_RE.search(text)
        or _CREDENTIAL_KV_RE.search(text)
        or _BEARER_RE.search(text)
    )


def has_credential_in_response(text: str) -> bool:
    """Check if a final response leaks credential-like values."""
    return has_credential_leak(text)


# ---------------------------------------------------------------------------
# Sensitive target detection
# ---------------------------------------------------------------------------

def is_sensitive_target(args: dict) -> bool:
    """Check if any arg value references a sensitive file/path."""
    for v in args.values():
        if isinstance(v, str):
            vl = v.lower()
            for s in SENSITIVE_TARGETS:
                if s in vl:
                    return True
    return False


def should_deny_outcome(outcome: str) -> bool:
    """Whether an enforcement outcome should deny execution.

    In unattended benchmark environments, only ``allow`` and ``audit``
    permit real execution.  Everything else (block, ask, inspect,
    sandbox, quarantine) is treated as deny.
    """
    return outcome in DENY_OUTCOMES
