"""AIRGuard v0 — Layer 1: Resource Trust Labeling.

Assigns publisher type and trust tier to runtime resources.
See proposal §1 "Resource Trust Labeling".
"""
from __future__ import annotations

import uuid

from .types import Constraint, Publisher, Resource, TrustTier


# ---------------------------------------------------------------------------
# Publisher -> default trust tier (v0 conservative defaults)
# ---------------------------------------------------------------------------
# TODO: per proposal §1, the exact publisher-to-trust mapping is not specified;
# these are conservative v0 defaults.
_DEFAULT_TRUST: dict[str, str] = {
    Publisher.USER: TrustTier.HIGH,
    Publisher.SYSTEM: TrustTier.HIGH,
    Publisher.ORG_POLICY: TrustTier.HIGH,
    Publisher.VERIFIED_REPO: TrustTier.MEDIUM,
    Publisher.POPULAR_PACKAGE: TrustTier.MEDIUM,
    Publisher.UNKNOWN_WEB: TrustTier.LOW,
    Publisher.GENERATED_CODE: TrustTier.LOW,
    Publisher.TOOL_OUTPUT: TrustTier.MEDIUM,
}

# ---------------------------------------------------------------------------
# Publisher -> default constraints (v0 conservative defaults)
# ---------------------------------------------------------------------------
# TODO: per proposal §1, specific constraint assignments per publisher are not
# specified; these are conservative v0 defaults.
_DEFAULT_CONSTRAINTS: dict[str, list[str]] = {
    Publisher.USER: [],
    Publisher.SYSTEM: [],
    Publisher.ORG_POLICY: [],
    Publisher.VERIFIED_REPO: [Constraint.INSPECT_BEFORE_EXEC],
    Publisher.POPULAR_PACKAGE: [
        Constraint.NO_SECRET,
        Constraint.INSPECT_BEFORE_EXEC,
    ],
    Publisher.UNKNOWN_WEB: [
        Constraint.LOCAL_ONLY,
        Constraint.NO_SECRET,
        Constraint.NO_PERSIST,
        Constraint.NO_NETWORK,
        Constraint.INSPECT_BEFORE_EXEC,
    ],
    Publisher.GENERATED_CODE: [
        Constraint.LOCAL_ONLY,
        Constraint.NO_SECRET,
        Constraint.NO_PERSIST,
        Constraint.INSPECT_BEFORE_EXEC,
    ],
    Publisher.TOOL_OUTPUT: [Constraint.NO_SECRET],
}


def label_resource(resource_descriptor: dict) -> Resource:
    """Assign publisher type and trust tier to a resource.

    Args:
        resource_descriptor: dict with optional keys:
            resource_id, publisher, trust_tier, constraints, content_ref.
    """
    resource_id = resource_descriptor.get("resource_id", str(uuid.uuid4()))
    publisher = resource_descriptor.get("publisher", Publisher.UNKNOWN_WEB)
    pub_str = publisher.value if isinstance(publisher, Publisher) else str(publisher)

    # Assign trust tier from publisher if not explicitly provided
    trust_tier = resource_descriptor.get("trust_tier")
    if trust_tier is None:
        trust_tier = _DEFAULT_TRUST.get(pub_str, TrustTier.UNKNOWN)

    # Apply external certification signals (all TODO stubs)
    trust_tier = _apply_certification_signals(pub_str, trust_tier, resource_descriptor)

    # Assign constraints from publisher if not explicitly provided
    constraints = resource_descriptor.get("constraints")
    if constraints is None:
        constraints = list(
            _DEFAULT_CONSTRAINTS.get(pub_str, [Constraint.INSPECT_BEFORE_EXEC])
        )

    content_ref = resource_descriptor.get("content_ref", "")

    return Resource(
        resource_id=resource_id,
        publisher=publisher,
        trust_tier=trust_tier,
        constraints=constraints,
        content_ref=content_ref,
    )


def _apply_certification_signals(
    publisher: str,
    current_trust: str,
    descriptor: dict,
) -> str:
    """Apply external certification signals to potentially upgrade trust.

    All signals are TODO stubs per proposal §1.  No real network calls are made.
    """
    # TODO: per proposal §1, integrate known package registry check
    # (e.g. PyPI/npm download count could upgrade trust)

    # TODO: per proposal §1, integrate GitHub reputation and activity check

    # TODO: per proposal §1, integrate signed release verification

    # TODO: per proposal §1, integrate verified publisher check

    # TODO: per proposal §1, integrate prior AV or security scan result

    # TODO: per proposal §1, integrate organization-approved tool set check

    return current_trust
