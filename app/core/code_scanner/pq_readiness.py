"""Post-quantum readiness summary.

Rolls the ``pqc.*`` findings from a scan into one migration-status
block: which quantum-vulnerable crypto families appear, how much of
the exposure is harvest-now-decrypt-later (confidentiality) versus
signatures, whether PQC adoption is already visible, and one
actionable recommendation. This is the CBOM-style view an analyst
reads first; the individual findings carry the file/line evidence.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.core.code_scanner.model import Finding

# Family tag per rule. "Key establishment" families are the HNDL
# (harvest-now-decrypt-later) exposure: ciphertext recorded today is
# readable once a cryptographically relevant quantum computer exists,
# so those call sites migrate first. RSA whose *usage* cannot be
# determined statically (a keygen call may feed transport or signing)
# is counted as potential HNDL exposure deliberately — for a
# migration-priority metric, over-counting beats silently missing key
# transport. Known signature-only uses (ssh-keygen, JWT, explicit
# signing APIs) are tagged "signature" by their rules instead.
_RULE_FAMILY: dict[str, str] = {
    "pqc.rsa-in-use": "rsa",
    "pqc.classical-key-exchange": "key_exchange",
    "pqc.classical-kex-pinned-config": "key_exchange_config",
    "pqc.classical-signature": "signature",
    "pqc.jwt-classical-alg": "signature",
    "pqc.weak-asymmetric-keysize": "weak_keysize",
    "pqc.small-symmetric-key": "symmetric_margin",
    "pqc.pqc-in-use": "pqc_adopted",
    "pqc.weak-pqc-parameter-set": "pqc_weak_params",
}

_HNDL_FAMILIES = frozenset({"rsa", "key_exchange", "key_exchange_config", "weak_keysize"})
_CLASSICAL_FAMILIES = _HNDL_FAMILIES | {"signature"}

_RECOMMENDATIONS: dict[str, str] = {
    "no_crypto_detected": (
        "No classical or post-quantum primitives detected at this scan depth."
    ),
    "quantum_vulnerable": (
        "Quantum-vulnerable cryptography with no visible PQC adoption. Start with "
        "the harvest-now-decrypt-later findings (key exchange / RSA transport): "
        "enable hybrid ML-KEM key establishment, then plan ML-DSA signatures "
        "before the NIST IR 8547 2030/2035 deadlines."
    ),
    "migration_in_progress": (
        "Both classical and post-quantum primitives detected — migration appears "
        "in progress. Close the remaining harvest-now-decrypt-later findings and "
        "confirm the PQC paths run in hybrid mode."
    ),
    "pq_ready": (
        "Only post-quantum primitives detected. Verify parameter sets meet NIST "
        "security category 3+ and that deployments stay hybrid until classical "
        "crypto is fully retired."
    ),
    "symmetric_margin_only": (
        "No quantum-breakable asymmetric cryptography detected — only symmetric-"
        "key margin findings (AES-128/192). Prefer AES-256 for data that must "
        "stay confidential long-term."
    ),
}


def summarize_pq_readiness(findings: Iterable[Finding]) -> dict[str, object]:
    """Build the ``pq_readiness`` block from a scan's findings."""
    families: dict[str, int] = {}
    files: set[str] = set()
    for finding in findings:
        family = _RULE_FAMILY.get(finding.rule_id)
        if family is None:
            continue
        families[family] = families.get(family, 0) + 1
        files.add(finding.file_path)

    hndl = sum(count for family, count in families.items() if family in _HNDL_FAMILIES)
    classical = sum(
        count for family, count in families.items() if family in _CLASSICAL_FAMILIES
    )
    adopted = families.get("pqc_adopted", 0)
    weak_params = families.get("pqc_weak_params", 0)
    # A weak-parameter hit (ML-KEM-512 etc.) is still evidence that PQC
    # is deployed — it must count as adoption or a below-strength-but-
    # migrated repo would misclassify.
    adopted_evidence = adopted + weak_params

    if not families:
        status = "no_crypto_detected"
    elif classical and adopted_evidence:
        status = "migration_in_progress"
    elif classical:
        status = "quantum_vulnerable"
    elif adopted_evidence:
        status = "pq_ready"
    else:
        # Only symmetric_margin findings: AES-128 is not quantum-broken,
        # but calling this "pq_ready" would be a false green light.
        status = "symmetric_margin_only"

    recommendation = _RECOMMENDATIONS[status]
    if status == "pq_ready" and weak_params:
        recommendation = (
            "Post-quantum primitives detected, but some parameter sets are below "
            "NIST security category 3 — upgrade those first. " + recommendation
        )

    return {
        "status": status,
        "hndl_exposure": hndl,
        "classical_findings": classical,
        "signature_findings": families.get("signature", 0),
        "pqc_findings": adopted,
        "weak_pqc_parameter_findings": weak_params,
        "files_affected": len(files),
        "families": dict(sorted(families.items())),
        "recommendation": recommendation,
    }


__all__ = ["summarize_pq_readiness"]
