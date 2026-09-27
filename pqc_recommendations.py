"""Purpose-aware PQC migration recommendation engine for ECDAT / PS-164."""
from __future__ import annotations


def _u(value) -> str:
    return str(value or "").strip().upper()


def _purpose(value) -> str:
    return str(value or "").strip().lower()


def get_pqc_recommendation(
    algorithm: str,
    purpose: str = "",
    asset_type: str = "",
    protocol: str = "",
    environment: str = "",
    risk_tier: str = "",
    evidence_type: str = "",
) -> dict:
    """Return a complete, purpose-aware migration recommendation.

    The engine deliberately distinguishes key establishment from signatures.
    RSA/ECDH/DH are not automatically mapped to a signature algorithm, and
    ECDSA/EdDSA are not mapped to a KEM.
    """
    algo = _u(algorithm)
    purp = _purpose(purpose)
    proto = _u(protocol)
    env = _u(environment)
    tier = _u(risk_tier)
    evidence = _u(evidence_type)

    base = {
        "replacement": "Manual cryptographic architecture review",
        "hybrid_option": "None required",
        "standard": "N/A",
        "migration_strategy": "Inventory and validate usage before changing the primitive.",
        "rationale": "The scanner could not map this artifact to a sufficiently specific migration profile.",
        "latency": "Unknown",
        "cost": "Variable",
        "compatibility": "Review protocol and library support",
        "confidence": 0.60,
    }

    # Already PQC: do not recommend migrating a standardized PQC asset.
    if any(k in algo for k in ("ML-KEM", "ML-DSA", "SLH-DSA")):
        base.update({
            "replacement": "Maintain current PQC implementation",
            "hybrid_option": "Optional classical+PQC hybrid during transition",
            "standard": "NIST FIPS 203/204/205",
            "migration_strategy": "Maintain, patch and monitor implementation; verify approved parameter set and crypto-module status.",
            "rationale": f"{algorithm} is already a NIST-standardized PQC family; migration should focus on implementation assurance and crypto-agility.",
            "latency": "Implementation-dependent",
            "cost": "Low",
            "compatibility": "Validate library/protocol support",
            "confidence": 0.99,
        })
        return base

    # KEM / key establishment.
    key_establishment = (
        purp == "key_establishment"
        or (not purp == "digital_signature" and any(k in algo for k in ("ECDH", "ECDHE", "DIFFIE-HELLMAN", "DH", "RSA")))
        or (not purp == "digital_signature" and "KEM" in algo)
    )
    if key_establishment:
        hybrid = "X25519 + ML-KEM-768"
        if "RSA" in algo:
            hybrid = "RSA/ECDHE + ML-KEM-768 during interoperability transition"
        if "TLS" in proto:
            hybrid = "TLS hybrid key exchange: classical ECDHE + ML-KEM-768"
        base.update({
            "replacement": "ML-KEM-768 (FIPS 203)",
            "hybrid_option": hybrid,
            "standard": "NIST FIPS 203",
            "migration_strategy": "Introduce ML-KEM at the key-establishment layer; use a hybrid construction where legacy interoperability is required, then retire the classical component after compatibility validation.",
            "rationale": f"{algorithm} is used for key establishment. A KEM is the appropriate PQC replacement class; ML-KEM-768 is the primary standardized target. {'External/TLS deployment favors a hybrid rollout.' if ('TLS' in proto or env in {'PRODUCTION','CLOUD','EDGE'}) else 'Validate application/library support before rollout.'}",
            "latency": "Moderate; benchmark handshake/key-establishment overhead",
            "cost": "Medium",
            "compatibility": "Protocol/library dependent; hybrid preferred for staged rollout",
            "confidence": 0.96,
        })
        return base

    # Digital signatures.
    signature = (
        purp == "digital_signature"
        or any(k in algo for k in ("ECDSA", "ED25519", "ED448", "DSA", "RSA-PSS", "RSA-SHA", "DILITHIUM"))
    )
    if signature:
        hybrid = "ECDSA/EdDSA + ML-DSA-65 during interoperability transition"
        if "RSA" in algo:
            hybrid = "RSA signature + ML-DSA-65 during interoperability transition"
        base.update({
            "replacement": "ML-DSA-65 (FIPS 204)",
            "hybrid_option": hybrid,
            "standard": "NIST FIPS 204",
            "migration_strategy": "Add ML-DSA verification/generation support, validate certificate/signature ecosystem compatibility, then migrate signing and verification paths in controlled stages.",
            "rationale": f"{algorithm} provides digital signatures. The appropriate standardized PQC signature replacement is ML-DSA rather than a KEM. A hybrid signature rollout can preserve interoperability while dependent systems migrate.",
            "latency": "Moderate; benchmark signature size and verification cost",
            "cost": "Medium",
            "compatibility": "Certificate, signing and protocol ecosystem dependent",
            "confidence": 0.95,
        })
        return base

    # Weak hashes are classical weaknesses; PQC migration is not the right label.
    if any(k in algo for k in ("MD5", "SHA-1", "SHA1")):
        base.update({
            "replacement": "SHA-256 or SHA-3",
            "hybrid_option": "Not applicable",
            "standard": "NIST-approved secure hash families",
            "migration_strategy": "Replace weak hashing uses based on function: integrity/password/storage uses require separate design review; do not treat a hash replacement as a PQC KEM/signature migration.",
            "rationale": f"{algorithm} is primarily a classical cryptographic weakness. The remediation is a stronger hash and/or redesign of the surrounding use case, not ML-KEM or ML-DSA.",
            "latency": "Negligible for typical application workloads",
            "cost": "Low",
            "compatibility": "Usually high; validate stored hashes and protocol formats",
            "confidence": 0.99,
        })
        return base

    # Symmetric encryption: quantum impact is different from public-key crypto.
    if any(k in algo for k in ("AES", "CHACHA20", "3DES", "DES", "RC4")) or purp == "data_encryption":
        if "3DES" in algo or "DES" in algo or "RC4" in algo:
            replacement = "AES-256-GCM"
            rationale = f"{algorithm} is a legacy symmetric cipher. Replace it with a modern authenticated-encryption construction; this is classical hygiene rather than a direct public-key PQC substitution."
        else:
            replacement = "AES-256-GCM (where appropriate)"
            rationale = f"{algorithm} is symmetric encryption. It does not require replacement by ML-KEM/ML-DSA; assess key size, mode, nonce handling and lifecycle."
        base.update({
            "replacement": replacement,
            "hybrid_option": "Not applicable",
            "standard": "Approved symmetric cryptography / organizational policy",
            "migration_strategy": "Verify key size, mode, nonce/IV handling and key lifecycle; upgrade legacy modes/ciphers where necessary.",
            "rationale": rationale,
            "latency": "Low",
            "cost": "Low",
            "compatibility": "Usually high; mode and key-management dependent",
            "confidence": 0.97,
        })
        return base

    # Provider/library inventory is not proof of algorithm usage.
    if asset_type == "library_provider" or evidence == "LIBRARY_PRESENCE":
        base.update({
            "replacement": "Validate active algorithms exposed by the provider",
            "hybrid_option": "Depends on active protocol/algorithm usage",
            "standard": "N/A",
            "migration_strategy": "Do not migrate solely because a crypto provider is installed. Trace actual algorithm calls, protocol configuration and certificate usage first.",
            "rationale": f"{algorithm} is provider/library inventory evidence, not proof of active cryptographic use. The next action is usage validation.",
            "latency": "Not assessed",
            "cost": "Low",
            "compatibility": "Provider/application dependent",
            "confidence": 0.98,
        })
        return base

    return base


def recommendation_columns() -> list[str]:
    return [
        "PQC Replacement", "Hybrid Option", "PQC Standard", "Migration Strategy",
        "Recommendation Rationale", "Latency Impact", "Migration Cost", "Compatibility",
        "Recommendation Confidence",
    ]
