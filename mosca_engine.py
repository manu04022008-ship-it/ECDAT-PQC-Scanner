"""ECDAT Quantum Risk & MOSCA Decision Engine (PS-164).

The engine keeps the three scenario methods exposed by the UI while making the
risk decision transparent: Mosca exposure (X+Y vs Z) is combined with data
sensitivity, business criticality, operational exposure, and classical status.
"""
from __future__ import annotations

import json
import os
from typing import Any

CATALOG_PATH = os.path.join(os.path.dirname(__file__), "data", "crypto_catalog.json")
CRYPTO_CATALOG: dict[str, Any] = {}
if os.path.exists(CATALOG_PATH):
    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            CRYPTO_CATALOG = json.load(f)
    except Exception:
        CRYPTO_CATALOG = {}


def _num(value: Any, default: float) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _scale(value: Any, default: int = 3) -> int:
    return max(1, min(5, int(round(_num(value, default)))))


def _catalog_for(algorithm: str) -> dict[str, Any]:
    algo = str(algorithm or "").upper().strip()
    if algo in CRYPTO_CATALOG:
        return CRYPTO_CATALOG[algo]
    # Match catalog families conservatively; exact algorithm names win.
    for key, entry in CRYPTO_CATALOG.items():
        if key.upper() in algo or algo in key.upper():
            return entry
    return {}


def derive_asset_context(finding: dict) -> dict:
    """Derive purpose, exposure, defaults and crypto status for one finding."""
    algorithm = str(finding.get("algorithm", "")).upper().strip()
    asset_type = str(finding.get("asset_type", "")).lower()
    source = str(finding.get("source", finding.get("file", ""))).lower()
    catalog = _catalog_for(algorithm)

    purposes = catalog.get("purposes") or []
    if purposes:
        purpose = purposes[0]
    elif any(k in algorithm for k in ("RSA", "ECDH", "ECDHE", "DH", "KYBER", "ML-KEM")):
        purpose = "key_establishment"
    elif any(k in algorithm for k in ("ECDSA", "ED25519", "ED448", "DSA", "DILITHIUM", "ML-DSA", "SLH-DSA")):
        purpose = "digital_signature"
    elif any(k in algorithm for k in ("AES", "DES", "3DES", "RC4", "CHACHA")):
        purpose = "data_encryption"
    elif any(k in algorithm for k in ("MD5", "SHA-1", "SHA1", "SHA-256", "SHA-384", "SHA-512", "SHA-3")):
        purpose = "hashing"
    else:
        purpose = "crypto_provider" if asset_type == "library_provider" else "unknown"

    defaults = {
        "key_establishment": (7.0, 3.0, 4, 4),
        "digital_signature": (6.0, 2.5, 4, 4),
        "data_encryption": (10.0, 2.0, 4, 4),
        "hashing": (2.0, 1.0, 2, 2),
        "crypto_provider": (5.0, 2.0, 2, 2),
        "unknown": (5.0, 2.0, 3, 3),
    }
    dx, dy, ds, db = defaults.get(purpose, defaults["unknown"])

    x = _num(finding.get("x_shelf_life"), dx)
    y = _num(finding.get("y_migration_time"), dy)
    sensitivity = _scale(finding.get("data_sensitivity"), ds)
    criticality = _scale(finding.get("business_criticality"), db)

    if any(k in source for k in ("nginx", "apache", "sshd", "server", "ingress", "gateway", "cert", ".pem", ".crt", "public")):
        exposure = "external_facing"
    elif any(k in source for k in ("config", "api", "client", "service", "container")):
        exposure = "internal_service"
    else:
        exposure = "isolated_code"

    q_status = str(catalog.get("quantum_status", finding.get("quantum_status", "QUANTUM-VULNERABLE"))).upper()
    if any(k in algorithm for k in ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS+")):
        q_status = "PQC-STANDARDIZED"
    elif any(k in algorithm for k in ("AES-256", "SHA-256", "SHA-384", "SHA-512", "SHA-3", "CHACHA20")):
        q_status = "QUANTUM-RESISTANT"

    classical = str(catalog.get("classical_status", finding.get("classical_status", "SECURE"))).upper()
    return {
        "purpose": purpose,
        "exposure": exposure,
        "quantum_status": q_status,
        "classical_status": classical,
        "x_shelf_life": x,
        "y_migration_time": y,
        "data_sensitivity": sensitivity,
        "business_criticality": criticality,
    }


def _safe_result(tier: str, priority: str, action: str, x: float, y: float, z: float,
                 metric: float, label: str, explanation: str, score: float = 0.0,
                 mosca_status: str = "NOT_APPLICABLE", margin: float = 0.0,
                 ratio: float = 0.0) -> dict:
    return {
        "tier": tier, "risk_tier": tier,
        "priority": priority, "action": action,
        "X": x, "Y": y, "Z": z,
        "exposure_years": round(x + y, 2),
        "metric_value": round(metric, 2), "metric_label": label,
        "risk_score": round(max(0.0, min(100.0, score)), 2),
        "mosca_status": mosca_status, "mosca_margin": round(margin, 2),
        "exposure_ratio": round(ratio, 2), "explanation": explanation,
    }


def evaluate_asset_risk(
    algorithm: str,
    purpose: str,
    quantum_status: str,
    classical_status: str,
    x_shelf_life: float,
    y_migration_time: float,
    z_crqc_horizon: float,
    data_sensitivity: int = 3,
    business_criticality: int = 3,
    method: str = "Standard Mosca Inequality (X + Y > Z)",
    exposure: str = "isolated_code",
):
    """Evaluate one asset using transparent PS-164 quantum-risk logic."""
    x = max(0.0, _num(x_shelf_life, 5.0))
    y = max(0.0, _num(y_migration_time, 2.0))
    z = max(1.0, _num(z_crqc_horizon, 10.0))
    sensitivity = _scale(data_sensitivity)
    criticality = _scale(business_criticality)
    q = str(quantum_status or "QUANTUM-VULNERABLE").upper()
    classical = str(classical_status or "SECURE").upper()
    algo = str(algorithm or "UNKNOWN")
    purpose = str(purpose or "unknown")

    total = x + y
    margin = total - z
    ratio = total / z
    mosca_status = "EXCEEDS_HORIZON" if total > z else "WITHIN_HORIZON"
    broken = classical in {"BROKEN", "DEPRECATED", "INSECURE"}
    pqc = q in {"PQC-STANDARDIZED", "QUANTUM-SAFE"} and not broken
    resistant = q == "QUANTUM-RESISTANT" and not broken

    # Already-standardized PQC is not assigned migration urgency.
    if pqc:
        return _safe_result(
            "LOW", "P3", "No PQC migration required; maintain crypto inventory",
            x, y, z, 0.0, "Safe (PQC)",
            f"{algo} is marked {q}; the asset is treated as PQC-ready under this assessment scenario.",
            5.0, "NOT_APPLICABLE", margin, ratio,
        )

    # Quantum-resistant symmetric/hash primitives can still be classically weak.
    if resistant and not broken:
        return _safe_result(
            "LOW", "P3", "No quantum migration required; continue lifecycle monitoring",
            x, y, z, 0.0, "Quantum-Resistant", 
            f"{algo} is treated as quantum-resistant for this scenario. Continue normal algorithm and key-lifecycle governance.",
            10.0, "NOT_APPLICABLE", margin, ratio,
        )

    # Classical break/deprecation always outranks a long Mosca horizon.
    if broken:
        score = 82 + 3 * (sensitivity - 3) + 3 * (criticality - 3)
        if exposure == "external_facing":
            score += 6
        tier = "CRITICAL" if score >= 80 else "HIGH"
        priority = "P0" if sensitivity >= 4 or criticality >= 4 or exposure == "external_facing" else "P1"
        action = f"Immediate remediation: {classical.lower()} classical cryptography ({algo})"
        explanation = (
            f"Classical status is {classical}. This overrides a favorable quantum horizon because the primitive is already broken/deprecated. "
            f"Sensitivity={sensitivity}/5, Business Criticality={criticality}/5, Exposure={exposure}."
        )
        return _safe_result(tier, priority, action, x, y, z, score, "Risk Score", explanation, score, mosca_status, margin, ratio)

    # Mosca base urgency. This is deliberately monotonic with X+Y vs Z.
    if ratio > 1.0:
        base = 72.0
    elif ratio >= 0.75:
        base = 57.0
    elif ratio >= 0.40:
        base = 38.0
    else:
        base = 22.0

    # Context modifiers make sensitive/mission-critical assets rise faster.
    context = 4.0 * (sensitivity - 3) + 4.0 * (criticality - 3)
    if purpose in {"key_establishment", "digital_signature"}:
        context += 5.0
    if exposure == "external_facing":
        context += 8.0
    elif exposure == "internal_service":
        context += 3.0
    score = max(0.0, min(100.0, base + context))

    if score >= 80:
        tier = "CRITICAL"
    elif score >= 60:
        tier = "HIGH"
    elif score >= 35:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    if tier == "CRITICAL":
        priority = "P0" if sensitivity >= 4 or criticality >= 4 or ratio > 1.0 else "P1"
        action = f"Start PQC migration immediately: {algo}"
    elif tier == "HIGH":
        priority = "P1" if sensitivity >= 4 or criticality >= 4 else "P2"
        action = f"Plan PQC migration: {algo}"
    elif tier == "MEDIUM":
        priority = "P2"
        action = f"Schedule PQC migration assessment: {algo}"
    else:
        priority = "P3"
        action = f"Inventory and monitor: {algo}"

    if method == "Standard Mosca Inequality (X + Y > Z)":
        metric, label = total, "Exposure (X+Y)"
    elif method == "Sensitivity-Weighted QPS (W × max(1, (X+Y)/Z))":
        metric = sensitivity * max(1.0, ratio)
        label = "Sensitivity-Weighted QPS"
    elif method == "Data Shelf-Life Ratio (X / Z)":
        metric = x / z
        label = "Shelf-Life Ratio (X/Z)"
    else:
        metric, label = total, "Exposure (X+Y)"

    explanation = (
        f"Mosca check: X={x:g} yrs + Y={y:g} yrs = {total:g} yrs vs Z={z:g} yrs; "
        f"margin={margin:g} yrs, ratio={ratio:.2f}x ({mosca_status}). "
        f"Sensitivity={sensitivity}/5, Business Criticality={criticality}/5, Exposure={exposure}. "
        f"Final ECDAT risk score={score:.1f}/100."
    )
    return _safe_result(tier, priority, action, x, y, z, metric, label, explanation, score, mosca_status, margin, ratio)
