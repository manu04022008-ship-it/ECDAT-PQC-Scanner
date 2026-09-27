"""CycloneDX v1.6 CBOM exporter using the ECDAT recommendation engine."""
from __future__ import annotations

import datetime
import uuid

from pqc_recommendations import get_pqc_recommendation


def get_recommendation(algorithm: str, purpose: str = "", asset_type: str = "", protocol: str = "", environment: str = "", risk_tier: str = "", evidence_type: str = "") -> dict:
    return get_pqc_recommendation(algorithm, purpose, asset_type, protocol, environment, risk_tier, evidence_type)


def _line(value) -> int:
    try:
        return int(value or 1)
    except (TypeError, ValueError):
        return 1


def export_cyclonedx_cbom(df) -> dict:
    components = []
    root_uuid = str(uuid.uuid4())
    components.append({
        "type": "application",
        "bom-ref": root_uuid,
        "name": "PS-164-Scanned-Project",
        "version": "1.0.0",
    })
    dep_depends_on = []

    for _, row in df.iterrows():
        comp_uuid = str(uuid.uuid4())
        dep_depends_on.append(comp_uuid)
        algo = str(row.get("algorithm", "UNKNOWN"))
        asset_type = str(row.get("asset_type", "algorithm"))
        purpose = str(row.get("purpose", "unknown"))
        q_status = str(row.get("quantum_status", "QUANTUM-VULNERABLE"))
        rec = get_recommendation(
            algo, purpose, asset_type, row.get("protocol", ""),
            row.get("environment", ""), row.get("Risk Tier", ""), row.get("evidence_type", ""),
        )
        cdx_type = "cryptographic-asset"
        if asset_type == "certificate": cdx_type = "certificate"
        elif asset_type == "library_provider": cdx_type = "library"
        elif asset_type == "protocol": cdx_type = "protocol"
        components.append({
            "type": cdx_type,
            "bom-ref": comp_uuid,
            "name": algo,
            "version": str(row.get("version", "1.0")),
            "cryptoProperties": {
                "assetType": asset_type,
                "purpose": purpose,
                "quantumRisk": q_status,
                "location": {"file": str(row.get("file", "")), "line": _line(row.get("line"))},
                "pqcRecommendation": {
                    "replacement": rec["replacement"],
                    "hybridOption": rec["hybrid_option"],
                    "standard": rec["standard"],
                    "migrationStrategy": rec["migration_strategy"],
                    "rationale": rec["rationale"],
                    "latencyImpact": rec["latency"],
                    "migrationCost": rec["cost"],
                    "compatibility": rec["compatibility"],
                },
            },
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [{"vendor": "PS-164", "name": "PQC Discovery & Quantum Risk Assessment Platform", "version": "1.0.0"}],
        },
        "components": components,
        "dependencies": [{"ref": root_uuid, "dependsOn": dep_depends_on}],
    }
