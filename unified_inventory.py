"""Unified CBOM inventory normalization and aggregation for ECDAT."""
from __future__ import annotations

import hashlib
from typing import Iterable

import pandas as pd


STANDARD_COLUMNS = [
    "asset_id", "source_type", "asset_type", "evidence_type", "algorithm",
    "purpose", "version", "mode", "key_size", "library_provider",
    "library_version", "protocol", "certificate", "file", "line",
    "container_image", "container_layer", "environment", "data_sensitivity",
    "business_criticality", "x_shelf_life", "y_migration_time",
    "quantum_status", "classical_status", "confidence", "Risk Tier",
    "Priority", "Action", "PQC Replacement", "Latency Impact",
    "Migration Cost", "Risk Explanation", "evidence", "snippet",
]

DISPLAY_COLUMNS = [
    "asset_id", "source_type", "asset_type", "evidence_type", "algorithm",
    "purpose", "version", "mode", "key_size", "library_provider",
    "library_version", "protocol", "certificate", "file", "line",
    "container_image", "container_layer", "environment", "quantum_status",
    "data_sensitivity", "business_criticality", "x_shelf_life",
    "y_migration_time", "Risk Tier", "Priority", "PQC Replacement",
    "Latency Impact", "Migration Cost", "confidence", "evidence", "snippet",
]


def _text(value, default="Not detected"):
    if value is None:
        return default
    try:
        if pd.isna(value):
            return default
    except Exception:
        pass
    value = str(value).strip()
    return value if value else default


def _num(value, default=0):
    try:
        if value is None or pd.isna(value):
            return default
        return value
    except Exception:
        return default


def _asset_id(row: dict) -> str:
    identity = "|".join([
        _text(row.get("source_type")),
        _text(row.get("asset_type")),
        _text(row.get("algorithm")),
        _text(row.get("file")),
        _text(row.get("line"), "0"),
        _text(row.get("purpose")),
        _text(row.get("container_image")),
        _text(row.get("library_provider")),
    ])
    return "ECDAT-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()


def normalize_findings(findings: Iterable[dict] | pd.DataFrame, source_type: str) -> pd.DataFrame:
    """Normalize findings from any scanner into one stable CBOM schema."""
    if isinstance(findings, pd.DataFrame):
        records = findings.to_dict(orient="records")
    else:
        records = list(findings or [])

    normalized = []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        row["source_type"] = _text(row.get("source_type"), source_type)
        row["asset_type"] = _text(row.get("asset_type"), "cryptographic_artifact")
        row["evidence_type"] = _text(row.get("evidence_type"), "ACTIVE_USAGE")
        row["algorithm"] = _text(row.get("algorithm"), "Not detected")
        row["purpose"] = _text(row.get("purpose"), "Not classified")
        row["version"] = _text(row.get("version"), "Not detected")
        row["mode"] = _text(row.get("mode"), "Not detected")
        row["key_size"] = _text(row.get("key_size"), "Not detected")
        row["library_provider"] = _text(row.get("library_provider"), "Not detected")
        row["library_version"] = _text(row.get("library_version"), "Not detected")
        row["protocol"] = _text(row.get("protocol"), "Not detected")
        row["certificate"] = _text(row.get("certificate"), "Not detected")
        row["file"] = _text(row.get("file"), "Not detected")
        row["line"] = int(_num(row.get("line"), 1) or 1)
        row["container_image"] = _text(row.get("container_image"), "Not applicable")
        row["container_layer"] = _text(row.get("layer"), "Not applicable")
        row["environment"] = _text(row.get("environment"), "Not specified")
        row["quantum_status"] = _text(row.get("quantum_status"), "QUANTUM-VULNERABLE")
        row["classical_status"] = _text(row.get("classical_status"), "SECURE")
        row["confidence"] = float(_num(row.get("confidence"), 0.95) or 0.95)
        row["data_sensitivity"] = int(_num(row.get("data_sensitivity"), 3) or 3)
        row["business_criticality"] = int(_num(row.get("business_criticality"), 3) or 3)
        row["x_shelf_life"] = float(_num(row.get("x_shelf_life"), 5.0) or 5.0)
        row["y_migration_time"] = float(_num(row.get("y_migration_time"), 2.0) or 2.0)
        row["evidence"] = _text(row.get("evidence", row.get("detection_method")), "Scanner evidence")
        row["snippet"] = _text(row.get("snippet", row.get("evidence")), "No source snippet captured")
        row["asset_id"] = _asset_id(row)
        normalized.append(row)

    if not normalized:
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    df = pd.DataFrame(normalized)
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = "Not detected"
    return df


def build_unified_inventory(
    repository_df=None,
    container_df=None,
    individual_df=None,
) -> pd.DataFrame:
    """Combine all currently available scanner results with deterministic de-duplication."""
    frames = []
    if repository_df is not None and not getattr(repository_df, "empty", True):
        frames.append(normalize_findings(repository_df, "source_repository"))
    if container_df is not None and not getattr(container_df, "empty", True):
        frames.append(normalize_findings(container_df, "docker_container"))
    if individual_df is not None and not getattr(individual_df, "empty", True):
        frames.append(normalize_findings(individual_df, "individual_asset"))

    if not frames:
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    df = pd.concat(frames, ignore_index=True, sort=False)
    # Same scanner + same evidence location + same algorithm is one asset.
    dedup_cols = ["source_type", "asset_type", "algorithm", "file", "line", "purpose", "container_image", "library_provider"]
    df = df.drop_duplicates(subset=dedup_cols, keep="first").reset_index(drop=True)
    df["asset_id"] = df.apply(lambda r: _asset_id(r.to_dict()), axis=1)
    return df


def inventory_summary(df: pd.DataFrame) -> dict:
    if df is None or df.empty:
        return {
            "total_assets": 0, "quantum_vulnerable": 0, "critical": 0,
            "high": 0, "medium": 0, "low": 0, "p0": 0, "p1": 0,
            "p2": 0, "p3": 0, "unique_algorithms": 0, "sources": 0,
        }
    risk = df.get("Risk Tier", pd.Series("Not assessed", index=df.index)).astype(str)
    priority = df.get("Priority", pd.Series("P3", index=df.index)).astype(str)
    qs = df.get("quantum_status", pd.Series("Not detected", index=df.index)).astype(str)
    return {
        "total_assets": len(df),
        "quantum_vulnerable": int(qs.eq("QUANTUM-VULNERABLE").sum()),
        "critical": int(risk.eq("CRITICAL").sum()),
        "high": int(risk.eq("HIGH").sum()),
        "medium": int(risk.eq("MEDIUM").sum()),
        "low": int(risk.eq("LOW").sum()),
        "p0": int(priority.eq("P0").sum()),
        "p1": int(priority.eq("P1").sum()),
        "p2": int(priority.eq("P2").sum()),
        "p3": int(priority.eq("P3").sum()),
        "unique_algorithms": int(df["algorithm"].nunique()) if "algorithm" in df else 0,
        "sources": int(df["source_type"].nunique()) if "source_type" in df else 0,
    }
