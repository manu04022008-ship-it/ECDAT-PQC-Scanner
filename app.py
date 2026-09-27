import streamlit as st
import pandas as pd
import plotly.express as px
import json
import tempfile
import zipfile
from pathlib import Path

# ============================================================
# LOCAL REPOSITORY FOLDER PICKER
# ============================================================

def select_repository_folder():
    """Open a native folder picker.

    Cross-platform via tkinter (works on Windows, macOS, Linux desktops).
    Raises on failure so the caller can fall back to manual path entry.
    """
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        folder = filedialog.askdirectory(
            title="Select Source Code Repository"
        )
    finally:
        root.destroy()

    return folder


import subprocess


# ============================================================
# LOCAL REPOSITORY FOLDER PICKER
# ============================================================





# ============================================================
# EXISTING PROJECT MODULES
# ============================================================

from scanner import scan_file

from repository_scanner import (
    scan_repository,
    get_repository_statistics,
)

from container_scanner import scan_live_docker_image, docker_available
from unified_inventory import build_unified_inventory, inventory_summary

from mosca_engine import (
    derive_asset_context,
    evaluate_asset_risk,
)

from cbom_formatter import (
    export_cyclonedx_cbom,
    get_recommendation,
)
from pqc_recommendations import get_pqc_recommendation, recommendation_columns
from algorithm_patcher import render_critical_algorithm_alerts
from migration_engine import render_migration_engine


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
    layout="wide",
)


# ============================================================
# TITLE
# ============================================================

st.title(
    "🛡️ Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)"
)

st.caption(
    "Standardized Cryptographic Bill of Materials (CBOM) "
    "& Per-Asset Quantum Risk Engine"
)

st.caption(
    "🌐 Web deployment: upload a repository ZIP or individual assets. "
    "Local-folder and live-Docker features require a local runtime with "
    "filesystem/Docker access."
)


# ============================================================
# ECDAT PLATFORM WORKFLOW
# ============================================================

st.markdown("---")
st.subheader("🛰️ ECDAT Cryptographic Security Pipeline")

workflow_cols = st.columns(5)

with workflow_cols[0]:
    st.markdown("### 1️⃣ Discovery")
    st.caption("Repositories • Containers • Assets")

with workflow_cols[1]:
    st.markdown("### 2️⃣ Inventory")
    st.caption("Unified cryptographic asset catalogue")

with workflow_cols[2]:
    st.markdown("### 3️⃣ Risk")
    st.caption("Quantum risk • Mosca • Criticality")

with workflow_cols[3]:
    st.markdown("### 4️⃣ Migration")
    st.caption("PQC recommendations • Priorities")

with workflow_cols[4]:
    st.markdown("### 5️⃣ CBOM")
    st.caption("Reports • Export • Compliance")

st.info(
    "ECDAT discovers cryptographic artefacts across software and infrastructure, "
    "normalizes them into a unified inventory, evaluates quantum readiness, "
    "and produces prioritized PQC migration recommendations and CBOM reports."
)

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header(
    "Risk Calculation & Scenario Settings"
)


calc_method = st.sidebar.radio(
    "Select Assessment Technique:",
    options=[
        "Standard Mosca Inequality (X + Y > Z)",
        "Sensitivity-Weighted QPS (W × max(1, (X+Y)/Z))",
        "Data Shelf-Life Ratio (X / Z)",
    ],
)


st.sidebar.markdown("---")

st.sidebar.subheader(
    "CRQC Horizon Assumption ($Z$)"
)


z_crqc = st.sidebar.slider(
    "Assumed Years until CRQC Arrival ($Z$):",
    min_value=5,
    max_value=25,
    value=10,
    step=1,
)


st.sidebar.caption(
    "📌 Z is a global scenario horizon assumption, "
    "whereas X (Shelf-Life) and Y (Migration Time) "
    "are evaluated per asset."
)


st.sidebar.markdown("---")

st.sidebar.subheader(
    "Global Environment & Defaults Override"
)


default_env = st.sidebar.selectbox(
    "Default Deployment Environment:",
    [
        "Production",
        "Staging",
        "Testing",
        "Development",
        "Cloud",
        "Edge",
    ],
)


enable_simulation = st.sidebar.toggle(
    "🔬 Enable PQC Migration Simulation Mode",
    value=False,
)


# ============================================================
# GENERATED FILES THAT SHOULD NEVER BE RESCANNED
# ============================================================

IGNORE_FILES = {
    "cbom_report.json",
    "cyclonedx_cbom_1.6.json",
    "cbom.json",
    "cbom_summary.csv",
    "executive_report.json",
}


# ============================================================
# HELPER: APPLY ASSET CONTEXT
# ============================================================

def enrich_findings(findings, environment):
    """
    Apply the existing asset-context engine to every finding.
    """

    enriched = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        finding = dict(finding)

        try:
            context = derive_asset_context(finding)

            if isinstance(context, dict):
                finding.update(context)

        except Exception:
            pass

        finding["line"] = finding.get("line", 1)

        finding["environment"] = finding.get(
            "environment",
            environment,
        )

        finding["classical_status"] = finding.get(
            "classical_status",
            "SECURE",
        )

        finding["confidence"] = finding.get(
            "confidence",
            0.98,
        )

        enriched.append(finding)

    return enriched


# ============================================================
# HELPER: PQC SIMULATION
# ============================================================

def simulate_pqc_migration(row):
    """
    Demonstration-only migration simulation.

    This does not modify the underlying scan.
    It changes the displayed inventory to show a
    hypothetical PQC migration state.
    """

    row = row.copy()

    algorithm = str(
        row.get("algorithm", "")
    ).upper()

    purpose = str(
        row.get("purpose", "")
    ).lower()

    quantum_status = str(
        row.get("quantum_status", "")
    )

    if quantum_status != "QUANTUM-VULNERABLE":
        return row

    # --------------------------------------------------------
    # Key establishment / RSA / ECDH
    # --------------------------------------------------------

    if (
        purpose == "key_establishment"
        or "RSA" in algorithm
        or "ECDH" in algorithm
        or "DH" in algorithm
    ):
        row["algorithm"] = "ML-KEM-768"
        row["quantum_status"] = "PQC-STANDARDIZED"

    # --------------------------------------------------------
    # Digital signatures
    # --------------------------------------------------------

    elif (
        purpose == "digital_signature"
        or "ECDSA" in algorithm
        or "DSA" in algorithm
    ):
        row["algorithm"] = "ML-DSA-65"
        row["quantum_status"] = "PQC-STANDARDIZED"

    # --------------------------------------------------------
    # Weak hashing
    # --------------------------------------------------------

    elif "SHA-1" in algorithm or "MD5" in algorithm:
        row["algorithm"] = "SHA-256"
        row["quantum_status"] = "QUANTUM-RESISTANT"

    # --------------------------------------------------------
    # Legacy symmetric cipher
    # --------------------------------------------------------

    elif "3DES" in algorithm or "DES" in algorithm:
        row["algorithm"] = "AES-256"
        row["quantum_status"] = "QUANTUM-RESISTANT"

    return row


# ============================================================
# HELPER: RISK ENGINE
# ============================================================

def apply_risk_engine(df):
    """
    Run the existing Mosca/risk engine on every asset.
    """

    if df.empty:
        return df

    risk_results = df.apply(
        lambda row: evaluate_asset_risk(
            algorithm=row.get(
                "algorithm",
                "UNKNOWN",
            ),
            purpose=row.get(
                "purpose",
                "unknown",
            ),
            quantum_status=row.get(
                "quantum_status",
                "QUANTUM-VULNERABLE",
            ),
            classical_status=row.get(
                "classical_status",
                "SECURE",
            ),
            x_shelf_life=float(
                row.get(
                    "x_shelf_life",
                    5.0,
                )
            ),
            y_migration_time=float(
                row.get(
                    "y_migration_time",
                    2.0,
                )
            ),
            z_crqc_horizon=z_crqc,
            data_sensitivity=int(
                row.get(
                    "data_sensitivity",
                    3,
                )
            ),
            business_criticality=int(
                row.get(
                    "business_criticality",
                    3,
                )
            ),
            method=calc_method,
            exposure=row.get("exposure", "isolated_code"),
        ),
        axis=1,
    )

    df = df.copy()

    df["X (Shelf-Life yrs)"] = [
        result.get("X", 0)
        for result in risk_results
    ]

    df["Y (Migration yrs)"] = [
        result.get("Y", 0)
        for result in risk_results
    ]

    df["Z (CRQC Horizon yrs)"] = [
        result.get("Z", z_crqc)
        for result in risk_results
    ]

    df["Risk Tier"] = [
        result.get("tier", "UNKNOWN")
        for result in risk_results
    ]

    df["Priority"] = [
        result.get("priority", "P3")
        for result in risk_results
    ]

    df["Action"] = [
        result.get("action", "")
        for result in risk_results
    ]

    df["Metric Value"] = [
        result.get("metric_value", 0)
        for result in risk_results
    ]

    df["Metric Label"] = [
        result.get("metric_label", "")
        for result in risk_results
    ]

    df["Risk Explanation"] = [
        result.get("explanation", "")
        for result in risk_results
    ]

    df["Risk Score"] = [
        result.get("risk_score", 0)
        for result in risk_results
    ]
    df["Mosca Status"] = [
        result.get("mosca_status", "NOT_APPLICABLE")
        for result in risk_results
    ]
    df["Mosca Margin (yrs)"] = [
        result.get("mosca_margin", 0)
        for result in risk_results
    ]
    df["Exposure Ratio (X+Y)/Z"] = [
        result.get("exposure_ratio", 0)
        for result in risk_results
    ]

    # --------------------------------------------------------
    # Purpose-aware PQC recommendations
    # --------------------------------------------------------
    recommendation_rows = []
    for _, row in df.iterrows():
        try:
            recommendation_rows.append(get_pqc_recommendation(
                algorithm=row.get("algorithm", "UNKNOWN"),
                purpose=row.get("purpose", ""),
                asset_type=row.get("asset_type", ""),
                protocol=row.get("protocol", ""),
                environment=row.get("environment", default_env),
                risk_tier=row.get("Risk Tier", ""),
                evidence_type=row.get("evidence_type", ""),
            ))
        except Exception:
            recommendation_rows.append(get_pqc_recommendation("UNKNOWN"))

    recommendation_df = pd.DataFrame(recommendation_rows)
    mapping = {
        "replacement": "PQC Replacement",
        "hybrid_option": "Hybrid Option",
        "standard": "PQC Standard",
        "migration_strategy": "Migration Strategy",
        "rationale": "Recommendation Rationale",
        "latency": "Latency Impact",
        "cost": "Migration Cost",
        "compatibility": "Compatibility",
        "confidence": "Recommendation Confidence",
    }
    for src, dst in mapping.items():
        df[dst] = recommendation_df[src].tolist() if src in recommendation_df else "Review Required"

    return df


# ============================================================
# ECDAT UNIFIED DISCOVERY CENTER
# ============================================================

st.markdown("---")
st.subheader("🛰️ ECDAT Discovery Center")
st.caption(
    "Select one discovery source. ECDAT uses the same downstream "
    "inventory, quantum-risk, PQC migration and CBOM pipeline "
    "for every source."
)

discovery_source = st.radio(
    "Select Discovery Source",
    [
        "📁 Source Repository",
        "🐳 Docker Container",
        "🎯 Targeted Asset",
    ],
    horizontal=True,
    key="ecdat_discovery_source",
)

st.caption(
    "The selected source opens its dedicated scanner below. "
    "All other discovery inputs remain hidden to keep the workflow unified."
)

if discovery_source == "📁 Source Repository":
    # ============================================================
    # FEATURE 1
    # SOURCE CODE REPOSITORY SCANNER
    # ============================================================

    st.markdown("---")

    st.header(
        "📁 Discovery Source — Source Code Repository"
    )

    st.caption(
        "Scan a local source-code repository folder or upload a ZIP. "
        "ECDAT recursively discovers source files, scans them "
        "for cryptographic artefacts and sends the findings "
        "through the same risk, Mosca and recommendation engines."
    )


    repository_input_mode = st.radio(
        "Repository Input",
        ["📁 Local Folder", "📦 ZIP Archive"],
        horizontal=True,
        index=1,
        key="repository_input_mode",
    )

    repository_zip = None

    # ------------------------------------------------------------
    # LOCAL FOLDER
    # ------------------------------------------------------------

    if repository_input_mode == "📁 Local Folder":

        st.caption(
            "Select an existing source-code repository/project folder — "
            "either click Browse to open a folder picker, or paste the "
            "full folder path directly into the box below."
        )

        browse_col, _spacer_col = st.columns([1, 3])

        with browse_col:

            if st.button(
                "📁 Browse...",
                key="select_repository_folder",
            ):

                try:

                    selected_folder = select_repository_folder()

                    if selected_folder:

                        selected_path = Path(
                            selected_folder
                        )

                        if (
                            selected_path.exists()
                            and selected_path.is_dir()
                        ):

                            st.session_state[
                                "selected_repository_folder"
                            ] = str(selected_path)

                        else:

                            st.error(
                                "Selected path is not a valid folder."
                            )

                except Exception as exc:

                    st.error(
                        f"Native folder browser is unavailable ({exc}). "
                        "Please paste the folder path into the box below "
                        "instead."
                    )

        typed_folder_path = st.text_input(
            "...or paste the full folder path here",
            key="selected_repository_folder",
            placeholder=r"e.g. C:\Users\you\Projects\my-repo  or  /home/you/my-repo",
        )

        selected_folder = st.session_state.get(
            "selected_repository_folder"
        )

        if selected_folder and not (
            Path(selected_folder).exists()
            and Path(selected_folder).is_dir()
        ):

            st.warning(
                "That path doesn't exist or isn't a folder yet -- "
                "finish typing/pasting the full path, or use Browse."
            )

            selected_folder = None

        if selected_folder:

            selected_path = Path(
                selected_folder
            )

            st.info(
                f"Repository selected: `{selected_path.name}`"
            )

            st.caption(
                str(selected_path)
            )

            # ----------------------------------------------------
            # Create a temporary ZIP representation.
            #
            # This allows the existing, tested ZIP repository
            # pipeline below to process local folders without
            # rewriting the rest of Feature 1.
            # ----------------------------------------------------

            try:

                folder_temp = tempfile.mkdtemp(
                    prefix="ecdat_folder_"
                )

                folder_zip = Path(
                    folder_temp
                ) / f"{selected_path.name}.zip"

                with zipfile.ZipFile(
                    folder_zip,
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as archive:

                    for item in selected_path.rglob("*"):

                        if item.is_file():

                            try:

                                relative_path = item.relative_to(
                                    selected_path
                                )

                                archive.write(
                                    item,
                                    Path(
                                        selected_path.name
                                    ) / relative_path,
                                )

                            except (
                                PermissionError,
                                OSError,
                            ):

                                continue

                class LocalFolderUpload:

                    def __init__(
                        self,
                        filename,
                        data,
                    ):
                        self.name = filename
                        self._data = data

                    def getvalue(self):
                        return self._data

                repository_zip = LocalFolderUpload(
                    folder_zip.name,
                    folder_zip.read_bytes(),
                )

            except Exception as exc:

                st.error(
                    f"Unable to prepare local repository: {exc}"
                )

    # ------------------------------------------------------------
    # ZIP ARCHIVE
    # ------------------------------------------------------------

    else:

        repository_zip = st.file_uploader(
            "Upload Source Code Repository (.zip)",
            type=["zip"],
            key="repository_zip",
        )



    if repository_zip is not None:

        st.info(
            f"Repository selected: `{repository_zip.name}`"
        )

        # --------------------------------------------------------
        # Extract + scan
        # --------------------------------------------------------

        try:

            with st.spinner(
                "Extracting and recursively scanning repository..."
            ):

                with tempfile.TemporaryDirectory() as temp_dir:

                    temp_path = Path(temp_dir)

                    zip_path = (
                        temp_path
                        / repository_zip.name
                    )

                    extract_path = (
                        temp_path
                        / "repository"
                    )

                    extract_path.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    # --------------------------------------------
                    # Save uploaded ZIP
                    # --------------------------------------------

                    zip_path.write_bytes(
                        repository_zip.getvalue()
                    )

                    # --------------------------------------------
                    # Validate ZIP
                    # --------------------------------------------

                    if not zipfile.is_zipfile(zip_path):
                        raise ValueError(
                            "The uploaded file is not a valid ZIP archive."
                        )

                    # --------------------------------------------
                    # Safe ZIP extraction
                    # --------------------------------------------

                    with zipfile.ZipFile(
                        zip_path,
                        "r",
                    ) as archive:

                        for member in archive.infolist():

                            member_path = (
                                extract_path
                                / member.filename
                            )

                            try:

                                member_path.resolve().relative_to(
                                    extract_path.resolve()
                                )

                            except ValueError:

                                raise ValueError(
                                    "Unsafe ZIP entry detected: "
                                    f"{member.filename}"
                                )

                        archive.extractall(
                            extract_path
                        )

                    # --------------------------------------------
                    # Find actual repository root
                    # --------------------------------------------

                    candidates = [
                        item
                        for item in extract_path.iterdir()
                    ]

                    directories = [
                        item
                        for item in candidates
                        if item.is_dir()
                    ]

                    files = [
                        item
                        for item in candidates
                        if item.is_file()
                    ]

                    if (
                        len(directories) == 1
                        and len(files) == 0
                    ):
                        repository_root = directories[0]
                    else:
                        repository_root = extract_path

                    # --------------------------------------------
                    # Repository statistics
                    # --------------------------------------------

                    repository_stats = (
                        get_repository_statistics(
                            str(repository_root)
                        )
                    )

                    # --------------------------------------------
                    # Repository crypto scan
                    # --------------------------------------------

                    raw_repository_findings = (
                        scan_repository(
                            str(repository_root)
                        )
                    )

                    # --------------------------------------------
                    # Run SAME context pipeline as normal assets
                    # --------------------------------------------

                    repository_findings = (
                        enrich_findings(
                            raw_repository_findings,
                            default_env,
                        )
                    )

                    # --------------------------------------------
                    # DataFrame
                    # --------------------------------------------

                    if repository_findings:

                        repository_df = pd.DataFrame(
                            repository_findings
                        )

                        repository_df = apply_risk_engine(
                            repository_df
                        )

                        # ----------------------------------------
                        # Simulation
                        # ----------------------------------------

                        if enable_simulation:

                            repository_df = (
                                repository_df.apply(
                                    simulate_pqc_migration,
                                    axis=1,
                                )
                            )

                        st.session_state["repository_inventory_df"] = repository_df.copy()

                        # ----------------------------------------
                        # Capture raw content for CRITICAL files only,
                        # while the temp directory still exists, so the
                        # Critical Algorithm Alerts feature can offer a
                        # patched download after this block exits and
                        # the temp directory is cleaned up. Isolated
                        # dict; nothing else reads or writes this.
                        # ----------------------------------------

                        _repo_file_content_lookup = {}
                        if "Risk Tier" in repository_df.columns:
                            _critical_files = set(
                                repository_df.loc[
                                    repository_df["Risk Tier"] == "CRITICAL",
                                    "file",
                                ].astype(str)
                            )
                            for _rel_path in _critical_files:
                                try:
                                    _abs_path = repository_root / _rel_path
                                    _repo_file_content_lookup[_rel_path] = (
                                        _abs_path.read_bytes()
                                    )
                                except Exception:
                                    pass

                        # ----------------------------------------
                        # Capture raw content for EVERY scanned file
                        # that has a finding (not just CRITICAL ones),
                        # while the temp directory still exists, so the
                        # project-wide Migration Engine can offer a
                        # migrated/original ZIP after this block exits
                        # and the temp directory is cleaned up. Isolated
                        # dict; nothing else reads or writes this, and
                        # the CRITICAL-only lookup above is untouched.
                        # ----------------------------------------

                        _repo_all_file_content_lookup = {}
                        if "file" in repository_df.columns:
                            _all_finding_files = set(
                                repository_df["file"].astype(str)
                            )
                            for _rel_path in _all_finding_files:
                                try:
                                    _abs_path = repository_root / _rel_path
                                    _repo_all_file_content_lookup[_rel_path] = (
                                        _abs_path.read_bytes()
                                    )
                                except Exception:
                                    pass

                    else:

                        repository_df = pd.DataFrame()
                        _repo_file_content_lookup = {}
                        _repo_all_file_content_lookup = {}

            # ====================================================
            # SUCCESS
            # ====================================================

            st.success(
                "Repository scan completed successfully."
            )

            # ====================================================
            # CRITICAL ALGORITHM ALERTS (additive, isolated feature)
            # Shown a step above the discovery metrics/table so
            # critical findings are surfaced immediately after
            # analysis.
            # ====================================================

            render_critical_algorithm_alerts(
                repository_df,
                _repo_file_content_lookup,
                scope_prefix="repo",
            )

            # ====================================================
            # PQC MIGRATION & REMEDIATION ENGINE (additive, isolated
            # feature) -- project-wide version of the alert above,
            # covering every finding rather than just CRITICAL ones.
            # ====================================================

            render_migration_engine(
                repository_df,
                _repo_all_file_content_lookup,
                scope_prefix="repo",
            )

            # ====================================================

            # DISCOVERY METRICS

            # ====================================================

            discovered_files = int(
                repository_stats.get(
                    "total_files",
                    0,
                )
            )

            ignored_files = int(
                repository_stats.get(
                    "ignored_files",
                    0,
                )
            )

            analyzed_files = max(
                discovered_files - ignored_files,
                0,
            )

            source_code_files = int(
                repository_stats.get(
                    "source_files",
                    0,
                )
            )

            crypto_assets = len(repository_df)

            language_count = len(
                repository_stats.get(
                    "languages",
                    {},
                )
            )

            metric1, metric2, metric3, metric4, metric5, metric6 = (
                st.columns(6)
            )

            metric1.metric(
                "Discovered Files",
                discovered_files,
            )

            metric2.metric(
                "Analyzed Files",
                analyzed_files,
            )

            metric3.metric(
                "Source-Code Files",
                source_code_files,
            )

            metric4.metric(
                "Crypto Assets",
                crypto_assets,
            )

            metric5.metric(
                "Ignored Files",
                ignored_files,
            )

            metric6.metric(
                "Languages",
                language_count,
            )

            st.caption(
                f"📋 File accounting: {discovered_files} discovered "
                f"→ {ignored_files} ignored → {analyzed_files} analyzed. "
                "Ignored files are excluded from cryptographic analysis."
            )

            # LANGUAGE BREAKDOWN
            # ====================================================

            st.subheader(
                "📊 Repository Composition"
            )

            languages = repository_stats.get(
                "languages",
                {},
            )

            if languages:

                language_df = pd.DataFrame(
                    [
                        {
                            "Language": language,
                            "Files": count,
                        }
                        for language, count
                        in languages.items()
                    ]
                )

                c1, c2 = st.columns(2)

                with c1:

                    st.dataframe(
                        language_df,
                        use_container_width=True,
                        hide_index=True,
                    )

                with c2:

                    fig_languages = px.bar(
                        language_df,
                        x="Language",
                        y="Files",
                        title="Source Files by Language",
                    )

                    st.plotly_chart(
                        fig_languages,
                        use_container_width=True,
                    )

            # ====================================================
            # SOURCE FILE DISCOVERY
            # ====================================================

            with st.expander(
                "📁 View Discovered Source Files"
            ):

                source_files = repository_stats.get(
                    "source_file_list",
                    [],
                )

                if source_files:

                    source_df = pd.DataFrame(
                        {
                            "Repository File": source_files
                        }
                    )

                    st.dataframe(
                        source_df,
                        use_container_width=True,
                        hide_index=True,
                    )

                else:

                    st.warning(
                        "No supported source files were discovered."
                    )

            # ====================================================
            # CRYPTO ASSET ANALYSIS
            # ====================================================

            if not repository_df.empty:

                st.markdown("---")

                st.header(
                    "🔐 Repository Cryptographic Asset Analysis"
                )

                if enable_simulation:

                    st.warning(
                        "🔬 SIMULATION ACTIVE: "
                        "The displayed algorithm inventory represents "
                        "a hypothetical PQC migration state."
                    )

                # ------------------------------------------------
                # TOP RISK METRICS
                # ------------------------------------------------

                r1, r2, r3, r4, r5 = st.columns(5)

                r1.metric(
                    "Crypto Assets",
                    len(repository_df),
                )

                r2.metric(
                    "Critical",
                    len(
                        repository_df[
                            repository_df["Risk Tier"]
                            == "CRITICAL"
                        ]
                    ),
                )

                r3.metric(
                    "High",
                    len(
                        repository_df[
                            repository_df["Risk Tier"]
                            == "HIGH"
                        ]
                    ),
                )

                r4.metric(
                    "P0",
                    len(
                        repository_df[
                            repository_df["Priority"]
                            == "P0"
                        ]
                    ),
                )

                r5.metric(
                    "P1",
                    len(
                        repository_df[
                            repository_df["Priority"]
                            == "P1"
                        ]
                    ),
                )

                # ------------------------------------------------
                # RISK DASHBOARD
                # ------------------------------------------------

                st.subheader(
                    "📈 Repository Risk Dashboard"
                )

                chart1, chart2, chart3 = (
                    st.columns(3)
                )

                with chart1:

                    if "Risk Tier" in repository_df:

                        risk_counts = (
                            repository_df[
                                "Risk Tier"
                            ]
                            .value_counts()
                            .reset_index()
                        )

                        risk_counts.columns = [
                            "Risk Tier",
                            "Count",
                        ]

                        fig_risk = px.pie(
                            risk_counts,
                            names="Risk Tier",
                            values="Count",
                            title="Risk Distribution",
                        )

                        st.plotly_chart(
                            fig_risk,
                            use_container_width=True,
                        )

                with chart2:

                    priority_counts = (
                        repository_df[
                            "Priority"
                        ]
                        .value_counts()
                        .reset_index()
                    )

                    priority_counts.columns = [
                        "Priority",
                        "Count",
                    ]

                    fig_priority = px.bar(
                        priority_counts,
                        x="Priority",
                        y="Count",
                        title="Migration Priority",
                    )

                    st.plotly_chart(
                        fig_priority,
                        use_container_width=True,
                    )

                with chart3:

                    algorithm_counts = (
                        repository_df[
                            "algorithm"
                        ]
                        .value_counts()
                        .reset_index()
                    )

                    algorithm_counts.columns = [
                        "Algorithm",
                        "Count",
                    ]

                    fig_algorithm = px.bar(
                        algorithm_counts,
                        x="Algorithm",
                        y="Count",
                        title="Cryptographic Algorithms",
                    )

                    st.plotly_chart(
                        fig_algorithm,
                        use_container_width=True,
                    )

                # =================================================
                # CBOM TABLE
                # =================================================

                st.subheader(
                    "📋 Repository CBOM & Risk Report"
                )

                st.info(
                    f"Assessment Method: **{calc_method}** | "
                    f"CRQC Horizon Z = **{z_crqc} years**"
                )

                # ------------------------------------------------
                # FILTERS
                # ------------------------------------------------

                f1, f2, f3, f4 = st.columns(4)

                with f1:

                    repository_file_filter = (
                        st.text_input(
                            "🔍 Filter by Repository File",
                            placeholder="payment/service.py",
                        )
                    )

                with f2:

                    repository_algorithm_filter = (
                        st.text_input(
                            "🔍 Filter by Algorithm",
                            placeholder="RSA, SHA, AES",
                        )
                    )

                with f3:

                    repository_risk_filter = (
                        st.selectbox(
                            "⚡ Risk Tier",
                            [
                                "ALL"
                            ]
                            + sorted(
                                repository_df[
                                    "Risk Tier"
                                ]
                                .dropna()
                                .astype(str)
                                .unique()
                                .tolist()
                            ),
                        )
                    )

                with f4:

                    repository_priority_filter = (
                        st.selectbox(
                            "🚨 Priority",
                            [
                                "ALL",
                                "P0",
                                "P1",
                                "P2",
                                "P3",
                            ],
                        )
                    )

                filtered_repository_df = (
                    repository_df.copy()
                )

                if repository_file_filter:

                    filtered_repository_df = (
                        filtered_repository_df[
                            filtered_repository_df[
                                "file"
                            ]
                            .astype(str)
                            .str.contains(
                                repository_file_filter,
                                case=False,
                                na=False,
                            )
                        ]
                    )

                if repository_algorithm_filter:

                    filtered_repository_df = (
                        filtered_repository_df[
                            filtered_repository_df[
                                "algorithm"
                            ]
                            .astype(str)
                            .str.contains(
                                repository_algorithm_filter,
                                case=False,
                                na=False,
                            )
                        ]
                    )

                if repository_risk_filter != "ALL":

                    filtered_repository_df = (
                        filtered_repository_df[
                            filtered_repository_df[
                                "Risk Tier"
                            ]
                            == repository_risk_filter
                        ]
                    )

                if repository_priority_filter != "ALL":

                    filtered_repository_df = (
                        filtered_repository_df[
                            filtered_repository_df[
                                "Priority"
                            ]
                            == repository_priority_filter
                        ]
                    )

                display_columns = [
                    "file",
                    "repository_file",
                    "language",
                    "line",
                    "asset_type",
                    "algorithm",
                    "purpose",
                    "quantum_status",
                    "classical_status",
                    "X (Shelf-Life yrs)",
                    "Y (Migration yrs)",
                    "Z (CRQC Horizon yrs)",
                    "Priority",
                    "Risk Tier",
                    "PQC Replacement",
                    "Hybrid Option",
                    "PQC Standard",
                    "Migration Strategy",
                    "Recommendation Rationale",
                    "Latency Impact",
                    "Migration Cost",
                    "Compatibility",
                    "Risk Explanation",
                ]

                valid_display_columns = [
                    column
                    for column in display_columns
                    if column
                    in filtered_repository_df.columns
                ]

                st.dataframe(
                    filtered_repository_df[
                        valid_display_columns
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

                # =================================================
                # ASSET INSPECTOR
                # =================================================

                st.subheader(
                    "🔎 Repository Asset Inspector"
                )

                asset_labels = []

                for index, row in repository_df.iterrows():

                    asset_labels.append(
                        f"{row.get('file', 'Unknown')} "
                        f"(Line {row.get('line', 1)}) - "
                        f"{row.get('algorithm', 'UNKNOWN')} "
                        f"[{row.get('Risk Tier', 'UNKNOWN')}]"
                    )

                if asset_labels:

                    selected_asset = st.selectbox(
                        "Select a discovered cryptographic asset:",
                        asset_labels,
                        key="repository_asset_selector",
                    )

                    selected_index = asset_labels.index(
                        selected_asset
                    )

                    selected_row = (
                        repository_df.iloc[
                            selected_index
                        ]
                    )

                    with st.expander(
                        "Detailed Asset Analysis",
                        expanded=True,
                    ):

                        d1, d2, d3 = st.columns(3)

                        with d1:

                            st.markdown(
                                f"**Repository File:** "
                                f"`{selected_row.get('repository_file', selected_row.get('file', 'Unknown'))}`"
                            )

                            st.markdown(
                                f"**Language:** "
                                f"`{selected_row.get('language', 'Unknown')}`"
                            )

                            st.markdown(
                                f"**Line:** "
                                f"`{selected_row.get('line', 1)}`"
                            )

                            st.markdown(
                                f"**Asset Type:** "
                                f"`{selected_row.get('asset_type', 'Unknown')}`"
                            )

                            st.markdown(
                                f"**Purpose:** "
                                f"`{selected_row.get('purpose', 'unknown')}`"
                            )

                        with d2:

                            st.markdown(
                                f"**Algorithm:** "
                                f"`{selected_row.get('algorithm', 'UNKNOWN')}`"
                            )

                            st.markdown(
                                f"**Quantum Status:** "
                                f"`{selected_row.get('quantum_status', 'UNKNOWN')}`"
                            )

                            st.markdown(
                                f"**Classical Status:** "
                                f"`{selected_row.get('classical_status', 'UNKNOWN')}`"
                            )

                            confidence = selected_row.get(
                                "confidence",
                                0.98,
                            )

                            try:
                                confidence_percent = (
                                    float(confidence)
                                    * 100
                                )
                            except (
                                TypeError,
                                ValueError,
                            ):
                                confidence_percent = 0

                            st.markdown(
                                f"**Detection Confidence:** "
                                f"`{confidence_percent:.0f}%`"
                            )

                        with d3:

                            st.markdown(
                                f"**Shelf Life (X):** "
                                f"`{selected_row.get('X (Shelf-Life yrs)', 0)} years`"
                            )

                            st.markdown(
                                f"**Migration Time (Y):** "
                                f"`{selected_row.get('Y (Migration yrs)', 0)} years`"
                            )

                            st.markdown(
                                f"**CRQC Horizon (Z):** "
                                f"`{selected_row.get('Z (CRQC Horizon yrs)', z_crqc)} years`"
                            )

                            st.markdown(
                                f"**Priority:** "
                                f"`{selected_row.get('Priority', 'P3')}`"
                            )

                            st.markdown(
                                f"**Risk Tier:** "
                                f"`{selected_row.get('Risk Tier', 'UNKNOWN')}`"
                            )

                        st.info(
                            "**Why is this risky?** "
                            + str(
                                selected_row.get(
                                    "Risk Explanation",
                                    "No explanation available.",
                                )
                            )
                        )

                        st.success(
                            "**Recommended Action:** "
                            f"Use **{selected_row.get('PQC Replacement', 'Review Required')}**"
                        )

                        st.markdown(
                            f"**Hybrid Option:** `{selected_row.get('Hybrid Option', 'None required')}`"
                        )
                        st.markdown(
                            f"**PQC Standard:** `{selected_row.get('PQC Standard', 'N/A')}`"
                        )
                        st.markdown(
                            f"**Migration Strategy:** {selected_row.get('Migration Strategy', 'Review required')}"
                        )
                        st.info(
                            "**Recommendation Rationale:** "
                            + str(selected_row.get('Recommendation Rationale', 'No rationale available.'))
                        )

                        st.markdown(
                            f"**Latency Impact:** "
                            f"`{selected_row.get('Latency Impact', 'Unknown')}`"
                        )

                        st.markdown(
                            f"**Migration Cost:** "
                            f"`{selected_row.get('Migration Cost', 'Unknown')}`"
                        )

                # =================================================
                # EXPORTS
                # =================================================

                st.markdown("---")

                st.subheader(
                    "📤 Export Repository CBOM Reports"
                )

                export1, export2, export3 = (
                    st.columns(3)
                )

                # ------------------------------------------------
                # CycloneDX
                # ------------------------------------------------

                try:

                    cbom_json = (
                        export_cyclonedx_cbom(
                            repository_df
                        )
                    )

                    export1.download_button(
                        label=(
                            "Download CycloneDX v1.6 CBOM (JSON)"
                        ),
                        data=json.dumps(
                            cbom_json,
                            indent=2,
                            default=str,
                        ),
                        file_name=(
                            "repository_cyclonedx_cbom_1.6.json"
                        ),
                        mime="application/json",
                    )

                except Exception as exc:

                    export1.error(
                        "CBOM export failed: "
                        + str(exc)
                    )

                # ------------------------------------------------
                # CSV
                # ------------------------------------------------

                csv_data = (
                    repository_df
                    .to_csv(index=False)
                )

                export2.download_button(
                    label=(
                        "Download Repository CBOM (CSV)"
                    ),
                    data=csv_data,
                    file_name=(
                        "repository_cbom_summary.csv"
                    ),
                    mime="text/csv",
                )

                # ------------------------------------------------
                # Executive report
                # ------------------------------------------------

                executive_report = {
                    "scan_type": "source_code_repository",
                    "repository": repository_zip.name,
                    "assessment_method": calc_method,
                    "crqc_horizon_years": z_crqc,
                    "total_files": repository_stats.get(
                        "total_files",
                        0,
                    ),
                    "source_files": repository_stats.get(
                        "source_files",
                        0,
                    ),
                    "ignored_files": repository_stats.get(
                        "ignored_files",
                        0,
                    ),
                    "languages": repository_stats.get(
                        "languages",
                        {},
                    ),
                    "total_crypto_assets": len(
                        repository_df
                    ),
                    "critical_risks": len(
                        repository_df[
                            repository_df["Risk Tier"]
                            == "CRITICAL"
                        ]
                    ),
                    "high_risks": len(
                        repository_df[
                            repository_df["Risk Tier"]
                            == "HIGH"
                        ]
                    ),
                    "p0_priorities": len(
                        repository_df[
                            repository_df["Priority"]
                            == "P0"
                        ]
                    ),
                    "p1_priorities": len(
                        repository_df[
                            repository_df["Priority"]
                            == "P1"
                        ]
                    ),
                    "findings": repository_df.to_dict(
                        orient="records"
                    ),
                }

                export3.download_button(
                    label=(
                        "Download Repository Executive Report (JSON)"
                    ),
                    data=json.dumps(
                        executive_report,
                        indent=2,
                        default=str,
                    ),
                    file_name=(
                        "repository_executive_report.json"
                    ),
                    mime="application/json",
                )

            else:

                st.warning(
                    "The repository was scanned successfully, "
                    "but no cryptographic assets were detected "
                    "by the current source-scanning rules."
                )

        except zipfile.BadZipFile:

            st.error(
                "Invalid ZIP archive. Please upload a valid "
                "source-code repository ZIP."
            )

        except Exception as exc:

            st.error(
                "Repository scan failed."
            )

            st.exception(exc)



if discovery_source == "🐳 Docker Container":
    # ============================================================
    # FEATURE 2
    # DOCKER CONTAINER IMAGE SCANNER
    # ============================================================

    st.markdown("---")

    st.header(
        "🐳 Discovery Source — Docker Container Image"
    )

    st.caption(
        "Scan a locally available Docker image, inspect its image layers, "
        "discover cryptographic usage in application code, inventory explicitly "
        "referenced crypto providers, assess quantum risk and export CBOM data."
    )

    container_image = st.text_input(
        "Docker Image / Tag",
        placeholder="pqc-test-image:latest",
        key="container_image_input",
    )

    docker_cli_available = docker_available()

    if not docker_cli_available:
        st.info(
            "Docker scanning is available when ECDAT is running on a machine "
            "with the Docker CLI/daemon. Public Streamlit hosting normally "
            "does not provide a Docker daemon, so use Source Repository ZIP "
            "or Targeted Asset upload for the public web application."
        )

    container_scan_clicked = st.button(
        "🔍 Scan Docker Image",
        type="primary",
        key="container_scan_button",
        disabled=not docker_cli_available,
    )

    if container_scan_clicked:
        if not container_image.strip():
            st.error("Enter a Docker image/tag before scanning.")
        else:
            try:
                with st.spinner(
                    f"Scanning Docker image `{container_image.strip()}`..."
                ):
                    container_result = scan_live_docker_image(
                        container_image.strip()
                    )

                st.session_state["container_scan_result"] = container_result

            except Exception as exc:
                st.session_state.pop("container_scan_result", None)
                st.error("Container scan failed.")
                st.exception(exc)

    container_result = st.session_state.get("container_scan_result")

    if container_result:
        try:
            container_findings_raw = container_result.get("findings", [])
            container_stats = container_result.get("statistics", {})

            # Preserve evidence classes. Only actual ACTIVE_USAGE and
            # CONFIGURATION findings enter the risk engine. Library presence is
            # inventory evidence and must not be mistaken for algorithm usage.
            container_findings = enrich_findings(
                container_findings_raw,
                default_env,
            )

            if container_findings:
                container_df = pd.DataFrame(container_findings)

                risk_scope_mask = container_df.get(
                    "evidence_type",
                    pd.Series(
                        ["ACTIVE_USAGE"] * len(container_df),
                        index=container_df.index,
                    ),
                ).isin(["ACTIVE_USAGE", "CONFIGURATION"])

                risk_df = container_df.loc[risk_scope_mask].copy()

                if not risk_df.empty:
                    risk_df = apply_risk_engine(risk_df)

                    for column in risk_df.columns:
                        container_df.loc[
                            risk_df.index,
                            column,
                        ] = risk_df[column]

                # Library/inventory rows intentionally do not receive a
                # vulnerability tier from algorithm usage. They are inventory
                # evidence rather than proof that the application actively uses
                # every algorithm supported by the provider.
                inventory_mask = container_df.get(
                    "evidence_type",
                    pd.Series("", index=container_df.index),
                ) == "LIBRARY_PRESENCE"

                if inventory_mask.any():
                    container_df.loc[
                        inventory_mask,
                        "Risk Tier",
                    ] = "INVENTORY"

                    container_df.loc[
                        inventory_mask,
                        "Priority",
                    ] = "P3"

                    container_df.loc[
                        inventory_mask,
                        "Action",
                    ] = "Validate active algorithm usage"

                    container_df.loc[
                        inventory_mask,
                        "PQC Replacement",
                    ] = "Not determined from library presence alone"

                    container_df.loc[
                        inventory_mask,
                        "Risk Explanation",
                    ] = (
                        "Library/provider presence is inventory evidence; "
                        "it does not prove that the application actively uses "
                        "a particular cryptographic algorithm."
                    )

                if enable_simulation:
                    container_df = container_df.apply(
                        simulate_pqc_migration,
                        axis=1,
                    )

                # Store the enriched result so it can be reused by exports and
                # remains available after Streamlit reruns.
                st.session_state["container_scan_df"] = container_df

            else:
                container_df = pd.DataFrame()
                st.session_state["container_scan_df"] = container_df

            # ------------------------------------------------------------
            # Container metadata
            # ------------------------------------------------------------

            st.success("Docker container scan completed successfully.")

            m1, m2, m3, m4, m5 = st.columns(5)

            m1.metric(
                "Layers Scanned",
                container_stats.get(
                    "layers_scanned",
                    container_result.get("layers_scanned", 0),
                ),
            )

            m2.metric(
                "Crypto Assets",
                container_stats.get("total_findings", 0),
            )

            m3.metric(
                "Active Usage",
                container_stats.get("active_crypto_usage", 0),
            )

            m4.metric(
                "Libraries",
                container_stats.get("library_presence", 0),
            )

            m5.metric(
                "Algorithms",
                container_stats.get("unique_algorithms", 0),
            )

            st.subheader("🐳 Container Inventory")

            c1, c2 = st.columns(2)

            with c1:
                st.markdown(
                    f"**Image:** `{container_result.get('image', container_image)}`"
                )
                st.markdown(
                    f"**Image ID:** `{container_result.get('image_id', 'Unknown')}`"
                )
                st.markdown(
                    f"**Architecture:** `{container_result.get('architecture', 'Unknown')}`"
                )

            with c2:
                st.markdown(
                    f"**OS:** `{container_result.get('os', 'Unknown')}`"
                )
                st.markdown(
                    f"**Created:** `{container_result.get('created', 'Unknown')}`"
                )
                st.markdown(
                    f"**Scan Mode:** `{container_result.get('scan_mode', 'live_docker')}`"
                )

            algorithms = container_stats.get("algorithms", [])

            if algorithms:
                st.info(
                    "Detected algorithms: "
                    + ", ".join(str(x) for x in algorithms)
                )

            if not container_df.empty:
                st.markdown("---")
                st.subheader("🔐 Container Cryptographic Risk Analysis")

                active_df = container_df[
                    container_df.get(
                        "evidence_type",
                        "",
                    ).astype(str) == "ACTIVE_USAGE"
                ].copy()

                config_df = container_df[
                    container_df.get(
                        "evidence_type",
                        "",
                    ).astype(str) == "CONFIGURATION"
                ].copy()

                library_df = container_df[
                    container_df.get(
                        "evidence_type",
                        "",
                    ).astype(str) == "LIBRARY_PRESENCE"
                ].copy()

                r1, r2, r3, r4 = st.columns(4)

                r1.metric("Active Crypto Usage", len(active_df))
                r2.metric(
                    "Critical",
                    int(
                        (
                            container_df.get(
                                "Risk Tier",
                                pd.Series(dtype=str),
                            ) == "CRITICAL"
                        ).sum()
                    ),
                )
                r3.metric(
                    "High",
                    int(
                        (
                            container_df.get(
                                "Risk Tier",
                                pd.Series(dtype=str),
                            ) == "HIGH"
                        ).sum()
                    ),
                )
                r4.metric(
                    "Inventory Libraries",
                    len(library_df),
                )

                # Risk chart
                risk_series = container_df.get(
                    "Risk Tier",
                    pd.Series(dtype=str),
                ).astype(str)

                if not risk_series.empty:
                    risk_counts = (
                        risk_series.value_counts()
                        .reset_index()
                    )
                    risk_counts.columns = ["Risk Tier", "Count"]

                    fig_container_risk = px.pie(
                        risk_counts,
                        names="Risk Tier",
                        values="Count",
                        title="Container Risk Distribution",
                    )

                    st.plotly_chart(
                        fig_container_risk,
                        use_container_width=True,
                    )

                # Evidence-aware table.
                display_columns = [
                    "file",
                    "layer",
                    "evidence_type",
                    "asset_type",
                    "algorithm",
                    "purpose",
                    "line",
                    "quantum_status",
                    "Risk Tier",
                    "Priority",
                    "PQC Replacement",
                    "confidence",
                    "snippet",
                ]

                valid_columns = [
                    column
                    for column in display_columns
                    if column in container_df.columns
                ]

                st.dataframe(
                    container_df[valid_columns],
                    use_container_width=True,
                    hide_index=True,
                )

                # Detailed active findings are especially useful during the SIH
                # demonstration because the judge can see the exact source line.
                if not active_df.empty:
                    st.subheader("🎯 Active Crypto Usage Evidence")

                    for _, row in active_df.iterrows():
                        risk_tier = row.get("Risk Tier", "UNKNOWN")
                        st.markdown(
                            f"**{row.get('algorithm', 'UNKNOWN')}** — "
                            f"`{row.get('file', 'Unknown')}:{row.get('line', 1)}` "
                            f"— **{risk_tier}**"
                        )
                        st.code(
                            str(row.get("snippet", "")),
                            language=str(
                                row.get("language", "")
                            ).lower() or "text",
                        )

                if not library_df.empty:
                    with st.expander(
                        "📚 Crypto Library / Provider Inventory"
                    ):
                        library_columns = [
                            "file",
                            "algorithm",
                            "evidence_type",
                            "confidence",
                            "Risk Tier",
                            "Risk Explanation",
                        ]

                        library_columns = [
                            c for c in library_columns
                            if c in library_df.columns
                        ]

                        st.dataframe(
                            library_df[library_columns],
                            use_container_width=True,
                            hide_index=True,
                        )

                # --------------------------------------------------------
                # Container CBOM exports
                # --------------------------------------------------------

                st.markdown("---")
                st.subheader("📤 Export Container CBOM Reports")

                e1, e2, e3 = st.columns(3)

                try:
                    container_cbom = export_cyclonedx_cbom(container_df)

                    e1.download_button(
                        "Download CycloneDX v1.6 Container CBOM (JSON)",
                        data=json.dumps(
                            container_cbom,
                            indent=2,
                            default=str,
                        ),
                        file_name="container_cyclonedx_cbom_1.6.json",
                        mime="application/json",
                        key="container_cbom_json",
                    )
                except Exception as exc:
                    e1.error(
                        "Container CBOM export failed: "
                        + str(exc)
                    )

                e2.download_button(
                    "Download Container CBOM (CSV)",
                    data=container_df.to_csv(index=False),
                    file_name="container_cbom_summary.csv",
                    mime="text/csv",
                    key="container_cbom_csv",
                )

                container_report = {
                    "scan_type": "docker_container_image",
                    "image": container_result.get(
                        "image",
                        container_image,
                    ),
                    "image_id": container_result.get(
                        "image_id",
                        "",
                    ),
                    "architecture": container_result.get(
                        "architecture",
                        "",
                    ),
                    "os": container_result.get(
                        "os",
                        "",
                    ),
                    "layers_scanned": container_stats.get(
                        "layers_scanned",
                        0,
                    ),
                    "statistics": container_stats,
                    "findings": container_df.to_dict(
                        orient="records"
                    ),
                }

                e3.download_button(
                    "Download Container Executive Report (JSON)",
                    data=json.dumps(
                        container_report,
                        indent=2,
                        default=str,
                    ),
                    file_name="container_executive_report.json",
                    mime="application/json",
                    key="container_executive_report",
                )

            else:
                st.warning(
                    "The image was scanned successfully, but no supported "
                    "cryptographic application evidence was detected."
                )

        except Exception as exc:
            st.error("Unable to display container scan results.")
            st.exception(exc)


if discovery_source == "🎯 Targeted Asset":
    # ============================================================
    # FEATURE 0 / EXISTING INDIVIDUAL ASSET SCANNER
    # ============================================================

    st.markdown("---")

    st.header(
        "🎯 Discovery Source — Targeted Cryptographic Asset"
    )

    st.caption(
        "Scan individual source files, certificates, manifests "
        "and binary assets."
    )


    uploaded_files = st.file_uploader(
        "Upload Assets",
        accept_multiple_files=True,
        type=[
            "c",
            "cpp",
            "h",
            "hpp",
            "java",
            "py",
            "go",
            "js",
            "jsx",
            "ts",
            "tsx",
            "rs",
            "pem",
            "crt",
            "cer",
            "txt",
            "xml",
            "json",
            "yaml",
            "yml",
            "jar",
            "so",
            "dll",
            "exe",
        ],
        key="individual_assets",
    )


    if uploaded_files:

        all_findings = []

        for uploaded_file in uploaded_files:

            if uploaded_file.name in IGNORE_FILES:
                continue

            try:

                content = uploaded_file.getvalue()

                findings = scan_file(
                    content,
                    uploaded_file.name,
                )

                findings = enrich_findings(
                    findings,
                    default_env,
                )

                for finding in findings:

                    finding["file"] = (
                        uploaded_file.name
                    )

                    finding["source_type"] = (
                        "individual_asset"
                    )

                all_findings.extend(
                    findings
                )

            except Exception as exc:

                st.warning(
                    f"Could not scan "
                    f"`{uploaded_file.name}`: {exc}"
                )

        if all_findings:

            df = pd.DataFrame(
                all_findings
            )

            # ----------------------------------------------------
            # SIMULATION
            # ----------------------------------------------------

            if enable_simulation:

                df = df.apply(
                    simulate_pqc_migration,
                    axis=1,
                )

            # ----------------------------------------------------
            # RISK ENGINE
            # ----------------------------------------------------

            df = apply_risk_engine(
                df
            )

            st.session_state["individual_inventory_df"] = df.copy()

            if enable_simulation:

                st.warning(
                    "🔬 SIMULATION ACTIVE: "
                    "Displaying hypothetical post-migration "
                    "inventory state."
                )

            # ====================================================
            # CRITICAL ALGORITHM ALERTS (additive, isolated feature)
            # Shown a step above the dashboard/table so critical
            # findings are surfaced immediately after analysis.
            # ====================================================

            _individual_file_content_lookup = {
                uf.name: uf.getvalue() for uf in uploaded_files
            }

            render_critical_algorithm_alerts(
                df,
                _individual_file_content_lookup,
                scope_prefix="indiv",
            )

            # ====================================================
            # PQC MIGRATION & REMEDIATION ENGINE (additive, isolated
            # feature) -- project-wide version of the alert above,
            # covering every finding rather than just CRITICAL ones.
            # ====================================================

            render_migration_engine(
                df,
                _individual_file_content_lookup,
                scope_prefix="indiv",
            )

            # ====================================================
            # EXECUTIVE METRICS
            # ====================================================

            col1, col2, col3, col4, col5 = (
                st.columns(5)
            )

            col1.metric(
                "Scanned Files",
                len(uploaded_files),
            )

            col2.metric(
                "Crypto Assets Found",
                len(df),
            )

            col3.metric(
                "Critical Risk",
                len(
                    df[
                        df["Risk Tier"]
                        == "CRITICAL"
                    ]
                ),
            )

            col4.metric(
                "P0 Immediate Priority",
                len(
                    df[
                        df["Priority"]
                        == "P0"
                    ]
                ),
            )

            col5.metric(
                "Avg Exposure Score",
                round(
                    df["Metric Value"].mean(),
                    2,
                ),
            )

            # ====================================================
            # DASHBOARD
            # ====================================================

            st.subheader(
                "📊 Cryptographic Risk Dashboard"
            )

            c1, c2, c3 = st.columns(3)

            with c1:

                risk_counts = (
                    df["Risk Tier"]
                    .value_counts()
                    .reset_index()
                )

                risk_counts.columns = [
                    "Risk Tier",
                    "Count",
                ]

                fig_risk = px.pie(
                    risk_counts,
                    names="Risk Tier",
                    values="Count",
                    title="Risk Distribution",
                )

                st.plotly_chart(
                    fig_risk,
                    use_container_width=True,
                )

            with c2:

                priority_counts = (
                    df["Priority"]
                    .value_counts()
                    .reset_index()
                )

                priority_counts.columns = [
                    "Priority",
                    "Count",
                ]

                fig_priority = px.bar(
                    priority_counts,
                    x="Priority",
                    y="Count",
                    title="Migration Priority",
                )

                st.plotly_chart(
                    fig_priority,
                    use_container_width=True,
                )

            with c3:

                algorithm_counts = (
                    df["algorithm"]
                    .value_counts()
                    .reset_index()
                )

                algorithm_counts.columns = [
                    "Algorithm",
                    "Count",
                ]

                fig_algorithm = px.bar(
                    algorithm_counts,
                    x="Algorithm",
                    y="Count",
                    title="Unique Algorithms",
                )

                st.plotly_chart(
                    fig_algorithm,
                    use_container_width=True,
                )

            # ====================================================
            # CBOM TABLE
            # ====================================================

            st.subheader(
                "📋 Cryptographic Bill of Materials (CBOM)"
            )

            st.info(
                f"Active Formula: **{calc_method}** | "
                f"CRQC Horizon: **{z_crqc} years**"
            )

            filter1, filter2, filter3, filter4, filter5 = (
                st.columns(5)
            )

            with filter1:

                file_search = st.text_input(
                    "🔍 Filter by File",
                    placeholder="PaymentService.java",
                    key="individual_file_filter",
                )

            with filter2:

                algo_search = st.text_input(
                    "🔍 Filter by Algorithm",
                    placeholder="RSA, SHA-1, AES",
                    key="individual_algorithm_filter",
                )

            with filter3:

                risk_select = st.selectbox(
                    "⚡ Risk",
                    ["ALL"]
                    + sorted(
                        df["Risk Tier"]
                        .dropna()
                        .astype(str)
                        .unique()
                        .tolist()
                    ),
                    key="individual_risk_filter",
                )

            with filter4:

                prio_select = st.selectbox(
                    "🚨 Priority",
                    [
                        "ALL",
                        "P0",
                        "P1",
                        "P2",
                        "P3",
                    ],
                    key="individual_priority_filter",
                )

            with filter5:

                env_values = (
                    df["environment"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                    if "environment" in df.columns
                    else []
                )

                env_select = st.selectbox(
                    "🏢 Environment",
                    ["ALL"] + sorted(
                        env_values
                    ),
                    key="individual_environment_filter",
                )

            filtered_df = df.copy()

            if file_search:

                filtered_df = filtered_df[
                    filtered_df["file"]
                    .astype(str)
                    .str.contains(
                        file_search,
                        case=False,
                        na=False,
                    )
                ]

            if algo_search:

                filtered_df = filtered_df[
                    filtered_df["algorithm"]
                    .astype(str)
                    .str.contains(
                        algo_search,
                        case=False,
                        na=False,
                    )
                ]

            if risk_select != "ALL":

                filtered_df = filtered_df[
                    filtered_df["Risk Tier"]
                    == risk_select
                ]

            if prio_select != "ALL":

                filtered_df = filtered_df[
                    filtered_df["Priority"]
                    == prio_select
                ]

            if env_select != "ALL":

                filtered_df = filtered_df[
                    filtered_df["environment"]
                    == env_select
                ]

            display_cols = [
                "file",
                "line",
                "environment",
                "asset_type",
                "algorithm",
                "purpose",
                "quantum_status",
                "X (Shelf-Life yrs)",
                "Y (Migration yrs)",
                "Z (CRQC Horizon yrs)",
                "Priority",
                "Risk Tier",
                "PQC Replacement",
                "Hybrid Option",
                "PQC Standard",
                "Migration Strategy",
                "Recommendation Rationale",
                "Latency Impact",
                "Migration Cost",
                "Compatibility",
                "Risk Explanation",
            ]

            valid_display_cols = [
                column
                for column in display_cols
                if column in filtered_df.columns
            ]

            st.dataframe(
                filtered_df[
                    valid_display_cols
                ],
                use_container_width=True,
                hide_index=True,
            )

            # ====================================================
            # INDIVIDUAL ASSET INSPECTOR
            # ====================================================

            st.subheader(
                "🔎 Deep-Dive Asset Inspector"
            )

            asset_options = []

            for _, row in df.iterrows():

                asset_options.append(
                    f"{row.get('file', 'Unknown')} "
                    f"(Line {row.get('line', 1)}) - "
                    f"{row.get('algorithm', 'UNKNOWN')} "
                    f"[{row.get('Risk Tier', 'UNKNOWN')}]"
                )

            if asset_options:

                selected_asset_label = st.selectbox(
                    "Select specific asset:",
                    asset_options,
                    key="individual_asset_selector",
                )

                selected_idx = (
                    asset_options.index(
                        selected_asset_label
                    )
                )

                selected_row = df.iloc[
                    selected_idx
                ]

                with st.expander(
                    "Detailed Analysis",
                    expanded=True,
                ):

                    d1, d2, d3 = (
                        st.columns(3)
                    )

                    with d1:

                        st.markdown(
                            f"**Source File:** "
                            f"`{selected_row.get('file', 'Unknown')}`"
                        )

                        st.markdown(
                            f"**Line:** "
                            f"`{selected_row.get('line', 1)}`"
                        )

                        st.markdown(
                            f"**Asset Type:** "
                            f"`{selected_row.get('asset_type', 'Unknown')}`"
                        )

                        st.markdown(
                            f"**Purpose:** "
                            f"`{selected_row.get('purpose', 'unknown')}`"
                        )

                    with d2:

                        st.markdown(
                            f"**Algorithm:** "
                            f"`{selected_row.get('algorithm', 'UNKNOWN')}`"
                        )

                        st.markdown(
                            f"**Quantum Status:** "
                            f"`{selected_row.get('quantum_status', 'UNKNOWN')}`"
                        )

                        st.markdown(
                            f"**Classical Status:** "
                            f"`{selected_row.get('classical_status', 'UNKNOWN')}`"
                        )

                        confidence = selected_row.get(
                            "confidence",
                            0.98,
                        )

                        try:
                            confidence_percent = (
                                float(confidence)
                                * 100
                            )
                        except (
                            TypeError,
                            ValueError,
                        ):
                            confidence_percent = 0

                        st.markdown(
                            f"**Confidence:** "
                            f"`{confidence_percent:.0f}%`"
                        )

                    with d3:

                        st.markdown(
                            f"**Shelf-Life (X):** "
                            f"`{selected_row.get('X (Shelf-Life yrs)', 0)} years`"
                        )

                        st.markdown(
                            f"**Migration Time (Y):** "
                            f"`{selected_row.get('Y (Migration yrs)', 0)} years`"
                        )

                        st.markdown(
                            f"**CRQC Horizon (Z):** "
                            f"`{selected_row.get('Z (CRQC Horizon yrs)', z_crqc)} years`"
                        )

                        st.markdown(
                            f"**Priority:** "
                            f"`{selected_row.get('Priority', 'P3')}`"
                        )

                    st.info(
                        "**Why is this risky?** "
                        + str(
                            selected_row.get(
                                "Risk Explanation",
                                "No explanation available.",
                            )
                        )
                    )

                    st.success(
                        "**Recommended Action:** "
                        f"Use **{selected_row.get('PQC Replacement', 'Review Required')}**"
                    )

                    st.markdown(
                        f"**Hybrid Option:** `{selected_row.get('Hybrid Option', 'None required')}`"
                    )
                    st.markdown(
                        f"**PQC Standard:** `{selected_row.get('PQC Standard', 'N/A')}`"
                    )
                    st.markdown(
                        f"**Migration Strategy:** {selected_row.get('Migration Strategy', 'Review required')}"
                    )
                    st.info(
                        "**Recommendation Rationale:** "
                        + str(selected_row.get('Recommendation Rationale', 'No rationale available.'))
                    )

                    st.markdown(
                        f"**Latency Impact:** `{selected_row.get('Latency Impact', 'Unknown')}`"
                    )
                    st.markdown(
                        f"**Migration Cost:** `{selected_row.get('Migration Cost', 'Unknown')}`"
                    )
                    st.markdown(
                        f"**Compatibility:** `{selected_row.get('Compatibility', 'Review required')}`"
                    )

            # ====================================================
            # EXPORTS
            # ====================================================

            st.subheader(
                "📤 Export Standardized CBOM Reports"
            )

            exp1, exp2, exp3 = (
                st.columns(3)
            )

            try:

                cbom_json = (
                    export_cyclonedx_cbom(
                        df
                    )
                )

                exp1.download_button(
                    label=(
                        "Download CycloneDX v1.6 CBOM (JSON)"
                    ),
                    data=json.dumps(
                        cbom_json,
                        indent=2,
                        default=str,
                    ),
                    file_name=(
                        "cyclonedx_cbom_1.6.json"
                    ),
                    mime="application/json",
                )

            except Exception as exc:

                exp1.error(
                    "CBOM export failed: "
                    + str(exc)
                )

            exp2.download_button(
                label=(
                    "Download CBOM Executive Summary (CSV)"
                ),
                data=df.to_csv(
                    index=False
                ),
                file_name=(
                    "cbom_summary.csv"
                ),
                mime="text/csv",
            )

            executive_report = {
                "scan_type": "individual_assets",
                "total_files": len(
                    uploaded_files
                ),
                "total_assets": len(df),
                "critical_risks": len(
                    df[
                        df["Risk Tier"]
                        == "CRITICAL"
                    ]
                ),
                "p0_priorities": len(
                    df[
                        df["Priority"]
                        == "P0"
                    ]
                ),
                "average_exposure_score": round(
                    df["Metric Value"].mean(),
                    2,
                ),
                "findings": df.to_dict(
                    orient="records"
                ),
            }

            exp3.download_button(
                label=(
                    "Download Executive Report (JSON)"
                ),
                data=json.dumps(
                    executive_report,
                    indent=2,
                    default=str,
                ),
                file_name=(
                    "executive_report.json"
                ),
                mime="application/json",
            )

        else:

            st.success(
                "No cryptographic algorithms or certificates "
                "were detected in the uploaded individual assets."
            )

    # ============================================================
    # UNIFIED CBOM / ENTERPRISE CRYPTO ASSET INVENTORY
    # ============================================================

    st.markdown("---")
st.header("🗂️ Unified Cryptographic Asset Inventory & Quantum Readiness")
st.caption(
    "One standardized CBOM view across source repositories, Docker containers "
    "and individually uploaded assets. Each asset receives a stable ECDAT ID, "
    "evidence classification and normalized risk/migration metadata."
)

_unified_df = build_unified_inventory(
    repository_df=st.session_state.get("repository_inventory_df"),
    container_df=st.session_state.get("container_scan_df"),
    individual_df=st.session_state.get("individual_inventory_df"),
)

if _unified_df.empty:
    st.info("Run at least one scanner above to populate the unified CBOM inventory.")
else:
    _summary = inventory_summary(_unified_df)

    # ========================================================
    # ECDAT EXECUTIVE SCAN DASHBOARD
    # ========================================================

    st.markdown("---")
    st.subheader("📊 ECDAT Executive Security Dashboard")

    total_assets = len(_unified_df)

    risk_series = (
        _unified_df["Risk Tier"].astype(str)
        if "Risk Tier" in _unified_df.columns
        else pd.Series([], dtype=str)
    )

    priority_series = (
        _unified_df["Priority"].astype(str)
        if "Priority" in _unified_df.columns
        else pd.Series([], dtype=str)
    )

    critical_count = int((risk_series == "CRITICAL").sum())
    high_count = int((risk_series == "HIGH").sum())
    medium_count = int((risk_series == "MEDIUM").sum())
    low_count = int((risk_series == "LOW").sum())

    p0_count = int((priority_series == "P0").sum())
    p1_count = int((priority_series == "P1").sum())

    dashboard_cols = st.columns(6)

    with dashboard_cols[0]:
        st.metric("🔐 Assets", total_assets)

    with dashboard_cols[1]:
        st.metric("🚨 Critical", critical_count)

    with dashboard_cols[2]:
        st.metric("⚠️ High", high_count)

    with dashboard_cols[3]:
        st.metric("🟡 Medium", medium_count)

    with dashboard_cols[4]:
        st.metric("🟢 Low", low_count)

    with dashboard_cols[5]:
        st.metric("🔥 P0 / P1", p0_count + p1_count)

    # --------------------------------------------------------
    # Risk + Discovery overview
    # --------------------------------------------------------

    overview_left, overview_right = st.columns(2)

    with overview_left:
        st.markdown("### ⚠️ Quantum Risk Distribution")

        risk_display = pd.DataFrame(
            {
                "Risk Tier": [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                ],
                "Assets": [
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                ],
            }
        )

        st.bar_chart(
            risk_display.set_index("Risk Tier")
        )

    with overview_right:
        st.markdown("### 🛰️ Discovery Source Distribution")

        if "source_type" in _unified_df.columns:
            source_display = (
                _unified_df["source_type"]
                .astype(str)
                .value_counts()
                .rename_axis("Discovery Source")
                .reset_index(name="Assets")
            )

            st.dataframe(
                source_display,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("Discovery source metadata is not available.")

    # --------------------------------------------------------
    # Highest priority migration queue
    # --------------------------------------------------------

    st.markdown("### 🔄 Highest-Priority PQC Migration")

    if "Priority" in _unified_df.columns:
        priority_order = {
            "P0": 0,
            "P1": 1,
            "P2": 2,
            "P3": 3,
        }

        migration_view = _unified_df.copy()

        migration_view["_priority_order"] = (
            migration_view["Priority"]
            .astype(str)
            .map(priority_order)
            .fillna(9)
        )

        migration_view = migration_view.sort_values(
            "_priority_order"
        )

        migration_columns = [
            column
            for column in [
                "Priority",
                "Risk Tier",
                "algorithm",
                "purpose",
                "source_type",
                "PQC Replacement",
                "Mosca Status",
            ]
            if column in migration_view.columns
        ]

        if migration_columns:
            st.dataframe(
                migration_view[
                    migration_columns
                ].head(10),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "Migration metadata is not available for the current inventory."
            )

    st.success(
        "ECDAT has completed discovery and normalized the "
        "results into the unified cryptographic inventory. "
        "Risk, migration priority and PQC recommendations "
        "are derived from the same asset records."
    )

    u1, u2, u3, u4, u5, u6 = st.columns(6)
    u1.metric("Total Crypto Assets", _summary["total_assets"])
    u2.metric("Quantum Vulnerable", _summary["quantum_vulnerable"])
    u3.metric("Critical", _summary["critical"])
    u4.metric("High", _summary["high"])
    u5.metric("P0 / P1", f'{_summary["p0"]} / {_summary["p1"]}')
    u6.metric("Scan Sources", _summary["sources"])

    st.subheader("📊 Enterprise Crypto Inventory Overview")
    uc1, uc2, uc3 = st.columns(3)
    with uc1:
        source_counts = _unified_df["source_type"].value_counts().reset_index()
        source_counts.columns = ["Source", "Assets"]
        st.plotly_chart(px.bar(source_counts, x="Source", y="Assets", title="Assets by Discovery Source"), use_container_width=True)
    with uc2:
        risk_counts = _unified_df["Risk Tier"].astype(str).value_counts().reset_index()
        risk_counts.columns = ["Risk Tier", "Assets"]
        st.plotly_chart(px.pie(risk_counts, names="Risk Tier", values="Assets", title="Unified Risk Distribution"), use_container_width=True)
    with uc3:
        algo_counts = _unified_df["algorithm"].astype(str).value_counts().head(12).reset_index()
        algo_counts.columns = ["Algorithm", "Assets"]
        st.plotly_chart(px.bar(algo_counts, x="Algorithm", y="Assets", title="Top Detected Algorithms"), use_container_width=True)

    st.subheader("🔎 Search & Filter Unified CBOM")
    uf1, uf2, uf3, uf4 = st.columns(4)
    with uf1:
        unified_source = st.selectbox("Discovery Source", ["ALL"] + sorted(_unified_df["source_type"].astype(str).unique().tolist()), key="unified_source_filter")
    with uf2:
        unified_risk = st.selectbox("Risk Tier", ["ALL"] + sorted(_unified_df["Risk Tier"].astype(str).unique().tolist()), key="unified_risk_filter")
    with uf3:
        unified_algo = st.text_input("Algorithm", key="unified_algorithm_filter", placeholder="RSA, ECDSA, SHA-1...")
    with uf4:
        unified_search = st.text_input("Search Asset / File", key="unified_text_filter", placeholder="payment, certificate, crypto_test...")

    filtered_unified = _unified_df.copy()
    if unified_source != "ALL":
        filtered_unified = filtered_unified[filtered_unified["source_type"] == unified_source]
    if unified_risk != "ALL":
        filtered_unified = filtered_unified[filtered_unified["Risk Tier"].astype(str) == unified_risk]
    if unified_algo.strip():
        filtered_unified = filtered_unified[filtered_unified["algorithm"].astype(str).str.contains(unified_algo.strip(), case=False, na=False)]
    if unified_search.strip():
        q = unified_search.strip()
        searchable = (filtered_unified["asset_id"].astype(str) + " " + filtered_unified["file"].astype(str) + " " + filtered_unified["algorithm"].astype(str) + " " + filtered_unified["purpose"].astype(str) + " " + filtered_unified["library_provider"].astype(str))
        filtered_unified = filtered_unified[searchable.str.contains(q, case=False, na=False)]

    st.caption(f"Showing {len(filtered_unified)} of {_summary['total_assets']} standardized assets")
    table_columns = ["asset_id", "source_type", "asset_type", "evidence_type", "algorithm", "purpose", "version", "mode", "key_size", "library_provider", "library_version", "protocol", "file", "line", "container_image", "quantum_status", "Risk Score", "Mosca Status", "Mosca Margin (yrs)", "Exposure Ratio (X+Y)/Z", "Risk Tier", "Priority", "PQC Replacement", "Hybrid Option", "PQC Standard", "Migration Strategy", "Recommendation Rationale", "Latency Impact", "Migration Cost", "Compatibility", "Recommendation Confidence", "confidence"]
    st.dataframe(filtered_unified[[c for c in table_columns if c in filtered_unified.columns]], use_container_width=True, hide_index=True)

    st.subheader("🎯 Highest-Priority Migration Queue")
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    queue = filtered_unified.copy()
    queue["_priority_order"] = queue["Priority"].map(priority_order).fillna(9)
    queue = queue.sort_values(["_priority_order", "confidence"], ascending=[True, False]).drop(columns=["_priority_order"])
    queue_cols = ["asset_id", "algorithm", "purpose", "file", "source_type", "Risk Tier", "Priority", "quantum_status", "PQC Replacement", "Hybrid Option", "PQC Standard", "Migration Strategy", "Recommendation Rationale", "Risk Explanation"]
    st.dataframe(queue[[c for c in queue_cols if c in queue.columns]].head(20), use_container_width=True, hide_index=True)

    unified_report = {
        "product": "ECDAT",
        "report_type": "unified_cryptographic_asset_inventory",
        "schema_version": "1.0",
        "assessment_method": calc_method,
        "crqc_horizon_years": z_crqc,
        "summary": _summary,
        "assets": _unified_df.to_dict(orient="records"),
    }
    ex1, ex2 = st.columns(2)
    ex1.download_button("📥 Download Unified CBOM (CSV)", data=_unified_df.to_csv(index=False), file_name="ecdat_unified_cbom.csv", mime="text/csv", key="download_unified_csv")
    ex2.download_button("📥 Download Unified CBOM Executive JSON", data=json.dumps(unified_report, indent=2, default=str), file_name="ecdat_unified_cbom_executive.json", mime="application/json", key="download_unified_json")
