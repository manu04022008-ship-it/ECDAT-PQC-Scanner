"""
migration_engine.py

Standalone, additive "PQC Migration & Remediation Engine" for whole
scans (a repository scan or a batch of individually-uploaded files).

Responsibility (and ONLY responsibility):
    Take a scan's finding table (df) plus the original bytes of every
    scanned file that is still available in this session, and offer a
    single, explicit action -- "Generate project migration" -- that:
      1. Builds a Migration Plan across every eligible finding (not
         just CRITICAL ones), showing current algorithm -> proposed
         target for each one, before anything is generated.
      2. Applies the existing, already-audited single-line patcher
         (algorithm_patcher.patch_algorithm_in_file) to every eligible
         finding in a file, working from the bottom of the file
         upward so earlier line numbers never drift as edits land.
      3. Re-scans every touched file with the same scanner the app
         already trusts and compares before/after counts, reusing
         algorithm_patcher.validate_migration.
      4. Packages the result as a ZIP with the untouched original
         under original/<path> and the migrated text under
         migrated/<path> -- nothing on disk is ever overwritten.
      5. Shows an aggregate before/after "PQC MIGRATION RESULT"
         summary and offers it, plus the ZIP, as downloads.

Design guarantees (same spirit as algorithm_patcher.py):
    - Pure functions for the engine logic (build_project_migration_plan,
      migrate_project, build_zip_bytes, build_project_report). Only
      render_migration_engine touches Streamlit, and it only imports
      Streamlit locally, so this module stays import-safe without it.
    - Never writes to disk and never mutates the `df` or the content
      lookup it is given.
    - Only reuses algorithm_patcher's existing, already-reviewed patch
      function for the actual text change -- this module does not
      invent a second way of editing a line. If algorithm_patcher
      refuses a line (drifted content, out-of-range line number) that
      finding is recorded as "skipped" with the refusal reason, never
      guessed at or forced through.
    - A finding is only auto-migrated when a STRONG replacement
      (algorithm_patcher.strength_tier == "strong") is available on
      either the "PQC Replacement" or "Hybrid Option" column --
      "PQC Replacement" is preferred, falling back to "Hybrid Option".
      Anything else (no strong target, or a refused patch) is left
      completely untouched and counted as a manual action, matching
      the "don't just string-replace, and don't guess" approach
      algorithm_patcher.py already uses.
    - This module does not import or modify app.py, scanner.py,
      repository_scanner.py, pqc_recommendations.py, cbom_formatter.py,
      mosca_engine.py, or unified_inventory.py, and it does not modify
      algorithm_patcher.py. It can be deleted with zero effect on any
      existing functionality.
"""
from __future__ import annotations

import io
import zipfile

from algorithm_patcher import (
    patch_algorithm_in_file,
    strength_tier,
    validate_migration,
)


def _pick_target_label(row):
    """STRONG 'PQC Replacement' first, then STRONG 'Hybrid Option', else None."""
    strong_label = str(row.get("PQC Replacement", "") or "")
    if strength_tier(strong_label) == "strong":
        return strong_label
    hybrid_label = str(row.get("Hybrid Option", "") or "")
    if strength_tier(hybrid_label) == "strong":
        return hybrid_label
    return None


def build_project_migration_plan(df) -> dict:
    """
    Aggregate, read-only view of what a project-wide migration would
    touch, one row per finding -- shown to the user BEFORE anything is
    generated. Does not read any file content and never modifies df.
    """
    if df is None or len(df) == 0:
        return {"rows": [], "eligible_count": 0, "manual_only_count": 0}

    plan_rows = []
    eligible = 0
    manual_only = 0

    for _, row in df.iterrows():
        target = _pick_target_label(row)
        if target:
            eligible += 1
        else:
            manual_only += 1
        plan_rows.append(
            {
                "file": str(row.get("file", "Unknown")),
                "line": row.get("line", 1),
                "algorithm": str(row.get("algorithm", "UNKNOWN")),
                "risk_tier": str(row.get("Risk Tier", "")),
                "target": target,
            }
        )

    return {
        "rows": plan_rows,
        "eligible_count": eligible,
        "manual_only_count": manual_only,
    }


def migrate_project(df, file_content_lookup: dict) -> dict:
    """
    Apply the existing single-line patcher to every eligible finding,
    per file, bottom-to-top so line numbers never drift mid-file as
    earlier (higher-line-number) patches insert extra TODO lines.

    Returns {"files": {file_name: {...}}, "summary": {...}} -- see the
    module docstring for the shape of each file's entry.
    """
    empty_summary = {
        "files_touched": 0,
        "algorithms_migrated": 0,
        "manual_actions_required": 0,
        "remaining_legacy_crypto": 0,
    }
    if df is None or len(df) == 0:
        return {"files": {}, "summary": empty_summary}

    results = {}
    algorithms_migrated = 0
    manual_actions_required = 0
    remaining_legacy_crypto = 0
    files_touched = 0

    file_series = df["file"].astype(str) if "file" in df.columns else None
    if file_series is None:
        return {"files": {}, "summary": empty_summary}

    for file_name, group in df.groupby(file_series):
        original_content = file_content_lookup.get(file_name)
        if original_content is None:
            # No content available in this session for this file --
            # every finding in it is left as a manual action rather
            # than being skipped silently.
            manual_actions_required += len(group)
            continue

        findings = group.sort_values("line", ascending=False) if "line" in group.columns else group

        current_text = (
            original_content.decode("utf-8", errors="ignore")
            if isinstance(original_content, (bytes, bytearray))
            else str(original_content)
        )
        changed = False
        patch_log = []

        for _, row in findings.iterrows():
            algorithm = str(row.get("algorithm", "UNKNOWN"))
            line_no = row.get("line", 1)
            target = _pick_target_label(row)

            if not target:
                manual_actions_required += 1
                patch_log.append(
                    {
                        "line": line_no,
                        "algorithm": algorithm,
                        "target": None,
                        "status": "manual",
                        "message": "No STRONG replacement available -- left unchanged.",
                    }
                )
                continue

            patched_text, note = patch_algorithm_in_file(
                content=current_text,
                filename=file_name,
                line_number=int(line_no) if str(line_no).isdigit() else 1,
                snippet=str(row.get("snippet", "")),
                old_algorithm=algorithm,
                new_algorithm_label=target,
            )

            if patched_text is None:
                manual_actions_required += 1
                patch_log.append(
                    {
                        "line": line_no,
                        "algorithm": algorithm,
                        "target": target,
                        "status": "skipped",
                        "message": note,
                    }
                )
                continue

            current_text = patched_text
            changed = True
            algorithms_migrated += 1
            patch_log.append(
                {
                    "line": line_no,
                    "algorithm": algorithm,
                    "target": target,
                    "status": "patched",
                    "message": note,
                }
            )

        validation = None
        if changed:
            files_touched += 1
            seen_algorithms = set(findings["algorithm"].astype(str)) if "algorithm" in findings.columns else set()
            before_total = 0
            after_total = 0
            warnings = []
            for algo in seen_algorithms:
                v = validate_migration(
                    original_content=original_content,
                    patched_text=current_text,
                    filename=file_name,
                    old_algorithm=algo,
                )
                if v:
                    before_total += v["before_count"]
                    after_total += v["after_count"]
                    warnings.extend(v["warnings"])
            validation = {
                "before_count": before_total,
                "after_count": after_total,
                "warnings": warnings,
            }
            remaining_legacy_crypto += after_total

        results[file_name] = {
            "original": original_content,
            "migrated": current_text if changed else None,
            "changed": changed,
            "patches": patch_log,
            "validation": validation,
        }

    return {
        "files": results,
        "summary": {
            "files_touched": files_touched,
            "algorithms_migrated": algorithms_migrated,
            "manual_actions_required": manual_actions_required,
            "remaining_legacy_crypto": remaining_legacy_crypto,
        },
    }


def build_zip_bytes(migration_result: dict) -> bytes:
    """
    Package changed files as an in-memory ZIP: the untouched original
    under original/<path>, the migrated text under migrated/<path>.
    Unchanged files are not included. This never touches disk -- the
    bytes are only ever handed to a Streamlit download button.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_name, info in migration_result.get("files", {}).items():
            if not info.get("changed"):
                continue
            original_bytes = info["original"]
            if isinstance(original_bytes, str):
                original_bytes = original_bytes.encode("utf-8", errors="ignore")
            zf.writestr(f"original/{file_name}", original_bytes)
            zf.writestr(f"migrated/{file_name}", info["migrated"].encode("utf-8", errors="ignore"))
    return buffer.getvalue()


def build_project_report(migration_result: dict) -> str:
    """Human-readable, aggregate before/after report (plain text)."""
    summary = migration_result.get("summary", {})
    lines = [
        "PQC MIGRATION RESULT",
        "-" * 40,
        f"Files touched:             {summary.get('files_touched', 0)}",
        f"Algorithms migrated:       {summary.get('algorithms_migrated', 0)}",
        f"Manual actions required:   {summary.get('manual_actions_required', 0)}",
        f"Remaining legacy crypto:   {summary.get('remaining_legacy_crypto', 0)}",
    ]
    per_file_lines = []
    for file_name, info in migration_result.get("files", {}).items():
        if not info.get("changed"):
            continue
        v = info.get("validation") or {}
        per_file_lines.append(
            f"  {file_name}: before={v.get('before_count', '?')} after={v.get('after_count', '?')}"
        )
    if per_file_lines:
        lines.append("")
        lines.append("Per file:")
        lines.extend(per_file_lines)
    return "\n".join(lines)


# ---------------------------------------------------------------------
# Self-contained UI block. Streamlit is only imported here, mirroring
# algorithm_patcher.render_critical_algorithm_alerts -- importing the
# pure functions above never requires Streamlit to be installed.
#
# Purely additive: renders its own subheader/widgets (keys namespaced
# under scope_prefix), never mutates the `df` or file_content_lookup
# it is given, and never touches any session_state key used elsewhere.
# ---------------------------------------------------------------------

def render_migration_engine(df, file_content_lookup: dict, scope_prefix: str):
    import streamlit as st  # local import: keeps this module import-safe without Streamlit

    if df is None or len(df) == 0:
        return

    plan = build_project_migration_plan(df)
    if not plan["rows"]:
        return

    st.subheader("🛠️ PQC Migration & Remediation Engine")
    st.caption(
        "Controlled automated PQC migration assistance -- not a fully "
        "automatic migration. This considers every finding in this scan "
        "(not just CRITICAL ones), applies the same audited, single-line "
        "patcher used above wherever a STRONG replacement exists, and "
        "leaves everything else for manual review. Your files on disk "
        "are never modified -- you get back a downloadable "
        "original/ + migrated/ ZIP."
    )

    col1, col2 = st.columns(2)
    col1.metric("Eligible for auto-migration", plan["eligible_count"])
    col2.metric("Require manual review", plan["manual_only_count"])

    with st.expander("📋 Project Migration Plan (per finding)"):
        for item in plan["rows"]:
            marker = "✅" if item["target"] else "✋"
            target_text = item["target"] or "no strong replacement -- manual review"
            st.markdown(
                f"{marker} `{item['file']}` line {item['line']}: "
                f"**{item['algorithm']}** \u2192 {target_text}"
            )

    files_in_plan = {row["file"] for row in plan["rows"]}
    available_files = sum(1 for f in files_in_plan if f in file_content_lookup)

    if available_files == 0:
        st.info(
            "No original file content is available in this session for "
            "the scanned files, so a project migration can't be "
            "generated. Re-run the scan and try again from this same "
            "session."
        )
        return

    if st.button("Generate project migration", key=f"generate_project_migration_{scope_prefix}"):
        result = migrate_project(df, file_content_lookup)
        summary = result["summary"]

        st.success("✅ Project migration generated.")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Files touched", summary["files_touched"])
        m2.metric("Algorithms migrated", summary["algorithms_migrated"])
        m3.metric("Manual actions required", summary["manual_actions_required"])
        m4.metric("Remaining legacy crypto", summary["remaining_legacy_crypto"])

        for file_name, info in result["files"].items():
            if not info["changed"]:
                continue
            with st.expander(f"📄 {file_name}"):
                for patch in info["patches"]:
                    if patch["status"] == "patched":
                        st.markdown(
                            f"- ✅ line {patch['line']}: {patch['algorithm']} \u2192 {patch['target']}"
                        )
                    elif patch["status"] == "skipped":
                        st.warning(f"- ⚠️ line {patch['line']}: {patch['message']}")
                    else:
                        st.markdown(
                            f"- ✋ line {patch['line']}: {patch['algorithm']} "
                            "(manual review -- no strong replacement)"
                        )
                v = info.get("validation")
                if v:
                    st.markdown(f"**Validation:** before={v['before_count']} after={v['after_count']}")
                    for warning in v["warnings"]:
                        st.warning(warning)

        report_text = build_project_report(result)
        st.code(report_text, language=None)

        zip_bytes = build_zip_bytes(result)
        col_a, col_b = st.columns(2)
        with col_a:
            st.download_button(
                "⬇️ Download migrated project (original/ + migrated/)",
                data=zip_bytes,
                file_name="pqc_migrated_project.zip",
                mime="application/zip",
                key=f"download_project_zip_{scope_prefix}",
            )
        with col_b:
            st.download_button(
                "⬇️ Download migration report",
                data=report_text.encode("utf-8"),
                file_name="pqc_migration_report.txt",
                mime="text/plain",
                key=f"download_project_report_{scope_prefix}",
            )
