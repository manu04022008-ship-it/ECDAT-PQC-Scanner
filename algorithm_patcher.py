"""
algorithm_patcher.py

Standalone, additive module for the "Critical Algorithm Alert" feature.

Responsibility (and ONLY responsibility):
    Given the exact line/snippet a scanner already flagged in ONE file,
    produce a NEW patched version of that file's text with the chosen
    PQC replacement applied at that single location.

Design guarantees:
    - Pure functions. Never mutates the input content, never touches
      global/session state, never reads or writes any other file.
    - Only ever changes the one flagged line. Every other line of the
      file is passed through byte-for-byte (via splitlines(keepends=True)).
    - If the flagged line can no longer be found (file drifted from what
      was scanned), it refuses to patch rather than guessing and
      corrupting the file.
    - Simple same-API swaps (weak hash / weak symmetric cipher) are
      rewritten in place. Asymmetric -> PQC swaps (KEM / signature)
      require a different library/API, so the original line is kept
      (commented out, for easy rollback/diff) and a clearly-labelled
      TODO block with the correct target primitive is inserted next to
      it. This is intentionally conservative: it never invents a fake
      "drop-in" call for an API that does not exist in the target
      library.

This module does not import, modify, or depend on scanner.py,
repository_scanner.py, pqc_recommendations.py, cbom_formatter.py,
mosca_engine.py, or app.py. It can be deleted with zero effect on any
existing functionality.
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------
# Language detection (comment style + display name only)
# ---------------------------------------------------------------------

_LANG_BY_EXT = {
    ".py": ("Python", "#"),
    ".java": ("Java", "//"),
    ".c": ("C", "//"),
    ".h": ("C", "//"),
    ".cpp": ("C++", "//"),
    ".cc": ("C++", "//"),
    ".hpp": ("C++", "//"),
    ".go": ("Go", "//"),
    ".js": ("JavaScript", "//"),
    ".jsx": ("JavaScript", "//"),
    ".ts": ("TypeScript", "//"),
    ".tsx": ("TypeScript", "//"),
    ".rs": ("Rust", "//"),
}


def _lang_for(filename: str):
    ext = Path(filename).suffix.lower()
    return _LANG_BY_EXT.get(ext, ("Unknown", "#"))


# ---------------------------------------------------------------------
# Classify the CHOSEN replacement label into a migration family.
# This drives whether a same-API swap is possible or a library change
# is required.
# ---------------------------------------------------------------------

def _classify_replacement(label: str) -> str:
    text = (label or "").upper()
    if "ML-KEM" in text or "KEM" in text:
        return "kem"
    if "ML-DSA" in text or "SLH-DSA" in text or "DSA" in text and "ECDSA" not in text:
        return "signature"
    if "SHA-256" in text or "SHA-3" in text or "SHA256" in text:
        return "hash"
    if "AES" in text:
        return "symmetric"
    return "generic"


def _clean_label(label: str) -> str:
    """'AES-256-GCM (where appropriate)' -> 'AES-256-GCM'."""
    text = (label or "").strip()
    text = re.split(r"\s+or\s+", text, maxsplit=1)[0]
    text = re.sub(r"\s*\(.*?\)\s*$", "", text).strip()
    return text or label


# ---------------------------------------------------------------------
# Library/API guidance shown in generated TODO blocks. Informational
# only -- never presented as a guaranteed drop-in replacement.
# ---------------------------------------------------------------------

_LIBRARY_HINTS = {
    "Python": {
        "kem": "liboqs-python (pip install liboqs-python) or a FIPS-203-certified provider",
        "signature": "liboqs-python (pip install liboqs-python) or a FIPS-204-certified provider",
    },
    "Java": {
        "kem": "a PQC-capable JCA provider (e.g. Bouncy Castle PQC) registered for \"ML-KEM\"",
        "signature": "a PQC-capable JCA provider (e.g. Bouncy Castle PQC) registered for \"ML-DSA\"",
    },
    "C": {
        "kem": "liboqs (OQS_KEM_new(\"ML-KEM-768\"))",
        "signature": "liboqs (OQS_SIG_new(\"ML-DSA-65\"))",
    },
    "C++": {
        "kem": "liboqs (OQS_KEM_new(\"ML-KEM-768\"))",
        "signature": "liboqs (OQS_SIG_new(\"ML-DSA-65\"))",
    },
    "Go": {
        "kem": "a Go ML-KEM implementation (e.g. golang.org/x/crypto/mlkem, or Cloudflare CIRCL)",
        "signature": "a Go ML-DSA implementation (e.g. Cloudflare CIRCL)",
    },
    "JavaScript": {
        "kem": "a WASM/liboqs-based ML-KEM library",
        "signature": "a WASM/liboqs-based ML-DSA library",
    },
    "TypeScript": {
        "kem": "a WASM/liboqs-based ML-KEM library",
        "signature": "a WASM/liboqs-based ML-DSA library",
    },
    "Rust": {
        "kem": "the pqcrypto or ml-kem crate",
        "signature": "the pqcrypto or ml-dsa crate",
    },
}

_HASH_SWAP_TOKENS = {
    "MD5": "SHA-256",
    "SHA1": "SHA-256",
    "SHA-1": "SHA-256",
}

_HASH_SWAP_IDENTIFIER_FORM = {
    "MD5": "sha256",
    "SHA1": "sha256",
    "SHA-1": "sha256",
}

_SYMMETRIC_SWAP_TOKENS = {
    "3DES": "AES-256-GCM",
    "TRIPLEDES": "AES-256-GCM",
    "DES": "AES-256-GCM",
    "RC4": "AES-256-GCM",
}


def _indent_of(line: str) -> str:
    match = re.match(r"^([ \t]*)", line)
    return match.group(1) if match else ""


def _line_ending_of(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    return ""


def patch_algorithm_in_file(
    content,
    filename: str,
    line_number: int,
    snippet: str,
    old_algorithm: str,
    new_algorithm_label: str,
):
    """
    Return (patched_text, message) on success, or (None, error_message)
    on failure. Does not raise for expected failure modes.

    Only the single line at `line_number` is ever modified. Everything
    else in `content` is preserved exactly.
    """
    try:
        text = (
            content.decode("utf-8", errors="ignore")
            if isinstance(content, (bytes, bytearray))
            else str(content)
        )
    except Exception as exc:  # pragma: no cover - defensive only
        return None, f"Could not read file content: {exc}"

    lines = text.splitlines(keepends=True)

    if not (1 <= int(line_number) <= len(lines)):
        return None, (
            f"Line {line_number} is outside this file's current length "
            f"({len(lines)} lines) -- refusing to patch."
        )

    idx = int(line_number) - 1
    target_line = lines[idx]

    snippet_norm = (snippet or "").strip()
    if snippet_norm and snippet_norm not in target_line:
        # Small drift tolerance: check one line above/below in case the
        # file shifted slightly since the scan.
        for candidate in (idx - 1, idx + 1):
            if 0 <= candidate < len(lines) and snippet_norm in lines[candidate]:
                idx = candidate
                target_line = lines[idx]
                break
        else:
            return None, (
                "The flagged line no longer matches what was scanned "
                "(the file may have changed). Refusing to patch to avoid "
                "corrupting unrelated content -- please re-scan this file "
                "and try again."
            )

    language, comment = _lang_for(filename)
    indent = _indent_of(target_line)
    eol = _line_ending_of(target_line)

    family = _classify_replacement(new_algorithm_label)
    clean_label = _clean_label(new_algorithm_label)

    if family == "hash":
        new_line, swapped = target_line, False
        for old_token, literal_form in _HASH_SWAP_TOKENS.items():
            identifier_form = _HASH_SWAP_IDENTIFIER_FORM[old_token]

            # Safe case 1: token sits inside a quoted string literal,
            # e.g. MessageDigest.getInstance("MD5") -- a string literal
            # can contain a hyphen safely.
            quoted_pattern = re.compile(
                r'(["\'])' + re.escape(old_token) + r'\1', re.IGNORECASE
            )
            if quoted_pattern.search(new_line):
                new_line = quoted_pattern.sub(
                    lambda m: m.group(1) + literal_form + m.group(1),
                    new_line,
                    count=1,
                )
                swapped = True
                break

            # Safe case 2: a hashlib-style dotted call, e.g. hashlib.sha1(
            # -- must use the identifier-safe form (no hyphen).
            call_pattern = re.compile(
                r'(\.)' + re.escape(old_token.lower()) + r'(\s*\()',
                re.IGNORECASE,
            )
            if call_pattern.search(new_line):
                new_line = call_pattern.sub(
                    r'\g<1>' + identifier_form + r'\g<2>',
                    new_line,
                    count=1,
                )
                swapped = True
                break

        if swapped:
            new_line = new_line.rstrip("\r\n") + f"  {comment} [PQC-MIGRATION] auto-updated to {clean_label}" + eol
            lines[idx] = new_line
            message = (
                f"Same-API swap applied on line {line_number} of `{filename}`: "
                f"weak hash replaced with {clean_label}. No other line was changed."
            )
            return "".join(lines), message
        # No safe swap target found (e.g. a bare class/identifier use) --
        # fall through to the generic comment+TODO block below rather
        # than risk producing invalid code.

    if family == "symmetric":
        new_line, swapped = target_line, False
        for old_token, new_token in _SYMMETRIC_SWAP_TOKENS.items():
            # Only swap inside a quoted string literal -- safe there
            # (e.g. Cipher.getInstance("DES")). Bare identifiers/class
            # references (e.g. DES.new(key)) are left to the TODO
            # template below, since "AES-256-GCM" is not a valid
            # identifier and would break the code.
            quoted_pattern = re.compile(
                r'(["\'])' + re.escape(old_token) + r'\1', re.IGNORECASE
            )
            if quoted_pattern.search(new_line):
                new_line = quoted_pattern.sub(
                    lambda m: m.group(1) + new_token + m.group(1),
                    new_line,
                    count=1,
                )
                swapped = True
                break

        if swapped:
            new_line = new_line.rstrip("\r\n") + f"  {comment} [PQC-MIGRATION] auto-updated to {clean_label}" + eol
            lines[idx] = new_line
            message = (
                f"Same-API swap applied on line {line_number} of `{filename}`: "
                f"legacy cipher replaced with {clean_label}. No other line was changed."
            )
            return "".join(lines), message
        # fall through if no safe (quoted) target was found

    # KEM / signature / generic / unmatched-hash / unmatched-symmetric:
    # keep the original call (commented out) and insert a clearly
    # labelled TODO block, since this requires a different library/API
    # rather than a same-signature swap.
    hint = _LIBRARY_HINTS.get(language, {}).get(family)
    stripped_original = target_line.rstrip("\r\n")

    todo_lines = [
        f"{indent}{comment} [PQC-MIGRATION] Original (kept for rollback/diff):{eol}",
        f"{indent}{comment} {stripped_original.strip()}{eol}",
        f"{indent}{comment} TODO: Replace the call above with {clean_label}.{eol}",
    ]
    if hint:
        todo_lines.append(f"{indent}{comment} Suggested library: {hint}.{eol}")
    todo_lines.append(
        f"{indent}{comment} This block was generated automatically -- verify before deploying.{eol}"
    )

    lines[idx : idx + 1] = todo_lines

    message = (
        f"Line {line_number} of `{filename}` was commented out and replaced with a "
        f"{clean_label} migration TODO block (requires a PQC library -- see comment). "
        "No other line or file was changed."
    )
    return "".join(lines), message


def strength_tier(label: str) -> str:
    """Cosmetic helper for the UI: 'strong' or 'moderate' badge."""
    if not label or label.strip().lower() in ("none required", "not applicable", "n/a"):
        return "none"
    return "strong"


# ---------------------------------------------------------------------
# Migration Plan / Validation / Report
#
# These three functions add the "Migration Planner", "Validation", and
# "Migration Report" stages on top of the existing patch engine above.
# They are purely additive: none of the existing functions in this file
# (patch_algorithm_in_file, strength_tier, render_critical_algorithm_alerts)
# are modified. render_critical_algorithm_alerts is extended, further
# down, to call these three new functions -- it is not rewritten.
# ---------------------------------------------------------------------

def build_migration_plan(
    file_name: str,
    old_algorithm: str,
    risk_tier: str,
    risk_score,
    chosen_label: str,
) -> dict:
    """
    Build a Current / Proposed / Impact plan for one finding, shown to
    the user BEFORE anything is generated. Pure function, no side
    effects.
    """
    family = _classify_replacement(chosen_label)
    clean_label = _clean_label(chosen_label)

    migration_type = "PQC" if family in ("kem", "signature") else (
        "Same-API upgrade" if family in ("hash", "symmetric") else "Manual review"
    )

    if family in ("kem", "signature"):
        impact = {
            "API change": "Required (different library/API)",
            "Key/format change": "Required",
            "Protocol integration": "Required (peer must also support the new algorithm)",
            "Compatibility impact": "High -- treat as a staged rollout, ideally via a Hybrid option first",
        }
    elif family in ("hash", "symmetric"):
        impact = {
            "API change": "None -- same function signature",
            "Key/format change": "None",
            "Protocol integration": "Not required",
            "Compatibility impact": "Low -- safe to apply directly",
        }
    else:
        impact = {
            "API change": "Unknown -- manual review recommended",
            "Key/format change": "Unknown",
            "Protocol integration": "Unknown",
            "Compatibility impact": "Unknown",
        }

    return {
        "current": {
            "file": file_name,
            "algorithm": old_algorithm,
            "risk_tier": risk_tier,
            "risk_score": risk_score,
        },
        "proposed": {
            "target": clean_label,
            "migration_type": migration_type,
        },
        "impact": impact,
    }


def validate_migration(
    original_content,
    patched_text: str,
    filename: str,
    old_algorithm: str,
):
    """
    Re-scan the ORIGINAL content and the PATCHED content with the same
    scanner the app already trusts (scanner.scan_file), and compare.
    This is a real before/after check, not a cosmetic message.

    Returns a dict: {
        "before_count": int,          # findings of old_algorithm before
        "after_count": int,           # findings of old_algorithm after
        "remaining_findings": [...],  # any findings still present after
        "warnings": [str, ...],
    }

    If scanner.scan_file can't be imported for some reason, returns
    None rather than raising -- callers must handle that gracefully.
    """
    try:
        from scanner import scan_file
    except Exception:
        return None

    def _as_bytes(content):
        if isinstance(content, (bytes, bytearray)):
            return bytes(content)
        return str(content).encode("utf-8", errors="ignore")

    try:
        before_findings = scan_file(_as_bytes(original_content), filename) or []
    except Exception:
        before_findings = []

    try:
        after_findings = scan_file(_as_bytes(patched_text), filename) or []
    except Exception:
        after_findings = []

    before_count = sum(
        1 for f in before_findings if f.get("algorithm") == old_algorithm
    )
    after_count = sum(
        1 for f in after_findings if f.get("algorithm") == old_algorithm
    )

    warnings = []
    family = _classify_replacement(old_algorithm)
    if "[PQC-MIGRATION]" in patched_text and "TODO" in patched_text:
        warnings.append(
            "This change inserted a TODO block requiring a PQC library "
            "integration -- it is not runnable as-is. Manual completion "
            "is required before deploying."
        )
    if after_count > 0:
        warnings.append(
            f"The scanner still detects {after_count} occurrence(s) of "
            f"{old_algorithm} in this file after patching (likely other, "
            "unrelated lines) -- review the file before deploying."
        )

    return {
        "before_count": before_count,
        "after_count": after_count,
        "remaining_findings": after_findings,
        "warnings": warnings,
    }


def build_migration_report(
    file_name: str,
    old_algorithm: str,
    new_algorithm_label: str,
    validation: dict,
) -> str:
    """Human-readable before/after report, as plain text."""
    clean_label = _clean_label(new_algorithm_label)

    if validation is None:
        status = "Patched (validation unavailable)"
        remaining_line = "Remaining legacy crypto: unknown"
        warnings_line = "Migration warnings: 0"
    else:
        status = (
            "Successful"
            if validation["after_count"] == 0
            else "Completed with remaining occurrences"
        )
        remaining_line = f"Remaining legacy crypto: {validation['after_count']}"
        warnings_line = f"Migration warnings: {len(validation['warnings'])}"

    lines = [
        "PQC MIGRATION RESULT",
        "-" * 40,
        f"File:                {file_name}",
        f"{old_algorithm:<20s} -> {clean_label}",
        f"Migration status:    {status}",
        remaining_line,
        warnings_line,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------
# Self-contained UI block. Streamlit is only imported here, at the
# bottom of the module, so importing the pure functions above never
# requires Streamlit to be installed/running.
#
# This function is purely additive: it renders its own subheader, its
# own widgets (all keys namespaced under scope_prefix), and never
# mutates the `df` it is given or any Streamlit session_state key used
# elsewhere in the app.
# ---------------------------------------------------------------------

def render_critical_algorithm_alerts(df, file_content_lookup: dict, scope_prefix: str):
    import streamlit as st  # local import: keeps this module import-safe without Streamlit

    if df is None or len(df) == 0 or "Risk Tier" not in df.columns:
        return

    critical_df = df[df["Risk Tier"] == "CRITICAL"]
    if critical_df.empty:
        return

    st.subheader("🚨 Critical Algorithm Alerts")
    st.caption(
        "These specific findings were scored CRITICAL. You can generate a "
        "PQC-migrated copy of the affected file for each one -- this never "
        "changes any other file or any other finding."
    )

    badge_css = (
        "display:inline-block;padding:2px 10px;border-radius:10px;"
        "font-size:11px;font-weight:600;margin-right:8px;"
    )
    strong_badge = f"<span style='{badge_css}background-color:#1b5e20;color:#ffffff;'>STRONG</span>"
    moderate_badge = f"<span style='{badge_css}background-color:#a5d6a7;color:#1b3a1e;'>MODERATE</span>"

    for row_pos, (orig_idx, row) in enumerate(critical_df.iterrows()):
        file_name = str(row.get("file", "Unknown"))
        line_no = row.get("line", 1)
        algorithm = str(row.get("algorithm", "UNKNOWN"))
        asset_key = f"{scope_prefix}_{row_pos}_{orig_idx}"

        with st.container(border=True):
            st.markdown(
                f"⚠️ **`{file_name}`** (line {line_no}) uses **{algorithm}** "
                "-- flagged **CRITICAL**."
            )

            decision = st.radio(
                "Change this algorithm now?",
                ["Not yet", "Yes, show me replacement options"],
                key=f"decision_{asset_key}",
                horizontal=True,
                index=0,
                label_visibility="collapsed",
            )

            if decision != "Yes, show me replacement options":
                continue

            strong_label = str(row.get("PQC Replacement", "") or "")
            moderate_label = str(row.get("Hybrid Option", "") or "")

            options = []
            if strength_tier(strong_label) == "strong":
                options.append(("STRONG", strong_label))
            if strength_tier(moderate_label) == "strong":
                options.append(("MODERATE", moderate_label))

            if not options:
                st.info(
                    "No automated stronger replacement is available for this "
                    "asset -- manual cryptographic review is recommended."
                )
                continue

            for tier, label in options:
                badge = strong_badge if tier == "STRONG" else moderate_badge
                st.markdown(f"{badge} {label}", unsafe_allow_html=True)

            chosen_label = st.radio(
                "Select the replacement algorithm to apply:",
                [label for _, label in options],
                key=f"choice_{asset_key}",
            )

            with st.expander("📋 Migration Plan (current / proposed / impact)"):
                plan = build_migration_plan(
                    file_name=file_name,
                    old_algorithm=algorithm,
                    risk_tier=str(row.get("Risk Tier", "")),
                    risk_score=row.get("Risk Score", row.get("risk_score", "")),
                    chosen_label=chosen_label,
                )
                st.markdown("**Current**")
                for k, v in plan["current"].items():
                    st.markdown(f"- {k}: `{v}`")
                st.markdown("**Proposed**")
                for k, v in plan["proposed"].items():
                    st.markdown(f"- {k}: `{v}`")
                st.markdown("**Impact**")
                for k, v in plan["impact"].items():
                    st.markdown(f"- {k}: {v}")

            if st.button("Apply this change to the file", key=f"apply_{asset_key}"):
                original_content = file_content_lookup.get(file_name)
                if original_content is None:
                    st.error(
                        "The original file content for this asset is not "
                        "available in this session, so it can't be patched. "
                        "Try re-uploading and scanning it again."
                    )
                else:
                    patched_text, note = patch_algorithm_in_file(
                        content=original_content,
                        filename=file_name,
                        line_number=int(line_no) if str(line_no).isdigit() else 1,
                        snippet=str(row.get("snippet", "")),
                        old_algorithm=algorithm,
                        new_algorithm_label=chosen_label,
                    )
                    if patched_text is None:
                        st.error(note)
                    else:
                        st.success(f"✅ {note}")

                        validation = validate_migration(
                            original_content=original_content,
                            patched_text=patched_text,
                            filename=file_name,
                            old_algorithm=algorithm,
                        )

                        if validation is not None:
                            st.markdown("**🔬 Validation (re-scanned automatically)**")
                            st.markdown(
                                f"- `{algorithm}` occurrences before: "
                                f"{validation['before_count']}"
                            )
                            st.markdown(
                                f"- `{algorithm}` occurrences after: "
                                f"{validation['after_count']}"
                            )
                            for warning in validation["warnings"]:
                                st.warning(warning)

                        report_text = build_migration_report(
                            file_name=file_name,
                            old_algorithm=algorithm,
                            new_algorithm_label=chosen_label,
                            validation=validation,
                        )
                        st.code(report_text, language=None)

                        st.download_button(
                            "⬇️ Download PQC-migrated file",
                            data=patched_text.encode("utf-8"),
                            file_name=f"pqc_patched_{Path(file_name).name}",
                            mime="text/plain",
                            key=f"download_{asset_key}",
                        )
