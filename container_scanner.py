"""
PS-164 Container Image Crypto Scanner
--------------------------------------

Purpose:
    Scan Docker container images for cryptographic artefacts while
    aggressively reducing false positives from documentation, package
    metadata, comments and system files.

Evidence classes:
    ACTIVE_USAGE       -> actual crypto API/code usage
    CONFIGURATION      -> crypto-related configuration
    LIBRARY_PRESENCE   -> installed crypto library/provider
    INVENTORY          -> supporting container metadata
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    "coverage",
    "dist",
    "build",
    "target",
    "out",
    "__MACOSX",
}

IGNORED_PATH_PARTS = {
    "/usr/share/doc/",
    "/usr/share/man/",
    "/usr/share/info/",
    "/usr/share/locale/",
    "/var/cache/",
    "/var/log/",
    "/var/backups/",
    "/usr/src/linux-headers/",
}


# Paths that normally represent application code inside a container.
# These receive full ACTIVE_USAGE analysis. Runtime/OS paths are not treated
# as application crypto usage merely because Python/Node/etc. uses crypto
# internally.
APPLICATION_ROOTS = (
    "/app/",
    "/src/",
    "/workspace/",
    "/project/",
    "/code/",
    "/service/",
    "/services/",
)

# Common runtime/dependency trees. These are deliberately excluded from
# ACTIVE_USAGE scanning to prevent language-runtime and package internals from
# dominating the CBOM.
RUNTIME_PATH_PREFIXES = (
    "/usr/local/lib/python",
    "/usr/lib/python",
    "/usr/local/lib/node_modules/",
    "/usr/lib/node_modules/",
    "/usr/lib/go/",
    "/usr/local/go/",
    "/usr/share/",
    "/usr/lib/",
    "/lib/",
    "/lib64/",
    "/var/lib/",
    "/opt/",
)


IGNORED_FILENAMES = {
    ".ds_store",
    "thumbs.db",
    "record",
    "records",
    "copyright",
    "changelog",
    "install",
    "debian",
}

IGNORED_EXTENSIONS = {
    ".md",
    ".rst",
    ".txt",
    ".html",
    ".htm",
    ".xml",
    ".po",
    ".pot",
    ".mo",
    ".map",
}

SOURCE_EXTENSIONS = {
    ".py": "Python",
    ".pyi": "Python",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".c": "C",
    ".h": "C/C++",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".go": "Go",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rs": "Rust",
}

CONFIG_EXTENSIONS = {
    ".conf",
    ".cfg",
    ".ini",
    ".properties",
    ".yaml",
    ".yml",
    ".json",
}

CRYPTO_LIBRARIES = {
    "pycryptodome": "PyCryptodome",
    "cryptography": "Python cryptography",
    "openssl": "OpenSSL",
    "libssl": "OpenSSL libssl",
    "libcrypto": "OpenSSL libcrypto",
    "bouncycastle": "Bouncy Castle",
    "bcprov": "Bouncy Castle Provider",
    "libsodium": "libsodium",
    "wolfssl": "wolfSSL",
    "mbedtls": "mbedTLS",
    "boringssl": "BoringSSL",
}

# Actual API patterns are deliberately more specific than simple
# keyword matching.
API_RULES = [
    # Python
    (
        r"\bRSA\.generate\s*\(",
        "RSA",
        "key_establishment",
        "Python PyCryptodome RSA API",
    ),
    (
        r"\bRSA\.import_key\s*\(",
        "RSA",
        "key_establishment",
        "Python PyCryptodome RSA API",
    ),
    (
        r"\b(?:rsa|cryptography).*?generate_private_key\s*\(",
        "RSA",
        "key_establishment",
        "Python cryptography key-generation API",
    ),
    (
        r"\bAES\.new\s*\(",
        "AES",
        "data_encryption",
        "Python PyCryptodome AES API",
    ),
    (
        r"\bhashlib\.sha256\s*\(",
        "SHA-256",
        "hashing",
        "Python hashlib SHA-256 API",
    ),
    (
        r"\bhashlib\.sha384\s*\(",
        "SHA-384",
        "hashing",
        "Python hashlib SHA-384 API",
    ),
    (
        r"\bhashlib\.sha512\s*\(",
        "SHA-512",
        "hashing",
        "Python hashlib SHA-512 API",
    ),
    (
        r"\bhashlib\.sha1\s*\(",
        "SHA-1",
        "hashing",
        "Python hashlib SHA-1 API",
    ),
    (
        r"\bhashlib\.md5\s*\(",
        "MD5",
        "hashing",
        "Python hashlib MD5 API",
    ),
    (
        r"\becdsa\.(?:SigningKey|VerifyingKey)",
        "ECDSA",
        "digital_signature",
        "Python ECDSA API",
    ),

    # Java
    (
        r"\bCipher\.getInstance\s*\(",
        "Cipher",
        "data_encryption",
        "Java JCA Cipher API",
    ),
    (
        r"\bSignature\.getInstance\s*\(",
        "Signature",
        "digital_signature",
        "Java JCA Signature API",
    ),
    (
        r"\bMessageDigest\.getInstance\s*\(",
        "MessageDigest",
        "hashing",
        "Java JCA MessageDigest API",
    ),
    (
        r"\bKeyPairGenerator\.getInstance\s*\(",
        "KeyPairGenerator",
        "key_establishment",
        "Java JCA KeyPairGenerator API",
    ),

    # C/C++ OpenSSL
    (
        r"\bRSA_generate_key(?:_ex)?\s*\(",
        "RSA",
        "key_establishment",
        "OpenSSL RSA API",
    ),
    (
        r"\bEVP_PKEY_keygen\s*\(",
        "EVP_PKEY",
        "key_establishment",
        "OpenSSL EVP key-generation API",
    ),
    (
        r"\bEVP_Digest(?:Sign|Verify)",
        "Digest",
        "digital_signature",
        "OpenSSL EVP digest API",
    ),
    (
        r"\bEVP_Encrypt",
        "Cipher",
        "data_encryption",
        "OpenSSL EVP encryption API",
    ),
    (
        r"\bAES_(?:set_encrypt_key|encrypt|decrypt)\s*\(",
        "AES",
        "data_encryption",
        "OpenSSL AES API",
    ),

    # Go
    (
        r"\brsa\.GenerateKey\s*\(",
        "RSA",
        "key_establishment",
        "Go crypto/rsa API",
    ),
    (
        r"\baes\.NewCipher\s*\(",
        "AES",
        "data_encryption",
        "Go crypto/aes API",
    ),
    (
        r"\bsha256\.New\s*\(",
        "SHA-256",
        "hashing",
        "Go crypto/sha256 API",
    ),
    (
        r"\bsha1\.New\s*\(",
        "SHA-1",
        "hashing",
        "Go crypto/sha1 API",
    ),

    # Node.js
    (
        r"\bcrypto\.createCipheriv\s*\(",
        "Cipher",
        "data_encryption",
        "Node.js crypto API",
    ),
    (
        r"\bcrypto\.createHash\s*\(",
        "Hash",
        "hashing",
        "Node.js crypto API",
    ),
    (
        r"\bcrypto\.createSign\s*\(",
        "Signature",
        "digital_signature",
        "Node.js crypto API",
    ),
    (
        r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(",
        "KeyPair",
        "key_establishment",
        "Node.js crypto API",
    ),
]


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------

def normalize_path(path: str) -> str:
    return "/" + path.replace("\\", "/").lstrip("/")


def should_ignore_path(path: str) -> bool:
    normalized = normalize_path(path)
    lower = normalized.lower()

    if any(part in lower for part in IGNORED_PATH_PARTS):
        return True

    parts = [p.lower() for p in normalized.split("/") if p]

    if any(part in IGNORED_DIRS for part in parts):
        return True

    filename = parts[-1] if parts else ""

    if filename in IGNORED_FILENAMES:
        return True

    suffix = Path(filename).suffix.lower()

    if suffix in IGNORED_EXTENSIONS:
        return True

    if filename.endswith(".dist-info"):
        return True

    return False


def is_probable_source(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in SOURCE_EXTENSIONS


def is_probable_config(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    name = Path(path).name.lower()

    return (
        suffix in CONFIG_EXTENSIONS
        or name in {
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "nginx.conf",
            "sshd_config",
            "openssl.cnf",
        }
    )


def safe_read_text(path: Path, max_bytes: int = 5 * 1024 * 1024) -> str | None:
    try:
        size = path.stat().st_size

        if size > max_bytes:
            return None

        data = path.read_bytes()

        # Binary detection.
        if b"\x00" in data[:4096]:
            return None

        return data.decode("utf-8", errors="ignore")

    except Exception:
        return None


def strip_comments(line: str, language: str) -> str:
    """
    Remove common single-line comments before API/algorithm matching.
    This prevents things such as:

        # RSA example
        // AES documentation

    from becoming findings.
    """

    stripped = line.strip()

    if language in {"Python"}:
        if stripped.startswith("#"):
            return ""

        return re.split(r"\s+#", line, maxsplit=1)[0]

    if language in {
        "Java",
        "Kotlin",
        "C",
        "C/C++",
        "C++",
        "Go",
        "JavaScript",
        "TypeScript",
        "Rust",
    }:
        if stripped.startswith("//"):
            return ""

        line = re.split(r"\s+//", line, maxsplit=1)[0]

        # Basic block-comment-only line.
        if stripped.startswith("/*") or stripped.startswith("*"):
            return ""

    return line


def infer_algorithm_from_api(line: str, default: str) -> str:
    upper = line.upper()

    # Specific algorithms first.
    if "RSA" in upper:
        return "RSA"

    if "AES" in upper:
        return "AES"

    if "SHA512" in upper or "SHA-512" in upper:
        return "SHA-512"

    if "SHA384" in upper or "SHA-384" in upper:
        return "SHA-384"

    if "SHA256" in upper or "SHA-256" in upper:
        return "SHA-256"

    if "SHA1" in upper or "SHA-1" in upper:
        return "SHA-1"

    if "MD5" in upper:
        return "MD5"

    if "ECDSA" in upper:
        return "ECDSA"

    return default


def make_asset_id(image_id: str, path: str, line: int | None, algorithm: str) -> str:
    raw = f"{image_id}|{path}|{line}|{algorithm}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"container_{digest}"


def is_application_path(path: str) -> bool:
    """Return True when a container path looks like application code."""
    normalized = normalize_path(path).lower()

    if normalized.startswith(APPLICATION_ROOTS):
        return True

    # Files outside known application roots can still be application code.
    # Treat common top-level executable/project locations conservatively.
    parts = [p for p in normalized.split("/") if p]
    if len(parts) >= 2 and parts[0] in {"home", "root"}:
        return True

    return False


def is_runtime_or_dependency_path(path: str) -> bool:
    normalized = normalize_path(path).lower()
    return normalized.startswith(RUNTIME_PATH_PREFIXES)


# ---------------------------------------------------------------------
# Source analysis
# ---------------------------------------------------------------------

def scan_source_content(
    image_name: str,
    image_id: str,
    path: str,
    content: str,
    language: str,
    layer: int | None = None,
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    lines = content.splitlines()

    for line_number, original_line in enumerate(lines, start=1):

        line = strip_comments(original_line, language)

        if not line.strip():
            continue

        for pattern, algorithm, purpose, method in API_RULES:

            try:
                matched = re.search(pattern, line, re.IGNORECASE)
            except re.error:
                matched = False

            if not matched:
                continue

            detected_algorithm = infer_algorithm_from_api(
                line,
                algorithm,
            )

            finding = {
                "asset_type": "algorithm",
                "algorithm": detected_algorithm,
                "purpose": purpose,
                "evidence_type": "ACTIVE_USAGE",
                "file": path,
                "line": line_number,
                "snippet": original_line.strip()[:500],
                "detection_method": method,
                "confidence": 0.98,
                "container_image": image_name,
                "image_id": image_id,
                "language": language,
                "scan_mode": "live_docker",
                "scan_scope": "application",
            }

            if layer is not None:
                finding["layer"] = layer

            finding["asset_id"] = make_asset_id(
                image_id,
                path,
                line_number,
                detected_algorithm,
            )

            findings.append(finding)

            # One active-usage finding per line.
            break

    return findings


# ---------------------------------------------------------------------
# Library inventory
# ---------------------------------------------------------------------

def detect_library_presence(
    image_name: str,
    image_id: str,
    path: str,
    content: str,
    layer: int | None = None,
) -> list[dict[str, Any]]:

    findings = []

    lower_content = content.lower()

    for key, library_name in CRYPTO_LIBRARIES.items():

        # Require actual package/import/config references rather than
        # arbitrary prose.
        patterns = [
            rf"(^|\s|['\"=:/]){re.escape(key)}([<>=:/'\"\s]|$)",
            rf"package:\s*{re.escape(key)}",
            rf"name:\s*{re.escape(key)}",
            rf"import\s+{re.escape(key)}",
            rf"from\s+{re.escape(key)}",
        ]

        matched = any(
            re.search(pattern, lower_content, re.IGNORECASE)
            for pattern in patterns
        )

        if not matched:
            continue

        asset_id = make_asset_id(
            image_id,
            path,
            None,
            library_name,
        )

        finding = {
            "asset_type": "library_provider",
            "algorithm": library_name,
            "purpose": "crypto_provider",
            "evidence_type": "LIBRARY_PRESENCE",
            "file": path,
            "line": None,
            "snippet": path,
            "detection_method": "Container package/import inventory",
            "confidence": 0.90,
            "container_image": image_name,
            "image_id": image_id,
            "scan_mode": "live_docker",
            "asset_id": asset_id,
        }

        if layer is not None:
            finding["layer"] = layer

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------
# Filesystem scanner
# ---------------------------------------------------------------------

def scan_extracted_filesystem(
    root: str,
    image_name: str,
    image_id: str,
) -> list[dict[str, Any]]:
    """
    Scan an extracted container filesystem.

    Precision policy:
      * application roots -> ACTIVE_USAGE + configuration
      * runtime/dependency roots -> no source ACTIVE_USAGE
      * dependency manifests -> LIBRARY_PRESENCE where explicitly referenced
      * documentation/metadata -> ignored
    """
    findings: list[dict[str, Any]] = []

    root_path = Path(root)

    for current_root, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d.lower() not in IGNORED_DIRS
        ]

        current_path = Path(current_root)

        for filename in files:
            file_path = current_path / filename

            try:
                relative = file_path.relative_to(root_path).as_posix()
            except ValueError:
                continue

            container_path = "/" + relative

            if should_ignore_path(container_path):
                continue

            source = is_probable_source(container_path)
            config = is_probable_config(container_path)

            if not source and not config:
                continue

            # The major precision rule: source files in OS/runtime/dependency
            # trees are not considered application ACTIVE_USAGE.
            application_scope = is_application_path(container_path)
            runtime_scope = is_runtime_or_dependency_path(container_path)

            if source and runtime_scope and not application_scope:
                continue

            language = SOURCE_EXTENSIONS.get(
                file_path.suffix.lower(),
                "Configuration",
            )

            content = safe_read_text(file_path)

            if content is None:
                continue

            if source and application_scope:
                findings.extend(
                    scan_source_content(
                        image_name=image_name,
                        image_id=image_id,
                        path=container_path,
                        content=content,
                        language=language,
                    )
                )

            # Library presence is only meaningful when a source/config file
            # explicitly references a crypto provider/package. Do not infer
            # library presence from arbitrary prose in runtime source.
            if source and application_scope:
                findings.extend(
                    detect_library_presence(
                        image_name=image_name,
                        image_id=image_id,
                        path=container_path,
                        content=content,
                    )
                )

            if config and application_scope:
                config_patterns = [
                    (
                        r"\bRSA(?:-\d+)?\b",
                        "RSA",
                        "key_establishment",
                    ),
                    (
                        r"\bECDSA\b",
                        "ECDSA",
                        "digital_signature",
                    ),
                    (
                        r"\bAES(?:-\d+)?\b",
                        "AES",
                        "data_encryption",
                    ),
                    (
                        r"\bTLS(?:v1\.[0-3])?\b",
                        "TLS",
                        "protocol",
                    ),
                ]

                for line_number, original_line in enumerate(
                    content.splitlines(),
                    start=1,
                ):
                    line = strip_comments(
                        original_line,
                        "Configuration",
                    )

                    if not line.strip():
                        continue

                    for pattern, algorithm, purpose in config_patterns:
                        if not re.search(
                            pattern,
                            line,
                            re.IGNORECASE,
                        ):
                            continue

                        finding = {
                            "asset_type": "configuration",
                            "algorithm": algorithm,
                            "purpose": purpose,
                            "evidence_type": "CONFIGURATION",
                            "file": container_path,
                            "line": line_number,
                            "snippet": original_line.strip()[:500],
                            "detection_method": "Container application configuration analysis",
                            "confidence": 0.85,
                            "container_image": image_name,
                            "image_id": image_id,
                            "language": "Configuration",
                            "scan_mode": "live_docker",
                            "asset_id": make_asset_id(
                                image_id,
                                container_path,
                                line_number,
                                algorithm,
                            ),
                        }

                        findings.append(finding)
                        break

    return findings


# ---------------------------------------------------------------------
# Docker metadata
# ---------------------------------------------------------------------

def docker_available() -> bool:
    return shutil.which("docker") is not None


def docker_inspect(image: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "inspect", image],
        capture_output=True,
        text=True,
        check=True,
    )

    data = json.loads(result.stdout)

    if not data:
        raise RuntimeError(f"Docker image not found: {image}")

    item = data[0]

    return {
        "image_id": item.get("Id", ""),
        "architecture": item.get("Architecture", ""),
        "os": item.get("Os", ""),
        "created": item.get("Created", ""),
        "size": item.get("Size", 0),
        "repo_tags": item.get("RepoTags", []),
        "repo_digests": item.get("RepoDigests", []),
    }


# ---------------------------------------------------------------------
# Main live scanner
# ---------------------------------------------------------------------

def _safe_extract_tar_bytes(tar_bytes: bytes, destination: str, max_members: int = 20000) -> int:
    """
    Safely extract a Docker layer tar into destination and return member count.
    Docker layer tars may contain whiteout files; they are ignored for static
    crypto discovery because the scanner analyzes the layer's contents.
    """
    import io
    import tarfile

    destination_path = Path(destination).resolve()
    count = 0

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        for member in tf:
            count += 1
            if count > max_members:
                break

            # Prevent path traversal from crafted archive members.
            member_path = (destination_path / member.name).resolve()
            if member_path != destination_path and destination_path not in member_path.parents:
                continue

            # Skip links that could escape the extraction root.
            if member.issym() or member.islnk():
                continue

            # Docker whiteouts represent deletions in later layers. They are
            # not themselves crypto evidence.
            if Path(member.name).name.startswith(".wh."):
                continue

            try:
                tf.extract(member, destination_path, set_attrs=False)
            except Exception:
                continue

    return count


def _scan_docker_layers(
    docker_save_dir: str,
    image_name: str,
    image_id: str,
    max_files: int,
) -> tuple[list[dict[str, Any]], int]:
    """
    Scan the actual layer.tar files produced by `docker save`.

    This is the critical distinction from scanning only the outer docker-save
    archive: the cryptographic source/config files live inside layer.tar.
    """
    import tarfile

    root = Path(docker_save_dir)
    findings: list[dict[str, Any]] = []
    layers_scanned = 0

    # Docker save produces directories containing layer.tar. Scan in manifest
    # order when possible, otherwise fall back to deterministic ordering.
    layer_paths: list[Path] = []

    manifest_path = root / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest and isinstance(manifest[0], dict):
                for layer_name in manifest[0].get("Layers", []):
                    candidate = root / layer_name
                    if candidate.exists():
                        layer_paths.append(candidate)
        except Exception:
            pass

    if not layer_paths:
        layer_paths = sorted(root.glob("**/layer.tar"))

    seen_layer_files: set[str] = set()

    for layer_tar in layer_paths:
        if not layer_tar.is_file():
            continue
        layer_key = str(layer_tar.resolve())
        if layer_key in seen_layer_files:
            continue
        seen_layer_files.add(layer_key)

        layers_scanned += 1
        layer_number = layers_scanned

        # Extract one layer to a temporary directory and scan its actual
        # filesystem entries. This keeps source parsing independent of tar
        # internals and lets the existing precision filters do their job.
        with tempfile.TemporaryDirectory(prefix=f"pqc_layer_{layer_number}_") as layer_dir:
            try:
                with tarfile.open(layer_tar, mode="r:*") as tf:
                    safe_members = []
                    for member in tf:
                        # Path traversal protection.
                        target = (Path(layer_dir) / member.name).resolve()
                        base = Path(layer_dir).resolve()
                        if target != base and base not in target.parents:
                            continue
                        if member.issym() or member.islnk():
                            continue
                        if Path(member.name).name.startswith(".wh."):
                            continue
                        safe_members.append(member)

                        if len(safe_members) >= max_files * 4:
                            break

                    # Extract only regular files/directories that can be
                    # meaningfully inspected.
                    for member in safe_members:
                        try:
                            tf.extract(member, layer_dir, set_attrs=False)
                        except Exception:
                            continue
            except Exception:
                continue

            layer_findings = scan_extracted_filesystem(
                root=layer_dir,
                image_name=image_name,
                image_id=image_id,
            )

            for finding in layer_findings:
                finding["layer"] = layer_number
                # Paths returned by scan_extracted_filesystem are rooted at
                # the temporary extraction directory. Keep only the layer
                # filesystem path, not the temporary host path.
                file_value = finding.get("file")
                if isinstance(file_value, str):
                    finding["file"] = "/" + file_value.lstrip("/")

                # Rebuild the asset ID after adding layer context.
                finding["asset_id"] = make_asset_id(
                    image_id,
                    finding.get("file", ""),
                    finding.get("line"),
                    finding.get("algorithm", ""),
                )

                findings.append(finding)

            if len(findings) >= max_files:
                break

    return findings[:max_files], layers_scanned


def scan_docker_image(
    image: str,
    max_files: int = 10000,
) -> dict[str, Any]:
    if not docker_available():
        raise RuntimeError(
            "Docker CLI was not found. Install/start Docker Desktop "
            "and verify with: docker version"
        )

    metadata = docker_inspect(image)
    image_id = metadata["image_id"]

    temp_dir = tempfile.mkdtemp(prefix="pqc_container_scan_")

    try:
        tar_path = os.path.join(temp_dir, "image.tar")

        # Export the Docker image in Docker's native save format.
        with open(tar_path, "wb") as output:
            process = subprocess.run(
                ["docker", "save", image],
                stdout=output,
                stderr=subprocess.PIPE,
                text=False,
            )

        if process.returncode != 0:
            raise RuntimeError(
                "docker save failed: "
                + process.stderr.decode(errors="ignore")
            )

        extract_dir = os.path.join(temp_dir, "image")
        os.makedirs(extract_dir, exist_ok=True)

        # Extract only the OUTER docker-save archive. The actual scan happens
        # below against each nested layer.tar.
        subprocess.run(
            ["tar", "-xf", tar_path, "-C", extract_dir],
            check=True,
            capture_output=True,
        )

        findings, layers_scanned = _scan_docker_layers(
            docker_save_dir=extract_dir,
            image_name=image,
            image_id=image_id,
            max_files=max_files,
        )

        # Deduplicate findings. The same crypto API can occur in multiple
        # layers; retain distinct evidence by file/line/type/algorithm.
        unique: dict[tuple[Any, ...], dict[str, Any]] = {}

        for finding in findings:
            key = (
                finding.get("asset_type"),
                finding.get("algorithm"),
                finding.get("file"),
                finding.get("line"),
                finding.get("evidence_type"),
            )
            unique[key] = finding

            if len(unique) >= max_files:
                break

        findings = list(unique.values())

        active = [
            f for f in findings
            if f.get("evidence_type") == "ACTIVE_USAGE"
        ]

        libraries = [
            f for f in findings
            if f.get("evidence_type") == "LIBRARY_PRESENCE"
        ]

        configurations = [
            f for f in findings
            if f.get("evidence_type") == "CONFIGURATION"
        ]

        algorithms = sorted(
            {
                f.get("algorithm")
                for f in findings
                if f.get("algorithm")
            }
        )

        return {
            "status": "success",
            "image": image,
            "image_id": image_id,
            "architecture": metadata["architecture"],
            "os": metadata["os"],
            "created": metadata["created"],
            "size": metadata["size"],
            "repo_tags": metadata["repo_tags"],
            "repo_digests": metadata["repo_digests"],
            "scan_mode": "live_docker",
            "layers_scanned": layers_scanned,
            "findings": findings,

            # Top-level summary fields for dashboard/API consumers.
            # Keep the nested "statistics" object below for compatibility.
            "total_findings": len(findings),
            "active_crypto_usage": len(active),
            "library_presence": len(libraries),
            "configuration_findings": len(configurations),
            "unique_algorithms": len(algorithms),
            "algorithms": algorithms,

            "statistics": {
                "total_findings": len(findings),
                "active_crypto_usage": len(active),
                "library_presence": len(libraries),
                "configuration_findings": len(configurations),
                "unique_algorithms": len(algorithms),
                "algorithms": algorithms,
                "layers_scanned": layers_scanned,
            },
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------

def scan_container_image(image: str) -> list[dict[str, Any]]:
    """
    Compatibility wrapper for dashboard integration.
    """
    result = scan_docker_image(image)
    return result["findings"]


def scan_live_docker_image(image: str) -> dict[str, Any]:
    return scan_docker_image(image)


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(
        description="PS-164 Docker Container Crypto Scanner"
    )

    parser.add_argument(
        "image",
        help="Docker image name/tag, e.g. pqc-test-image:latest",
    )

    args = parser.parse_args()

    result = scan_docker_image(args.image)

    print(
        json.dumps(
            result,
            indent=2,
        )
    )