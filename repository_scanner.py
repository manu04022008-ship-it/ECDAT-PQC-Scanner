"""
repository_scanner.py

PS-164 Feature 1:
Recursive source-code repository scanner.

Responsibilities:
1. Walk through a project/repository directory.
2. Identify supported source-code files.
3. Ignore build artifacts, virtual environments and generated files.
4. Send each source file to the existing source scanner.
5. Return normalized findings with repository-relative paths.
"""

from pathlib import Path
from scanners.source_scanner import scan_source_file


# ---------------------------------------------------------
# Supported source-code extensions
# ---------------------------------------------------------

SOURCE_EXTENSIONS = {
    ".py": "Python",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".go": "Go",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".rs": "Rust",
}


# ---------------------------------------------------------
# Directories that should NOT be scanned
# ---------------------------------------------------------

IGNORED_DIRECTORIES = {
    ".git",
    ".github",
    ".idea",
    ".vscode",

    "__pycache__",
    ".pytest_cache",

    "venv",
    ".venv",
    "env",
    ".env",

    "node_modules",

    "build",
    "dist",
    "target",
    "out",

    ".gradle",
    ".mvn",

    "coverage",
    ".coverage",

    "__MACOSX",
}


# ---------------------------------------------------------
# Files that should NOT be scanned
# ---------------------------------------------------------

IGNORED_FILES = {
    ".DS_Store",
}


# ---------------------------------------------------------
# Maximum source file size
# ---------------------------------------------------------

MAX_SOURCE_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ---------------------------------------------------------
# Check whether a file is source code
# ---------------------------------------------------------

def is_source_file(path: Path) -> bool:
    """
    Return True if the file has a supported source-code extension.
    """

    return path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS


# ---------------------------------------------------------
# Check whether a path should be ignored
# ---------------------------------------------------------

def should_ignore(path: Path) -> bool:
    """
    Prevent scanning generated files, virtual environments,
    Git metadata, dependency directories, etc.
    """

    # Ignore directory components
    for part in path.parts:
        if part in IGNORED_DIRECTORIES:
            return True

    # Ignore known files
    if path.name in IGNORED_FILES:
        return True

    return False


# ---------------------------------------------------------
# Read source safely
# ---------------------------------------------------------

def read_source_file(path: Path) -> str:
    """
    Read source code using UTF-8 with safe fallback handling.
    """

    return path.read_text(
        encoding="utf-8",
        errors="ignore"
    )


# ---------------------------------------------------------
# Scan repository
# ---------------------------------------------------------

def scan_repository(repository_path: str) -> list:
    """
    Recursively scan a source-code repository.

    Parameters
    ----------
    repository_path:
        Local path to the extracted repository/project.

    Returns
    -------
    list
        Normalized cryptographic findings.
    """

    root = Path(repository_path).resolve()

    if not root.exists():
        raise FileNotFoundError(
            f"Repository path does not exist: {root}"
        )

    if not root.is_dir():
        raise ValueError(
            f"Repository path is not a directory: {root}"
        )

    findings = []

    for path in root.rglob("*"):

        # Ignore unwanted files/directories
        if should_ignore(path):
            continue

        # Only source files
        if not is_source_file(path):
            continue

        # Ignore oversized files
        try:
            file_size = path.stat().st_size
        except OSError:
            continue

        if file_size > MAX_SOURCE_FILE_SIZE:
            continue

        # Read source
        try:
            content = read_source_file(path)
        except (OSError, UnicodeError):
            continue

        # Repository-relative path
        relative_path = path.relative_to(root)

        # Existing source scanner
        file_findings = scan_source_file(
            str(relative_path),
            content
        )

        # Normalize findings
        for finding in file_findings:

            finding["repository_file"] = str(relative_path)

            finding["language"] = SOURCE_EXTENSIONS.get(
                path.suffix.lower(),
                "Unknown"
            )

            finding["source_type"] = "repository"

            finding["file_size_bytes"] = file_size

            # Keep existing file field compatible
            finding["file"] = str(relative_path)

        findings.extend(file_findings)

    return findings


# ---------------------------------------------------------
# Repository statistics
# ---------------------------------------------------------

def get_repository_statistics(repository_path: str) -> dict:
    """
    Return basic repository discovery statistics.

    This is separate from crypto detection so the GUI
    can explain exactly what was scanned.
    """

    root = Path(repository_path).resolve()

    statistics = {
        "total_files": 0,
        "source_files": 0,
        "languages": {},
        "ignored_files": 0,
        "total_source_bytes": 0,
    }

    if not root.exists() or not root.is_dir():
        return statistics

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        statistics["total_files"] += 1

        if should_ignore(path):
            statistics["ignored_files"] += 1
            continue

        if not is_source_file(path):
            continue

        statistics["source_files"] += 1

        language = SOURCE_EXTENSIONS.get(
            path.suffix.lower(),
            "Unknown"
        )

        statistics["languages"][language] = (
            statistics["languages"].get(language, 0) + 1
        )

        try:
            statistics["total_source_bytes"] += path.stat().st_size
        except OSError:
            pass

    return statistics