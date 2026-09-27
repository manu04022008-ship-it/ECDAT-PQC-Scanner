"""
scanner.py
Master Scan Orchestrator Unifying Discovery Engines (PS-164)
"""

from scanners.source_scanner import scan_source_file
from scanners.dependency_scanner import scan_dependency_file
from scanners.protocol_scanner import scan_protocol_file
from scanners.binary_scanner import scan_binary_file
from scanners.config_scanner import scan_config_file

# Safe resilient import for certificate scanner
try:
    from scanners.certificate_scanner import parse_certificate_file
except ImportError:
    try:
        from scanners.certificate_scanner import scan_certificate_file as parse_certificate_file
    except ImportError:
        try:
            from scanners.certificate_scanner import scan_certificate as parse_certificate_file
        except ImportError:
            def parse_certificate_file(filename, content_str):
                return []


def scan_file(content_input, filename: str) -> list:
    """
    Orchestrates file inspection across dedicated scanners based on file type 
    and returns a unified list of normalized cryptographic findings.
    """
    findings = []
    f_lower = filename.lower()
    
    # 1. Handle X.509 Certificate files (.pem, .crt, .cer, .der)
    if any(f_lower.endswith(ext) for ext in ['.pem', '.crt', '.cer', '.der']):
        certificate_input = (
            content_input
            if isinstance(content_input, bytes)
            else str(content_input)
        )
        findings.extend(parse_certificate_file(filename, certificate_input))
        return findings

    # 2. Handle Binary files (.jar, .class, .so, .dll, .exe)
    binary_extensions = ['.jar', '.class', '.so', '.dll', '.exe', '.bin']
    if any(f_lower.endswith(ext) for ext in binary_extensions):
        content_bytes = (
            content_input if isinstance(content_input, bytes)
            else str(content_input).encode('utf-8', errors='ignore')
        )
        findings.extend(scan_binary_file(filename, content_bytes))
        return findings

    # Ensure content is string for text/manifest/source/config analysis
    content_str = (
        content_input.decode('utf-8', errors='ignore') 
        if isinstance(content_input, bytes) 
        else str(content_input)
    )

    # 3. Handle Dependency & Library Manifest Files
    dep_files = ['requirements.txt', 'pipfile', 'package.json', 'pom.xml', 'build.gradle', 'go.mod', 'cargo.toml']
    if any(f_lower.endswith(d) or d in f_lower for d in dep_files):
        findings.extend(scan_dependency_file(filename, content_str))
        return findings

    # 4. Handle Protocol & Server Configuration Files (e.g., nginx.conf, sshd_config)
    config_exts = ['.conf', '.config', '.ini', '.properties']
    if any(f_lower.endswith(ext) for ext in config_exts) or 'nginx' in f_lower or 'sshd' in f_lower:
        findings.extend(scan_config_file(filename, content_str))
        findings.extend(scan_protocol_file(filename, content_str))
        return findings

    # 5. Default to Source Code Scanner (Java, Python, C/C++, Go, JS, Rust, etc.)
    findings.extend(scan_source_file(filename, content_str))
    
    return findings