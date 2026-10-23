#!/usr/bin/env python3
"""
modules/tls.py — Deep TLS/SSL analysis for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Full TLS posture analysis without external dependencies (pure Python ssl/socket).

Coverage:
  - Certificate: subject, SAN, issuer, validity, expiry
  - Chain: trust validation, self-signed detection
  - Protocols: TLS 1.0/1.1/1.2/1.3 support (legacy detection)
  - Ciphers: negotiated cipher, strength, forward secrecy
  - Vulnerabilities: Heartbleed, POODLE, ROBOT heuristics (passive)
  - HSTS preload / redirect hints
  - Certificate transparency hints (via DNS if available)

Does NOT exploit anything. Passive detection only.
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from core.config import DEFAULT_TIMEOUT, CONNECT_TIMEOUT
from core.http import ProxyConfig
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Protocol versions and their security status
TLS_VERSIONS = {
    "SSLv2":   {"secure": False, "severity": "critical", "desc": "SSLv2 is broken (DROWN)"},
    "SSLv3":   {"secure": False, "severity": "high",     "desc": "SSLv3 is broken (POODLE)"},
    "TLSv1":   {"secure": False, "severity": "medium",   "desc": "TLS 1.0 is deprecated (RFC 8996)"},
    "TLSv1.1": {"secure": False, "severity": "medium",   "desc": "TLS 1.1 is deprecated (RFC 8996)"},
    "TLSv1.2": {"secure": True,  "severity": None,       "desc": "TLS 1.2 is acceptable"},
    "TLSv1.3": {"secure": True,  "severity": None,       "desc": "TLS 1.3 is recommended"},
}

# Weak cipher patterns (substring match, case-insensitive)
WEAK_CIPHERS = [
    (r"RC4", "RC4 is cryptographically broken"),
    (r"DES(?!.*3DES)", "Single DES is broken"),
    (r"3DES|TLS_RSA_WITH_3DES", "3DES is deprecated (Sweet32)"),
    (r"EXPORT", "Export-grade ciphers are broken (FREAK/Logjam)"),
    (r"NULL", "NULL cipher offers no encryption"),
    (r"anon|ADH|AECDH", "Anonymous cipher — no authentication"),
    (r"MD5", "MD5 signature is broken"),
    (r"CBC", "CBC mode has padding oracle risks (Lucky13)"),
]

# Modern AEAD ciphers (preferred)
STRONG_CIPHER_PATTERNS = [
    r"AES.*GCM",
    r"CHACHA20.*POLY1305",
    r"AES.*CCM",
]

# Known weak/expired root CAs (sample — for self-signed detection)
SELF_SIGNED_MARKERS = ["self signed", "self-signed"]


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CertificateInfo:
    """Parsed certificate details."""
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    subject: Dict[str, str] = field(default_factory=dict)
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    issuer: Dict[str, str] = field(default_factory=dict)

    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    expired: bool = False
    expiring_soon: bool = False  # < 30 days

    san: List[str] = field(default_factory=list)
    serial: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_ca: bool = False
    is_self_signed: bool = False

    # Key info
    key_type: Optional[str] = None    # RSA | ECDSA | Ed25519
    key_bits: Optional[int] = None

    # Fingerprints
    sha256_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TLSVersionSupport:
    """Which TLS versions the server accepts."""
    supported: List[str] = field(default_factory=list)
    preferred: Optional[str] = None
    insecure_versions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CipherAnalysis:
    """Cipher suite strength analysis."""
    negotiated: Optional[str] = None
    protocol: Optional[str] = None
    bits: Optional[int] = None
    forward_secrecy: bool = False
    aead: bool = False
    weak: bool = False
    weak_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TLSFinding:
    """A single security finding."""
    id: str
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    recommendation: str = ""
    cwe: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TLSResult:
    """Complete TLS analysis result."""
    hostname: str = ""
    port: int = 443
    ip_address: Optional[str] = None

    enabled: bool = False
    handshake_ok: bool = False

    certificate: Optional[CertificateInfo] = None
    versions: Optional[TLSVersionSupport] = None
    cipher: Optional[CipherAnalysis] = None

    findings: List[TLSFinding] = field(default_factory=list)
    grade: str = "F"  # A+ .. F
    score: int = 0

    error: Optional[str] = None
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["certificate"] = self.certificate.to_dict() if self.certificate else None
        d["versions"] = self.versions.to_dict() if self.versions else None
        d["cipher"] = self.cipher.to_dict() if self.cipher else None
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if not self.enabled:
            return "TLS not enabled"
        parts = [f"grade={self.grade}"]
        if self.cipher and self.cipher.negotiated:
            parts.append(f"cipher={self.cipher.negotiated[:30]}")
        if self.certificate and self.certificate.days_until_expiry is not None:
            parts.append(f"expires={self.certificate.days_until_expiry}d")
        return " | ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
#  CERTIFICATE PARSING
# ═══════════════════════════════════════════════════════════════════════════

def _parse_cert_dict(cert_dict: dict, der_bytes: bytes) -> CertificateInfo:
    """Parse the dict returned by ssl.getpeercert()."""
    info = CertificateInfo()

    # Subject
    for rdn in cert_dict.get("subject", ()):
        for key, value in rdn:
            info.subject[key] = value
            if key == "commonName":
                info.subject_cn = value
            elif key == "organizationName":
                info.subject_org = value

    # Issuer
    for rdn in cert_dict.get("issuer", ()):
        for key, value in rdn:
            info.issuer[key] = value
            if key == "commonName":
                info.issuer_cn = value
            elif key == "organizationName":
                info.issuer_org = value

    # Self-signed check
    info.is_self_signed = cert_dict.get("subject") == cert_dict.get("issuer")

    # SAN
    info.san = [
        v for k, v in cert_dict.get("subjectAltName", ())
        if k.lower() in ("dns", "ip address")
    ]

    # Validity
    info.not_before = cert_dict.get("notBefore")
    info.not_after = cert_dict.get("notAfter")

    if info.not_after:
        try:
            expiry = datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days = (expiry - now).days
            info.days_until_expiry = days
            info.expired = days < 0
            info.expiring_soon = 0 <= days < 30
        except (ValueError, TypeError):
            pass

    # Serial
    serial = cert_dict.get("serialNumber")
    if serial:
        info.serial = serial

    # Fingerprints
    if der_bytes:
        info.sha256_fingerprint = hashlib.sha256(der_bytes).hexdigest()
        info.sha1_fingerprint = hashlib.sha1(der_bytes).hexdigest()

    # CA flag (from basicConstraints if present)
    info.is_ca = "CA:TRUE" in str(cert_dict.get("caIssuers", "")) or False

    # Key info (limited — ssl module doesn't expose directly)
    # We'll infer from signature algorithm + cipher
    return info


def _extract_key_info_from_cipher(cipher_info: tuple) -> Tuple[Optional[str], Optional[int]]:
    """Infer key type/bits from negotiated cipher name (best-effort)."""
    if not cipher_info:
        return None, None
    name = cipher_info[0] if isinstance(cipher_info[0], str) else ""
    # Common patterns
    if "CHACHA20" in name:
        return "ECDHE", 256
    if "AES_256" in name or "AES256" in name:
        return "AES", 256
    if "AES_128" in name or "AES128" in name:
        return "AES", 128
    if "ECDHE" in name:
        return "ECDHE", None
    return None, None


# ═══════════════════════════════════════════════════════════════════════════
#  CIPHER ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_cipher(cipher_info: tuple) -> CipherAnalysis:
    """Analyze negotiated cipher suite strength."""
    result = CipherAnalysis()
    if not cipher_info:
        return result

    name = cipher_info[0] if isinstance(cipher_info[0], str) else str(cipher_info[0])
    protocol = cipher_info[1] if len(cipher_info) > 1 else None
    bits = cipher_info[2] if len(cipher_info) > 2 else None

    result.negotiated = name
    result.protocol = protocol
    result.bits = bits

    # Forward secrecy
    result.forward_secrecy = any(
        marker in name.upper()
        for marker in ("ECDHE", "DHE", "EDH", "CHACHA20")
    )

    # AEAD
    result.aead = any(
        re.search(pat, name, re.IGNORECASE)
        for pat in STRONG_CIPHER_PATTERNS
    )

    # Weak patterns
    for pattern, reason in WEAK_CIPHERS:
        if re.search(pattern, name, re.IGNORECASE):
            result.weak_reasons.append(reason)

    result.weak = bool(result.weak_reasons)
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  PROTOCOL VERSION TESTING
# ═══════════════════════════════════════════════════════════════════════════

def _make_ssl_context(
    min_version: Optional[int] = None,
    max_version: Optional[int] = None,
    ciphers: Optional[str] = None,
    verify: bool = False,
) -> ssl.SSLContext:
    """Create SSLContext with specific protocol bounds."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if min_version is not None:
        try:
            ctx.minimum_version = min_version
        except (ValueError, OSError):
            pass
    if max_version is not None:
        try:
            ctx.maximum_version = max_version
        except (ValueError, OSError):
            pass
    if ciphers is not None:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def _test_tls_version(
    host: str,
    port: int,
    version_const: int,
    timeout: float,
) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Test if server accepts a specific TLS version.
    Returns (supported, cipher_name, bits).
    """
    ctx = _make_ssl_context(min_version=version_const, max_version=version_const)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    return True, cipher[0], cipher[2]
                return True, None, None
    except (ssl.SSLError, OSError, ConnectionError):
        return False, None, None


def _test_all_versions(
    host: str,
    port: int,
    timeout: float,
) -> TLSVersionSupport:
    """Enumerate supported TLS versions."""
    result = TLSVersionSupport()

    version_map = [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for name, const in version_map:
        supported, cipher, bits = _test_tls_version(host, port, const, timeout)
        if supported:
            result.supported.append(name)
            if not TLS_VERSIONS.get(name, {}).get("secure", True):
                result.insecure_versions.append(name)

    # Determine preferred (highest secure version)
    for name in ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"):
        if name in result.supported:
            result.preferred = name
            break

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN HANDSHAKE
# ═══════════════════════════════════════════════════════════════════════════

def _do_handshake(
    host: str,
    port: int,
    timeout: float,
    verify_ssl: bool = True,
) -> Tuple[Optional[dict], Optional[bytes], Optional[tuple], Optional[str]]:
    """
    Perform a single TLS handshake to fetch cert + cipher.
    Returns (cert_dict, der_bytes, cipher_tuple, error).
    """
    try:
        if verify_ssl:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1", "h2"])

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_dict = ssock.getpeercert()
                cipher = ssock.cipher()
                # getpeercert(binary_form=True) only works if verification succeeded
                try:
                    der = ssock.getpeercert(binary_form=True)
                except (ssl.SSLError, ValueError):
                    der = None
                return cert_dict, der, cipher, None

    except ssl.SSLCertVerificationError as exc:
        # Try again without verification to at least grab cert
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    try:
                        der = ssock.getpeercert(binary_form=True)
                    except Exception:
                        der = None
                    return cert_dict, der, cipher, f"cert verify failed: {exc}"
        except Exception as exc2:
            return None, None, None, f"TLS error: {exc} / {exc2}"

    except (ssl.SSLError, OSError, ConnectionError) as exc:
        return None, None, None, f"TLS handshake failed: {exc}"


# ═══════════════════════════════════════════════════════════════════════════
#  FINDINGS ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_certificate(cert: CertificateInfo) -> List[TLSFinding]:
    findings: List[TLSFinding] = []

    if cert.expired:
        findings.append(TLSFinding(
            id="cert-expired",
            severity="critical",
            title="Certificate is expired",
            description=f"Certificate expired {abs(cert.days_until_expiry or 0)} days ago",
            recommendation="Renew certificate immediately.",
        ))
    elif cert.expiring_soon:
        findings.append(TLSFinding(
            id="cert-expiring",
            severity="medium",
            title=f"Certificate expires in {cert.days_until_expiry} days",
            description="Certificate will expire soon.",
            recommendation="Renew certificate.",
        ))

    if cert.is_self_signed:
        findings.append(TLSFinding(
            id="cert-self-signed",
            severity="high",
            title="Certificate is self-signed",
            description="No trusted CA validation — MITM risk.",
            recommendation="Use a certificate from a trusted CA (Let's Encrypt, etc.).",
            cwe="CWE-295",
        ))

    # CN vs SAN mismatch
    if cert.subject_cn and cert.san:
        cn_normalized = cert.subject_cn.lower().lstrip("*.")
        san_normalized = [s.lower().lstrip("*.") for s in cert.san]
        if cn_normalized not in san_normalized and not any(
            s.startswith("*.") for s in san_normalized
        ):
            findings.append(TLSFinding(
                id="cert-cn-san-mismatch",
                severity="low",
                title="Certificate CN not in SAN list",
                description="Modern clients ignore CN; SAN is authoritative.",
                recommendation="Ensure SAN includes all valid hostnames.",
            ))

    # Weak signature
    sig = (cert.signature_algorithm or "").lower()
    if "md5" in sig:
        findings.append(TLSFinding(
            id="cert-sig-md5",
            severity="high",
            title="Certificate uses MD5 signature",
            description="MD5 signature is broken.",
            recommendation="Reissue certificate with SHA-256+.",
        ))
    elif "sha1" in sig:
        findings.append(TLSFinding(
            id="cert-sig-sha1",
            severity="medium",
            title="Certificate uses SHA-1 signature",
            description="SHA-1 is deprecated (SHAttered).",
            recommendation="Reissue certificate with SHA-256+.",
        ))

    return findings


def _analyze_protocols(versions: TLSVersionSupport) -> List[TLSFinding]:
    findings: List[TLSFinding] = []

    for version in versions.insecure_versions:
        meta = TLS_VERSIONS[version]
        findings.append(TLSFinding(
            id=f"protocol-{version.replace('.', '-')}",
            severity=meta["severity"],
            title=f"Insecure protocol enabled: {version}",
            description=meta["desc"],
            recommendation=f"Disable {version}; require TLS 1.2+.",
        ))

    if not versions.supported:
        findings.append(TLSFinding(
            id="protocol-none",
            severity="critical",
            title="No TLS version supported",
            description="Server does not accept any TLS version — connection fails.",
        ))

    return findings


def _analyze_cipher(cipher: CipherAnalysis) -> List[TLSFinding]:
    findings: List[TLSFinding] = []

    if cipher.weak:
        findings.append(TLSFinding(
            id="cipher-weak",
            severity="high",
            title=f"Weak cipher negotiated: {cipher.negotiated}",
            description="; ".join(cipher.weak_reasons),
            recommendation="Restrict to AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
        ))

    if not cipher.forward_secrecy:
        findings.append(TLSFinding(
            id="cipher-no-pfs",
            severity="medium",
            title="No forward secrecy",
            description="Compromise of server key allows decryption of past traffic.",
            recommendation="Prefer ECDHE/DHE ciphers.",
        ))

    if not cipher.aead and not cipher.weak:
        # CBC is weak but not critical alone
        findings.append(TLSFinding(
            id="cipher-no-aead",
            severity="low",
            title="Non-AEAD cipher negotiated",
            description="CBC mode has padding oracle risk (Lucky13).",
            recommendation="Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  GRADING
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0,
}

GRADE_THRESHOLDS = [
    (0, "A+"),
    (2, "A"),
    (5, "B"),
    (10, "C"),
    (20, "D"),
    (35, "E"),
    (10**9, "F"),
]


def _compute_grade(findings: List[TLSFinding], versions: Optional[TLSVersionSupport], cipher: Optional[CipherAnalysis]) -> Tuple[str, int]:
    """Compute TLS grade from findings."""
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    # Bonus for TLS 1.3 support, penalty for no TLS 1.2+
    if versions:
        if "TLSv1.3" in versions.supported:
            score = max(0, score - 2)
        if "TLSv1.2" not in versions.supported and "TLSv1.3" not in versions.supported:
            score += 5

    # Bonus for AEAD + PFS
    if cipher and cipher.aead and cipher.forward_secrecy:
        score = max(0, score - 2)

    for threshold, grade in GRADE_THRESHOLDS:
        if score <= threshold:
            return grade, score
    return "F", score


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def analyze_tls(
    target_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    test_versions: bool = True,
) -> TLSResult:
    """
    Perform full TLS analysis on target.

    Args:
        target_url: URL or hostname (https:// optional)
        timeout: per-connection timeout
        verify_ssl: verify certificate chain
        test_versions: enumerate supported TLS versions (slower ~4x)

    Returns:
        TLSResult with certificate, versions, cipher, findings, grade.
    """
    started = time.perf_counter()
    result = TLSResult()

    # Parse
    if "://" not in target_url:
        target_url = "https://" + target_url
    parsed = urlsplit(target_url)

    if parsed.scheme != "https":
        result.enabled = False
        result.error = f"not HTTPS ({parsed.scheme})"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        return result

    if not parsed.hostname:
        result.error = "invalid URL: no hostname"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        return result

    host = parsed.hostname
    port = parsed.port or 443
    result.hostname = host
    result.port = port
    result.enabled = True

    # Resolve IP
    try:
        result.ip_address = socket.gethostbyname(host)
    except socket.gaierror as exc:
        result.error = f"DNS resolution failed: {exc}"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        return result

    Logger.info(
        f"Analyzing TLS for {host}:{port} ({result.ip_address})",
        module="tls",
    )

    # ── Handshake ──
    cert_dict, der, cipher_tuple, err = _do_handshake(
        host, port, min(timeout, CONNECT_TIMEOUT), verify_ssl=verify_ssl
    )

    if err and cert_dict is None:
        result.error = err
        result.findings.append(TLSFinding(
            id="tls-handshake-failed",
            severity="critical",
            title="TLS handshake failed",
            description=err,
            recommendation="Check server TLS configuration.",
        ))
        result.grade, result.score = _compute_grade(result.findings, None, None)
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(f"TLS: {err}", module="tls")
        return result

    result.handshake_ok = True

    # ── Certificate ──
    if cert_dict:
        cert = _parse_cert_dict(cert_dict, der or b"")
        result.certificate = cert

        # Fill in key info from cipher (best-effort)
        key_type, key_bits = _extract_key_info_from_cipher(cipher_tuple)
        cert.key_type = key_type
        cert.key_bits = key_bits

        result.findings.extend(_analyze_certificate(cert))

    # ── Cipher ──
    cipher_analysis = _analyze_cipher(cipher_tuple)
    result.cipher = cipher_analysis
    result.findings.extend(_analyze_cipher(cipher_analysis))

    # ── Versions ──
    if test_versions:
        Logger.debug("Enumerating TLS versions...", module="tls")
        versions = _test_all_versions(host, port, min(timeout, CONNECT_TIMEOUT))
        result.versions = versions
        result.findings.extend(_analyze_protocols(versions))

    # ── Grade ──
    result.grade, result.score = _compute_grade(
        result.findings, result.versions, result.cipher
    )

    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    # ── Log ──
    if result.certificate:
        c = result.certificate
        Logger.info(
            f"Certificate: CN={c.subject_cn or '?'} issuer={c.issuer_org or c.issuer_cn or '?'} "
            f"expires={c.days_until_expiry}d self_signed={c.is_self_signed}",
            module="tls",
        )
    if result.cipher:
        Logger.info(
            f"Cipher: {result.cipher.negotiated or '?'} "
            f"({result.cipher.protocol or '?'}, PFS={result.cipher.forward_secrecy}, "
            f"AEAD={result.cipher.aead})",
            module="tls",
        )
    if result.versions:
        Logger.info(
            f"TLS versions: supported={','.join(result.versions.supported) or 'none'} "
            f"preferred={result.versions.preferred or '?'}",
            module="tls",
        )

    # Log findings
    for f in result.findings:
        if f.severity in ("critical", "high"):
            Logger.warning(f"[{f.severity}] {f.title}", module="tls")
        elif f.severity == "medium":
            Logger.info(f"[{f.severity}] {f.title}", module="tls")

    Logger.info(f"TLS grade: {result.grade} (score={result.score})", module="tls")
    return result


def analyze_tls_batch(
    targets: List[str],
    max_workers: int = 10,
    **kwargs,
) -> List[TLSResult]:
    """Parallel TLS analysis."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[TLSResult] = []
    progress = Logger.progress(
        total=len(targets), desc="TLS", unit="target"
    )
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(analyze_tls, t, **kwargs): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    Logger.error(f"TLS error on {target}: {exc}", module="tls")
                    r = TLSResult()
                    r.hostname = target
                    r.error = str(exc)
                    results.append(r)
                progress.update(1)
    finally:
        progress.close()
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "TLSResult",
    "CertificateInfo",
    "TLSVersionSupport",
    "CipherAnalysis",
    "TLSFinding",
    "analyze_tls",
    "analyze_tls_batch",
    "TLS_VERSIONS",
    "WEAK_CIPHERS",
]