#!/usr/bin/env python3
"""
modules/headers.py — Security header audit for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Deep security header analysis with value validation + grading.
  Complements modules/fingerprint.py (which only checks presence).

What this module checks:
  1. Presence  — is the header there?
  2. Value     — is it configured securely (weak/strong/absent)?
  3. Consistency — does it apply to redirects, error pages?
  4. Info leaks — Server, X-Powered-By, X-AspNet-Version, etc.
  5. Cookie flags — Secure, HttpOnly, SameSite, Domain, Path, Max-Age
  6. CORS policy — overly permissive Access-Control-Allow-*
  7. CSP quality — unsafe-inline, unsafe-eval, wildcard, data: URIs
  8. Grading — A-F based on weighted findings

Does NOT send crash probes. All requests are benign GET.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.config import (
    SECURITY_HEADERS,
    DEFAULT_TIMEOUT,
)
from core.http import (
    HTTPResult,
    http_get,
    ProxyConfig,
)
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  SEVERITY + GRADING WEIGHTS
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


# ═══════════════════════════════════════════════════════════════════════════
#  HEADER EXPECTATIONS (value validation rules)
# ═══════════════════════════════════════════════════════════════════════════

# HSTS: recommended min max-age = 6 months (15552000s)
HSTS_MIN_AGE = 15552000
HSTS_RECOMMENDED_AGE = 63072000  # 2 years

# Referrer-Policy values in decreasing security
REFERRER_POLICY_STRONG = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
REFERRER_POLICY_WEAK = {"origin", "origin-when-cross-origin", "same-origin"}
REFERRER_POLICY_INSECURE = {"unsafe-url", "no-referrer-when-downgrade"}

# X-Frame-Options valid values
XFO_VALID = {"DENY", "SAMEORIGIN"}
XFO_OBSOLETE = {"ALLOW-FROM"}

# Permissions-Policy: sensitive features that should be disabled
SENSITIVE_PERMISSIONS = [
    "camera", "microphone", "geolocation", "payment", "usb",
    "magnetometer", "gyroscope", "accelerometer", "interest-cohort",
]

# Info-disclosure headers (should be removed or minimized)
INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-Runtime",
    "X-Varnish",
    "X-Backend-Server",
    "X-Served-By",
    "X-Cache",
    "X-Cache-Hits",
    "X-Timer",
    "X-Request-Id",
    "Via",
    "X-Forwarded-Server",
    "X-Forwarded-Host",
    "X-Proxy-Id",
]

# CORS headers
CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
]


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """A single security finding."""
    id: str
    category: str           # hsts | csp | xfo | cookie | cors | info | ...
    severity: str           # critical | high | medium | low | info
    header: Optional[str]   # header involved, or None for cookie/CORS
    title: str
    description: str
    value: Optional[str] = None
    recommendation: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CookieAnalysis:
    """Per-cookie security analysis."""
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None   # None | 'strict' | 'lax' | 'none'
    domain: Optional[str] = None
    path: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[str] = None
    __host_prefix: bool = False
    __secure_prefix: bool = False
    issues: List[str] = field(default_factory=list)
    severity: str = "info"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HeaderScore:
    """Score breakdown for grading."""
    total_score: int = 0
    grade: str = "F"
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    top_issues: List[str] = field(default_factory=list)


@dataclass
class HeadersResult:
    """Complete header audit result."""
    target: str = ""
    final_url: str = ""
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    headers_raw_count: int = 0

    # Findings
    findings: List[Finding] = field(default_factory=list)
    cookies: List[CookieAnalysis] = field(default_factory=list)
    info_leaks: Dict[str, str] = field(default_factory=dict)
    cors_issues: List[str] = field(default_factory=list)

    # Score
    score: HeaderScore = field(default_factory=HeaderScore)

    # Meta
    error: Optional[str] = None
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        d["cookies"] = [asdict(c) for c in self.cookies]
        return d

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        return (
            f"Grade {self.score.grade} ({self.score.total_score} pts, "
            f"{len(self.findings)} finding(s))"
        )


# ═══════════════════════════════════════════════════════════════════════════
#  HEADER LOOKUP HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return None


def header_present(headers: Dict[str, str], name: str) -> bool:
    return get_header(headers, name) is not None


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: HSTS
# ═══════════════════════════════════════════════════════════════════════════

def audit_hsts(response: HTTPResult) -> List[Finding]:
    """Audit Strict-Transport-Security."""
    findings: List[Finding] = []
    value = get_header(response.headers, "Strict-Transport-Security")

    if value is None:
        findings.append(Finding(
            id="hsts-missing",
            category="hsts",
            severity="medium",
            header="Strict-Transport-Security",
            title="HSTS header missing",
            description=(
                "Strict-Transport-Security not set. Users can be downgraded "
                "to HTTP via MITM (SSL stripping)."
            ),
            recommendation="Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            cwe="CWE-319",
            owasp="A02:2021",
        ))
        return findings

    lvalue = value.lower()

    # Parse max-age
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", lvalue)
    if not max_age_match:
        findings.append(Finding(
            id="hsts-no-maxage",
            category="hsts",
            severity="medium",
            header="Strict-Transport-Security",
            title="HSTS missing max-age",
            description="HSTS is set but max-age directive is absent — treated as 0 (disabled).",
            value=value,
            recommendation="Add max-age=<seconds>",
        ))
        return findings

    max_age = int(max_age_match.group(1))
    if max_age == 0:
        findings.append(Finding(
            id="hsts-zero",
            category="hsts",
            severity="medium",
            header="Strict-Transport-Security",
            title="HSTS max-age=0 (disabled)",
            description="max-age=0 disables HSTS. This clears any prior HSTS policy.",
            value=value,
            recommendation="Set max-age to at least 15552000 (180 days).",
        ))
    elif max_age < HSTS_MIN_AGE:
        findings.append(Finding(
            id="hsts-short",
            category="hsts",
            severity="low",
            header="Strict-Transport-Security",
            title=f"HSTS max-age too short ({max_age}s)",
            description=(
                f"HSTS max-age {max_age}s is less than recommended 6 months "
                f"(15552000s)."
            ),
            value=value,
            recommendation="Set max-age to at least 31536000 (1 year).",
        ))

    if "includesubdomains" not in lvalue:
        findings.append(Finding(
            id="hsts-no-subdomains",
            category="hsts",
            severity="low",
            header="Strict-Transport-Security",
            title="HSTS missing includeSubDomains",
            description="Subdomains are not covered by HSTS — they can be downgraded.",
            value=value,
            recommendation="Add includeSubDomains.",
        ))

    if "preload" not in lvalue:
        findings.append(Finding(
            id="hsts-no-preload",
            category="hsts",
            severity="info",
            header="Strict-Transport-Security",
            title="HSTS missing preload",
            description="Preload directive not set (minor — only needed for preload list inclusion).",
            value=value,
            recommendation="Add preload (after registering at hstspreload.org).",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: CSP
# ═══════════════════════════════════════════════════════════════════════════

def audit_csp(response: HTTPResult) -> List[Finding]:
    """Audit Content-Security-Policy."""
    findings: List[Finding] = []
    value = get_header(response.headers, "Content-Security-Policy")
    if value is None:
        # Legacy header (report-only shouldn't count as enforcement)
        report_only = get_header(response.headers, "Content-Security-Policy-Report-Only")
        if report_only:
            findings.append(Finding(
                id="csp-report-only",
                category="csp",
                severity="medium",
                header="Content-Security-Policy-Report-Only",
                title="CSP is report-only (not enforced)",
                description=(
                    "CSP is only in report-only mode — XSS attacks are detected "
                    "but not blocked."
                ),
                value=report_only,
                recommendation="Enforce CSP by setting Content-Security-Policy (not -Report-Only).",
            ))
        else:
            findings.append(Finding(
                id="csp-missing",
                category="csp",
                severity="medium",
                header="Content-Security-Policy",
                title="CSP header missing",
                description=(
                    "Content-Security-Policy not set. XSS mitigation relies "
                    "entirely on input sanitization."
                ),
                recommendation="Set a strict CSP starting with: default-src 'self'; script-src 'self'",
                cwe="CWE-693",
                owasp="A05:2021",
            ))
        return findings

    lvalue = value.lower()

    # Weak directives
    if "unsafe-inline" in lvalue:
        findings.append(Finding(
            id="csp-unsafe-inline",
            category="csp",
            severity="medium",
            header="Content-Security-Policy",
            title="CSP allows 'unsafe-inline'",
            description="'unsafe-inline' allows inline scripts/styles — most XSS payloads work.",
            value=value[:200],
            recommendation="Use nonces or hashes instead of 'unsafe-inline'.",
        ))

    if "unsafe-eval" in lvalue:
        findings.append(Finding(
            id="csp-unsafe-eval",
            category="csp",
            severity="medium",
            header="Content-Security-Policy",
            title="CSP allows 'unsafe-eval'",
            description="'unsafe-eval' permits eval() and similar — DOM-based XSS risk.",
            value=value[:200],
            recommendation="Remove 'unsafe-eval' unless absolutely required.",
        ))

    if re.search(r"(?:^|[\s;])\*", lvalue) or "http:" in lvalue or "https:" in lvalue:
        findings.append(Finding(
            id="csp-wildcard",
            category="csp",
            severity="medium",
            header="Content-Security-Policy",
            title="CSP allows wildcard / http: sources",
            description="Wildcard (*) or scheme-only sources defeat CSP's purpose.",
            value=value[:200],
            recommendation="Restrict sources to specific domains.",
        ))

    # data: in script-src is dangerous
    if re.search(r"script-src[^;]*\bdata:", lvalue):
        findings.append(Finding(
            id="csp-data-script",
            category="csp",
            severity="high",
            header="Content-Security-Policy",
            title="CSP allows data: in script-src",
            description="data: URIs in script-src allow inline attack payloads.",
            value=value[:200],
            recommendation="Remove data: from script-src.",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: X-Frame-Options
# ═══════════════════════════════════════════════════════════════════════════

def audit_xfo(response: HTTPResult) -> List[Finding]:
    findings: List[Finding] = []
    value = get_header(response.headers, "X-Frame-Options")
    csp = get_header(response.headers, "Content-Security-Policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if value is None:
        if has_frame_ancestors:
            return findings  # CSP frame-ancestors covers clickjacking
        findings.append(Finding(
            id="xfo-missing",
            category="xfo",
            severity="medium",
            header="X-Frame-Options",
            title="X-Frame-Options missing (and no CSP frame-ancestors)",
            description="Site can be embedded in iframes — clickjacking risk.",
            recommendation="Add: X-Frame-Options: DENY  (or CSP frame-ancestors 'none')",
            cwe="CWE-1021",
            owasp="A05:2021",
        ))
        return findings

    upper = value.strip().upper()
    if upper in XFO_OBSOLETE:
        findings.append(Finding(
            id="xfo-obsolete",
            category="xfo",
            severity="medium",
            header="X-Frame-Options",
            title="X-Frame-Options uses obsolete ALLOW-FROM",
            description="ALLOW-FROM is deprecated and ignored by modern browsers.",
            value=value,
            recommendation="Use CSP frame-ancestors <uri> instead.",
        ))
    elif upper not in XFO_VALID and not upper.startswith("ALLOW-FROM"):
        findings.append(Finding(
            id="xfo-invalid",
            category="xfo",
            severity="low",
            header="X-Frame-Options",
            title=f"X-Frame-Options has unexpected value: {value}",
            description="Value should be DENY or SAMEORIGIN.",
            value=value,
            recommendation="Set to DENY (most secure) or SAMEORIGIN.",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: X-Content-Type-Options
# ═══════════════════════════════════════════════════════════════════════════

def audit_content_type_options(response: HTTPResult) -> List[Finding]:
    findings: List[Finding] = []
    value = get_header(response.headers, "X-Content-Type-Options")
    if value is None:
        findings.append(Finding(
            id="xcto-missing",
            category="content-type",
            severity="low",
            header="X-Content-Type-Options",
            title="X-Content-Type-Options missing",
            description="MIME-sniffing protection missing — browsers may mis-interpret content.",
            recommendation="Add: X-Content-Type-Options: nosniff",
            cwe="CWE-16",
        ))
    elif value.strip().lower() != "nosniff":
        findings.append(Finding(
            id="xcto-invalid",
            category="content-type",
            severity="low",
            header="X-Content-Type-Options",
            title=f"X-Content-Type-Options has unexpected value: {value}",
            description="Only 'nosniff' is valid.",
            value=value,
            recommendation="Set to nosniff.",
        ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: Referrer-Policy
# ═══════════════════════════════════════════════════════════════════════════

def audit_referrer_policy(response: HTTPResult) -> List[Finding]:
    findings: List[Finding] = []
    value = get_header(response.headers, "Referrer-Policy")
    if value is None:
        findings.append(Finding(
            id="referrer-missing",
            category="referrer",
            severity="low",
            header="Referrer-Policy",
            title="Referrer-Policy missing",
            description="Full referrer URLs may leak to third parties (including tokens in query).",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        ))
        return findings

    lvalue = value.strip().lower()
    if lvalue in REFERRER_POLICY_INSECURE:
        findings.append(Finding(
            id="referrer-insecure",
            category="referrer",
            severity="low",
            header="Referrer-Policy",
            title=f"Referrer-Policy is insecure: {value}",
            description="May leak full URLs to third parties.",
            value=value,
            recommendation="Use strict-origin-when-cross-origin or no-referrer.",
        ))
    elif lvalue in REFERRER_POLICY_WEAK:
        findings.append(Finding(
            id="referrer-weak",
            category="referrer",
            severity="info",
            header="Referrer-Policy",
            title=f"Referrer-Policy is acceptable but not optimal: {value}",
            description="Consider strict-origin-when-cross-origin for better privacy.",
            value=value,
        ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: Permissions-Policy
# ═══════════════════════════════════════════════════════════════════════════

def audit_permissions_policy(response: HTTPResult) -> List[Finding]:
    findings: List[Finding] = []
    value = get_header(response.headers, "Permissions-Policy")
    if value is None:
        findings.append(Finding(
            id="permissions-missing",
            category="permissions",
            severity="info",
            header="Permissions-Policy",
            title="Permissions-Policy missing",
            description="Sensitive browser features (camera, mic, geolocation) not restricted.",
            recommendation=(
                "Add: Permissions-Policy: camera=(), microphone=(), "
                "geolocation=(), interest-cohort=()"
            ),
        ))
        return findings
    # Check if any sensitive permission is granted to *
    lvalue = value.lower()
    for perm in SENSITIVE_PERMISSIONS:
        if re.search(rf"{re.escape(perm)}\s*=\s*\*", lvalue):
            findings.append(Finding(
                id=f"permissions-wildcard-{perm}",
                category="permissions",
                severity="low",
                header="Permissions-Policy",
                title=f"Permissions-Policy grants '{perm}' to all origins",
                description=f"Feature '{perm}' is allowed for any origin (*).",
                value=value[:200],
                recommendation=f"Restrict or disable {perm}.",
            ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: Info Disclosure
# ═══════════════════════════════════════════════════════════════════════════

def audit_info_disclosure(response: HTTPResult) -> Tuple[List[Finding], Dict[str, str]]:
    findings: List[Finding] = []
    leaks: Dict[str, str] = {}

    for header in INFO_DISCLOSURE_HEADERS:
        val = get_header(response.headers, header)
        if val:
            leaks[header] = val

    # Specific severity by header
    severity_map = {
        "Server": "info",
        "X-Powered-By": "low",
        "X-AspNet-Version": "low",
        "X-AspNetMvc-Version": "low",
        "X-Generator": "info",
        "X-Runtime": "info",
        "X-Varnish": "info",
        "X-Backend-Server": "medium",
        "X-Served-By": "info",
        "X-Forwarded-Server": "medium",
        "X-Forwarded-Host": "medium",
        "X-Proxy-Id": "medium",
    }
    for header, val in leaks.items():
        findings.append(Finding(
            id=f"info-{header.lower().replace('-', '_')}",
            category="info-disclosure",
            severity=severity_map.get(header, "info"),
            header=header,
            title=f"Information disclosure via {header}",
            description=f"Header leaks internal info: {val}",
            value=val,
            recommendation=f"Remove or minimize {header} header.",
        ))
    return findings, leaks


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: Cookies
# ═══════════════════════════════════════════════════════════════════════════

def _parse_set_cookie(raw: str) -> CookieAnalysis:
    """Parse a single Set-Cookie header line."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts or "=" not in parts[0]:
        return CookieAnalysis(name="<invalid>")

    name = parts[0].split("=", 1)[0].strip()
    cookie = CookieAnalysis(name=name)

    # Detect __Host- / __Secure- prefixes
    if name.startswith("__Host-"):
        cookie.__host_prefix = True
    elif name.startswith("__Secure-"):
        cookie.__secure_prefix = True

    for attr in parts[1:]:
        attr = attr.strip()
        if not attr:
            continue
        if "=" in attr:
            k, v = attr.split("=", 1)
            k = k.strip().lower()
            v = v.strip().strip('"')
            if k == "domain":
                cookie.domain = v
            elif k == "path":
                cookie.path = v
            elif k == "max-age":
                try:
                    cookie.max_age = int(v)
                except ValueError:
                    pass
            elif k == "expires":
                cookie.expires = v
            elif k == "samesite":
                cookie.samesite = v.lower()
        else:
            attr_l = attr.lower()
            if attr_l == "secure":
                cookie.secure = True
            elif attr_l == "httponly":
                cookie.httponly = True

    # Analyze issues
    issues = []
    severity = "info"

    if not cookie.secure:
        issues.append("Missing Secure flag — sent over HTTP")
        severity = "medium"

    if not cookie.httponly:
        issues.append("Missing HttpOnly flag — accessible to JavaScript (XSS risk)")
        if severity == "info" or severity == "low":
            severity = "medium"

    if cookie.samesite is None:
        issues.append("Missing SameSite attribute")
        if severity == "info":
            severity = "low"
    elif cookie.samesite == "none" and not cookie.secure:
        issues.append("SameSite=None without Secure flag — cookie will be rejected")
        severity = "high"
    elif cookie.samesite == "none":
        issues.append("SameSite=None allows cross-site sending (CSRF risk)")
        if severity in ("info", "low"):
            severity = "low"

    # __Host- prefix requirements
    if cookie.__host_prefix:
        if not cookie.secure:
            issues.append("__Host- prefix requires Secure")
            severity = "high"
        if cookie.domain:
            issues.append("__Host- prefix must not set Domain")
            severity = "high"
        if cookie.path != "/":
            issues.append("__Host- prefix requires Path=/")
            severity = "high"

    if cookie.__secure_prefix and not cookie.secure:
        issues.append("__Secure- prefix requires Secure flag")
        severity = "high"

    if cookie.max_age is not None and cookie.max_age > 31536000:  # >1 year
        issues.append(f"Max-Age is very long ({cookie.max_age}s)")
        if severity in ("info", "low"):
            severity = "low"

    cookie.issues = issues
    cookie.severity = severity
    return cookie


def audit_cookies(response: HTTPResult) -> List[Finding]:
    """Audit Set-Cookie headers."""
    findings: List[Finding] = []
    raw_cookies = response.header_all("set-cookie")
    # header_all joins with \n if multiple — split back
    all_raw: List[str] = []
    for c in raw_cookies:
        all_raw.extend(c.split("\n"))

    for raw in all_raw:
        parsed = _parse_set_cookie(raw)
        if parsed.name == "<invalid>":
            continue
        if parsed.issues:
            findings.append(Finding(
                id=f"cookie-{parsed.name}",
                category="cookie",
                severity=parsed.severity,
                header="Set-Cookie",
                title=f"Cookie '{parsed.name}' has insecure attributes",
                description="; ".join(parsed.issues),
                value=parsed.name,
                recommendation="Add Secure; HttpOnly; SameSite=Lax/Strict to all cookies.",
                cwe="CWE-614",
            ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATORS: CORS
# ═══════════════════════════════════════════════════════════════════════════

def audit_cors(response: HTTPResult) -> Tuple[List[Finding], List[str]]:
    """Audit CORS headers."""
    findings: List[Finding] = []
    issues: List[str] = []

    origin = get_header(response.headers, "Access-Control-Allow-Origin")
    creds = get_header(response.headers, "Access-Control-Allow-Credentials")

    if origin is None:
        return findings, issues

    if origin.strip() == "*" and (creds or "").strip().lower() == "true":
        findings.append(Finding(
            id="cors-wildcard-creds",
            category="cors",
            severity="high",
            header="Access-Control-Allow-Origin",
            title="CORS allows * with credentials",
            description=(
                "Wildcard origin + Allow-Credentials=true — any site can read "
                "authenticated responses. (Browsers reject this, but a buggy "
                "server may still send it.)"
            ),
            value=f"ACAO: {origin}, ACAC: {creds}",
            recommendation="Never combine * with Allow-Credentials=true.",
            cwe="CWE-942",
        ))
        issues.append("wildcard + credentials")

    elif origin.strip() == "*":
        findings.append(Finding(
            id="cors-wildcard",
            category="cors",
            severity="low",
            header="Access-Control-Allow-Origin",
            title="CORS allows *",
            description="Any origin can read responses (no credentials).",
            value=origin,
            recommendation="Restrict to specific trusted origins.",
        ))
        issues.append("wildcard")

    # Reflected origin (server echoes back arbitrary Origin)
    if origin and origin.strip() != "*":
        # If the header value looks like a URL and is not a fixed list, flag as potential reflection
        if origin.strip().startswith(("http://", "https://")):
            issues.append(f"fixed-origin:{origin.strip()}")
            # We can't test reflection without a second request — note it
            findings.append(Finding(
                id="cors-fixed-origin",
                category="cors",
                severity="info",
                header="Access-Control-Allow-Origin",
                title=f"CORS fixed origin: {origin}",
                description="Single origin allowed — verify it's actually trusted.",
                value=origin,
            ))

    if get_header(response.headers, "Access-Control-Allow-Methods"):
        methods = get_header(response.headers, "Access-Control-Allow-Methods") or ""
        if "*" in methods:
            findings.append(Finding(
                id="cors-methods-wildcard",
                category="cors",
                severity="low",
                header="Access-Control-Allow-Methods",
                title="CORS allows all methods",
                description="ACAO allows *, which includes sensitive methods.",
                value=methods,
            ))

    return findings, issues


# ═══════════════════════════════════════════════════════════════════════════
#  SCORING
# ═══════════════════════════════════════════════════════════════════════════

def compute_score(findings: List[Finding]) -> HeaderScore:
    """Compute A-F grade from findings."""
    score = HeaderScore()
    by_sev: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        total += SEVERITY_WEIGHTS.get(f.severity, 0)

    score.total_score = total
    score.findings_by_severity = by_sev

    # Grade
    for threshold, grade in GRADE_THRESHOLDS:
        if total <= threshold:
            score.grade = grade
            break

    # Top 3 issues (highest severity)
    ordered = sorted(
        [f for f in findings if f.severity != "info"],
        key=lambda f: -SEVERITY_WEIGHTS.get(f.severity, 0),
    )
    score.top_issues = [f.title for f in ordered[:3]]
    return score


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def audit_headers(
    target_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    proxy: Optional[ProxyConfig] = None,
    custom_headers: Optional[Dict[str, str]] = None,
) -> HeadersResult:
    """
    Perform a full security header audit against target_url.

    Sends a single GET request and analyzes the response headers.
    """
    started = time.perf_counter()
    result = HeadersResult()
    result.target = target_url

    # Validate
    parsed = urlsplit(target_url)
    if not parsed.hostname:
        result.error = "invalid URL: no hostname"
        return result

    Logger.info(f"Auditing headers: {target_url}", module="headers")

    response = http_get(
        target_url,
        headers=dict(custom_headers or {}),
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=True,
        proxy=proxy,
        retries=1,
        rate_limit=True,
    )

    if response.error:
        result.error = f"request failed: {response.error}"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(result.error, module="headers")
        return result

    result.status_code = response.status_code
    result.final_url = response.final_url
    result.headers = dict(response.headers)
    result.headers_raw_count = len(response.headers)

    # ── Run auditors ──
    result.findings.extend(audit_hsts(response))
    result.findings.extend(audit_csp(response))
    result.findings.extend(audit_xfo(response))
    result.findings.extend(audit_content_type_options(response))
    result.findings.extend(audit_referrer_policy(response))
    result.findings.extend(audit_permissions_policy(response))

    info_findings, info_leaks = audit_info_disclosure(response)
    result.findings.extend(info_findings)
    result.info_leaks = info_leaks

    result.findings.extend(audit_cookies(response))

    cors_findings, cors_issues = audit_cors(response)
    result.findings.extend(cors_findings)
    result.cors_issues = cors_issues

    # ── Parse cookies for detailed view ──
    raw_cookies: List[str] = []
    for c in response.header_all("set-cookie"):
        raw_cookies.extend(c.split("\n"))
    for raw in raw_cookies:
        parsed_c = _parse_set_cookie(raw)
        if parsed_c.name != "<invalid>":
            result.cookies.append(parsed_c)

    # ── Score ──    result.score = compute_score(result.findings)

    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    # ── Log summary ──
    by_sev = result.score.findings_by_severity
    summary_parts = [f"{sev}={cnt}" for sev, cnt in by_sev.items() if cnt]
    Logger.info(
        f"Audit complete: grade={result.score.grade} "
        f"({', '.join(summary_parts) if summary_parts else 'no findings'})",
        module="headers",
    )
    for f in result.findings:
        if f.severity in ("critical", "high"):
            Logger.warning(f"[{f.severity}] {f.title}", module="headers")
        elif f.severity == "medium":
            Logger.info(f"[{f.severity}] {f.title}", module="headers")

    return result


def audit_headers_batch(
    targets: List[str],
    max_workers: int = 10,
    **kwargs,
) -> List[HeadersResult]:
    """Parallel header audit."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[HeadersResult] = []
    progress = Logger.progress(
        total=len(targets), desc="Headers", unit="target"
    )
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(audit_headers, t, **kwargs): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    Logger.error(
                        f"Header audit error on {target}: {exc}",
                        module="headers",
                    )
                    r = HeadersResult()
                    r.target = target
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
    "HeadersResult",
    "Finding",
    "CookieAnalysis",
    "HeaderScore",
    "audit_headers",
    "audit_headers_batch",
    "audit_hsts",
    "audit_csp",
    "audit_xfo",
    "audit_content_type_options",
    "audit_referrer_policy",
    "audit_permissions_policy",
    "audit_info_disclosure",
    "audit_cookies",
    "audit_cors",
    "compute_score",
]