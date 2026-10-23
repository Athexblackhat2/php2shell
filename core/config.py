#!/usr/bin/env python3
"""
core/config.py — Central configuration for php2shell v3.1
Author: ATHEX BLACK HAT

Yeh file SAARE constants, signatures, aur settings rakhti hai.
Koi bhi module yahan se import kare — magic numbers kahin nahi.
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

# ═══════════════════════════════════════════════════════════════════════════
#  TOOL IDENTITY
# ═══════════════════════════════════════════════════════════════════════════

TOOL_NAME: str = "php2shell"
TOOL_VERSION: str = "3.1.0"
TOOL_AUTHOR: str = "ATHEX BLACK HAT"
TOOL_HOMEPAGE: str = "https://github.com/athexx/php2shell"  # placeholder
TOOL_LICENSE: str = "For authorized security testing only"

CVES: str = "CVE-2026-109618 / CVE-2026-109619"


# ═══════════════════════════════════════════════════════════════════════════
#  DEFAULT TARGET PATHS
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_PATH: str = "/index.php"
PHPMYADMIN_PATH: str = "/show_config_errors.php"
PHPMYADMIN_MARKER: bytes = b"phpMyAdmin"

# Common PHP paths for auto-discovery (used by fingerprint module)
COMMON_PHP_PATHS: Tuple[str, ...] = (
    "/index.php",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
    "/admin.php",
    "/login.php",
    "/wp-login.php",
    "/api/index.php",
    "/app.php",
    "/config.php",
    "/.env",
    "/composer.json",
)


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP / TRANSPORT LIMITS
# ═══════════════════════════════════════════════════════════════════════════

CONNECT_TIMEOUT: int = 10                        # seconds
BODY_READ_LIMIT: int = 1 << 20                   # 1 MiB — max body we keep in RAM
EXCERPT_LIMIT: int = 2048                        # bytes — for logging/dump
MAX_RESPONSE_HEADER_BYTES: int = 10 << 20        # 10 MiB — h11 header limit

UPLOAD_CHUNK_SIZE: int = 64 << 10                # 64 KiB — streaming chunk size

READ_BUFFER_HIGH_WATER: int = 256 << 10          # 256 KiB — pause reading
READ_BUFFER_LOW_WATER: int = 64 << 10            # 64 KiB — resume reading
WRITE_BUFFER_HIGH_WATER: int = 256 << 10         # 256 KiB — pause writing
WRITE_BUFFER_LOW_WATER: int = 64 << 10           # 64 KiB — resume writing

DEFAULT_TIMEOUT: int = 60                        # seconds — per request
DEFAULT_THREADS: int = 10                        # concurrent hosts
MAX_REDIRECTS: int = 10                          # follow_redirects hops

# Rate limiting (used by future async refactor)
DEFAULT_RATE_PER_HOST: float = 2.0               # requests/second per host
DEFAULT_GLOBAL_RATE: float = 20.0                # requests/second overall


# ═══════════════════════════════════════════════════════════════════════════
#  USER-AGENT / HEADERS
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/120.0.0.0 Safari/537.36 {TOOL_NAME}/{TOOL_VERSION}"
)

CRAWLER_USER_AGENT: str = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

DEFAULT_ACCEPT: str = "*/*"
DEFAULT_ACCEPT_ENCODING: str = "gzip"

# Headers that must be redacted in logs / dumps
SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
})

# Regex that validates HTTP header names (RFC 7230)
HEADER_NAME_PATTERN: str = r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"


# ═══════════════════════════════════════════════════════════════════════════
#  CVE PROBE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Multipart boundary strings used for probes
CONTROL_BOUNDARY: str = "x"
PROBE_BOUNDARY: str = ""

# Minimal control body (well-formed multipart, no crash triggers)
CONTROL_BODY: bytes = b"--x\nContent-Disposition:name=a;filename=\n\n"

# Number of nested keys — matches the CVE trigger
NESTED_KEYS: int = 62

# (size_MiB, num_parts) tuples — sent in order
PROBES: Tuple[Tuple[int, int], ...] = (
    (1, 4000),
    (8, 1020),
    (20, 1020),
)

# HTTP statuses that indicate the WAF/proxy rejected the request
# BEFORE PHP parser got to it — no crash signal expected.
REJECTED_STATUSES: frozenset[int] = frozenset({
    400,  # Bad Request
    403,  # Forbidden (WAF)
    411,  # Length Required
    413,  # Payload Too Large
    414,  # URI Too Long
    417,  # Expectation Failed
    422,  # Unprocessable Entity
    429,  # Too Many Requests
    431,  # Request Header Fields Too Large
})

# HTTP statuses indicating a worker/backend died
DEAD_WORKER_STATUSES: frozenset[int] = frozenset({502, 503, 504})


# ═══════════════════════════════════════════════════════════════════════════
#  PHP VERSION FIX TABLE
# ═══════════════════════════════════════════════════════════════════════════
#
# Format: (major, minor) -> first_patched_patch
# If site reports PHP/x.y.z with z < patched, it's VULNERABLE.
#

FIXED_VERSIONS: Dict[Tuple[int, int], int] = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

# Regex to extract PHP version from X-Powered-By
VERSION_PATTERN: str = r"PHP/(\d+)\.(\d+)\.(\d+)"


# ═══════════════════════════════════════════════════════════════════════════
#  WAF / CDN / IPS SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════
#
# Each entry: (name, type, header_patterns, body_patterns, cookie_patterns)
#   - header_patterns : regex on "name: value" header string (case-insensitive)
#   - body_patterns   : regex on response body (case-insensitive)
#   - cookie_patterns : regex on Set-Cookie values
#
# confidence is computed from evidence count by waf_detect module.
#

WAF_SIGNATURES: List[Tuple[str, str, List[str], List[str], List[str]]] = [
    # ── Cloudflare ──
    (
        "Cloudflare", "CDN/WAF",
        [r"^cf-ray:", r"^cf-cache-status:", r"^server:\s*cloudflare", r"^cf-request-id:"],
        [r"cloudflare", r"attention required! \| cloudflare", r"error 1020"],
        [r"__cf_bm", r"__cfduid", r"cf_clearance", r"cf_chl_"],
    ),
    # ── AWS CloudFront ──
    (
        "CloudFront", "CDN",
        [r"^x-amz-cf-id:", r"^x-amz-cf-pop:", r"^via:.*cloudfront", r"^server:\s*cloudfront"],
        [r"cloudfront", r"request blocked"],
        [],
    ),
    # ── Akamai ──
    (
        "Akamai", "CDN/WAF",
        [r"^x-akamai-transformed:", r"^akamai-ghost-ip", r"^server:\s*akamaighost",
         r"^x-akamai-request-id:"],
        [r"akamai", r"access denied.*akamai", r"reference #\d+\.\d+"],
        [r"ak_bmsc", r"bm_sv", r"akavpau"],
    ),
    # ── Fastly ──
    (
        "Fastly", "CDN",
        [r"^x-fastly-request-id:", r"^fastly-", r"^x-served-by:.*cache-",
         r"^x-timer:", r"^x-cache:.*fastly"],
        [r"fastly"],
        [],
    ),
    # ── Imperva / Incapsula ──
    (
        "Imperva/Incapsula", "WAF",
        [r"^x-iinfo:", r"^x-cdn:\s*incapsula", r"^x-cdn:\s*imperva"],
        [r"incapsula", r"imperva", r"_incap_ses", r"visid_incap",
         r"request unsuccessful\. incapsula"],
        [r"incap_ses", r"visid_incap"],
    ),
    # ── Sucuri ──
    (
        "Sucuri", "WAF",
        [r"^x-sucuri-id:", r"^x-sucuri-cache:", r"^server:\s*sucuri"],
        [r"sucuri", r"access denied.*sucuri", r"sucuri website firewall"],
        [r"sucuri_cloudproxy"],
    ),
    # ── F5 BIG-IP ASM ──
    (
        "F5 BIG-IP ASM", "WAF",
        [r"^x-wa-info:", r"^server:.*big-?ip", r"^bigipserver", r"^x-cnection:"],
        [r"the requested url was rejected.*big-?ip", r"bigip", r"support id"],
        [r"bigipserver", r"f5_", r"ts[a-f0-9]{8}"],
    ),
    # ── Barracuda ──
    (
        "Barracuda", "WAF",
        [r"^barra_counter_session", r"^server:\s*barracuda"],
        [r"barracuda", r"barra_counter_session"],
        [r"barra_counter_session"],
    ),
    # ── Citrix NetScaler ──
    (
        "Citrix NetScaler", "WAF",
        [r"^ns_af", r"^citrix-", r"^server:.*netscaler", r"^x-citrix-"],
        [r"netscaler", r"citrix", r"ns_af"],
        [r"ns_af", r"citrix_ns_id"],
    ),
    # ── Fortinet FortiWeb ──
    (
        "Fortinet FortiWeb", "WAF",
        [r"^fortiwafsid", r"^server:.*fortiweb", r"^x-fw-"],
        [r"fortiweb", r"fortigate", r"fortiweb blocked"],
        [r"fortiwafsid", r"fgt_"],
    ),
    # ── AWS WAF ──
    (
        "AWS WAF", "WAF",
        [r"^x-amzn-requestid:.*waf", r"^x-amzn-waf-action"],
        [r"request blocked.*aws", r"aws waf"],
        [r"aws-waf-token"],
    ),
    # ── Azure Front Door / App Gateway ──
    (
        "Azure Front Door", "CDN/WAF",
        [r"^x-azure-ref:", r"^x-fd-healthprobe", r"^x-msedge-ref:"],
        [r"azure front door", r"our services aren't available"],
        [],
    ),
    # ── Google Cloud Armor ──
    (
        "Google Cloud Armor", "WAF",
        [r"^server:\s*google frontend", r"^x-cloud-trace-context:"],
        [r"google cloud armor", r"the request was blocked"],
        [],
    ),
    # ── ModSecurity ──
    (
        "ModSecurity", "WAF",
        [r"^server:.*mod_security", r"^x-mod-security"],
        [r"mod_security", r"not acceptable.*mod_security", r"406 not acceptable",
         r"this error was generated by mod_security"],
        [],
    ),
    # ── Wordfence ──
    (
        "Wordfence", "WAF",
        [r"^server:.*wordfence"],
        [r"wordfence", r"your access to this site has been limited",
         r"generated by wordfence"],
        [r"wfvt_", r"wordfence_verifiedhuman"],
    ),
    # ── Wallarm ──
    (
        "Wallarm", "WAF",
        [r"^server:.*wallarm", r"^x-wallarm-"],
        [r"wallarm", r"blocked by wallarm"],
        [],
    ),
    # ── Reblaze ──
    (
        "Reblaze", "WAF",
        [r"^server:.*reblaze", r"^x-reblaze-"],
        [r"reblaze", r"rbz"],
        [r"rbzsessionid"],
    ),
    # ── Signal Sciences / Fastly NG ──
    (
        "Signal Sciences", "WAF",
        [r"^x-sigsci-", r"^server:.*sigsci"],
        [r"signal sciences", r"sigsci"],
        [],
    ),
    # ── StackPath ──
    (
        "StackPath", "CDN/WAF",
        [r"^server:.*stackpath", r"^x-sp-"],
        [r"stackpath"],
        [],
    ),
    # ── Radware ──
    (
        "Radware", "WAF",
        [r"^x-rdwr-", r"^server:.*radware"],
        [r"radware", r"rdwr"],
        [],
    ),
    # ── DenyAll ──
    (
        "DenyAll", "WAF",
        [r"^server:.*denyall"],
        [r"denyall"],
        [],
    ),
    # ── Edgecast / Verizon ──
    (
        "Edgecast/Verizon", "CDN",
        [r"^server:\s*ecd", r"^x-ec-"],
        [r"edgecast"],
        [],
    ),
    # ── Limelight ──
    (
        "Limelight", "CDN",
        [r"^server:.*limelight", r"^x-llid"],
        [r"limelight"],
        [],
    ),
    # ── KeyCDN ──
    (
        "KeyCDN", "CDN",
        [r"^server:\s*keycdn", r"^x-cache.*keycdn"],
        [r"keycdn"],
        [],
    ),
    # ── Varnish (cache, not WAF but useful) ──
    (
        "Varnish", "Cache",
        [r"^x-varnish:", r"^via:.*varnish"],
        [r"varnish"],
        [],
    ),
    # ── Generic block page (last resort) ──
    (
        "Generic WAF block page", "WAF",
        [],
        [r"access denied", r"request blocked", r"you have been blocked",
         r"security policy", r"web application firewall", r"suspicious activity",
         r"your request has been blocked"],
        [],
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
#  SECURITY HEADER AUDIT
# ═══════════════════════════════════════════════════════════════════════════
#
# Format: header_name -> {required, severity, desc}
#

SECURITY_HEADERS: Dict[str, Dict] = {
    "Strict-Transport-Security": {
        "required": True,
        "severity": "medium",
        "desc": "HSTS missing — SSL stripping / downgrade attacks possible",
    },
    "Content-Security-Policy": {
        "required": True,
        "severity": "medium",
        "desc": "CSP missing — XSS mitigation absent",
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity": "low",
        "desc": "MIME sniffing protection missing (should be 'nosniff')",
    },
    "X-Frame-Options": {
        "required": True,
        "severity": "medium",
        "desc": "Clickjacking protection missing (should be 'DENY' or 'SAMEORIGIN')",
    },
    "Referrer-Policy": {
        "required": False,
        "severity": "low",
        "desc": "Referrer policy missing — may leak sensitive URLs",
    },
    "Permissions-Policy": {
        "required": False,
        "severity": "low",
        "desc": "Permissions-Policy missing — browser features not restricted",
    },
    "X-XSS-Protection": {
        "required": False,
        "severity": "info",
        "desc": "Legacy XSS filter header missing (minor, deprecated)",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
#  BYPASS TECHNIQUES (generic — no weaponized payloads)
# ═══════════════════════════════════════════════════════════════════════════
#
# Each entry describes a technique. The waf_bypass module applies it.
# "apply" is NOT stored here (config shouldn't contain callables);
# instead it's referenced by name in the module.
#

BYPASS_TECHNIQUES: List[Dict] = [
    {
        "id": "header_case",
        "name": "Header case manipulation",
        "desc": "WAF may be case-sensitive when matching header names",
        "risk": "low",
    },
    {
        "id": "no_user_agent",
        "name": "Remove User-Agent",
        "desc": "Some WAFs block non-browser UAs, some block missing UA",
        "risk": "low",
    },
    {
        "id": "googlebot_ua",
        "name": "Googlebot User-Agent",
        "desc": "WAFs often whitelist verified crawlers (may still verify IP)",
        "risk": "low",
    },
    {
        "id": "xff_localhost",
        "name": "X-Forwarded-For: 127.0.0.1",
        "desc": "Some misconfigured WAFs trust XFF and skip filtering for localhost",
        "risk": "medium",
    },
    {
        "id": "xff_private",
        "name": "X-Forwarded-For: 10.0.0.1 / 192.168.1.1",
        "desc": "Alternate private IP XFF — same class of bypass",
        "risk": "medium",
    },
    {
        "id": "originating_ip",
        "name": "X-Originating-IP / X-Remote-Addr",
        "desc": "Alternate IP-spoofing headers some WAFs trust",
        "risk": "medium",
    },
    {
        "id": "chunked_te",
        "name": "Chunked Transfer-Encoding",
        "desc": "Some WAFs don't reassemble chunked bodies to inspect them",
        "risk": "medium",
    },
    {
        "id": "boundary_random",
        "name": "Random multipart boundary",
        "desc": "WAF may fail to parse multipart with unusual boundary chars",
        "risk": "low",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
#  OUTPUT / FORMATTING
# ═══════════════════════════════════════════════════════════════════════════

OUTPUT_JSON_DEFAULT: str = "php2shell_results.json"
OUTPUT_CSV_DEFAULT: str = "php2shell_results.csv"

SUPPORTED_FORMATS: Tuple[str, ...] = ("json", "csv", "ndjson", "html")


# ═══════════════════════════════════════════════════════════════════════════
#  ENVIRONMENT OVERRIDES
# ═══════════════════════════════════════════════════════════════════════════
#
# Users can override any of the above via env vars.
# Example:  PHP2SHELL_TIMEOUT=120 php2shell -u ...
#

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Apply overrides (rebind module-level constants)
DEFAULT_TIMEOUT = _env_int("PHP2SHELL_TIMEOUT", DEFAULT_TIMEOUT)
DEFAULT_THREADS = _env_int("PHP2SHELL_THREADS", DEFAULT_THREADS)
DEFAULT_RATE_PER_HOST = _env_float("PHP2SHELL_RATE_HOST", DEFAULT_RATE_PER_HOST)
DEFAULT_GLOBAL_RATE = _env_float("PHP2SHELL_RATE_GLOBAL", DEFAULT_GLOBAL_RATE)
CONNECT_TIMEOUT = _env_int("PHP2SHELL_CONNECT_TIMEOUT", CONNECT_TIMEOUT)
BODY_READ_LIMIT = _env_int("PHP2SHELL_BODY_LIMIT", BODY_READ_LIMIT)


# ═══════════════════════════════════════════════════════════════════════════
#  SANITY CHECKS (fail fast on bad config)
# ═══════════════════════════════════════════════════════════════════════════

def sanity_check() -> None:
    """Validate config at import time. Raises ValueError on bad values."""
    assert DEFAULT_TIMEOUT > 0, "DEFAULT_TIMEOUT must be > 0"
    assert DEFAULT_THREADS > 0, "DEFAULT_THREADS must be > 0"
    assert CONNECT_TIMEOUT > 0, "CONNECT_TIMEOUT must be > 0"
    assert BODY_READ_LIMIT > 0, "BODY_READ_LIMIT must be > 0"
    assert UPLOAD_CHUNK_SIZE > 0, "UPLOAD_CHUNK_SIZE must be > 0"
    assert NESTED_KEYS > 0, "NESTED_KEYS must be > 0"
    assert len(PROBES) > 0, "PROBES must not be empty"
    assert all(s > 0 and p > 0 for s, p in PROBES), "PROBES must have positive values"
    assert MAX_REDIRECTS >= 0, "MAX_REDIRECTS must be >= 0"
    assert len(WAF_SIGNATURES) > 0, "WAF_SIGNATURES must not be empty"
    assert len(BYPASS_TECHNIQUES) > 0, "BYPASS_TECHNIQUES must not be empty"


sanity_check()


# ═══════════════════════════════════════════════════════════════════════════
#  CONVENIENCE EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Identity
    "TOOL_NAME", "TOOL_VERSION", "TOOL_AUTHOR", "TOOL_HOMEPAGE",
    "TOOL_LICENSE", "CVES",
    # Paths
    "DEFAULT_PATH", "PHPMYADMIN_PATH", "PHPMYADMIN_MARKER", "COMMON_PHP_PATHS",
    # HTTP limits
    "CONNECT_TIMEOUT", "BODY_READ_LIMIT", "EXCERPT_LIMIT",
    "MAX_RESPONSE_HEADER_BYTES", "UPLOAD_CHUNK_SIZE",
    "READ_BUFFER_HIGH_WATER", "READ_BUFFER_LOW_WATER",
    "WRITE_BUFFER_HIGH_WATER", "WRITE_BUFFER_LOW_WATER",
    "DEFAULT_TIMEOUT", "DEFAULT_THREADS", "MAX_REDIRECTS",
    "DEFAULT_RATE_PER_HOST", "DEFAULT_GLOBAL_RATE",
    # Headers
    "DEFAULT_USER_AGENT", "CRAWLER_USER_AGENT", "DEFAULT_ACCEPT",
    "DEFAULT_ACCEPT_ENCODING", "SENSITIVE_HEADERS", "HEADER_NAME_PATTERN",
    # CVE probes
    "CONTROL_BOUNDARY", "PROBE_BOUNDARY", "CONTROL_BODY", "NESTED_KEYS",
    "PROBES", "REJECTED_STATUSES", "DEAD_WORKER_STATUSES",
    "FIXED_VERSIONS", "VERSION_PATTERN",
    # Detection
    "WAF_SIGNATURES", "SECURITY_HEADERS", "BYPASS_TECHNIQUES",
    # Output
    "OUTPUT_JSON_DEFAULT", "OUTPUT_CSV_DEFAULT", "SUPPORTED_FORMATS",
    # Utils
    "sanity_check",
]