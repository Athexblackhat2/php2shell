#!/usr/bin/env python3
"""
modules/fingerprint.py — Technology fingerprinting aggregator for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Build a complete profile of the target BEFORE running active tests:
    - Web server (Apache, nginx, IIS, Caddy, LiteSpeed, ...)
    - Language runtime (PHP, ASP.NET, Node, Python, ...)
    - PHP version + patch status (via X-Powered-By + header leaks)
    - Frameworks / CMS (WordPress, Laravel, Drupal, Joomla, Magento, ...)
    - Reverse proxy / CDN hints (Varnish, Cloudflare, Akamai, ...)
    - WAF hints (quick pass — deeper detection in modules/waf_detect.py)
    - Security posture (HTTPS, HTTP/2, redirect to HTTPS)
    - Interesting files (phpinfo, .git, .env, robots.txt) — passive GET only

Does NOT send crash probes. All requests are benign GET / HEAD.
Use this fingerprint to inform later modules (crash, waf_bypass, headers).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.config import (
    DEFAULT_PATH,
    PHPMYADMIN_PATH,
    PHPMYADMIN_MARKER,
    DEFAULT_TIMEOUT,
    COMMON_PHP_PATHS,
    WAF_SIGNATURES,
    VERSION_PATTERN,
    FIXED_VERSIONS,
)
from core.http import (
    HTTPResult,
    send_request,
    http_get,
    http_head,
    ProxyConfig,
)
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  SIGNATURE TABLES
# ═══════════════════════════════════════════════════════════════════════════

# Web server detection from Server: header
SERVER_SIGNATURES: List[Tuple[str, str]] = [
    (r"apache(?:/(\d+\.\d+\.\d+))?", "Apache"),
    (r"nginx(?:/(\d+\.\d+\.\d+))?", "nginx"),
    (r"microsoft-iis(?:/(\d+\.\d+))?", "IIS"),
    (r"litespeed", "LiteSpeed"),
    (r"openlitespeed", "OpenLiteSpeed"),
    (r"caddy", "Caddy"),
    (r"envoy", "Envoy"),
    (r"gunicorn", "Gunicorn"),
    (r"uvicorn", "Uvicorn"),
    (r"werkzeug", "Werkzeug (Flask dev)"),
    (r"jetty", "Jetty"),
    (r"tomcat", "Tomcat"),
    (r"cloudflare", "Cloudflare"),
    (r"akamaighost", "Akamai"),
    (r"google frontend", "Google Frontend"),
    (r"cloudfront", "CloudFront"),
    (r"barracuda", "Barracuda"),
    (r"big-?ip", "F5 BIG-IP"),
    (r"netscaler", "Citrix NetScaler"),
    (r"kestrel", "Kestrel (ASP.NET Core)"),
    (r"python", "Python (unspecified server)"),
    (r"php", "PHP built-in server"),
]

# Framework/CMS detection from body content
CMS_SIGNATURES: List[Tuple[str, List[str], str]] = [
    # (name, [body markers], category)
    ("WordPress", [r"wp-content", r"wp-includes", r"/wp-login\.php", r'name="generator" content="WordPress'],
     "CMS"),
    ("Drupal", [r"Drupal\.settings", r"sites/default/files", r"drupal\.org",
                r'name="generator" content="Drupal'], "CMS"),
    ("Joomla", [r"/components/com_", r"/media/jui/", r"joomla", r'content="Joomla'], "CMS"),
    ("Magento", [r"/skin/frontend/", r"mage/cookies", r"Magento", r"X-Magento"], "E-commerce"),
    ("PrestaShop", [r"prestashop", r"/modules/ps_"], "E-commerce"),
    ("Shopify", [r"cdn\.shopify\.com", r"Shopify\.theme"], "E-commerce"),
    ("Laravel", [r"laravel", r"XSRF-TOKEN", r"laravel_session"], "Framework"),
    ("Symfony", [r"symfony", r"X-Symfony"], "Framework"),
    ("CodeIgniter", [r"codeigniter", r"ci_session"], "Framework"),
    ("CakePHP", [r"cakephp", r"CAKEPHP"], "Framework"),
    ("Yii", [r"Yii", r"yii_debug"], "Framework"),
    ("Zend", [r"zend", r"Zend_"], "Framework"),
    ("Django", [r"csrfmiddlewaretoken", r"django", r"__admin_media_prefix__"], "Framework"),
    ("Rails", [r"csrf-token", r"rails", r"_session_id"], "Framework"),
    ("Express", [r"express", r"X-Powered-By: Express"], "Framework"),
    ("Next.js", [r"__NEXT_DATA__", r"/_next/static/"], "Framework"),
    ("Nuxt", [r"__NUXT__", r"/_nuxt/"], "Framework"),
    ("Spring", [r"org\.springframework", r"JSESSIONID"], "Framework"),
    ("ASP.NET", [r"__VIEWSTATE", r"__EVENTVALIDATION", r"ASP\.NET_SessionId"], "Framework"),
    ("Flask", [r"werkzeug", r"flask"], "Framework"),
    ("FastAPI", [r"fastapi", r'openapi'], "Framework"),
    ("phpMyAdmin", [r"phpMyAdmin", r"pma_"], "Admin panel"),
    ("WordPress admin", [r"wp-admin", r"wp-login"], "Admin panel"),
    ("Jenkins", [r"Jenkins", r"hudson"], "CI/CD"),
    ("GitLab", [r"gitlab", r"gon\.gitlab"], "DevOps"),
    ("Grafana", [r"grafana", r"Grafana"], "Dashboard"),
    ("Kibana", [r"kibana", r"Kbn-Version"], "Dashboard"),
]

# Language/runtime detection from various headers/body markers
LANGUAGE_SIGNATURES: List[Tuple[str, str, str]] = [
    # (language, marker, source) — source: header|body
    ("PHP", r"PHP/[\d.]+", "x-powered-by"),
    ("PHP", r"\.php", "url"),
    ("PHP", r"PHPSESSID", "set-cookie"),
    ("ASP.NET", r"ASP\.NET", "x-powered-by"),
    ("ASP.NET", r"ASP\.NET_SessionId", "set-cookie"),
    ("Node.js", r"Express", "x-powered-by"),
    ("Python", r"Python/[\d.]+", "server"),
    ("Python", r"Werkzeug", "server"),
    ("Python", r"gunicorn", "server"),
    ("Ruby", r"Phusion Passenger", "server"),
    ("Ruby", r"Ruby", "x-powered-by"),
    ("Java", r"Java/[\d.]+", "server"),
    ("Java", r"JSESSIONID", "set-cookie"),
    ("Go", r"Go-http-client", "user-agent"),
]

# Security header presence (for quick posture summary)
SECURITY_HEADERS_QUICK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Interesting passive files — checked with HEAD / small GET only
INTERESTING_FILES: List[Tuple[str, str]] = [
    ("/robots.txt", "Disallow paths may reveal admin panels"),
    ("/sitemap.xml", "May reveal hidden URLs"),
    ("/.git/HEAD", "CRITICAL: git repo exposed"),
    ("/.env", "CRITICAL: environment vars exposed"),
    ("/.env.local", "CRITICAL: env vars exposed"),
    ("/composer.json", "Package info leak"),
    ("/package.json", "Package info leak (Node)"),
    ("/server-status", "Apache mod_status exposed"),
    ("/phpinfo.php", "CRITICAL: phpinfo() exposed"),
    ("/info.php", "CRITICAL: phpinfo() exposed"),
    ("/.DS_Store", "macOS metadata leak"),
    ("/crossdomain.xml", "Old Flash policy"),
    ("/phpmyadmin/", "phpMyAdmin panel"),
    ("/admin/", "Admin panel"),
    ("/api/", "API root"),
    ("/backup.zip", "Backup file exposed"),
    ("/config.php.bak", "Source backup exposed"),
]


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ServerInfo:
    name: Optional[str] = None
    version: Optional[str] = None
    raw: Optional[str] = None


@dataclass
class PHPInfo:
    detected: bool = False
    version: Optional[str] = None
    patch_status: Optional[str] = None  # FIXED | VULNERABLE | UNKNOWN
    x_powered_by: Optional[str] = None
    session_cookie: bool = False  # PHPSESSID seen


@dataclass
class Framework:
    name: str
    category: str
    confidence: str  # high | medium | low
    evidence: str


@dataclass
class CDNHint:
    name: str
    type: str  # CDN | WAF | Cache | Proxy
    confidence: str  # high | medium | low
    evidence: str


@dataclass
class SecurityPosture:
    https: bool = False
    http_to_https_redirect: bool = False
    hsts: bool = False
    security_headers: Dict[str, bool] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)


@dataclass
class InterestingFile:
    path: str
    status_code: int
    size: int
    content_type: str
    note: str = ""
    severity: str = "info"  # info | low | medium | high | critical


@dataclass
class FingerprintResult:
    """Complete fingerprint of a target."""
    # Target
    target: str = ""
    final_url: str = ""
    scheme: str = "https"
    host: str = ""
    port: Optional[int] = None

    # Stack
    server: ServerInfo = field(default_factory=ServerInfo)
    php: PHPInfo = field(default_factory=PHPInfo)
    language: Optional[str] = None
    frameworks: List[Framework] = field(default_factory=list)
    cdn: List[CDNHint] = field(default_factory=list)

    # Security
    security: SecurityPosture = field(default_factory=SecurityPosture)

    # Passive findings
    interesting_files: List[InterestingFile] = field(default_factory=list)

    # Raw response (control GET)
    response: Optional[dict] = None

    # Meta
    status_code: Optional[int] = None
    error: Optional[str] = None
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["frameworks"] = [asdict(f) if isinstance(f, Framework) else f
                           for f in self.frameworks]
        d["cdn"] = [asdict(c) if isinstance(c, CDNHint) else c for c in self.cdn]
        d["interesting_files"] = [
            asdict(f) if isinstance(f, InterestingFile) else f
            for f in self.interesting_files
        ]
        return d

    def summary_line(self) -> str:
        """One-line summary for logs."""
        parts = []
        if self.server.name:
            parts.append(self.server.name + (f"/{self.server.version}" if self.server.version else ""))
        if self.php.detected:
            php = "PHP" + (f"/{self.php.version}" if self.php.version else "")
            if self.php.patch_status:
                php += f"[{self.php.patch_status}]"
            parts.append(php)
        if self.frameworks:
            parts.append(self.frameworks[0].name)
        if self.cdn:
            parts.append(self.cdn[0].name)
        return " | ".join(parts) if parts else "unknown stack"


# ═══════════════════════════════════════════════════════════════════════════
#  DETECTORS
# ═══════════════════════════════════════════════════════════════════════════

def detect_server(response: HTTPResult) -> ServerInfo:
    """Parse Server: header for web server name + version."""
    raw = response.server
    if not raw:
        return ServerInfo()
    for pattern, name in SERVER_SIGNATURES:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            version = match.group(1) if match.groups() else None
            return ServerInfo(name=name, version=version, raw=raw)
    # Fallback: use first token
    token = raw.split("/")[0].split()[0] if raw else None
    return ServerInfo(name=token, raw=raw)


def detect_php(response: HTTPResult) -> PHPInfo:
    """Detect PHP + version + patch status."""
    info = PHPInfo()
    powered_by = response.powered_by
    if powered_by:
        info.x_powered_by = powered_by
        match = re.search(VERSION_PATTERN, powered_by)
        if match:
            info.detected = True
            major, minor, patch = (int(x) for x in match.groups())
            info.version = f"{major}.{minor}.{patch}"
            fixed = FIXED_VERSIONS.get((major, minor))
            if fixed is not None:
                info.patch_status = "FIXED" if patch >= fixed else "VULNERABLE"
            else:
                info.patch_status = "UNKNOWN"
    # Session cookie check
    cookies = response.header_all("set-cookie")
    for c in cookies:
        if "PHPSESSID" in c.upper():
            info.detected = True
            info.session_cookie = True
            break
    # URL check
    if not info.detected and ".php" in response.final_url.lower():
        info.detected = True
    # Body marker check
    if not info.detected and b"PHP" in response.body[:4096]:
        info.detected = True
    return info


def detect_language(response: HTTPResult) -> Optional[str]:
    """Detect primary runtime language."""
    # Priority: X-Powered-By > Server > Cookie > URL
    if response.powered_by:
        pb = response.powered_by
        if "PHP" in pb:
            return "PHP"
        if "ASP.NET" in pb:
            return "ASP.NET"
        if "Express" in pb or "Node" in pb:
            return "Node.js"
        if "Servlet" in pb or "JSP" in pb:
            return "Java"
        if "Ruby" in pb:
            return "Ruby"
        if "Python" in pb:
            return "Python"
    server = response.server.lower()
    if "php" in server: return "PHP"
    if "kestrel" in server or "iis" in server: return "ASP.NET"
    if "gunicorn" in server or "uvicorn" in server or "werkzeug" in server:
        return "Python"
    if "jetty" in server or "tomcat" in server: return "Java"
    if "passenger" in server: return "Ruby"
    if "caddy" in server: return "Mixed"
    # Cookie hints
    for c in response.header_all("set-cookie"):
        cu = c.upper()
        if "PHPSESSID" in cu: return "PHP"
        if "ASP.NET_SESSIONID" in cu or "ASP.NET_SESSION" in cu: return "ASP.NET"
        if "JSESSIONID" in cu: return "Java"
        if "RAILS" in cu: return "Ruby"
        if "DJANGO" in cu or "CSRFTOKEN" in cu: return "Python"
    # URL hint
    if ".php" in response.final_url.lower():
        return "PHP"
    if ".aspx" in response.final_url.lower() or ".asp" in response.final_url.lower():
        return "ASP.NET"
    return None


def detect_frameworks(response: HTTPResult) -> List[Framework]:
    """Detect CMS/frameworks from body + headers + cookies."""
    found: List[Framework] = []
    body_lower = response.body_text.lower()
    headers_blob = "\n".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
    cookies_blob = ",".join(response.header_all("set-cookie")).lower()

    for name, patterns, category in CMS_SIGNATURES:
        evidence = []
        for pat in patterns:
            pat_l = pat.lower()
            if pat_l in body_lower or pat_l in headers_blob or pat_l in cookies_blob:
                evidence.append(pat)
        if evidence:
            confidence = "high" if len(evidence) >= 2 else "medium"
            found.append(Framework(
                name=name, category=category,
                confidence=confidence, evidence=evidence[0],
            ))

    # Deduplicate by name
    seen = set()
    unique = []
    for f in found:
        if f.name not in seen:
            seen.add(f.name)
            unique.append(f)
    return unique


def detect_cdn_hints(response: HTTPResult) -> List[CDNHint]:
    """Quick CDN/proxy/WAF hint pass (full detection in waf_detect module)."""
    hints: List[CDNHint] = []
    headers_blob = "\n".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
    cookies_blob = ",".join(response.header_all("set-cookie")).lower()
    body_lower = response.body_text.lower()

    for name, wtype, hpatterns, bpatterns, cpatterns in WAF_SIGNATURES:
        evidence = []
        for pat in hpatterns:
            try:
                if re.search(pat, headers_blob, re.IGNORECASE):
                    evidence.append(f"header:{pat}")
            except re.error:
                continue
        for pat in cpatterns:
            try:
                if re.search(pat, cookies_blob, re.IGNORECASE):
                    evidence.append(f"cookie:{pat}")
            except re.error:
                continue
        # Body patterns only checked for stronger CDN signals (avoid noise)
        if wtype in ("CDN", "Cache") or not evidence:
            for pat in bpatterns[:2]:  # limit body matches
                try:
                    if re.search(pat, body_lower, re.IGNORECASE):
                        evidence.append(f"body:{pat}")
                        break
                except re.error:
                    continue
        if evidence:
            confidence = "high" if len(evidence) >= 2 else "medium"
            hints.append(CDNHint(
                name=name, type=wtype, confidence=confidence,
                evidence=evidence[0],
            ))
    return hints


def detect_security_posture(response: HTTPResult, target_url: str) -> SecurityPosture:
    """Quick security posture from control response."""
    posture = SecurityPosture()
    posture.https = target_url.startswith("https://")
    posture.hsts = bool(response.header("strict-transport-security"))

    present = {k.lower() for k in response.headers}
    for header in SECURITY_HEADERS_QUICK:
        has = header.lower() in present
        posture.security_headers[header] = has
        if not has:
            posture.missing_headers.append(header)
    return posture


# ═══════════════════════════════════════════════════════════════════════════
#  HTTPS REDIRECT CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_https_redirect(
    target_url: str,
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig],
) -> bool:
    """
    Check if http:// redirects to https://.
    Only called when target is already https:// (to avoid double work).
    """
    parsed = urlsplit(target_url)
    if parsed.scheme != "https":
        return False
    http_url = urlunsplit(("http", parsed.netloc, parsed.path or "/", "", ""))
    try:
        r = http_get(
            http_url,
            timeout=min(timeout, 10),
            verify_ssl=False,  # http doesn't need TLS
            follow_redirects=False,
            proxy=proxy,
            retries=0,
            rate_limit=True,
        )
        if r.error or r.status_code is None:
            return False
        location = r.header("Location")
        return r.status_code in (301, 302, 307, 308) and "https://" in location.lower()
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  PASSIVE FILE CHECKS
# ═══════════════════════════════════════════════════════════════════════════

def _classify_interesting_file(
    path: str, note: str, result: HTTPResult
) -> Optional[InterestingFile]:
    """Convert a raw response into an InterestingFile if it's actually exposed."""
    if result.error or result.status_code is None:
        return None
    # Not exposed: 404, 410, 403 (403 means exists but protected — still info)
    if result.status_code in (404, 410):
        return None
    if result.status_code == 403:
        # Exists but blocked — still interesting for some files
        if path in ("/.git/HEAD", "/.env", "/.env.local", "/phpinfo.php", "/info.php"):
            return InterestingFile(
                path=path, status_code=result.status_code,
                size=len(result.body), content_type=result.content_type,
                note=f"{note} (but 403 — exists, blocked)",
                severity="low",
            )
        return None
    # 5xx errors — server has issues
    if result.status_code >= 500:
        return None
    # Determine severity
    severity = "info"
    if path in ("/.git/HEAD", "/.env", "/.env.local"):
        severity = "critical"
    elif path in ("/phpinfo.php", "/info.php"):
        severity = "critical"
    elif path in ("/backup.zip", "/config.php.bak", "/.DS_Store"):
        severity = "high"
    elif path in ("/server-status", "/phpmyadmin/", "/admin/"):
        severity = "medium"
    elif path in ("/robots.txt", "/sitemap.xml", "/crossdomain.xml"):
        severity = "info"
    elif path in ("/composer.json", "/package.json"):
        severity = "low"
    elif path in ("/api/",):
        severity = "info"

    # Sanity: HTML response for a file that should not be HTML suggests soft-404
    body_text = result.body_text.lower()
    if "not found" in body_text or "404" in body_text[:200]:
        if result.status_code == 200:
            # Soft 404 page
            return None

    return InterestingFile(
        path=path, status_code=result.status_code,
        size=len(result.body), content_type=result.content_type,
        note=note, severity=severity,
    )


def check_interesting_files(
    target_url: str,
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig],
) -> List[InterestingFile]:
    """Passive GET on common sensitive paths. Uses HEAD where safe."""
    parsed = urlsplit(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    found: List[InterestingFile] = []

    for path, note in INTERESTING_FILES:
        url = base + path
        try:
            r = http_get(
                url,
                timeout=min(timeout, 10),
                verify_ssl=verify_ssl,
                follow_redirects=False,
                proxy=proxy,
                retries=0,
                rate_limit=True,
            )
        except Exception as exc:
            Logger.debug(
                f"Passive check failed for {path}: {exc}",
                module="fingerprint",
            )
            continue
        item = _classify_interesting_file(path, note, r)
        if item:
            found.append(item)
            if item.severity in ("critical", "high"):
                Logger.warning(
                    f"Exposed: {path} (HTTP {item.status_code}, {item.severity})",
                    module="fingerprint",
                )
            else:
                Logger.info(
                    f"Found: {path} (HTTP {item.status_code}, {item.severity})",
                    module="fingerprint",
                )
    return found


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def fingerprint(
    target_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    proxy: Optional[ProxyConfig] = None,
    passive_files: bool = True,
    check_https_redirect: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
) -> FingerprintResult:
    """
    Build complete fingerprint of target.

    Args:
        target_url: full URL with scheme
        timeout: per-request timeout
        verify_ssl: TLS verify
        proxy: optional ProxyConfig
        passive_files: run passive checks on common sensitive paths
        check_https_redirect: check if http→https redirect exists
        custom_headers: additional request headers

    Returns:
        FingerprintResult with all detection info populated.
    """
    started = time.perf_counter()
    result = FingerprintResult()

    # ── Validate ──
    parsed = urlsplit(target_url)
    if not parsed.hostname:
        result.error = "invalid URL: no hostname"
        return result

    result.target = target_url
    result.final_url = target_url
    result.scheme = parsed.scheme
    result.host = parsed.hostname
    result.port = parsed.port

    headers = dict(custom_headers or {})

    # ── Control GET ──
    Logger.info(f"Fetching {target_url}", module="fingerprint")
    response = http_get(
        target_url,
        headers=headers,
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=True,
        proxy=proxy,
        retries=1,
        rate_limit=True,
    )

    if response.error:
        result.error = f"request failed: {response.error}"
        result.status_code = None
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(result.error, module="fingerprint")
        return result

    result.status_code = response.status_code
    result.final_url = response.final_url
    result.response = {
        "status_code": response.status_code,
        "reason": response.reason,
        "bytes_received": response.bytes_received,
        "elapsed_ms": round(response.elapsed * 1000, 1),
        "redirects": response.redirects,
        "server": response.server or None,
        "powered_by": response.powered_by or None,
        "content_type": response.content_type or None,
    }

    # ── Detectors ──
    result.server = detect_server(response)
    result.php = detect_php(response)
    result.language = detect_language(response)
    result.frameworks = detect_frameworks(response)
    result.cdn = detect_cdn_hints(response)
    result.security = detect_security_posture(response, target_url)

    # ── HTTPS redirect check ──
    if check_https_redirect and target_url.startswith("https://"):
        result.security.http_to_https_redirect = check_https_redirect(
            target_url, timeout, verify_ssl, proxy
        )

    # ── Passive file checks ──
    if passive_files:
        Logger.info("Running passive file checks...", module="fingerprint")
        result.interesting_files = check_interesting_files(
            target_url, timeout, verify_ssl, proxy
        )

    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    return result


def fingerprint_batch(
    targets: List[str],
    max_workers: int = 10,
    **kwargs,
) -> List[FingerprintResult]:
    """Parallel fingerprinting for multiple targets."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[FingerprintResult] = []
    progress = Logger.progress(
        total=len(targets), desc="Fingerprint", unit="target"
    )
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(fingerprint, t, **kwargs): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    Logger.error(
                        f"Fingerprint error on {target}: {exc}",
                        module="fingerprint",
                    )
                    r = FingerprintResult()
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
    "FingerprintResult",
    "ServerInfo",
    "PHPInfo",
    "Framework",
    "CDNHint",
    "SecurityPosture",
    "InterestingFile",
    "fingerprint",
    "fingerprint_batch",
    "detect_server",
    "detect_php",
    "detect_language",
    "detect_frameworks",
    "detect_cdn_hints",
    "detect_security_posture",
    "check_https_redirect",
    "check_interesting_files",
]