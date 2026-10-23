#!/usr/bin/env python3
"""
modules/waf_detect.py — Full WAF/CDN/IPS detection for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Accurate WAF/CDN/IPS fingerprinting via multi-signal analysis.

Stages:
  1. PASSIVE     — signature match on benign GET headers/body/cookies
  2. ACTIVE      — trigger benign-but-suspicious payloads, observe blocks
  3. DIFFERENTIAL— compare benign vs malicious response (status/body/size/timing)
  4. CORROBORATE — repeat to filter out flaky servers / random 5xx
  5. PROFILE     — determine vendor + type + confidence + likely bypasses

Why not just fingerprint.py?
  fingerprint.py does a quick single-request hint (fast, 1 req).
  This module does 6-8 requests with behavioral analysis (accurate, slow).
  Use fingerprint for bulk; use this for targeted deep-dive.

Signals used:
  - Header signature (cf-ray, x-sucuri-id, ...)
  - Cookie signature (__cf_bm, visid_incap, ...)
  - Body fingerprint ("Access Denied", "cloudflare", ...)
  - Differential status (200 → 403 on suspicious payload)
  - Differential body (same content but shorter on attack)
  - Latency anomaly (WAF adds ~100-300ms on triggers)
  - Retry consistency (same result N times = confident)
"""

from __future__ import annotations

import re
import statistics
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, urlencode

from core.config import (
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    WAF_SIGNATURES,
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

# Suspicious-but-benign trigger payloads (not real exploits)
# Used to elicit a WAF response — safe, single-char triggers
TRIGGERS = [
    # (name, query_value, description)
    ("sqli-basic", "' OR '1'='1", "SQL injection trigger"),
    ("xss-basic", "<script>alert(1)</script>", "XSS trigger"),
    ("traversal", "../../etc/passwd", "Path traversal trigger"),
    ("cmd", ";id", "Command injection trigger"),
    ("sqli-union", "1 UNION SELECT NULL--", "UNION-based SQLi"),
]

# Statuses that indicate WAF blocked the request
WAF_BLOCK_STATUSES = {403, 406, 429, 501, 503}

# Statuses indicating server processed the request normally
NORMAL_STATUSES = {200, 201, 204, 301, 302, 303, 307, 308}

# Latency threshold (ms) for WAF detection (WAF adds overhead on triggers)
LATENCY_DELTA_MS = 150

# Confidence levels
CONF_HIGH = "high"
CONF_MEDIUM = "medium"
CONF_LOW = "low"
CONF_NONE = "none"


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class WAFDetection:
    """A single WAF/CDN/IPS detection with evidence."""
    name: str
    type: str  # CDN | WAF | CDN/WAF | Cache | IPS
    confidence: str = CONF_MEDIUM
    score: int = 0
    evidence: List[str] = field(default_factory=list)
    source: str = ""  # passive | active | differential | latency

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PassiveResult:
    """Passive signature detection result."""
    detections: List[WAFDetection] = field(default_factory=list)
    headers_seen: List[str] = field(default_factory=list)
    cookies_seen: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detections": [d.to_dict() for d in self.detections],
            "headers_seen": self.headers_seen,
            "cookies_seen": self.cookies_seen,
        }


@dataclass
class ActiveResult:
    """Active trigger testing result."""
    triggers_tested: int = 0
    blocked_count: int = 0
    block_ratio: float = 0.0
    typical_block_status: Optional[int] = None
    block_statuses_seen: List[int] = field(default_factory=list)
    samples: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DifferentialResult:
    """Differential analysis result."""
    status_changed: bool = False
    size_shrunk: bool = False
    latency_anomaly: bool = False
    body_changed: bool = False
    benign_status: Optional[int] = None
    suspicious_status: Optional[int] = None
    benign_bytes: int = 0
    suspicious_bytes: int = 0
    benign_latency_ms: float = 0.0
    suspicious_latency_ms: float = 0.0
    delta_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WAFResult:
    """Complete WAF detection result."""
    target: str = ""
    detected: bool = False
    primary: Optional[WAFDetection] = None
    all_detections: List[WAFDetection] = field(default_factory=list)

    # Sub-stages
    passive: Optional[PassiveResult] = None
    active: Optional[ActiveResult] = None
    differential: Optional[DifferentialResult] = None

    # Verdict
    verdict: str = "UNKNOWN"  # WAF_PRESENT | WAF_PROBABLE | NO_WAF | INCONCLUSIVE | ERROR
    confidence: str = CONF_NONE
    reason: str = ""

    # Meta
    requests_made: int = 0
    error: Optional[str] = None
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["primary"] = self.primary.to_dict() if self.primary else None
        d["all_detections"] = [x.to_dict() for x in self.all_detections]
        d["passive"] = self.passive.to_dict() if self.passive else None
        d["active"] = self.active.to_dict() if self.active else None
        d["differential"] = (
            self.differential.to_dict() if self.differential else None
        )
        return d

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.detected and self.primary:
            return (
                f"{self.primary.name} ({self.primary.type}, "
                f"confidence={self.confidence})"
            )
        return f"{self.verdict} — {self.reason}"


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _build_trigger_url(base_url: str, trigger_value: str, key: str = "q") -> str:
    """Append trigger as query param."""
    parsed = urlsplit(base_url)
    trigger_qs = urlencode({key: trigger_value})
    new_query = f"{parsed.query}&{trigger_qs}" if parsed.query else trigger_qs
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", new_query, "")
    )


def _headers_blob(headers: Dict[str, str]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()


def _cookies_blob(headers: Dict[str, str]) -> str:
    parts = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            parts.extend(v.split("\n"))
    return ",".join(parts).lower()


def _safe_re_search(pattern: str, text: str) -> bool:
    try:
        return bool(re.search(pattern, text, re.IGNORECASE))
    except re.error:
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  STAGE 1: PASSIVE DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_passive(response: HTTPResult) -> PassiveResult:
    """Match signature database against benign response."""
    result = PassiveResult()

    hdrs = _headers_blob(response.headers)
    body = response.body_text.lower()
    cookies = _cookies_blob(response.headers)

    # Track headers/cookies for reporting
    result.headers_seen = sorted(set(response.headers.keys()))
    if cookies:
        result.cookies_seen = [c.split("=")[0].strip() for c in cookies.split(",") if "=" in c]

    for name, wtype, hpatterns, bpatterns, cpatterns in WAF_SIGNATURES:
        evidence: List[str] = []
        score = 0

        for pat in hpatterns:
            if _safe_re_search(pat, hdrs):
                evidence.append(f"header:{pat}")
                score += 2

        for pat in cpatterns:
            if _safe_re_search(pat, cookies):
                evidence.append(f"cookie:{pat}")
                score += 2

        for pat in bpatterns:
            if _safe_re_search(pat, body):
                evidence.append(f"body:{pat}")
                score += 1

        if evidence:
            confidence = CONF_HIGH if score >= 4 else CONF_MEDIUM if score >= 2 else CONF_LOW
            result.detections.append(WAFDetection(
                name=name,
                type=wtype,
                confidence=confidence,
                score=score,
                evidence=evidence[:5],
                source="passive",
            ))

    # Sort by score descending
    result.detections.sort(key=lambda d: d.score, reverse=True)
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  STAGE 2: ACTIVE TRIGGER TESTING
# ═══════════════════════════════════════════════════════════════════════════

def _test_active_triggers(
    target_url: str,
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig],
    custom_headers: Dict[str, str],
    attempts_per_trigger: int = 1,
) -> Tuple[ActiveResult, List[HTTPResult]]:
    """Send benign-but-suspicious triggers; observe WAF responses."""
    result = ActiveResult()
    responses: List[HTTPResult] = []

    for trigger_name, trigger_value, _desc in TRIGGERS:
        url = _build_trigger_url(target_url, trigger_value)
        for _ in range(attempts_per_trigger):
            try:
                r = http_get(
                    url,
                    headers=dict(custom_headers),
                    timeout=timeout,
                    verify_ssl=verify_ssl,
                    follow_redirects=False,
                    proxy=proxy,
                    retries=0,
                    rate_limit=True,
                )
            except Exception as exc:
                Logger.debug(
                    f"Trigger {trigger_name} error: {exc}",
                    module="waf_detect",
                )
                continue

            result.triggers_tested += 1
            responses.append(r)

            if r.status_code in WAF_BLOCK_STATUSES:
                result.blocked_count += 1
                result.block_statuses_seen.append(r.status_code)
                if result.typical_block_status is None:
                    result.typical_block_status = r.status_code

            result.samples.append({
                "trigger": trigger_name,
                "status": r.status_code,
                "bytes": len(r.body),
                "elapsed_ms": round(r.elapsed * 1000, 1),
                "error": r.error,
            })

    if result.triggers_tested:
        result.block_ratio = result.blocked_count / result.triggers_tested
    return result, responses


# ═══════════════════════════════════════════════════════════════════════════
#  STAGE 3: DIFFERENTIAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_differential(
    benign: HTTPResult,
    triggers: List[HTTPResult],
) -> DifferentialResult:
    """Compare benign vs suspicious responses."""
    result = DifferentialResult()
    if benign.error or not triggers:
        return result

    result.benign_status = benign.status_code
    result.benign_bytes = len(benign.body)
    result.benign_latency_ms = round(benign.elapsed * 1000, 1)

    # Use median for stable comparison
    valid = [t for t in triggers if not t.error and t.status_code is not None]
    if not valid:
        return result

    statuses = [t.status_code for t in valid]
    sizes = [len(t.body) for t in valid]
    latencies = [t.elapsed * 1000 for t in valid]

    # Most common trigger status
    result.suspicious_status = max(set(statuses), key=statuses.count)
    result.suspicious_bytes = int(statistics.median(sizes))
    result.suspicious_latency_ms = round(statistics.median(latencies), 1)

    # Status changed to block?
    if (
        result.benign_status in NORMAL_STATUSES
        and result.suspicious_status in WAF_BLOCK_STATUSES
    ):
        result.status_changed = True

    # Size shrank significantly (WAF block pages are usually shorter)
    if result.benign_bytes > 200 and result.suspicious_bytes < result.benign_bytes * 0.3:
        result.size_shrunk = True

    # Latency anomaly
    result.delta_ms = result.suspicious_latency_ms - result.benign_latency_ms
    if result.delta_ms > LATENCY_DELTA_MS:
        result.latency_anomaly = True

    # Body similarity check (rough — different first 100 bytes)
    if benign.body and valid[0].body:
        if benign.body[:100] != valid[0].body[:100]:
            result.body_changed = True

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  STAGE 4: VERDICT
# ═══════════════════════════════════════════════════════════════════════════

def _compute_verdict(
    passive: PassiveResult,
    active: ActiveResult,
    differential: DifferentialResult,
) -> Tuple[bool, str, str, str, List[WAFDetection]]:
    """
    Combine all signals into a verdict.

    Returns: (detected, verdict, confidence, reason, all_detections)
    """
    all_detections: List[WAFDetection] = list(passive.detections)

    # ── Active-based detections (vendor-agnostic) ──
    if active.block_ratio >= 0.4:
        conf = CONF_HIGH if active.block_ratio >= 0.8 else CONF_MEDIUM
        all_detections.append(WAFDetection(
            name="Unknown WAF (active)",
            type="WAF",
            confidence=conf,
            score=int(active.block_ratio * 10),
            evidence=[
                f"{active.blocked_count}/{active.triggers_tested} triggers blocked",
                f"typical status={active.typical_block_status}",
            ],
            source="active",
        ))

    # ── Differential-based detections ──
    diff_signals = sum([
        differential.status_changed,
        differential.size_shrunk,
        differential.latency_anomaly,
        differential.body_changed,
    ])
    if diff_signals >= 2 and active.block_ratio < 0.4:
        all_detections.append(WAFDetection(
            name="Unknown WAF (differential)",
            type="WAF",
            confidence=CONF_MEDIUM if diff_signals == 2 else CONF_HIGH,
            score=diff_signals,
            evidence=[
                s for s, flag in [
                    ("status changed", differential.status_changed),
                    ("size shrank", differential.size_shrunk),
                    ("latency anomaly", differential.latency_anomaly),
                    ("body changed", differential.body_changed),
                ] if flag
            ],
            source="differential",
        ))

    # ── Verdict ──
    if not all_detections:
        # Maybe server returns 4xx to everything — inconclusive
        if active.triggers_tested == 0:
            return False, "INCONCLUSIVE", CONF_LOW, "no requests succeeded", []
        return False, "NO_WAF", CONF_MEDIUM, "no WAF signals in any stage", []

    # Rank by score
    all_detections.sort(key=lambda d: d.score, reverse=True)
    primary = all_detections[0]

    # Boost primary if multiple sources agree
    sources = {d.source for d in all_detections if d.name == primary.name}
    if len(sources) >= 2:
        primary.confidence = CONF_HIGH
        primary.score += 2

    # Boost if passive + active both detected same-name vendor
    names = [d.name for d in all_detections]
    if names.count(primary.name) >= 2 and primary.confidence != CONF_HIGH:
        primary.confidence = CONF_HIGH

    detected = True
    if primary.confidence == CONF_HIGH:
        verdict = "WAF_PRESENT"
        reason = f"{primary.name} confirmed ({', '.join(primary.evidence[:2])})"
    elif primary.confidence == CONF_MEDIUM:
        verdict = "WAF_PROBABLE"
        reason = f"{primary.name} detected ({', '.join(primary.evidence[:2])})"
    else:
        verdict = "WAF_PROBABLE"
        reason = f"possible {primary.name} (weak signals)"

    return detected, verdict, primary.confidence, reason, all_detections


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def detect_waf(
    target_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    proxy: Optional[ProxyConfig] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    full_scan: bool = True,
    triggers_per_test: int = 1,
) -> WAFResult:
    """
    Run full WAF/CDN/IPS detection against target.

    Args:
        target_url: URL to probe
        timeout: per-request timeout
        verify_ssl: TLS verify
        proxy: optional ProxyConfig
        custom_headers: additional headers (auth, etc.)
        full_scan: if False, only run passive + 1 trigger (fast, less accurate)
        triggers_per_test: how many times to send each trigger (retries for consistency)

    Returns:
        WAFResult with all evidence + verdict.
    """
    started = time.perf_counter()
    result = WAFResult()
    custom_headers = custom_headers or {}

    # Validate
    parsed = urlsplit(target_url)
    if not parsed.hostname:
        result.error = "invalid URL: no hostname"
        return result

    result.target = target_url
    requests_made = 0

    Logger.audit(f"Starting WAF/CDN/IPS detection: {target_url}", module="waf_detect")

    # ── Stage 1: Benign baseline (passive) ──
    Logger.info("Stage 1/4: passive fingerprint", module="waf_detect")
    base_headers = {
        "User-Agent": custom_headers.get("User-Agent", DEFAULT_USER_AGENT),
        "Accept": "*/*",
        **{k: v for k, v in custom_headers.items() if k.lower() != "user-agent"},
    }
    try:
        benign = http_get(
            target_url,
            headers=base_headers,
            timeout=timeout,
            verify_ssl=verify_ssl,
            follow_redirects=True,
            proxy=proxy,
            retries=0,
            rate_limit=True,
        )
        requests_made += 1
    except Exception as exc:
        result.error = f"baseline request failed: {exc}"
        result.verdict = "ERROR"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(result.error, module="waf_detect")
        return result

    if benign.error:
        result.error = f"baseline request failed: {benign.error}"
        result.verdict = "ERROR"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.error(result.error, module="waf_detect")
        return result

    result.passive = _detect_passive(benign)
    if result.passive.detections:
        top = result.passive.detections[0]
        Logger.waf(
            f"Passive: {top.name} ({top.type}, confidence={top.confidence}, "
            f"score={top.score})",
            module="waf_detect",
        )
    else:
        Logger.info("Passive: no WAF signatures in headers/body", module="waf_detect")

    # ── Stage 2/3: Active + differential ──
    if full_scan:
        Logger.info("Stage 2/4: active trigger testing", module="waf_detect")
        triggers_per = max(1, triggers_per_test) if full_scan else 1
        active, trigger_responses = _test_active_triggers(
            target_url, timeout, verify_ssl, proxy, base_headers,
            attempts_per_trigger=triggers_per,
        )
        requests_made += active.triggers_tested
        result.active = active
        if active.triggers_tested:
            Logger.info(
                f"Active: {active.blocked_count}/{active.triggers_tested} "
                f"triggers blocked (ratio={active.block_ratio:.0%})",
                module="waf_detect",
            )

        Logger.info("Stage 3/4: differential analysis", module="waf_detect")
        result.differential = _analyze_differential(benign, trigger_responses)
        if result.differential.status_changed:
            Logger.info(
                f"Differential: status changed "
                f"{result.differential.benign_status}→{result.differential.suspicious_status}",
                module="waf_detect",
            )
        if result.differential.latency_anomaly:
            Logger.info(
                f"Differential: latency +{result.differential.delta_ms:.0f}ms on trigger",
                module="waf_detect",
            )
    else:
        # Fast mode: single trigger
        fast_url = _build_trigger_url(target_url, TRIGGERS[0][1])
        try:
            fast_resp = http_get(
                fast_url, headers=base_headers, timeout=timeout,
                verify_ssl=verify_ssl, follow_redirects=False,
                proxy=proxy, retries=0, rate_limit=True,
            )
            requests_made += 1
            active = ActiveResult(
                triggers_tested=1,
                blocked_count=1 if fast_resp.status_code in WAF_BLOCK_STATUSES else 0,
                block_ratio=1.0 if fast_resp.status_code in WAF_BLOCK_STATUSES else 0.0,
                typical_block_status=fast_resp.status_code if fast_resp.status_code in WAF_BLOCK_STATUSES else None,
            )
            result.active = active
        except Exception:
            pass

    # ── Stage 4: Verdict ──
    Logger.info("Stage 4/4: computing verdict", module="waf_detect")
    detected, verdict, confidence, reason, all_detections = _compute_verdict(
        result.passive,
        result.active or ActiveResult(),
        result.differential or DifferentialResult(),
    )

    result.detected = detected
    result.verdict = verdict
    result.confidence = confidence
    result.reason = reason
    result.all_detections = all_detections
    result.primary = all_detections[0] if all_detections else None
    result.requests_made = requests_made
    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    # Final log
    if detected and result.primary:
        Logger.waf(
            f"{verdict}: {result.primary.name} ({result.primary.type}, "
            f"confidence={confidence}) — {reason}",
            module="waf_detect",
        )
    else:
        Logger.info(f"{verdict}: {reason}", module="waf_detect")

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  BATCH
# ═══════════════════════════════════════════════════════════════════════════

def detect_waf_batch(
    targets: List[str],
    max_workers: int = 5,
    **kwargs,
) -> List[WAFResult]:
    """Parallel WAF detection."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[WAFResult] = []
    progress = Logger.progress(
        total=len(targets), desc="WAF detect", unit="target"
    )
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(detect_waf, t, **kwargs): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    Logger.error(
                        f"WAF detect error on {target}: {exc}",
                        module="waf_detect",
                    )
                    r = WAFResult(target=target)
                    r.error = str(exc)
                    r.verdict = "ERROR"
                    results.append(r)
                progress.update(1)
    finally:
        progress.close()
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "WAFResult",
    "WAFDetection",
    "PassiveResult",
    "ActiveResult",
    "DifferentialResult",
    "detect_waf",
    "detect_waf_batch",
    "TRIGGERS",
    "WAF_BLOCK_STATUSES",
]