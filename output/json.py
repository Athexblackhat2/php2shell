#!/usr/bin/env python3
"""
output/json.py — JSON reporter for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Produce structured, machine-readable JSON output for automation,
  SIEM ingestion, CI/CD pipelines, and programmatic post-processing.

Formats supported:
  - aggregate  : one big JSON object with all results
  - ndjson     : newline-delimited JSON (one object per line, streaming)
  - per-target : one JSON file per target (bulk scans)

Design:
  - Schema versioned (v1.0)
  - Deterministic key order (sort_keys=True)
  - Sensitive headers redacted
  - Bytes encoded as base64 only if requested
  - Pretty (indent=2) or compact (separators) modes
  - Compatible with jq, Python json, JS JSON.parse
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.config import TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, CVES


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA_VERSION = "1.0"

# Max embedded string length (body snippets, evidence)
MAX_STRING_LEN = 4096

# Bytes encoded when include_raw_bytes=True
MAX_RAW_BYTES = 8192

# Sensitive header names to redact
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _truncate(value: str, limit: int = MAX_STRING_LEN) -> str:
    if value is None:
        return ""
    if len(value) <= limit:
        return value
    return value[:limit] + f"... [truncated, {len(value) - limit} bytes]"


def _encode_bytes(data: bytes, include: bool) -> Optional[str]:
    """Optionally encode raw bytes as base64; else None."""
    if not include or not data:
        return None
    try:
        return base64.b64encode(data[:MAX_RAW_BYTES]).decode("ascii")
    except Exception:
        return None


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return headers with sensitive values redacted."""
    out: Dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADERS:
            out[name] = "<redacted>"
        else:
            out[name] = _truncate(str(value))
    return out


def _sanitize(obj: Any, include_raw_bytes: bool = False) -> Any:
    """
    Recursively sanitize an object for JSON serialization:
      - bytes → base64 (if include_raw_bytes) else truncated str
      - str → truncated
      - dict/list → recurse
      - sets/tuples → lists
      - callables → string repr
      - datetime → iso string
    """
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return _truncate(obj)
    if isinstance(obj, bytes):
        if include_raw_bytes:
            return _encode_bytes(obj, True)
        return _truncate(obj.decode("utf-8", errors="replace"))
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _sanitize(v, include_raw_bytes) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_sanitize(v, include_raw_bytes) for v in obj]
    if callable(obj):
        return f"<callable {getattr(obj, '__name__', '?')}>"
    return _truncate(str(obj))


def _ensure_parent_dir(path: str) -> None:
    parent = Path(path).expanduser().parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
#  PAYLOAD BUILDERS
# ═══════════════════════════════════════════════════════════════════════════

def _tool_metadata() -> dict:
    """Common metadata block included in every payload."""
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "author": TOOL_AUTHOR,
        "cves": CVES,
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now_iso(),
    }


def _normalize_target_result(raw: dict, include_raw_bytes: bool) -> dict:
    """
    Take a per-target result dict from orchestrator and normalize
    into a clean, deterministic schema.
    """
    out: Dict[str, Any] = {
        "target": raw.get("target", ""),
        "timestamp": raw.get("timestamp", _utc_now_iso()),
        "total_elapsed_ms": raw.get("total_elapsed_ms"),
        "error": raw.get("error"),
    }

    # Fingerprint
    fp = raw.get("fingerprint")
    if fp:
        out["fingerprint"] = _sanitize(fp, include_raw_bytes)

    # Headers
    hdr = raw.get("headers")
    if hdr:
        # Deep copy + sanitize
        hdr_clean = _sanitize(hdr, include_raw_bytes)
        # Redact raw headers if present
        if isinstance(hdr_clean, dict) and "headers" in hdr_clean:
            hdr_clean["headers"] = _redact_headers(
                hdr.get("headers") or {}
            )
        out["headers"] = hdr_clean

    # WAF
    waf = raw.get("waf")
    if waf:
        out["waf"] = _sanitize(waf, include_raw_bytes)

    # Bypass
    bypass = raw.get("bypass")
    if bypass:
        out["bypass"] = _sanitize(bypass, include_raw_bytes)

    # TLS
    tls = raw.get("tls")
    if tls:
        out["tls"] = _sanitize(tls, include_raw_bytes)

    # Takeover
    takeover = raw.get("takeover")
    if takeover:
        out["takeover"] = _sanitize(takeover, include_raw_bytes)

    # Crash
    crash = raw.get("crash")
    if crash:
        out["crash"] = _sanitize(crash, include_raw_bytes)

    return out


def build_aggregate_payload(
    results: List[dict],
    include_raw_bytes: bool = False,
    include_summary: bool = True,
) -> dict:
    """
    Build the full aggregate JSON payload.

    Structure:
      {
        "schema_version": "1.0",
        "tool": "...",
        "generated_at": "...",
        "scan_metadata": {...},
        "summary": {...},
        "results": [ {...}, ... ]
      }
    """
    payload: Dict[str, Any] = _tool_metadata()

    # Normalize results
    normalized = [
        _normalize_target_result(r, include_raw_bytes) for r in results
    ]

    # Scan metadata
    payload["scan_metadata"] = {
        "total_targets": len(normalized),
        "scan_started_at": normalized[0]["timestamp"] if normalized else None,
        "scan_ended_at": _utc_now_iso(),
    }

    # Summary
    if include_summary:
        payload["summary"] = _compute_summary(normalized)

    payload["results"] = normalized
    return payload


def _compute_summary(results: List[dict]) -> dict:
    """Aggregate counts across all results."""
    summary: Dict[str, Any] = {
        "total_targets": len(results),
        "with_errors": 0,
        "vulnerable_targets": 0,
        "vulnerable_by_module": {
            "crash": 0,
            "takeover": 0,
            "waf_bypass": 0,
        },
        "waf_detected": 0,
        "waf_vendors": {},
        "php_vulnerable": 0,
        "php_fixed": 0,
        "php_unknown": 0,
        "tls_grade_distribution": {},
        "headers_grade_distribution": {},
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    }

    for r in results:
        if r.get("error"):
            summary["with_errors"] += 1

        # Crash vuln
        crash = r.get("crash") or {}
        if crash.get("vulnerable") is True:
            summary["vulnerable_by_module"]["crash"] += 1
            summary["vulnerable_targets"] += 1

        # Takeover vuln
        takeover = r.get("takeover") or {}
        if takeover.get("vulnerable") is True:
            summary["vulnerable_by_module"]["takeover"] += 1
            summary["vulnerable_targets"] += 1

        # Bypass
        bypass = r.get("bypass") or {}
        if bypass.get("bypassable"):
            summary["vulnerable_by_module"]["waf_bypass"] += 1

        # WAF
        waf = r.get("waf") or {}
        if waf.get("detected"):
            summary["waf_detected"] += 1
            name = (waf.get("primary") or {}).get("name", "Unknown")
            summary["waf_vendors"][name] = (
                summary["waf_vendors"].get(name, 0) + 1
            )

        # PHP version
        fp = r.get("fingerprint") or {}
        php = fp.get("php") or {}
        status = php.get("patch_status")
        if status == "VULNERABLE":
            summary["php_vulnerable"] += 1
        elif status == "FIXED":
            summary["php_fixed"] += 1
        elif php.get("detected"):
            summary["php_unknown"] += 1

        # TLS grade
        tls = r.get("tls") or {}
        grade = tls.get("grade")
        if grade:
            summary["tls_grade_distribution"][grade] = (
                summary["tls_grade_distribution"].get(grade, 0) + 1
            )

        # Headers grade
        hdr = r.get("headers") or {}
        hscore = hdr.get("score") or {}
        hgrade = hscore.get("grade")
        if hgrade:
            summary["headers_grade_distribution"][hgrade] = (
                summary["headers_grade_distribution"].get(hgrade, 0) + 1
            )

        # Findings severity
        for f in (hdr.get("findings") or []):
            sev = f.get("severity", "info")
            if sev in summary["severity_counts"]:
                summary["severity_counts"][sev] += 1
        for f in (tls.get("findings") or []):
            sev = f.get("severity", "info")
            if sev in summary["severity_counts"]:
                summary["severity_counts"][sev] += 1

    return summary


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class JSONExportResult:
    """Result of a JSON export operation."""
    success: bool = False
    path: Optional[str] = None
    bytes_written: int = 0
    records: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        return f"{self.path} ({self.records} records, {self.bytes_written} bytes)"


def export_json(
    results: List[dict],
    path: str = "php2shell_results.json",
    pretty: bool = True,
    include_raw_bytes: bool = False,
    include_summary: bool = True,
    indent: int = 2,
) -> JSONExportResult:
    """
    Export all results to a single aggregate JSON file.

    Args:
        results: list of per-target result dicts
        path: output file path
        pretty: indent output (True = 2 spaces, False = compact)
        include_raw_bytes: base64-encode raw request/response bodies
        include_summary: add aggregate summary block
        indent: indent size when pretty=True

    Returns:
        JSONExportResult with path, size, record count.
    """
    export = JSONExportResult()
    try:
        payload = build_aggregate_payload(
            results,
            include_raw_bytes=include_raw_bytes,
            include_summary=include_summary,
        )
        _ensure_parent_dir(path)

        with open(path, "w", encoding="utf-8") as f:
            if pretty:
                json.dump(
                    payload, f, indent=indent, sort_keys=True,
                    ensure_ascii=False, default=str,
                )
            else:
                json.dump(
                    payload, f, separators=(",", ":"), sort_keys=True,
                    ensure_ascii=False, default=str,
                )

        export.success = True
        export.path = path
        export.bytes_written = os.path.getsize(path)
        export.records = len(results)
        return export

    except OSError as exc:
        export.error = f"write failed: {exc}"
        return export
    except (TypeError, ValueError) as exc:
        export.error = f"serialization failed: {exc}"
        return export


def export_ndjson(
    results: List[dict],
    path: str = "php2shell_results.ndjson",
    include_raw_bytes: bool = False,
    include_metadata_header: bool = True,
) -> JSONExportResult:
    """
    Export results as NDJSON (newline-delimited JSON).

    Line 1 (optional): metadata header
    Line 2..N: one result per line (compact JSON)

    Perfect for streaming ingestion (Splunk, Elastic, jq -c).
    """
    export = JSONExportResult()
    try:
        _ensure_parent_dir(path)
        lines_written = 0

        with open(path, "w", encoding="utf-8") as f:
            if include_metadata_header:
                header = {
                    **_tool_metadata(),
                    "type": "metadata",
                    "total_targets": len(results),
                }
                f.write(json.dumps(header, sort_keys=True, ensure_ascii=False, default=str))
                f.write("\n")
                lines_written += 1

            for r in results:
                normalized = _normalize_target_result(r, include_raw_bytes)
                record = {
                    "type": "target",
                    "target": normalized.get("target", ""),
                    "timestamp": normalized.get("timestamp"),
                    "data": normalized,
                }
                f.write(json.dumps(record, sort_keys=True, ensure_ascii=False, default=str))
                f.write("\n")
                lines_written += 1

        export.success = True
        export.path = path
        export.bytes_written = os.path.getsize(path)
        export.records = lines_written
        return export

    except OSError as exc:
        export.error = f"write failed: {exc}"
        return export


def export_per_target(
    results: List[dict],
    out_dir: str = "./json_reports",
    pretty: bool = True,
    include_raw_bytes: bool = False,
    include_summary: bool = True,
) -> JSONExportResult:
    """
    Export one JSON file per target.

    Filename: <sanitized-host>.json (host part from URL).
    """
    export = JSONExportResult()
    out_dir = out_dir or "./json_reports"
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    files_written = 0
    errors: List[str] = []
    total_bytes = 0

    for r in results:
        try:
            target = r.get("target", "unknown")
            # Sanitize filename
            from urllib.parse import urlsplit
            parsed = urlsplit(target if "://" in target else "https://" + target)
            base = parsed.hostname or "unknown"
            if parsed.port:
                base += f"_{parsed.port}"
            safe_name = "".join(
                c if c.isalnum() or c in "._-" else "_" for c in base
            )
            path = os.path.join(out_dir, f"{safe_name}.json")

            payload = build_aggregate_payload(
                [r],
                include_raw_bytes=include_raw_bytes,
                include_summary=include_summary,
            )
            with open(path, "w", encoding="utf-8") as f:
                if pretty:
                    json.dump(payload, f, indent=2, sort_keys=True,
                              ensure_ascii=False, default=str)
                else:
                    json.dump(payload, f, separators=(",", ":"),
                              sort_keys=True, ensure_ascii=False, default=str)
            files_written += 1
            total_bytes += os.path.getsize(path)
        except Exception as exc:
            errors.append(f"{r.get('target', '?')}: {exc}")

    if errors:
        export.error = "; ".join(errors[:3])
        if len(errors) > 3:
            export.error += f" (+{len(errors) - 3} more)"
    export.success = files_written > 0 or not errors
    export.path = out_dir
    export.bytes_written = total_bytes
    export.records = files_written
    return export


def export_json_both(
    results: List[dict],
    base_path: str = "php2shell_results",
    include_raw_bytes: bool = False,
) -> Dict[str, JSONExportResult]:
    """
    Convenience: write aggregate + NDJSON + per-target in one call.

    base_path: e.g. "reports/scan" → creates
        reports/scan.json
        reports/scan.ndjson
        reports/scan_per_target/
    """
    base = Path(base_path)
    out_dir = str(base.parent) if base.parent != Path(".") else "."
    stem = base.stem or "php2shell"

    return {
        "aggregate": export_json(
            results,
            path=f"{base}.json",
            include_raw_bytes=include_raw_bytes,
        ),
        "ndjson": export_ndjson(
            results,
            path=f"{base}.ndjson",
            include_raw_bytes=include_raw_bytes,
        ),
        "per_target": export_per_target(
            results,
            out_dir=os.path.join(out_dir, f"{stem}_per_target"),
            include_raw_bytes=include_raw_bytes,
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  SMALL UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def dumps(result_or_list) -> str:
    """
    Convenience: serialize a result (or list) to JSON string.

    Useful for one-off debugging.
    """
    if isinstance(result_or_list, dict):
        payload = _normalize_target_result(result_or_list, False)
    else:
        payload = build_aggregate_payload(result_or_list)
    return json.dumps(payload, indent=2, sort_keys=True,
                      ensure_ascii=False, default=str)


def validate_payload(payload: dict) -> List[str]:
    """
    Validate that a payload has the expected schema keys.

    Returns list of issues (empty = valid).
    """
    issues: List[str] = []
    required = ["tool", "version", "schema_version", "generated_at", "results"]
    for key in required:
        if key not in payload:
            issues.append(f"missing required key: {key}")
    if "results" in payload and not isinstance(payload["results"], list):
        issues.append("results must be a list")
    return issues


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "JSONExportResult",
    "SCHEMA_VERSION",
    "export_json",
    "export_ndjson",
    "export_per_target",
    "export_json_both",
    "build_aggregate_payload",
    "dumps",
    "validate_payload",
]