#!/usr/bin/env python3
"""
output/csv.py — CSV reporter for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Convert scan results into flat CSV files that open cleanly in Excel,
  Google Sheets, or any spreadsheet tool.

Output files (per scan):
  <prefix>_summary.csv      — one row per target, all module verdicts
  <prefix>_findings.csv     — one row per finding (headers/TLS/WAF/etc.)
  <prefix>_endpoints.csv    — one row per interesting file endpoint
  <prefix>_probes.csv       — one row per crash probe attempt
  <prefix>_cookies.csv      — one row per cookie (header module)
  <prefix>_tls.csv          — one row per certificate/TLS finding

Design:
  - UTF-8 with BOM (Excel compatibility)
  - RFC 4180 quoting (via csv module)
  - Header row always present
  - Safe against formula injection (prefixes =, +, -, @ with ')
  - Timestamps in ISO 8601 UTC
"""

from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

TOOL_NAME = "php2shell"
TOOL_VERSION = "3.1.0"
AUTHOR = "ATHEX BLACK HAT"

# Excel formula injection prefixes (CVE-2014-3529 style protection)
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# UTF-8 BOM for Excel
UTF8_BOM = "\ufeff"

# Separator for multi-value cells
MULTI_SEP = "; "


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _sanitize_cell(value: Any) -> str:
    """
    Sanitize a value for CSV output:
      - None → empty string
      - bool → "true"/"false"
      - list/dict → JSON-ish string
      - strings starting with formula prefix → prefixed with '
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        parts = [_sanitize_cell(v) for v in value]
        return MULTI_SEP.join(p for p in parts if p)
    if isinstance(value, dict):
        parts = [f"{k}={_sanitize_cell(v)}" for k, v in value.items()]
        return MULTI_SEP.join(p for p in parts if p)
    text = str(value)
    if text and text[0] in FORMULA_PREFIXES:
        text = "'" + text
    return text


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_parent_dir(path: str) -> None:
    """Create parent directory if missing."""
    parent = Path(path).expanduser().parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def _write_csv(
    path: str,
    headers: List[str],
    rows: List[List[Any]],
) -> str:
    """
    Write a single CSV file with UTF-8 BOM.

    Returns the path written.
    """
    _ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(
            f,
            quoting=csv.QUOTE_MINIMAL,
            escapechar="\\",
            lineterminator="\r\n",  # RFC 4180
        )
        writer.writerow([_sanitize_cell(h) for h in headers])
        for row in rows:
            writer.writerow([_sanitize_cell(c) for c in row])
    return path


# ═══════════════════════════════════════════════════════════════════════════
#  SUMMARY ROW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

SUMMARY_COLUMNS = [
    # Target
    "target",
    "final_url",
    "scheme",
    "host",
    "port",
    "status_code",
    # Stack
    "server",
    "server_version",
    "php_detected",
    "php_version",
    "php_patch_status",
    "language",
    "frameworks",
    "cdn",
    # Security
    "https",
    "http_to_https_redirect",
    "hsts",
    "missing_headers",
    "header_grade",
    "header_score",
    # WAF
    "waf_detected",
    "waf_name",
    "waf_type",
    "waf_confidence",
    "waf_verdict",
    "bypass_possible",
    "bypass_techniques",
    # TLS
    "tls_grade",
    "tls_score",
    "tls_protocol",
    "tls_cipher",
    "cert_subject_cn",
    "cert_issuer",
    "cert_days_until_expiry",
    "cert_self_signed",
    "cert_expired",
    # Takeover
    "takeover_vulnerable",
    "takeover_provider",
    "takeover_confidence",
    # Crash / CVE
    "crash_vulnerable",
    "crash_verdict",
    "crash_sapi",
    "crash_confidence",
    "crash_reason",
    # Meta
    "total_elapsed_ms",
    "error",
    "timestamp",
]


def _extract_summary_row(target_result: dict) -> List[Any]:
    """Extract a flat row from a combined per-target result dict."""
    fp = target_result.get("fingerprint") or {}
    hdr = target_result.get("headers") or {}
    waf = target_result.get("waf") or {}
    bypass = target_result.get("bypass") or {}
    tls = target_result.get("tls") or {}
    takeover = target_result.get("takeover") or {}
    crash = target_result.get("crash") or {}

    cert = tls.get("certificate") or {}
    versions = tls.get("versions") or {}
    cipher = tls.get("cipher") or {}

    php = fp.get("php") or {}
    server = fp.get("server") or {}
    security = fp.get("security") or {}

    frameworks = fp.get("frameworks") or []
    fw_names = [f.get("name") for f in frameworks if f.get("name")]

    cdn_list = fp.get("cdn") or []
    cdn_names = [c.get("name") for c in cdn_list if c.get("name")]

    primary_waf = waf.get("primary") or {}

    score = hdr.get("score") or {}
    tls_score = tls.get("score", 0)

    return [
        # Target
        target_result.get("target", ""),
        fp.get("final_url", ""),
        fp.get("scheme", ""),
        fp.get("host", ""),
        fp.get("port", ""),
        fp.get("status_code", ""),
        # Stack
        server.get("name", ""),
        server.get("version", ""),
        php.get("detected", False),
        php.get("version", ""),
        php.get("patch_status", ""),
        fp.get("language", ""),
        fw_names,
        cdn_names,
        # Security
        security.get("https", False),
        security.get("http_to_https_redirect", False),
        security.get("hsts", False),
        security.get("missing_headers", []),
        score.get("grade", ""),
        score.get("total_score", ""),
        # WAF
        waf.get("detected", False),
        primary_waf.get("name", ""),
        primary_waf.get("type", ""),
        waf.get("confidence", ""),
        waf.get("verdict", ""),
        bypass.get("bypassable", False),
        bypass.get("working_techniques", []),
        # TLS
        tls.get("grade", ""),
        tls_score,
        versions.get("preferred", "") or cipher.get("protocol", ""),
        cipher.get("negotiated", ""),
        cert.get("subject_cn", ""),
        cert.get("issuer_org") or cert.get("issuer_cn", ""),
        cert.get("days_until_expiry", ""),
        cert.get("is_self_signed", False),
        cert.get("expired", False),
        # Takeover
        takeover.get("vulnerable", ""),
        takeover.get("provider", ""),
        takeover.get("confidence", ""),
        # Crash
        crash.get("vulnerable", ""),
        crash.get("verdict", ""),
        crash.get("sapi", ""),
        crash.get("confidence", ""),
        crash.get("reason", ""),
        # Meta
        target_result.get("total_elapsed_ms", ""),
        target_result.get("error", ""),
        target_result.get("timestamp", _utc_now_iso()),
    ]


# ═══════════════════════════════════════════════════════════════════════════
#  FINDINGS ROW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

FINDINGS_COLUMNS = [
    "target",
    "module",
    "category",
    "severity",
    "id",
    "title",
    "description",
    "value",
    "recommendation",
    "cwe",
    "owasp",
    "evidence",
    "timestamp",
]


def _extract_finding_rows(target_result: dict) -> List[List[Any]]:
    """Flatten all findings from all modules into rows."""
    rows: List[List[Any]] = []
    target = target_result.get("target", "")
    ts = target_result.get("timestamp", _utc_now_iso())

    # Headers module findings
    hdr = target_result.get("headers") or {}
    for f in hdr.get("findings") or []:
        rows.append([
            target, "headers", f.get("category", ""), f.get("severity", ""),
            f.get("id", ""), f.get("title", ""), f.get("description", ""),
            f.get("value", ""), f.get("recommendation", ""),
            f.get("cwe", ""), f.get("owasp", ""),
            f.get("header", ""), ts,
        ])

    # TLS findings
    tls = target_result.get("tls") or {}
    for f in tls.get("findings") or []:
        rows.append([
            target, "tls", "tls", f.get("severity", ""),
            f.get("id", ""), f.get("title", ""), f.get("description", ""),
            "", f.get("recommendation", ""),
            f.get("cwe", ""), "", "", ts,
        ])

    # WAF detection (as info finding)
    waf = target_result.get("waf") or {}
    if waf.get("detected"):
        primary = waf.get("primary") or {}
        rows.append([
            target, "waf_detect", "waf", "info",
            f"waf-detected-{primary.get('name', 'unknown').lower().replace(' ', '-')}",
            f"WAF detected: {primary.get('name', '?')}",
            f"Type: {primary.get('type', '?')}, "
            f"confidence: {waf.get('confidence', '?')}",
            primary.get("name", ""), "", "", "",
            "; ".join(primary.get("evidence", [])), ts,
        ])

    # WAF bypass (as medium finding — mitigation weakness)
    bypass = target_result.get("bypass") or {}
    if bypass.get("bypassable"):
        rows.append([
            target, "waf_bypass", "mitigation", "medium",
            "waf-bypassable",
            "WAF bypassable",
            f"WAF can be bypassed via: {', '.join(bypass.get('working_techniques', []))}",
            ", ".join(bypass.get("working_techniques", [])),
            "Treat bypass as mitigation weakness, not vulnerability. "
            "Chain with real exploit to report.",
            "", "",
            f"{bypass.get('bypassed_count', 0)}/"
            f"{len(bypass.get('attempts', []))} techniques worked",
            ts,
        ])

    # Takeover (critical)
    takeover = target_result.get("takeover") or {}
    if takeover.get("vulnerable") is True:
        rows.append([
            target, "takeover", "subdomain-takeover", takeover.get("severity", "high"),
            "subdomain-takeover",
            f"Subdomain takeover: {takeover.get('provider', '?')}",
            takeover.get("reason", ""),
            takeover.get("provider", ""),
            f"Claim at: {(takeover.get('evidence') or [{}])[0].get('claim_url', '')}",
            "CWE-350", "",
            takeover.get("dns", {}).get("final_cname", ""),
            ts,
        ])

    # Crash (critical)
    crash = target_result.get("crash") or {}
    if crash.get("vulnerable") is True:
        rows.append([
            target, "crash", "cve", "critical",
            "cve-2026-109618-9",
            f"PHP multipart crash: {crash.get('sapi', '?')}",
            crash.get("reason", ""),
            crash.get("sapi", ""),
            "Upgrade PHP to fixed version.",
            "CWE-400", "",
            f"confidence={crash.get('confidence', '?')}, "
            f"crash_count={crash.get('crash_count', 0)}",
            ts,
        ])

    # Fingerprint interesting files (as findings)
    fp = target_result.get("fingerprint") or {}
    for item in fp.get("interesting_files") or []:
        sev = item.get("severity", "info")
        if sev == "info":
            continue
        rows.append([
            target, "fingerprint", "exposed-file", sev,
            f"exposed-{item.get('path', '').replace('/', '-').strip('-')}",
            f"Exposed file: {item.get('path', '')}",
            f"HTTP {item.get('status_code')}, "
            f"{item.get('size', 0)}B, {item.get('content_type', '')}",
            item.get("path", ""),
            f"Remove or restrict access to {item.get('path', '')}",
            "", "",
            item.get("note", ""),
            ts,
        ])

    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  ENDPOINTS ROW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

ENDPOINTS_COLUMNS = [
    "target",
    "path",
    "status_code",
    "size_bytes",
    "content_type",
    "severity",
    "note",
    "timestamp",
]


def _extract_endpoint_rows(target_result: dict) -> List[List[Any]]:
    rows: List[List[Any]] = []
    target = target_result.get("target", "")
    ts = target_result.get("timestamp", _utc_now_iso())
    fp = target_result.get("fingerprint") or {}
    for item in fp.get("interesting_files") or []:
        rows.append([
            target,
            item.get("path", ""),
            item.get("status_code", ""),
            item.get("size", ""),
            item.get("content_type", ""),
            item.get("severity", "info"),
            item.get("note", ""),
            ts,
        ])
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  PROBES ROW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

PROBES_COLUMNS = [
    "target",
    "probe_index",
    "size_mib",
    "parts",
    "nested_keys",
    "status_code",
    "reason",
    "response_bytes",
    "bytes_sent",
    "elapsed_ms",
    "error",
    "timestamp",
]


def _extract_probe_rows(target_result: dict) -> List[List[Any]]:
    rows: List[List[Any]] = []
    target = target_result.get("target", "")
    ts = target_result.get("timestamp", _utc_now_iso())
    crash = target_result.get("crash") or {}
    for p in crash.get("probes") or []:
        rows.append([
            target,
            p.get("index", ""),
            p.get("size_mib", ""),
            p.get("parts", ""),
            p.get("nested_keys", ""),
            p.get("status_code", ""),
            p.get("reason", ""),
            p.get("response_bytes", ""),
            p.get("bytes_sent", ""),
            p.get("elapsed_ms", ""),
            p.get("error", ""),
            ts,
        ])
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  COOKIES ROW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

COOKIES_COLUMNS = [
    "target",
    "name",
    "secure",
    "httponly",
    "samesite",
    "domain",
    "path",
    "max_age",
    "severity",
    "issues",
    "timestamp",
]


def _extract_cookie_rows(target_result: dict) -> List[List[Any]]:
    rows: List[List[Any]] = []
    target = target_result.get("target", "")
    ts = target_result.get("timestamp", _utc_now_iso())
    hdr = target_result.get("headers") or {}
    for c in hdr.get("cookies") or []:
        rows.append([
            target,
            c.get("name", ""),
            c.get("secure", False),
            c.get("httponly", False),
            c.get("samesite", "") or "",
            c.get("domain", "") or "",
            c.get("path", "") or "",
            c.get("max_age", "") if c.get("max_age") is not None else "",
            c.get("severity", ""),
            c.get("issues", []),
            ts,
        ])
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  TLS ROW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

TLS_COLUMNS = [
    "target",
    "grade",
    "score",
    "tls_versions",
    "preferred_version",
    "cipher",
    "cipher_protocol",
    "cipher_bits",
    "forward_secrecy",
    "aead",
    "cert_cn",
    "cert_issuer_org",
    "cert_not_after",
    "cert_days_until_expiry",
    "cert_self_signed",
    "cert_expired",
    "cert_san",
    "cert_sha256",
    "error",
    "timestamp",
]


def _extract_tls_rows(target_result: dict) -> List[List[Any]]:
    tls = target_result.get("tls") or {}
    if not tls:
        return []
    cert = tls.get("certificate") or {}
    versions = tls.get("versions") or {}
    cipher = tls.get("cipher") or {}
    return [[
        target_result.get("target", ""),
        tls.get("grade", ""),
        tls.get("score", ""),
        versions.get("supported", []),
        versions.get("preferred", "") or "",
        cipher.get("negotiated", "") or "",
        cipher.get("protocol", "") or "",
        cipher.get("bits", "") if cipher.get("bits") is not None else "",
        cipher.get("forward_secrecy", False),
        cipher.get("aead", False),
        cert.get("subject_cn", "") or "",
        cert.get("issuer_org", "") or "",
        cert.get("not_after", "") or "",
        cert.get("days_until_expiry", "") if cert.get("days_until_expiry") is not None else "",
        cert.get("is_self_signed", False),
        cert.get("expired", False),
        cert.get("san", []),
        cert.get("sha256_fingerprint", "") or "",
        tls.get("error", "") or "",
        target_result.get("timestamp", _utc_now_iso()),
    ]]


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CSVExportResult:
    """Result of a CSV export operation."""
    success: bool = False
    files_written: Dict[str, str] = field(default_factory=dict)
    files_failed: Dict[str, str] = field(default_factory=dict)
    total_rows: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        return (
            f"{len(self.files_written)} file(s) written, "
            f"{sum(self.total_rows.values())} total rows"
        )


def export_csv(
    results: List[dict],
    prefix: str = "php2shell",
    out_dir: str = ".",
    include_empty: bool = False,
    files: Optional[List[str]] = None,
) -> CSVExportResult:
    """
    Export scan results to CSV files.

    Args:
        results: List of per-target result dicts (each containing
                 keys: target, fingerprint, headers, waf, bypass, tls,
                 takeover, crash, total_elapsed_ms, error, timestamp)
        prefix: filename prefix (e.g. "scan" → "scan_summary.csv")
        out_dir: directory to write files
        include_empty: write files even with 0 rows
        files: subset of ["summary", "findings", "endpoints", "probes",
               "cookies", "tls"]. None = all.

    Returns:
        CSVExportResult with paths + row counts.
    """
    export = CSVExportResult()
    out_dir = out_dir or "."
    prefix = prefix or "php2shell"
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # Default: all sections
    if files is None:
        files = ["summary", "findings", "endpoints", "probes", "cookies", "tls"]

    # ── Summary ──
    if "summary" in files:
        try:
            rows = [_extract_summary_row(r) for r in results]
            if rows or include_empty:
                path = os.path.join(out_dir, f"{prefix}_summary.csv")
                _write_csv(path, SUMMARY_COLUMNS, rows)
                export.files_written["summary"] = path
                export.total_rows["summary"] = len(rows)
        except Exception as exc:
            export.files_failed["summary"] = str(exc)

    # ── Findings ──
    if "findings" in files:
        try:
            rows: List[List[Any]] = []
            for r in results:
                rows.extend(_extract_finding_rows(r))
            if rows or include_empty:
                path = os.path.join(out_dir, f"{prefix}_findings.csv")
                _write_csv(path, FINDINGS_COLUMNS, rows)
                export.files_written["findings"] = path
                export.total_rows["findings"] = len(rows)
        except Exception as exc:
            export.files_failed["findings"] = str(exc)

    # ── Endpoints ──
    if "endpoints" in files:
        try:
            rows = []
            for r in results:
                rows.extend(_extract_endpoint_rows(r))
            if rows or include_empty:
                path = os.path.join(out_dir, f"{prefix}_endpoints.csv")
                _write_csv(path, ENDPOINTS_COLUMNS, rows)
                export.files_written["endpoints"] = path
                export.total_rows["endpoints"] = len(rows)
        except Exception as exc:
            export.files_failed["endpoints"] = str(exc)

    # ── Probes ──
    if "probes" in files:
        try:
            rows = []
            for r in results:
                rows.extend(_extract_probe_rows(r))
            if rows or include_empty:
                path = os.path.join(out_dir, f"{prefix}_probes.csv")
                _write_csv(path, PROBES_COLUMNS, rows)
                export.files_written["probes"] = path
                export.total_rows["probes"] = len(rows)
        except Exception as exc:
            export.files_failed["probes"] = str(exc)

    # ── Cookies ──
    if "cookies" in files:
        try:
            rows = []
            for r in results:
                rows.extend(_extract_cookie_rows(r))
            if rows or include_empty:
                path = os.path.join(out_dir, f"{prefix}_cookies.csv")
                _write_csv(path, COOKIES_COLUMNS, rows)
                export.files_written["cookies"] = path
                export.total_rows["cookies"] = len(rows)
        except Exception as exc:
            export.files_failed["cookies"] = str(exc)

    # ── TLS ──
    if "tls" in files:
        try:
            rows = []
            for r in results:
                rows.extend(_extract_tls_rows(r))
            if rows or include_empty:
                path = os.path.join(out_dir, f"{prefix}_tls.csv")
                _write_csv(path, TLS_COLUMNS, rows)
                export.files_written["tls"] = path
                export.total_rows["tls"] = len(rows)
        except Exception as exc:
            export.files_failed["tls"] = str(exc)

    # ── Status ──
    if export.files_failed:
        export.error = f"failed sections: {list(export.files_failed.keys())}"
    export.success = bool(export.files_written) and not export.files_failed
    return export


# ═══════════════════════════════════════════════════════════════════════════
#  SINGLE-FILE FLAT EXPORT (alternative)
# ═══════════════════════════════════════════════════════════════════════════

FLAT_COLUMNS = [
    "target", "module", "kind", "severity",
    "name", "status", "detail", "bytes", "elapsed_ms", "timestamp",
]


def export_csv_flat(
    results: List[dict],
    path: str = "php2shell_flat.csv",
) -> CSVExportResult:
    """
    Export everything into a single flat CSV — useful when you want
    one file with all events, filtered by `module` / `kind` in Excel.

    Schema:
      target, module, kind, severity, name, status, detail,
      bytes, elapsed_ms, timestamp
    """
    export = CSVExportResult()
    rows: List[List[Any]] = []

    for r in results:
        target = r.get("target", "")
        ts = r.get("timestamp", _utc_now_iso())

        # Fingerprint: interesting files
        fp = r.get("fingerprint") or {}
        for item in fp.get("interesting_files") or []:
            rows.append([
                target, "fingerprint", "exposed_file",
                item.get("severity", "info"),
                item.get("path", ""),
                f"HTTP {item.get('status_code')}",
                item.get("note", ""),
                item.get("size", ""),
                "", ts,
            ])

        # Headers findings
        hdr = r.get("headers") or {}
        for f in hdr.get("findings") or []:
            rows.append([
                target, "headers", f.get("category", ""),
                f.get("severity", ""), f.get("title", ""),
                "", f.get("description", ""), "", "", ts,
            ])

        # TLS findings
        tls = r.get("tls") or {}
        for f in tls.get("findings") or []:
            rows.append([
                target, "tls", "tls", f.get("severity", ""),
                f.get("title", ""), "", f.get("description", ""),
                "", "", ts,
            ])

        # WAF detection
        waf = r.get("waf") or {}
        if waf.get("detected"):
            p = waf.get("primary") or {}
            rows.append([
                target, "waf_detect", "detection",
                "info", p.get("name", ""),
                f"HTTP {waf.get('verdict', '')}",
                "; ".join(p.get("evidence", [])), "", "", ts,
            ])

        # WAF bypass
        bypass = r.get("bypass") or {}
        if bypass.get("bypassable"):
            rows.append([
                target, "waf_bypass", "bypass",
                "medium", "WAF bypassable",
                f"{bypass.get('bypassed_count', 0)}/{len(bypass.get('attempts', []))}",
                ", ".join(bypass.get("working_techniques", [])),
                "", "", ts,
            ])

        # Takeover
        tk = r.get("takeover") or {}
        if tk.get("vulnerable") is True:
            rows.append([
                target, "takeover", "vulnerability",
                tk.get("severity", "high"),
                f"{tk.get('provider', '?')} takeover",
                f"confidence={tk.get('confidence', '?')}",
                tk.get("reason", ""), "", "", ts,
            ])

        # Crash probes
        crash = r.get("crash") or {}
        for p in crash.get("probes") or []:
            rows.append([
                target, "crash", "probe",
                "critical" if crash.get("vulnerable") is True and p.get("index") == 1 else "info",
                f"probe {p.get('index')} ({p.get('size_mib')} MiB)",
                f"HTTP {p.get('status_code')}",
                p.get("error") or p.get("reason", ""),
                p.get("response_bytes", ""),
                p.get("elapsed_ms", ""),
                ts,
            ])

    try:
        if rows:
            _write_csv(path, FLAT_COLUMNS, rows)
            export.files_written["flat"] = path
            export.total_rows["flat"] = len(rows)
            export.success = True
        else:
            export.success = True  # no data, no error
    except Exception as exc:
        export.files_failed["flat"] = str(exc)
        export.error = str(exc)

    return export


# ═══════════════════════════════════════════════════════════════════════════
#  COLUMN REFERENCE (for --help)
# ═══════════════════════════════════════════════════════════════════════════

def get_column_reference() -> Dict[str, List[str]]:
    """Return column schemas for all CSV files (for docs/help)."""
    return {
        "summary": SUMMARY_COLUMNS,
        "findings": FINDINGS_COLUMNS,
        "endpoints": ENDPOINTS_COLUMNS,
        "probes": PROBES_COLUMNS,
        "cookies": COOKIES_COLUMNS,
        "tls": TLS_COLUMNS,
        "flat": FLAT_COLUMNS,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "CSVExportResult",
    "export_csv",
    "export_csv_flat",
    "get_column_reference",
    "SUMMARY_COLUMNS",
    "FINDINGS_COLUMNS",
    "ENDPOINTS_COLUMNS",
    "PROBES_COLUMNS",
    "COOKIES_COLUMNS",
    "TLS_COLUMNS",
    "FLAT_COLUMNS",
]