#!/usr/bin/env python3
"""
output/html.py — HTML report generator for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Generate a professional, self-contained HTML report suitable for:
    - Client deliverables (bug bounty / pentest)
    - Team triage (filter by severity, module, target)
    - Archive/print (PDF via browser Ctrl+P)
    - Sharing (single file, no external assets)

Design:
  - Zero external dependencies (all CSS/JS inlined)
  - Dark/light theme toggle (pure CSS + tiny JS)
  - Interactive filtering (severity, module, search)
  - Inline SVG charts (grade distribution, severity counts)
  - HTML-escaped output (no self-XSS in report)
  - Print stylesheet (@media print)
  - Responsive layout
"""

from __future__ import annotations

import html
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, CVES


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA_VERSION = "1.0"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#65a30d",
    "info":     "#0891b2",
}
SEVERITY_LABELS = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
}


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def e(value: Any) -> str:
    """HTML-escape any value (None → empty)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _attr(value: Any) -> str:
    """HTML-escape for attribute values."""
    return e(value)


def _safe_id(text: str) -> str:
    """Sanitize a string for use as an HTML id/data attribute."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(text))[:64]


def _truncate(text: str, limit: int = 2000) -> str:
    if not text:
        return ""
    s = str(text)
    if len(s) <= limit:
        return s
    return s[:limit] + f"... [+{len(s) - limit} chars]"


def _ensure_parent(path: str) -> None:
    parent = Path(path).expanduser().parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
#  DATA EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _extract_targets(results: List[dict]) -> List[dict]:
    """Return normalized per-target rows for rendering."""
    out = []
    for r in results:
        fp = r.get("fingerprint") or {}
        hdr = r.get("headers") or {}
        waf = r.get("waf") or {}
        bypass = r.get("bypass") or {}
        tls = r.get("tls") or {}
        takeover = r.get("takeover") or {}
        crash = r.get("crash") or {}

        php = fp.get("php") or {}
        server = fp.get("server") or {}
        security = fp.get("security") or {}
        hdr_score = hdr.get("score") or {}
        primary_waf = waf.get("primary") or {}
        cert = tls.get("certificate") or {}

        # Determine overall status
        is_vuln = (
            crash.get("vulnerable") is True
            or takeover.get("vulnerable") is True
        )
        is_warn = (
            bypass.get("bypassable") is True
            or waf.get("detected") is True
            or php.get("patch_status") == "VULNERABLE"
        )

        if r.get("error"):
            status = "error"
        elif is_vuln:
            status = "vuln"
        elif is_warn:
            status = "warn"
        else:
            status = "ok"

        out.append({
            "target": r.get("target", ""),
            "final_url": fp.get("final_url", r.get("target", "")),
            "status": status,
            "error": r.get("error"),
            "server": server.get("name", ""),
            "server_version": server.get("version", ""),
            "php_detected": php.get("detected", False),
            "php_version": php.get("version", ""),
            "php_patch": php.get("patch_status", ""),
            "language": fp.get("language", ""),
            "frameworks": [f.get("name") for f in (fp.get("frameworks") or [])],
            "cdn": [c.get("name") for c in (fp.get("cdn") or [])],
            "https": security.get("https", False),
            "hsts": security.get("hsts", False),
            "missing_headers": security.get("missing_headers", []),
            "headers_grade": hdr_score.get("grade", ""),
            "headers_score": hdr_score.get("total_score", ""),
            "waf_detected": waf.get("detected", False),
            "waf_name": primary_waf.get("name", ""),
            "waf_type": primary_waf.get("type", ""),
            "waf_confidence": waf.get("confidence", ""),
            "bypass_possible": bypass.get("bypassable", False),
            "bypass_techniques": bypass.get("working_techniques", []),
            "tls_grade": tls.get("grade", ""),
            "tls_protocol": (tls.get("versions") or {}).get("preferred", ""),
            "tls_cipher": (tls.get("cipher") or {}).get("negotiated", ""),
            "cert_cn": cert.get("subject_cn", ""),
            "cert_days": cert.get("days_until_expiry", ""),
            "cert_self_signed": cert.get("is_self_signed", False),
            "takeover_vuln": takeover.get("vulnerable"),
            "takeover_provider": takeover.get("provider", ""),
            "takeover_confidence": takeover.get("confidence", ""),
            "crash_vuln": crash.get("vulnerable"),
            "crash_verdict": crash.get("verdict", ""),
            "crash_sapi": crash.get("sapi", ""),
            "crash_confidence": crash.get("confidence", ""),
            "crash_reason": crash.get("reason", ""),
            "total_elapsed_ms": r.get("total_elapsed_ms", ""),
            "timestamp": r.get("timestamp", ""),
            # Raw data for modal
            "raw_findings": _collect_findings(r),
        })
    return out


def _collect_findings(target: dict) -> List[dict]:
    """Flatten all findings for a single target (for modal display)."""
    findings: List[dict] = []

    # Headers
    hdr = target.get("headers") or {}
    for f in hdr.get("findings") or []:
        findings.append({
            "module": "headers",
            "severity": f.get("severity", "info"),
            "title": f.get("title", ""),
            "description": _truncate(f.get("description", ""), 500),
            "recommendation": f.get("recommendation", ""),
            "cwe": f.get("cwe", ""),
        })

    # TLS
    tls = target.get("tls") or {}
    for f in tls.get("findings") or []:
        findings.append({
            "module": "tls",
            "severity": f.get("severity", "info"),
            "title": f.get("title", ""),
            "description": _truncate(f.get("description", ""), 500),
            "recommendation": f.get("recommendation", ""),
            "cwe": f.get("cwe", ""),
        })

    # WAF
    waf = target.get("waf") or {}
    if waf.get("detected"):
        p = waf.get("primary") or {}
        findings.append({
            "module": "waf_detect",
            "severity": "info",
            "title": f"WAF detected: {p.get('name', '?')} ({p.get('type', '?')})",
            "description": f"Confidence: {waf.get('confidence', '?')}. "
                           f"Evidence: {', '.join(p.get('evidence', [])[:3])}",
            "recommendation": "",
        })

    # Bypass
    bypass = target.get("bypass") or {}
    if bypass.get("bypassable"):
        findings.append({
            "module": "waf_bypass",
            "severity": "medium",
            "title": "WAF bypassable",
            "description": f"Working techniques: {', '.join(bypass.get('working_techniques', []))}",
            "recommendation": "Treat as mitigation weakness. Chain with real exploit to report.",
        })

    # Takeover
    tk = target.get("takeover") or {}
    if tk.get("vulnerable") is True:
        evidence = (tk.get("evidence") or [{}])[0]
        findings.append({
            "module": "takeover",
            "severity": "critical",
            "title": f"Subdomain takeover: {tk.get('provider', '?')}",
            "description": tk.get("reason", ""),
            "recommendation": f"Claim at: {evidence.get('claim_url', 'N/A')}",
        })

    # Crash
    crash = target.get("crash") or {}
    if crash.get("vulnerable") is True:
        findings.append({
            "module": "crash",
            "severity": "critical",
            "title": f"PHP multipart crash: {crash.get('sapi', '?')}",
            "description": crash.get("reason", ""),
            "recommendation": "Upgrade PHP to fixed version.",
        })

    # Exposed files
    fp = target.get("fingerprint") or {}
    for item in fp.get("interesting_files") or []:
        sev = item.get("severity", "info")
        if sev == "info":
            continue
        findings.append({
            "module": "fingerprint",
            "severity": sev,
            "title": f"Exposed file: {item.get('path', '')}",
            "description": f"HTTP {item.get('status_code')}, {item.get('size', 0)}B. {item.get('note', '')}",
            "recommendation": f"Remove or restrict access to {item.get('path', '')}.",
        })

    # Sort by severity
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: severity_rank.get(f["severity"], 99))
    return findings


def _count_severity(targets: List[dict]) -> Dict[str, int]:
    """Count findings by severity across all targets."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for t in targets:
        for f in t.get("raw_findings", []):
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
    return counts


# ═══════════════════════════════════════════════════════════════════════════
#  CSS
# ═══════════════════════════════════════════════════════════════════════════

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --bg: #0f172a;
    --bg-elev: #1e293b;
    --bg-elev-2: #334155;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --border: #334155;
    --accent: #38bdf8;
    --accent-dark: #0284c7;
    --critical: #dc2626;
    --high: #ea580c;
    --medium: #ca8a04;
    --low: #65a30d;
    --info: #0891b2;
    --ok: #10b981;
    --vuln: #dc2626;
    --warn: #f59e0b;
    --error: #7f1d1d;
}

[data-theme="light"] {
    --bg: #f8fafc;
    --bg-elev: #ffffff;
    --bg-elev-2: #e2e8f0;
    --text: #0f172a;
    --text-dim: #64748b;
    --border: #cbd5e1;
    --accent: #0284c7;
    --accent-dark: #075985;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    font-size: 14px;
    padding: 24px;
    transition: background 0.2s, color 0.2s;
}

.container { max-width: 1400px; margin: 0 auto; }

/* Header */
.header {
    border-bottom: 2px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 16px;
}
.header h1 {
    font-size: 24px;
    font-weight: 700;
    color: var(--accent);
    display: flex;
    align-items: center;
    gap: 12px;
}
.header .brand {
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 14px;
    color: var(--text-dim);
    margin-top: 4px;
}
.header .meta {
    text-align: right;
    color: var(--text-dim);
    font-size: 12px;
}
.theme-toggle {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 12px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
    margin-left: 8px;
}
.theme-toggle:hover { border-color: var(--accent); }

/* Stats cards */
.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
}
.stat-card {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}
.stat-card .num { font-size: 32px; font-weight: 700; line-height: 1; }
.stat-card .label { font-size: 12px; color: var(--text-dim); margin-top: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-card.critical .num { color: var(--critical); }
.stat-card.high .num { color: var(--high); }
.stat-card.medium .num { color: var(--medium); }
.stat-card.low .num { color: var(--low); }
.stat-card.info .num { color: var(--info); }
.stat-card.ok .num { color: var(--ok); }
.stat-card.vuln .num { color: var(--vuln); }

/* Charts */
.charts {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 24px;
}
@media (max-width: 768px) { .charts { grid-template-columns: 1fr; } }
.chart-card {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
}
.chart-card h3 {
    font-size: 13px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
}

/* Filters */
.filters {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    align-items: center;
}
.filters input[type="search"] {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 14px;
    flex: 1;
    min-width: 240px;
}
.filters input[type="search"]:focus { outline: 2px solid var(--accent); border-color: transparent; }
.filter-btn {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 12px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
    transition: all 0.15s;
}
.filter-btn:hover { border-color: var(--accent); }
.filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }

/* Table */
.results-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-elev);
    border-radius: 8px;
    overflow: hidden;
    font-size: 13px;
}
.results-table thead {
    background: var(--bg-elev-2);
}
.results-table th {
    text-align: left;
    padding: 10px 12px;
    font-size: 11px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
    border-bottom: 1px solid var(--border);
}
.results-table td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
.results-table tbody tr { cursor: pointer; transition: background 0.15s; }
.results-table tbody tr:hover { background: var(--bg-elev-2); }
.results-table tbody tr:last-child td { border-bottom: none; }

.status-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #fff;
}
.status-badge.vuln   { background: var(--vuln); }
.status-badge.warn   { background: var(--warn); color: #000; }
.status-badge.ok     { background: var(--ok); }
.status-badge.error  { background: var(--error); }

.grade {
    display: inline-block;
    min-width: 28px;
    text-align: center;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 12px;
    font-family: "JetBrains Mono", monospace;
}
.grade-a { background: #166534; color: #bbf7d0; }
.grade-b { background: #3f6212; color: #d9f99d; }
.grade-c { background: #854d0e; color: #fef08a; }
.grade-d { background: #9a3412; color: #fed7aa; }
.grade-f { background: #7f1d1d; color: #fecaca; }

.tag {
    display: inline-block;
    padding: 2px 6px;
    margin: 1px 2px;
    background: var(--bg-elev-2);
    border-radius: 3px;
    font-size: 11px;
    color: var(--text-dim);
    font-family: "JetBrains Mono", monospace;
}

/* Modal */
.modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    z-index: 1000;
    padding: 40px 20px;
    overflow-y: auto;
}
.modal-overlay.open { display: block; }
.modal {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 8px;
    max-width: 900px;
    margin: 0 auto;
    padding: 24px;
}
.modal h2 {
    font-size: 18px;
    margin-bottom: 4px;
    color: var(--accent);
}
.modal .modal-sub {
    color: var(--text-dim);
    font-size: 12px;
    margin-bottom: 20px;
    word-break: break-all;
}
.modal .close-btn {
    position: absolute;
    top: 12px;
    right: 12px;
    background: var(--bg-elev-2);
    border: none;
    color: var(--text);
    font-size: 20px;
    width: 32px;
    height: 32px;
    border-radius: 6px;
    cursor: pointer;
}
.modal .close-btn:hover { background: var(--critical); }
.modal-section { margin-top: 20px; }
.modal-section h3 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-dim);
    margin-bottom: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
}
.modal-section table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.modal-section table td {
    padding: 6px 0;
    vertical-align: top;
}
.modal-section table td:first-child {
    color: var(--text-dim);
    width: 30%;
    font-size: 12px;
}
.finding-card {
    background: var(--bg-elev-2);
    border-left: 3px solid var(--info);
    padding: 10px 12px;
    border-radius: 4px;
    margin-bottom: 8px;
}
.finding-card.critical { border-left-color: var(--critical); }
.finding-card.high { border-left-color: var(--high); }
.finding-card.medium { border-left-color: var(--medium); }
.finding-card.low { border-left-color: var(--low); }
.finding-card .finding-title {
    font-weight: 600;
    font-size: 13px;
    margin-bottom: 4px;
}
.finding-card .finding-desc {
    color: var(--text-dim);
    font-size: 12px;
    margin-bottom: 4px;
}
.finding-card .finding-rec {
    color: var(--accent);
    font-size: 12px;
    font-style: italic;
}

/* Footer */
.footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-dim);
    font-size: 12px;
}

/* Print */
@media print {
    body { background: #fff; color: #000; padding: 0; }
    .theme-toggle, .filters, .modal-overlay, .close-btn { display: none !important; }
    .stat-card, .chart-card, .results-table {
        background: #fff !important;
        border: 1px solid #ccc !important;
        break-inside: avoid;
    }
    .results-table thead { background: #eee !important; }
    .header h1 { color: #000 !important; }
    .status-badge, .grade { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    a { color: #000 !important; text-decoration: none; }
}
"""


# ═══════════════════════════════════════════════════════════════════════════
#  JS
# ═══════════════════════════════════════════════════════════════════════════

JS = """
(function() {
    // Theme toggle
    const root = document.documentElement;
    const saved = localStorage.getItem('php2shell-theme');
    if (saved) root.setAttribute('data-theme', saved);

    window.toggleTheme = function() {
        const cur = root.getAttribute('data-theme') || 'dark';
        const next = cur === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        localStorage.setItem('php2shell-theme', next);
    };

    // Filter state
    let filterText = '';
    let filterStatus = 'all';

    function applyFilters() {
        const rows = document.querySelectorAll('tbody tr[data-status]');
        rows.forEach(row => {
            const status = row.getAttribute('data-status');
            const text = row.textContent.toLowerCase();
            const matchesStatus = filterStatus === 'all' || status === filterStatus;
            const matchesText = !filterText || text.includes(filterText);
            row.style.display = (matchesStatus && matchesText) ? '' : 'none';
        });
    }

    window.setFilter = function(status, btn) {
        filterStatus = status;
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
        applyFilters();
    };

    window.filterByText = function(value) {
        filterText = (value || '').toLowerCase().trim();
        applyFilters();
    };

    // Modal
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal-content');

    window.openModal = function(dataId) {
        const data = window.__TARGETS__ && window.__TARGETS__[dataId];
        if (!data) return;
        modal.innerHTML = renderModal(data);
        overlay.classList.add('open');
        document.body.style.overflow = 'hidden';
    };

    window.closeModal = function() {
        overlay.classList.remove('open');
        document.body.style.overflow = '';
    };

    overlay && overlay.addEventListener('click', function(ev) {
        if (ev.target === overlay) closeModal();
    });

    document.addEventListener('keydown', function(ev) {
        if (ev.key === 'Escape') closeModal();
    });

    // Row click handlers
    document.querySelectorAll('tr[data-target-id]').forEach(row => {
        row.addEventListener('click', function() {
            openModal(row.getAttribute('data-target-id'));
        });
    });

    function escape(s) {
        if (s === null || s === undefined) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function rowKV(k, v) {
        return '<tr><td>' + escape(k) + '</td><td>' + escape(v) + '</td></tr>';
    }

    function renderModal(d) {
        let html = '<button class="close-btn" onclick="closeModal()">×</button>';
        html += '<h2>' + escape(d.target) + '</h2>';
        html += '<div class="modal-sub">' + escape(d.final_url || '') + '</div>';

        // Overview
        html += '<div class="modal-section"><h3>Overview</h3><table>';
        html += rowKV('Status', d.status);
        if (d.error) html += rowKV('Error', d.error);
        if (d.server) html += rowKV('Server', d.server + (d.server_version ? '/' + d.server_version : ''));
        if (d.php_detected) html += rowKV('PHP', d.php_version + (d.php_patch ? ' [' + d.php_patch + ']' : ''));
        if (d.language) html += rowKV('Language', d.language);
        if (d.frameworks && d.frameworks.length) html += rowKV('Frameworks', d.frameworks.join(', '));
        if (d.cdn && d.cdn.length) html += rowKV('CDN', d.cdn.join(', '));
        if (d.https !== undefined) html += rowKV('HTTPS', d.https ? 'Yes' : 'No');
        if (d.hsts !== undefined) html += rowKV('HSTS', d.hsts ? 'Yes' : 'No');
        if (d.total_elapsed_ms) html += rowKV('Scan time', d.total_elapsed_ms + ' ms');
        html += '</table></div>';

        // WAF
        if (d.waf_detected) {
            html += '<div class="modal-section"><h3>WAF / CDN</h3><table>';
            html += rowKV('Vendor', d.waf_name + ' (' + d.waf_type + ')');
            html += rowKV('Confidence', d.waf_confidence);
            if (d.bypass_possible) {
                html += rowKV('Bypassable', 'Yes — ' + (d.bypass_techniques || []).join(', '));
            }
            html += '</table></div>';
        }

        // TLS
        if (d.tls_grade) {
            html += '<div class="modal-section"><h3>TLS / Certificate</h3><table>';
            html += rowKV('Grade', d.tls_grade);
            if (d.tls_protocol) html += rowKV('Protocol', d.tls_protocol);
            if (d.tls_cipher) html += rowKV('Cipher', d.tls_cipher);
            if (d.cert_cn) html += rowKV('Cert CN', d.cert_cn);
            if (d.cert_days !== '' && d.cert_days !== undefined) html += rowKV('Expires in', d.cert_days + ' days');
            if (d.cert_self_signed) html += rowKV('Self-signed', 'Yes');
            html += '</table></div>';
        }

        // Takeover
        if (d.takeover_vuln === true) {
            html += '<div class="modal-section"><h3>Subdomain Takeover</h3><table>';
            html += rowKV('Vulnerable', 'YES');
            html += rowKV('Provider', d.takeover_provider);
            html += rowKV('Confidence', d.takeover_confidence);
            html += '</table></div>';
        }

        // Crash
        if (d.crash_vuln === true) {
            html += '<div class="modal-section"><h3>PHP Crash (CVE)</h3><table>';
            html += rowKV('Vulnerable', 'YES');
            html += rowKV('SAPI', d.crash_sapi);
            html += rowKV('Confidence', d.crash_confidence);
            html += rowKV('Reason', d.crash_reason);
            html += '</table></div>';
        }

        // Headers grade
        if (d.headers_grade) {
            html += '<div class="modal-section"><h3>Security Headers</h3><table>';
            html += rowKV('Grade', d.headers_grade);
            html += rowKV('Score', d.headers_score);
            if (d.missing_headers && d.missing_headers.length) {
                html += rowKV('Missing', d.missing_headers.join(', '));
            }
            html += '</table></div>';
        }

        // Findings
        if (d.raw_findings && d.raw_findings.length) {
            html += '<div class="modal-section"><h3>Findings (' + d.raw_findings.length + ')</h3>';
            d.raw_findings.forEach(f => {
                html += '<div class="finding-card ' + escape(f.severity) + '">';
                html += '<div class="finding-title">[' + escape(f.severity.toUpperCase()) + '] ' + escape(f.title) + '</div>';
                html += '<div class="finding-desc">' + escape(f.description) + '</div>';
                if (f.recommendation) html += '<div class="finding-rec">→ ' + escape(f.recommendation) + '</div>';
                html += '</div>';
            });
            html += '</div>';
        }

        return html;
    }
})();
"""


# ═══════════════════════════════════════════════════════════════════════════
#  RENDER COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════

def _render_header(total: int, elapsed_ms: float) -> str:
    return f"""
    <div class="header">
        <div>
            <h1>
                🛡 php2shell
                <span style="font-size: 13px; font-weight: 400; color: var(--text-dim);">v{TOOL_VERSION}</span>
            </h1>
            <div class="brand">by {e(TOOL_AUTHOR)} &nbsp;·&nbsp; {e(CVES)}</div>
        </div>
        <div class="meta">
            <div>Generated: {e(_utc_now())}</div>
            <div>Targets: {total} &nbsp;·&nbsp; Duration: {elapsed_ms:.0f} ms</div>
            <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
        </div>
    </div>
    """


def _render_stats(targets: List[dict], severity_counts: Dict[str, int]) -> str:
    total = len(targets)
    vuln = sum(1 for t in targets if t["status"] == "vuln")
    warn = sum(1 for t in targets if t["status"] == "warn")
    ok = sum(1 for t in targets if t["status"] == "ok")
    err = sum(1 for t in targets if t["status"] == "error")

    cards = [
        ("Total Targets", total, ""),
        ("Vulnerable", vuln, "vuln"),
        ("Warnings", warn, ""),
        ("Clean", ok, "ok"),
        ("Errors", err, ""),
    ]
    for sev in SEVERITY_ORDER:
        cards.append((SEVERITY_LABELS[sev], severity_counts.get(sev, 0), sev))

    html_parts = ['<div class="stats">']
    for label, num, cls in cards:
        html_parts.append(
            f'<div class="stat-card {cls}">'
            f'<div class="num">{num}</div>'
            f'<div class="label">{e(label)}</div>'
            f'</div>'
        )
    html_parts.append('</div>')
    return "".join(html_parts)


def _render_severity_chart(severity_counts: Dict[str, int]) -> str:
    total = sum(severity_counts.values()) or 1
    bars = []
    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count == 0:
            continue
        pct = (count / total) * 100
        color = SEVERITY_COLORS[sev]
        bars.append(
            f'<div style="margin-bottom: 6px;">'
            f'<div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 2px;">'
            f'<span style="color: var(--text-dim);">{e(SEVERITY_LABELS[sev])}</span>'
            f'<span style="font-weight: 600;">{count}</span>'
            f'</div>'
            f'<div style="height: 8px; background: var(--bg-elev-2); border-radius: 4px; overflow: hidden;">'
            f'<div style="height: 100%; width: {pct:.1f}%; background: {color};"></div>'
            f'</div>'
            f'</div>'
        )
    if not bars:
        return '<div style="color: var(--text-dim); font-size: 12px;">No findings</div>'
    return "".join(bars)


def _render_grade_chart(targets: List[dict]) -> str:
    """Simple bar chart of TLS/header grades."""
    tls_grades: Dict[str, int] = {}
    hdr_grades: Dict[str, int] = {}
    for t in targets:
        g = t.get("tls_grade") or ""
        if g:
            tls_grades[g] = tls_grades.get(g, 0) + 1
        h = t.get("headers_grade") or ""
        if h:
            hdr_grades[h] = hdr_grades.get(h, 0) + 1

    def bars_for(grades: Dict[str, int]) -> str:
        if not grades:
            return '<div style="color: var(--text-dim); font-size: 12px;">No data</div>'
        order = ["A+", "A", "B", "C", "D", "E", "F"]
        parts = []
        for g in order:
            if g not in grades:
                continue
            cls = "grade-" + g[0].lower()
            parts.append(
                f'<span class="grade {cls}">{e(g)}</span> '
                f'<span style="font-size: 12px; color: var(--text-dim);">×{grades[g]}</span> &nbsp; '
            )
        return "".join(parts)

    return f"""
    <div style="margin-bottom: 12px;">
        <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 4px;">TLS Grade</div>
        {bars_for(tls_grades)}
    </div>
    <div>
        <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 4px;">Headers Grade</div>
        {bars_for(hdr_grades)}
    </div>
    """


def _render_filters() -> str:
    return """
    <div class="filters">
        <input type="search" placeholder="Search targets..." oninput="filterByText(this.value)">
        <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
        <button class="filter-btn" onclick="setFilter('vuln', this)">Vulnerable</button>
        <button class="filter-btn" onclick="setFilter('warn', this)">Warnings</button>
        <button class="filter-btn" onclick="setFilter('ok', this)">Clean</button>
        <button class="filter-btn" onclick="setFilter('error', this)">Errors</button>
    </div>
    """


def _render_results_table(targets: List[dict]) -> str:
    rows = []
    for i, t in enumerate(targets):
        status = t["status"]
        status_label = {
            "vuln": "VULN",
            "warn": "WARN",
            "ok": "OK",
            "error": "ERROR",
        }.get(status, status.upper())

        # Grade badges
        tls_grade = t.get("tls_grade") or ""
        tls_html = (
            f'<span class="grade grade-{tls_grade[0].lower()}">{e(tls_grade)}</span>'
            if tls_grade else '<span style="color: var(--text-dim);">—</span>'
        )
        hdr_grade = t.get("headers_grade") or ""
        hdr_html = (
            f'<span class="grade grade-{hdr_grade[0].lower()}">{e(hdr_grade)}</span>'
            if hdr_grade else '<span style="color: var(--text-dim);">—</span>'
        )

        # WAF badge
        waf_html = ""
        if t.get("waf_detected"):
            waf_html = f'<span class="tag">{e(t["waf_name"])}</span>'
            if t.get("bypass_possible"):
                waf_html += '<span class="tag" style="background: var(--medium); color: #fff;">BYPASS</span>'

        # PHP badge
        php_html = ""
        if t.get("php_detected"):
            patch = t.get("php_patch", "")
            cls = ""
            if patch == "VULNERABLE":
                cls = 'style="color: var(--vuln); font-weight: 600;"'
            elif patch == "FIXED":
                cls = 'style="color: var(--ok);"'
            php_html = f'<span {cls}>{e(t["php_version"] or "?")}</span>'

        # Takeover/crash badges
        extra = ""
        if t.get("takeover_vuln") is True:
            extra += '<span class="tag" style="background: var(--critical); color: #fff;">TAKEOVER</span>'
        if t.get("crash_vuln") is True:
            extra += '<span class="tag" style="background: var(--critical); color: #fff;">CRASH</span>'

        # Findings count
        findings_count = len(t.get("raw_findings", []))

        rows.append(f"""
        <tr data-status="{e(status)}" data-target-id="{i}">
            <td><span class="status-badge {e(status)}">{e(status_label)}</span></td>
            <td style="max-width: 320px; word-break: break-all;">
                <strong>{e(t['target'])}</strong>
                {('<br><span style="color: var(--text-dim); font-size: 11px;">' + e(t['error']) + '</span>') if t.get('error') else ''}
            </td>
            <td>{e(t['server'] or '—')}</td>
            <td>{php_html or '—'}</td>
            <td>{waf_html or '—'}</td>
            <td>{tls_html}</td>
            <td>{hdr_html}</td>
            <td>{findings_count}</td>
            <td>{extra or ''}</td>
        </tr>
        """)

    return f"""
    <table class="results-table">
        <thead>
            <tr>
                <th>Status</th>
                <th>Target</th>
                <th>Server</th>
                <th>PHP</th>
                <th>WAF</th>
                <th>TLS</th>
                <th>Headers</th>
                <th>Findings</th>
                <th>Flags</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_modal_shell() -> str:
    return """
    <div id="modal-overlay" class="modal-overlay">
        <div id="modal-content" class="modal" style="position: relative;">
            <button class="close-btn" onclick="closeModal()">×</button>
        </div>
    </div>
    """


def _render_footer() -> str:
    return f"""
    <div class="footer">
        <div>
            <strong>php2shell v{TOOL_VERSION}</strong> — {e(TOOL_AUTHOR)}
        </div>
        <div style="margin-top: 4px;">
            Generated {e(_utc_now())} · Schema v{SCHEMA_VERSION}
        </div>
        <div style="margin-top: 4px; font-size: 11px;">
            ⚠ For authorized security testing only. Do not use without permission.
        </div>
    </div>
    """


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class HTMLExportResult:
    """Result of an HTML export operation."""
    success: bool = False
    path: Optional[str] = None
    bytes_written: int = 0
    targets: int = 0
    findings: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        return (
            f"{self.path} ({self.targets} targets, "
            f"{self.findings} findings, {self.bytes_written:,} bytes)"
        )


def build_html_report(
    results: List[dict],
    title: str = "php2shell Report",
) -> str:
    """
    Build complete HTML report as a string.

    Args:
        results: list of per-target result dicts
        title: report title (browser tab)

    Returns:
        Complete HTML document as a string.
    """
    targets = _extract_targets(results)
    severity_counts = _count_severity(targets)

    # Compute total elapsed
    total_elapsed = 0.0
    for r in results:
        try:
            total_elapsed += float(r.get("total_elapsed_ms", 0) or 0)
        except (TypeError, ValueError):
            pass

    # Serialize targets for JS modal
    targets_json = json.dumps(targets, ensure_ascii=False, default=str)

    # Build page
    html_doc = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="php2shell/{TOOL_VERSION}">
    <title>{e(title)}</title>
    <style>{CSS}</style>
</head>
<body>
    <div class="container">
        {_render_header(len(targets), total_elapsed)}
        {_render_stats(targets, severity_counts)}
        <div class="charts">
            <div class="chart-card">
                <h3>Findings by Severity</h3>
                {_render_severity_chart(severity_counts)}
            </div>
            <div class="chart-card">
                <h3>Grade Distribution</h3>
                {_render_grade_chart(targets)}
            </div>
        </div>
        {_render_filters()}
        {_render_results_table(targets)}
        {_render_modal_shell()}
        {_render_footer()}
    </div>
    <script>
        window.__TARGETS__ = {targets_json};
        {JS}
    </script>
</body>
</html>
"""
    return html_doc


def export_html(
    results: List[dict],
    path: str = "php2shell_report.html",
    title: str = "php2shell Report",
) -> HTMLExportResult:
    """
    Export results to a self-contained HTML file.

    Args:
        results: list of per-target result dicts
        path: output file path
        title: report title

    Returns:
        HTMLExportResult with path, size, counts.
    """
    export = HTMLExportResult()
    try:
        doc = build_html_report(results, title=title)
        _ensure_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)

        targets = _extract_targets(results)
        findings_count = sum(len(t.get("raw_findings", [])) for t in targets)

        export.success = True
        export.path = path
        export.bytes_written = os.path.getsize(path)
        export.targets = len(targets)
        export.findings = findings_count
        return export

    except OSError as exc:
        export.error = f"write failed: {exc}"
        return export
    except Exception as exc:
        export.error = f"build failed: {exc}"
        return export


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "HTMLExportResult",
    "build_html_report",
    "export_html",
    "SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "SEVERITY_COLORS",
]