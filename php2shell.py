#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["h11>=0.14.0", "tqdm>=4.64.0"]
# ///
"""
php2shell — All-in-One Web Vulnerability Scanner
Author: ATHEX BLACK HAT

CVE-2026-109618 / CVE-2026-109619 + WAF/CDN/IPS detection
+ subdomain takeover + TLS analysis + security header audit
+ multi-format reporting (JSON / CSV / HTML)

⚠  Use only on systems you own or have explicit written permission to test.
   Unauthorized use is illegal (CFAA / PECA / CMA / etc.).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

# ── Bootstrap: verify environment before importing modules ──
try:
    import h11  # noqa: F401
except ImportError:
    print("Error: 'h11' library required. Install with: pip install h11", file=sys.stderr)
    sys.exit(1)

try:
    from tqdm import tqdm  # noqa: F401
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm", file=sys.stderr)
    sys.exit(1)

# ── Core ──
from core.config import (
    TOOL_NAME,
    TOOL_VERSION,
    TOOL_AUTHOR,
    TOOL_LICENSE,
    CVES,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_PATH,
    PROBES,
)
from core.logger import Logger, Colors, colorize
from core.http import (
    HTTPResult,
    send_request,
    http_get,
    ProxyConfig,
    shutdown_thread_loop,
)

# ── Detection modules ──
from modules.fingerprint import fingerprint, FingerprintResult
from modules.headers import audit_headers, HeadersResult
from modules.tls import analyze_tls, TLSResult
from modules.waf_detect import detect_waf, WAFResult
from modules.waf_bypass import test_bypass, BypassResult
from modules.takeover import check_takeover, TakeoverResult
from modules.crash import check_crash, CrashResult

# ── Reporters ──
from output.json import export_json, export_ndjson
from output.csv import export_csv, export_csv_flat
from output.html import export_html


# ═══════════════════════════════════════════════════════════════════════════
#  ASCII BANNER
# ═══════════════════════════════════════════════════════════════════════════

BANNER = r"""
   ▄▄▄▄▄   ▄  ▄  ▄▄▄▄▄    ▄▄▄▄  ▄  ▄  ▄▄▄▄▄ ▄    ▄
   █   █   █  █  █   █    █     █  █  █     █    █
   █▄▄▄█   █▄▄█  █▄▄▄█    █▄▄▄  █▄▄█  █▄▄▄  █    █
   █       █  █  █           ▄  █  █  █     █    █    
   █       █  █  █        █▄▄█  █  █  █▄▄▄  █▄▄▄ █▄▄▄
"""

BANNER_ALT = r"""
██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                        
"""


def _print_banner(no_color: bool = False) -> None:
    """Print the ASCII banner with branding."""
    if no_color:
        print(BANNER_ALT)
        print(f"    {TOOL_NAME} v{TOOL_VERSION}  —  by {TOOL_AUTHOR}")
        print(f"    {CVES}")
        print(f"    {TOOL_LICENSE}")
        print()
        return

    print(colorize(BANNER_ALT, Colors.CYAN + Colors.BOLD))
    print(colorize(
        f"    {TOOL_NAME} v{TOOL_VERSION}",
        Colors.WHITE + Colors.BOLD
    ) + colorize(f"  —  by {TOOL_AUTHOR}", Colors.GREEN))
    print(colorize(f"    {CVES}", Colors.YELLOW))
    print(colorize(
        f"    All-in-One Web Vulnerability Scanner "
        f"| WAF · TLS · Takeover · CVE · Headers",
        Colors.GRAY
    ))
    print(colorize("    " + "─" * 62, Colors.GRAY))
    print(colorize(
        "    ⚠  For authorized security testing only. Do not use without permission.",
        Colors.RED + Colors.DIM
    ))
    print()


# ═══════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{TOOL_VERSION} — {TOOL_AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Basic single-target scan (all modules)
  %(prog)s -u https://target.com

  # Batch scan with all reporters
  %(prog)s -l targets.txt -o scan.json --csv --html

  # Fast scan (skip active WAF bypass + version probing)
  %(prog)s -u https://target.com --no-bypass --no-tls-versions

  # Bug bounty recon (fingerprint + takeover + crash only)
  %(prog)s -l subdomains.txt --only fingerprint,takeover,crash -o out.json

  # Via Burp proxy, with custom headers
  %(prog)s -u https://target.com -p http://127.0.0.1:8080 \\
           -H "Authorization: Bearer <token>"

Modules:
  fingerprint    Server/PHP/framework detection + passive file checks
  headers        Security header audit with A-F grading
  tls            TLS/cert analysis with grading
  waf_detect     WAF/CDN/IPS detection (passive + active)
  waf_bypass     Generic WAF bypass testing (non-weaponized)
  takeover       Subdomain takeover (dangling CNAME)
  crash          CVE-2026-109618/9 (PHP multipart crash)

Reporters:
  JSON           --output FILE.json
  NDJSON         --output FILE.ndjson
  CSV            --csv (multi-file) or --csv-flat FILE.csv
  HTML           --html [FILE.html]

Legal:
  {TOOL_LICENSE}
""",
    )

    # ── Input ──
    inp = p.add_mutually_exclusive_group(required=True)
    inp.add_argument("-u", "--url", help="Single target URL")
    inp.add_argument("-l", "--list", help="File with targets (one per line, # = comment)")

    # ── Module selection ──
    mod = p.add_argument_group("Module selection")
    mod.add_argument(
        "--only", metavar="MODS",
        help="Comma-separated modules to run (fingerprint,headers,tls,"
             "waf_detect,waf_bypass,takeover,crash). Default: all.",
    )
    mod.add_argument(
        "--skip", metavar="MODS",
        help="Comma-separated modules to skip",
    )
    mod.add_argument("--no-fingerprint", action="store_true", help="Skip fingerprinting")
    mod.add_argument("--no-headers", action="store_true", help="Skip header audit")
    mod.add_argument("--no-tls", action="store_true", help="Skip TLS analysis")
    mod.add_argument("--no-waf", action="store_true", help="Skip WAF detection")
    mod.add_argument("--no-bypass", action="store_true", help="Skip WAF bypass testing")
    mod.add_argument("--no-takeover", action="store_true", help="Skip takeover check")
    mod.add_argument("--no-cve", action="store_true", help="Skip CVE crash test")

    # ── Performance ──
    perf = p.add_argument_group("Performance")
    perf.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                      help=f"Concurrent threads (default {DEFAULT_THREADS})")
    perf.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                      help=f"Per-request timeout in seconds (default {DEFAULT_TIMEOUT})")
    perf.add_argument("--no-tls-versions", action="store_true",
                      help="Skip TLS version enumeration (4x faster)")
    perf.add_argument("--fast", action="store_true",
                      help="Fast mode: passive-only WAF, no version probing")
    perf.add_argument("--rate-limit", type=float, default=None,
                      help="Max requests/second per host (default: config)")

    # ── HTTP ──
    http = p.add_argument_group("HTTP")
    http.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    http.add_argument("--follow-redirects", action="store_true", help="Follow 3xx redirects")
    http.add_argument("-H", "--header", action="append", dest="headers",
                      metavar="'Key: Value'", help="Custom header (repeatable)")
    http.add_argument("-p", "--proxy", metavar="URL",
                      help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    http.add_argument("--path", action="append", dest="paths",
                      help="Custom path(s) to test (repeatable)")
    http.add_argument("--user-agent", help="Override User-Agent")
    http.add_argument("--retries", type=int, default=1,
                      help="Network retries per request (default 1)")

    # ── Output ──
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="JSON output file (.json → aggregate, .ndjson → streaming)")
    out.add_argument("--csv", action="store_true", help="Write CSVs (6 files)")
    out.add_argument("--csv-flat", metavar="FILE", help="Write single flat CSV file")
    out.add_argument("--csv-prefix", default="php2shell", help="CSV filename prefix")
    out.add_argument("--csv-dir", default=".", help="CSV output directory")
    out.add_argument("--html", nargs="?", const="php2shell_report.html",
                     metavar="FILE", help="Write HTML report (default: php2shell_report.html)")
    out.add_argument("--raw-bytes", action="store_true",
                     help="Include base64 raw request/response in JSON")
    out.add_argument("--no-summary", action="store_true",
                     help="Omit aggregate summary block from JSON")
    out.add_argument("--quiet", "-q", action="store_true", help="Only show findings")
    out.add_argument("--verbose", "-v", action="count", default=0,
                     help="Increase verbosity (-v, -vv)")
    out.add_argument("--no-color", action="store_true", help="Disable colors")
    out.add_argument("--no-banner", action="store_true", help="Skip ASCII banner")
    out.add_argument("--version", action="version",
                     version=f"{TOOL_NAME} v{TOOL_VERSION} — {TOOL_AUTHOR}")

    return p


# ═══════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_target(raw: str) -> str:
    """Normalize URL: add scheme if missing, ensure path present."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if not parsed.hostname:
        raise ValueError(f"invalid target: {raw}")
    path = parsed.path or DEFAULT_PATH
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def _load_targets(args) -> List[str]:
    """Load and normalize targets from -u or -l."""
    if args.url:
        return [_normalize_target(args.url)]
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as exc:
            Logger.critical(f"Failed to read list: {exc}")
            sys.exit(2)
        targets = []
        for line in lines:
            try:
                targets.append(_normalize_target(line))
            except ValueError as exc:
                Logger.warning(f"Skipping invalid target: {exc}")
        return targets
    return []


def _parse_headers(headers_list: Optional[List[str]]) -> Dict[str, str]:
    """Parse -H 'Key: Value' into dict."""
    from core.config import HEADER_NAME_PATTERN
    import re
    out: Dict[str, str] = {}
    for h in headers_list or []:
        if ":" not in h:
            Logger.warning(f"Invalid header (missing ':'): {h!r} — skipped")
            continue
        k, v = h.split(":", 1)
        k = k.strip()
        if not re.fullmatch(HEADER_NAME_PATTERN, k):
            Logger.warning(f"Invalid header name: {k!r} — skipped")
            continue
        out[k] = v.lstrip()
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════

ALL_MODULES = [
    "fingerprint", "headers", "tls",
    "waf_detect", "waf_bypass", "takeover", "crash",
]


def _resolve_modules(args) -> List[str]:
    """Determine which modules to run based on args."""
    if args.only:
        selected = [m.strip().lower() for m in args.only.split(",") if m.strip()]
        invalid = [m for m in selected if m not in ALL_MODULES]
        if invalid:
            Logger.critical(f"Unknown module(s): {', '.join(invalid)}")
            Logger.info(f"Available: {', '.join(ALL_MODULES)}")
            sys.exit(2)
    else:
        selected = list(ALL_MODULES)

    # Apply --skip
    if args.skip:
        skip = {m.strip().lower() for m in args.skip.split(",") if m.strip()}
        selected = [m for m in selected if m not in skip]

    # Apply --no-* flags
    flag_map = {
        "fingerprint": args.no_fingerprint,
        "headers": args.no_headers,
        "tls": args.no_tls,
        "waf_detect": args.no_waf,
        "waf_bypass": args.no_bypass,
        "takeover": args.no_takeover,
        "crash": args.no_cve,
    }
    for mod, skip_flag in flag_map.items():
        if skip_flag and mod in selected:
            selected.remove(mod)

    if not selected:
        Logger.critical("No modules selected to run")
        sys.exit(2)
    return selected


# ═══════════════════════════════════════════════════════════════════════════
#  PER-TARGET SCAN
# ═══════════════════════════════════════════════════════════════════════════

def scan_target(
    target: str,
    args,
    modules: List[str],
    custom_headers: Dict[str, str],
    proxy: Optional[ProxyConfig],
) -> dict:
    """
    Run selected modules against a single target.

    Returns a combined dict with keys per module + metadata.
    """
    result: Dict[str, Any] = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "modules_run": modules,
        "total_elapsed_ms": 0.0,
        "error": None,
    }

    t0 = time.perf_counter()
    verify_ssl = not args.insecure

    # Determine effective target (may be retargeted by fingerprint)
    effective_target = target
    fp = None

    # ── Fingerprint (first — provides context) ──
    if "fingerprint" in modules:
        try:
            Logger.fingerprint(f"Fingerprinting {target}", module="orchestrator", target=target)
            fp = fingerprint(
                target,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                passive_files=not args.fast,
                check_https_redirect=not args.fast,
                custom_headers=custom_headers,
            )
            result["fingerprint"] = fp.to_dict()
            if fp.error:
                Logger.warning(f"Fingerprint: {fp.error}", module="orchestrator", target=target)
            else:
                Logger.info(f"Stack: {fp.summary_line()}", module="orchestrator", target=target)
                if fp.final_url:
                    effective_target = fp.final_url
        except Exception as exc:
            Logger.error(f"Fingerprint crashed: {exc}", module="orchestrator", target=target)
            result["fingerprint"] = {"error": str(exc)}

    # ── Headers ──
    if "headers" in modules:
        try:
            Logger.audit(f"Auditing headers: {effective_target}", module="orchestrator")
            hdr = audit_headers(
                effective_target,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                custom_headers=custom_headers,
            )
            result["headers"] = hdr.to_dict()
            if hdr.error:
                Logger.warning(f"Headers: {hdr.error}", module="orchestrator", target=target)
            else:
                Logger.info(f"Headers: {hdr.summary_line()}", module="orchestrator", target=target)
        except Exception as exc:
            Logger.error(f"Headers crashed: {exc}", module="orchestrator", target=target)
            result["headers"] = {"error": str(exc)}

    # ── TLS ──
    if "tls" in modules:
        try:
            Logger.tls(f"Analyzing TLS: {effective_target}", module="orchestrator")
            tls = analyze_tls(
                effective_target,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                test_versions=not (args.fast or args.no_tls_versions),
            )
            result["tls"] = tls.to_dict()
            if tls.error:
                Logger.warning(f"TLS: {tls.error}", module="orchestrator", target=target)
            else:
                Logger.info(f"TLS: {tls.summary_line()}", module="orchestrator", target=target)
        except Exception as exc:
            Logger.error(f"TLS crashed: {exc}", module="orchestrator", target=target)
            result["tls"] = {"error": str(exc)}

    # ── WAF detection ──
    if "waf_detect" in modules:
        try:
            Logger.audit(f"Detecting WAF/CDN/IPS: {effective_target}", module="orchestrator")
            waf = detect_waf(
                effective_target,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                custom_headers=custom_headers,
                full_scan=not args.fast,
            )
            result["waf"] = waf.to_dict()
            if waf.detected:
                Logger.waf(
                    f"WAF: {waf.primary.name} ({waf.primary.type}, "
                    f"confidence={waf.confidence})",
                    module="orchestrator", target=target,
                )
            else:
                Logger.info(f"WAF: {waf.verdict}", module="orchestrator", target=target)
        except Exception as exc:
            Logger.error(f"WAF detect crashed: {exc}", module="orchestrator", target=target)
            result["waf"] = {"error": str(exc)}

    # ── WAF bypass (only if WAF detected) ──
    if "waf_bypass" in modules:
        waf_info = result.get("waf") or {}
        if waf_info.get("detected") or not args.fast:
            try:
                Logger.audit(f"Testing WAF bypass: {effective_target}", module="orchestrator")
                bypass = test_bypass(
                    effective_target,
                    timeout=args.timeout,
                    verify_ssl=verify_ssl,
                    proxy=proxy,
                    custom_headers=custom_headers,
                )
                result["bypass"] = bypass.to_dict()
                if bypass.bypassable:
                    Logger.bypass(
                        f"Bypassable: {', '.join(bypass.working_techniques)}",
                        module="orchestrator", target=target,
                    )
                else:
                    Logger.info(
                        f"Bypass: {bypass.summary_line()}",
                        module="orchestrator", target=target,
                    )
            except Exception as exc:
                Logger.error(f"Bypass crashed: {exc}", module="orchestrator", target=target)
                result["bypass"] = {"error": str(exc)}

    # ── Takeover ──
    if "takeover" in modules:
        try:
            parsed = urlsplit(effective_target)
            hostname = parsed.hostname or ""
            Logger.info(f"Checking takeover: {hostname}", module="orchestrator")
            tk = check_takeover(
                hostname,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                scheme=parsed.scheme or "https",
                custom_headers=custom_headers,
            )
            result["takeover"] = tk.to_dict()
            if tk.vulnerable is True:
                Logger.vuln(
                    f"TAKEOVER: {tk.provider} ({tk.confidence})",
                    module="orchestrator", target=target,
                )
            elif tk.vulnerable is None:
                Logger.warning(
                    f"Takeover: {tk.reason}",
                    module="orchestrator", target=target,
                )
            else:
                Logger.info(
                    f"Takeover: {tk.summary_line()}",
                    module="orchestrator", target=target,
                )
        except Exception as exc:
            Logger.error(f"Takeover crashed: {exc}", module="orchestrator", target=target)
            result["takeover"] = {"error": str(exc)}

    # ── Crash (CVE) ──
    if "crash" in modules:
        try:
            Logger.payload(f"Running CVE crash probe: {effective_target}", module="orchestrator")
            crash = check_crash(
                effective_target,
                custom_headers=custom_headers,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                follow_redirects=args.follow_redirects,
                proxy=proxy,
                retries=args.retries,
                probe_retries=1,
            )
            result["crash"] = crash.to_dict()
            if crash.vulnerable is True:
                Logger.vuln(
                    f"CVE VULNERABLE: {crash.sapi} ({crash.confidence})",
                    module="orchestrator", target=target,
                )
            elif crash.vulnerable is False:
                Logger.fixed(
                    f"CVE: {crash.verdict}",
                    module="orchestrator", target=target,
                )
            else:
                Logger.info(
                    f"CVE: {crash.verdict} — {crash.reason}",
                    module="orchestrator", target=target,
                )
        except Exception as exc:
            Logger.error(f"Crash module crashed: {exc}", module="orchestrator", target=target)
            result["crash"] = {"error": str(exc)}

    result["total_elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  REPORTING
# ═══════════════════════════════════════════════════════════════════════════

def _print_scan_summary(results: List[dict], elapsed: float) -> None:
    """Print final summary table."""
    Logger.header(f"SCAN SUMMARY — {TOOL_NAME} v{TOOL_VERSION}")

    total = len(results)
    vuln = 0
    warn = 0
    errors = 0
    findings_total = 0

    for r in results:
        if r.get("error"):
            errors += 1
            continue
        crash = r.get("crash") or {}
        tk = r.get("takeover") or {}
        if crash.get("vulnerable") is True or tk.get("vulnerable") is True:
            vuln += 1
        else:
            waf = r.get("waf") or {}
            bypass = r.get("bypass") or {}
            fp = r.get("fingerprint") or {}
            php = fp.get("php") or {}
            if (waf.get("detected") or bypass.get("bypassable")
                    or php.get("patch_status") == "VULNERABLE"):
                warn += 1

        hdr = r.get("headers") or {}
        findings_total += len(hdr.get("findings") or [])
        tls = r.get("tls") or {}
        findings_total += len(tls.get("findings") or [])

    def _fmt(label: str, value: Any, color: Optional[str] = None) -> str:
        s = f"  {label:<24} {value}"
        return colorize(s, color) if color else s

    print(_fmt("Total targets:", total))
    print(_fmt("Vulnerable:", vuln, Colors.RED + Colors.BOLD if vuln else None))
    print(_fmt("Warnings:", warn, Colors.YELLOW if warn else None))
    print(_fmt("Clean:", total - vuln - warn - errors))
    print(_fmt("Errors:", errors, Colors.RED if errors else None))
    print(_fmt("Total findings:", findings_total))
    print(_fmt("Total time:", f"{elapsed:.2f}s"))
    if total > 1:
        print(_fmt("Avg per target:", f"{elapsed / total:.2f}s"))
    print(colorize("─" * 62, Colors.GRAY))


def _save_all_reports(results: List[dict], args) -> bool:
    """Save JSON/CSV/HTML reports based on args. Returns True if all succeeded."""
    all_ok = True

    # ── JSON ──
    if args.output:
        path = args.output
        if path.endswith(".ndjson"):
            r = export_ndjson(results, path=path, include_raw_bytes=args.raw_bytes)
        else:
            r = export_json(
                results, path=path,
                pretty=True,
                include_raw_bytes=args.raw_bytes,
                include_summary=not args.no_summary,
            )
        if r.success:
            Logger.success(f"JSON: {r.summary_line()}", module="report")
        else:
            Logger.error(f"JSON: {r.error}", module="report")
            all_ok = False

    # ── CSV ──
    if args.csv:
        r = export_csv(
            results,
            prefix=args.csv_prefix,
            out_dir=args.csv_dir,
        )
        if r.success:
            Logger.success(f"CSV: {r.summary_line()}", module="report")
            for kind, path in r.files_written.items():
                Logger.info(f"  {kind}: {path} ({r.total_rows.get(kind, 0)} rows)",
                            module="report")
        else:
            Logger.error(f"CSV: {r.error}", module="report")
            all_ok = False

    if args.csv_flat:
        r = export_csv_flat(results, path=args.csv_flat)
        if r.success:
            Logger.success(f"CSV flat: {r.summary_line()}", module="report")
        else:
            Logger.error(f"CSV flat: {r.error}", module="report")
            all_ok = False

    # ── HTML ──
    if args.html:
        r = export_html(
            results,
            path=args.html,
            title=f"{TOOL_NAME} Scan — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        )
        if r.success:
            Logger.success(f"HTML: {r.summary_line()}", module="report")
        else:
            Logger.error(f"HTML: {r.error}", module="report")
            all_ok = False

    return all_ok


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Setup logging ──
    no_color = args.no_color or not sys.stdout.isatty()
    Logger.configure(
        level="DEBUG" if args.verbose >= 2 else "INFO",
        color=not no_color,
        quiet=args.quiet,
        verbosity=args.verbose,
        no_color=no_color,
    )

    # ── Banner ──
    if not args.no_banner and not args.quiet:
        _print_banner(no_color)

    # ── Validate ──
    if args.threads < 1:
        Logger.critical("--threads must be >= 1")
        return 2
    if args.timeout < 1:
        Logger.critical("--timeout must be >= 1")
        return 2

    # ── Parse headers + proxy ──
    custom_headers = _parse_headers(args.headers)
    if args.user_agent:
        custom_headers["User-Agent"] = args.user_agent

    proxy: Optional[ProxyConfig] = None
    if args.proxy:
        try:
            proxy = ProxyConfig.parse(args.proxy)
            Logger.info(f"Using proxy: {proxy.host}:{proxy.port}", module="setup")
        except ValueError as exc:
            Logger.critical(f"Invalid proxy: {exc}")
            return 2

    # ── Resolve modules ──
    modules = _resolve_modules(args)
    if not args.quiet:
        Logger.info(f"Modules: {', '.join(modules)}", module="setup")

    # ── Load targets ──
    targets = _load_targets(args)
    if not targets:
        Logger.critical("No targets to scan")
        return 2

    if not args.quiet:
        Logger.info(f"Targets: {len(targets)}", module="setup")
        Logger.info(f"Threads: {args.threads}", module="setup")
        Logger.info(f"Timeout: {args.timeout}s", module="setup")
        if args.insecure:
            Logger.warning("TLS verification disabled", module="setup")

    # ── Warm up probe bodies (avoid lazy build in threads) ──
    if "crash" in modules:
        try:
            from modules.crash import build_probe_body
            for size_mib, parts in PROBES:
                build_probe_body(size_mib, parts)
        except Exception:
            pass

    # ── Signal handler for clean Ctrl+C ──
    interrupted = {"flag": False}

    def _sigint_handler(signum, frame):
        if interrupted["flag"]:
            Logger.critical("Force exit")
            sys.exit(130)
        interrupted["flag"] = True
        Logger.warning("Interrupted — finishing current targets... (Ctrl+C again to force)")

    original_sigint = signal.signal(signal.SIGINT, _sigint_handler)

    # ── Scan ──
    scan_start = time.perf_counter()
    results: List[dict] = []

    try:
        if len(targets) == 1:
            # Single-target mode: direct
            result = scan_target(
                targets[0], args, modules, custom_headers, proxy
            )
            results.append(result)
        else:
            # Batch mode: thread pool
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                futures = {
                    ex.submit(
                        scan_target, t, args, modules, custom_headers, proxy
                    ): t
                    for t in targets
                }
                progress = Logger.progress(
                    total=len(targets), desc="Scanning", unit="target"
                )
                try:
                    for fut in as_completed(futures):
                        if interrupted["flag"]:
                            break
                        target = futures[fut]
                        try:
                            result = fut.result()
                        except Exception as exc:
                            Logger.error(
                                f"Target {target} crashed: {exc}",
                                module="orchestrator",
                            )
                            result = {
                                "target": target,
                                "error": str(exc),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                        results.append(result)
                        progress.update(1)
                finally:
                    progress.close()
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        # Clean up thread-local event loops
        try:
            shutdown_thread_loop()
        except Exception:
            pass

    scan_elapsed = time.perf_counter() - scan_start

    # ── Summary + reports ──
    if not args.quiet:
        _print_scan_summary(results, scan_elapsed)

    reports_ok = _save_all_reports(results, args)

    # ── Exit code ──
    if not reports_ok:
        return 2
    any_vuln = any(
        (r.get("crash") or {}).get("vulnerable") is True
        or (r.get("takeover") or {}).get("vulnerable") is True
        for r in results
    )
    return 1 if any_vuln else 0


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        Logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception:
        Logger.critical("Fatal error:")
        traceback.print_exc()
        sys.exit(3)