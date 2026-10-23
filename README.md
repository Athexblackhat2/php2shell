<div align="center">

```

██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                              
```

# php2shell

**All-in-One Web Vulnerability Scanner**

*CVE-2026-109618 / CVE-2026-109619 · WAF Detection · TLS Analysis · Subdomain Takeover · Security Headers*

[![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)](#)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/license-Authorized%20Testing%20Only-red.svg)](#-legal-notice)

**by [ATHEX BLACK HAT](#-author)**

⚠️ **For authorized security testing only** — do not use on systems you don't own or lack written permission to test.

</div>

---

## 📖 Table of Contents

- [What is php2shell?](#-what-is-php2shell)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Basic Examples](#basic-examples)
  - [Module Selection](#module-selection)
  - [Custom Headers & Auth](#custom-headers--auth)
  - [Proxy Support](#proxy-support)
  - [Output Formats](#output-formats)
  - [Bug Bounty Workflows](#bug-bounty-workflows)
- [Modules Deep Dive](#-modules-deep-dive)
- [CLI Reference](#-cli-reference)
- [Output Formats](#-output-formats)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [FAQ](#-faq)
- [Troubleshooting](#-troubleshooting)
- [Legal Notice](#-legal-notice)
- [Author](#-author)

---

## 🎯 What is php2shell?

`php2shell` is a **modular, all-in-one web vulnerability scanner** designed for bug bounty hunters, pentesters, and security researchers. It combines **seven detection modules** and **three reporting formats** into a single, fast, async-powered tool.

### What it detects

| Category | Coverage |
|---|---|
| **CVE Detection** | CVE-2026-109618 / CVE-2026-109619 (PHP multipart parser crash) |
| **WAF / CDN / IPS** | Cloudflare, Akamai, Imperva, F5, AWS WAF, ModSecurity, 25+ vendors |
| **WAF Bypass** | 17 generic evasion techniques (header tricks, XFF spoofing, encoding) |
| **Subdomain Takeover** | 30+ cloud providers (S3, GitHub Pages, Heroku, Azure, Netlify, …) |
| **TLS/SSL** | Certificate, protocol versions, cipher strength, A+ → F grading |
| **Security Headers** | HSTS, CSP, XFO, cookies, CORS, info leaks — A+ → F grading |
| **Tech Fingerprint** | Server, PHP version, frameworks, CMS, CDN, exposed files |

### What makes it different

- ✅ **Async core** — thread-local event loops (10× faster than `asyncio.run()` per request)
- ✅ **Rate-limited** — per-host + global token bucket (won't DoS the target)
- ✅ **Multi-signal crash detection** — retries + version corroboration (low false positives)
- ✅ **Three reporters** — JSON (structured), CSV (spreadsheet), HTML (client deliverable)
- ✅ **Zero external deps** beyond `h11` + `tqdm` — no Chromium, no heavy frameworks
- ✅ **Proxy-ready** — Burp / ZAP / SOCKS5 support via HTTP CONNECT

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Detection
- PHP CVE crash probe (nested multipart)
- WAF/CDN/IPS fingerprinting (passive + active)
- WAF bypass testing (non-weaponized)
- Subdomain takeover (dangling CNAME)
- TLS certificate analysis
- Security header audit
- Tech stack fingerprinting
- Exposed file detection

</td>
<td width="50%">

### ⚙️ Engineering
- Async h11 transport (streaming, backpressure)
- Per-thread event loop reuse
- Token-bucket rate limiter
- gzip response decoding
- HTTP proxy (CONNECT tunnel)
- Retry with exponential backoff
- Graceful Ctrl+C handling
- Signal-safe interrupt

</td>
</tr>
<tr>
<td>

### 📊 Reporting
- JSON (aggregate + NDJSON streaming)
- CSV (6 focused files + flat mode)
- HTML (interactive, dark/light, print-ready)
- Auto summary block
- Sensitive header redaction
- Formula injection protection (CSV)
- Schema versioning

</td>
<td>

### 🎛️ Control
- Per-module enable/disable
- Fast mode (passive-only)
- Custom headers + auth tokens
- Custom paths
- Proxy support
- Rate limiting
- Verbosity levels (-v / -vv)
- Quiet mode (CI-friendly)

</td>
</tr>
</table>

---

## ⚡ Quick Start

```bash
# 1. Install dependencies
pip install h11 tqdm

# 2. Clone / download php2shell
git clone https://github.com/Athexblackhat2/php2shell.git
cd php2shell

# 3. Create package markers (if not present)
touch core/__init__.py modules/__init__.py output/__init__.py

# 4. Run first scan
python3 php2shell.py -u https://example.com

# 5. Full scan with all reports
python3 php2shell.py -u https://example.com -o scan.json --csv --html
```

**Expected output:**
```
██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                   

    php2shell v3.1.0  —  by ATHEX BLACK HAT
    CVE-2026-109618 / CVE-2026-109619

[16:55:02] [FP] (orchestrator) Fingerprinting https://example.com/
[16:55:03] [INFO] Stack: nginx/1.24.0 | PHP/8.3.36[FIXED]
[16:55:04] [INFO] Headers: Grade A (2 pts, 2 findings)
[16:55:05] [INFO] TLS: grade=A+ | cipher=TLS_AES_256_GCM_SHA384
[16:55:07] [INFO] WAF: NO_WAF
[16:55:08] [INFO] Takeover: not vulnerable
[16:55:09] [FIXED] CVE: FIXED
...
```

---

## 📦 Installation

### Requirements

- **Python 3.10+**
- **`h11 >= 0.14.0`** — HTTP/1.1 protocol
- **`tqdm >= 4.64.0`** — progress bars

### Method 1: pip (recommended)

```bash
pip install h11 tqdm
```

### Method 2: PEP 723 (inline script deps)

The `php2shell.py` file has inline PEP 723 metadata:

```python
# /// script
# requires-python = ">=3.10"
# dependencies = ["h11>=0.14.0", "tqdm>=4.64.0"]
# ///
```

If you have `pipx` or `uv`, you can run directly:

```bash
# Using uv (fastest)
uv run php2shell.py -u https://example.com

# Using pipx
pipx run php2shell.py -u https://example.com
```

### Method 3: Docker (build your own)

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir h11 tqdm
ENTRYPOINT ["python3", "php2shell.py"]
```

```bash
docker build -t php2shell .
docker run --rm php2shell -u https://example.com
```

### Method 4: From source

```bash
git clone https://github.com/Athexblackhat2/php2shell.git
cd php2shell
pip install h11 tqdm
python3 php2shell.py --help
```

### Verify Installation

```bash
python3 php2shell.py --version
# php2shell 3.1.0 — ATHEX BLACK HAT
```

---

## 🚀 Usage

### Basic Examples

**Scan a single target (all modules):**
```bash
python3 php2shell.py -u https://target.com
```

**Scan with all reporters:**
```bash
python3 php2shell.py -u https://target.com \
    -o scan.json \
    --csv \
    --html
```

**Batch scan from file:**
```bash
python3 php2shell.py -l targets.txt -t 20 --csv-flat results.csv
```

**Fast mode (passive-only WAF, no TLS version enumeration):**
```bash
python3 php2shell.py -u https://target.com --fast
```

### Module Selection

php2shell has **7 modules** — run them all or pick specific ones.

**Available modules:**

| ID | Description | Fast? |
|---|---|---|
| `fingerprint` | Server/PHP/framework + exposed files | medium |
| `headers` | Security header audit | fast |
| `tls` | TLS/cert analysis | medium |
| `waf_detect` | WAF/CDN/IPS fingerprint | medium |
| `waf_bypass` | Generic bypass testing | slow |
| `takeover` | Subdomain takeover check | fast |
| `crash` | CVE multipart crash probe | slow |

**Run specific modules:**
```bash
# Only fingerprint + takeover + crash
python3 php2shell.py -l subs.txt --only fingerprint,takeover,crash
```

**Skip specific modules:**
```bash
# All except WAF bypass (slow)
python3 php2shell.py -u https://target.com --skip waf_bypass
```

**Individual flags:**
```bash
# Skip header audit + TLS
python3 php2shell.py -u https://target.com --no-headers --no-tls
```

### Custom Headers & Auth

**Add custom headers:**
```bash
python3 php2shell.py -u https://target.com \
    -H "Authorization: Bearer eyJhbGci..." \
    -H "X-Custom-Client: web" \
    -H "Cookie: session=abc123"
```

**Override User-Agent:**
```bash
python3 php2shell.py -u https://target.com \
    --user-agent "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"
```

**Custom paths (instead of default `/index.php`):**
```bash
python3 php2shell.py -u https://target.com \
    --path /api/v1 \
    --path /admin \
    --path /upload.php
```

### Proxy Support

**Burp Suite / OWASP ZAP:**
```bash
# Burp on localhost:8080
python3 php2shell.py -u https://target.com -p http://127.0.0.1:8080

# ZAP on localhost:8090
python3 php2shell.py -u https://target.com -p http://127.0.0.1:8090

# Proxy with auth
python3 php2shell.py -u https://target.com -p http://user:pass@proxy:8080
```

**Why use a proxy?**
- Capture full request/response history in Burp
- Modify requests manually
- Feed into other tools
- Debug the scanner's behavior

### Output Formats

**JSON (aggregate):**
```bash
python3 php2shell.py -u https://target.com -o scan.json
# → scan.json (nested, complete, schema v1.0)
```

**NDJSON (streaming — for Splunk/Elastic):**
```bash
python3 php2shell.py -l targets.txt -o scan.ndjson
# → scan.ndjson (one JSON per line, streaming)
```

**CSV (6 focused files):**
```bash
python3 php2shell.py -u https://target.com --csv --csv-dir ./reports
# → reports/php2shell_summary.csv
# → reports/php2shell_findings.csv
# → reports/php2shell_endpoints.csv
# → reports/php2shell_probes.csv
# → reports/php2shell_cookies.csv
# → reports/php2shell_tls.csv
```

**CSV (flat — single file):**
```bash
python3 php2shell.py -l targets.txt --csv-flat all_findings.csv
# → all_findings.csv (filter by module/kind in Excel)
```

**HTML (interactive report):**
```bash
python3 php2shell.py -u https://target.com --html report.html
# → report.html (open in browser, dark/light, filterable, print-ready)
```

**All three at once:**
```bash
python3 php2shell.py -l targets.txt \
    -o scan.json \
    --csv \
    --html report.html
```

### Bug Bounty Workflows

#### Workflow 1: Subdomain recon

```bash
# Get subdomains from crt.sh, amass, subfinder, etc.
subfinder -d example.com -silent > subs.txt

# Fast scan — fingerprint + takeover only
python3 php2shell.py -l subs.txt \
    --only fingerprint,takeover \
    -t 30 --fast \
    -o recon.json \
    --csv-flat recon.csv
```

#### Workflow 2: Deep-dive on interesting targets

```bash
# Full scan on 5 promising subdomains
python3 php2shell.py -l interesting.txt \
    -t 5 --timeout 90 \
    -o deep.json \
    --csv --html deep_report.html
```

#### Workflow 3: Client deliverable

```bash
python3 php2shell.py -l client_assets.txt \
    -t 20 \
    -o client_scan.json \
    --csv --html client_report.html \
    --no-banner
```

#### Workflow 4: CI/CD integration

```bash
# Returns exit 1 if vulnerability found (CI fails)
python3 php2shell.py -l production_urls.txt \
    --only crash,takeover \
    -o ci_scan.json \
    -q --no-banner

# In GitHub Actions:
# - name: Security scan
#   run: python3 php2shell.py -l urls.txt -q --no-banner
```

#### Workflow 5: Via Burp for manual review

```bash
# Proxy everything through Burp — inspect traffic manually
python3 php2shell.py -u https://target.com \
    -p http://127.0.0.1:8080 \
    --only fingerprint,headers,waf_detect \
    -v
```

---

## 🧩 Modules Deep Dive

### 1. `fingerprint` — Tech Stack Detection

**What it does:**
- Server name + version (Apache, nginx, IIS, LiteSpeed, Caddy, …)
- PHP detection + version + patch status
- Language runtime (PHP, ASP.NET, Node, Python, Ruby, Java)
- Frameworks/CMS (WordPress, Laravel, Django, Next.js, …)
- CDN hints (quick pass — full detection in `waf_detect`)
- Security posture (HTTPS, HSTS, missing headers)
- **Exposed files** (`.git/HEAD`, `.env`, `phpinfo.php`, `robots.txt`, …)

**Requests:** 1 (main) + up to 17 (passive files, skipped in `--fast`)

**Output:**
```json
{
  "server": {"name": "Apache", "version": "2.4.52"},
  "php": {"detected": true, "version": "8.1.2", "patch_status": "VULNERABLE"},
  "frameworks": [{"name": "WordPress", "confidence": "high"}],
  "interesting_files": [{"path": "/.env", "severity": "critical"}]
}
```

---

### 2. `headers` — Security Header Audit

**What it does:**
- HSTS (max-age, includeSubDomains, preload validation)
- CSP (`unsafe-inline`, `unsafe-eval`, wildcards, `data:` in script-src)
- X-Frame-Options (DENY, SAMEORIGIN, obsolete ALLOW-FROM)
- X-Content-Type-Options (`nosniff`)
- Referrer-Policy (strong/weak/insecure)
- Permissions-Policy (wildcards on sensitive features)
- **Cookies** (Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefix)
- **CORS** (wildcard + credentials, reflected origin)
- **Info disclosure** (Server, X-Powered-By, X-AspNet-Version, X-Forwarded-*)
- **A+ → F grading** (weighted by severity)

**Requests:** 1

**Output:**
```json
{
  "score": {"grade": "C", "total_score": 13},
  "findings": [
    {"severity": "high", "title": "CORS allows * with credentials"},
    {"severity": "medium", "title": "CSP allows 'unsafe-inline'"}
  ]
}
```

---

### 3. `tls` — TLS/SSL Analysis

**What it does:**
- Certificate: subject, SAN, issuer, validity, expiry
- Self-signed detection
- CN/SAN mismatch
- Signature algorithm (MD5, SHA-1 → insecure)
- Protocol versions (TLS 1.0/1.1/1.2/1.3 support)
- Cipher strength (PFS, AEAD, weak ciphers)
- SHA-256/SHA-1 fingerprints
- **A+ → F grading**

**Requests:** 1 (handshake) + 4 (version enumeration, skipped in `--fast`)

**Output:**
```json
{
  "grade": "A",
  "certificate": {
    "subject_cn": "target.com",
    "issuer_org": "Let's Encrypt",
    "days_until_expiry": 42,
    "is_self_signed": false
  },
  "versions": {"supported": ["TLSv1.2", "TLSv1.3"]},
  "cipher": {"negotiated": "TLS_AES_256_GCM_SHA384", "forward_secrecy": true}
}
```

---

### 4. `waf_detect` — WAF/CDN/IPS Detection

**What it does:**
- **Passive** — 25+ vendor signatures (headers, cookies, body)
- **Active** — 5 benign triggers (SQLi, XSS, traversal, cmd, union)
- **Differential** — status change, size shrink, latency anomaly, body change
- **Corroboration** — consistent result across attempts

**Requests:** 1 (baseline) + 5 (triggers) = ~6

**Detection confidence:** high / medium / low

**Output:**
```json
{
  "detected": true,
  "primary": {"name": "Cloudflare", "type": "CDN/WAF", "confidence": "high"},
  "active": {"block_ratio": 0.8, "typical_block_status": 403}
}
```

---

### 5. `waf_bypass` — WAF Bypass Testing

**What it does:**
- **17 generic techniques** (non-weaponized):
  - Header case manipulation
  - Missing / empty / crawler User-Agent
  - X-Forwarded-For: 127.0.0.1 / private IPs
  - Multi-IP spoof headers
  - Content-Type charset variation
  - Multipart boundary randomization
  - Path normalization (`//`, `/./`, trailing `/`)
  - Double URL encoding
  - Unicode-style encoding (`%u0027`)
  - X-HTTP-Method-Override
  - Cache-buster param

**Bypass = WAF block status (403/406/429) → non-block status (200/201/…)**

**Requests:** 1 (baseline) + 17 (techniques)

> ⚠️ **WAF bypass alone is usually NOT accepted as a bug bounty finding.** Chain with a real exploit (SQLi/XSS/RCE) to report.

**Output:**
```json
{
  "bypassable": true,
  "bypassed_count": 1,
  "working_techniques": ["X-Forwarded-For: 127.0.0.1"]
}
```

---

### 6. `takeover` — Subdomain Takeover

**What it does:**
- CNAME chain resolution (dangling record detection)
- 30+ provider fingerprints (S3, GitHub Pages, Heroku, Azure, Netlify, …)
- "Not found" page signature match
- NXDOMAIN + provider match → **high confidence takeover**

**Requests:** 0-2 (DNS only, or DNS + HTTP body check)

**Output:**
```json
{
  "vulnerable": true,
  "provider": "GitHub Pages",
  "confidence": "high",
  "dns": {"final_cname": "olduser.github.io"},
  "evidence": [{"claim_url": "https://github.com/settings/pages"}]
}
```

> ⚠️ **Do NOT claim** a takeover on a domain you don't own. Report to the owner instead.

---

### 7. `crash` — CVE Multipart Crash

**What it does:**
- Baseline control (minimal multipart)
- 3 probes: 1 MiB (4000 parts), 8 MiB (1020 parts), 20 MiB (1020 parts)
- **62 nested keys** (`a[][a][a]...`) — CVE trigger
- **Multi-signal crash detection**:
  - In-band memory error (strong)
  - HTTP 500 empty body (control had output)
  - HTTP 502/503/504 (FPM worker died)
  - HTTP 200 empty body (worker died)
- **Version corroboration** (`X-Powered-By`)
- **Retry for consistency** (reduces false positives)

**Requests:** 1 (control) + 3 (probes) + retries

**Verdicts:** VULNERABLE / FIXED / NO SIGNAL / INCONCLUSIVE / ERROR

**Output:**
```json
{
  "vulnerable": true,
  "verdict": "VULNERABLE",
  "sapi": "mod_php",
  "confidence": "high",
  "crash_count": 2,
  "reason": "probe 2: HTTP 500 empty body..."
}
```

---

## 🎛️ CLI Reference

### Input

| Flag | Description |
|---|---|
| `-u, --url URL` | Single target URL |
| `-l, --list FILE` | File with targets (one per line, `#` = comment) |

### Module Selection

| Flag | Description |
|---|---|
| `--only MODS` | Comma-separated modules to run (`fingerprint,headers,tls,waf_detect,waf_bypass,takeover,crash`) |
| `--skip MODS` | Comma-separated modules to skip |
| `--no-fingerprint` | Skip fingerprint |
| `--no-headers` | Skip header audit |
| `--no-tls` | Skip TLS analysis |
| `--no-waf` | Skip WAF detection |
| `--no-bypass` | Skip WAF bypass testing |
| `--no-takeover` | Skip takeover check |
| `--no-cve` | Skip CVE crash test |

### Performance

| Flag | Description | Default |
|---|---|---|
| `-t, --threads N` | Concurrent threads | `10` |
| `--timeout N` | Per-request timeout (seconds) | `60` |
| `--no-tls-versions` | Skip TLS version enumeration | `false` |
| `--fast` | Fast mode (passive WAF, no passive files) | `false` |
| `--rate-limit N` | Max requests/second per host | config |

### HTTP

| Flag | Description |
|---|---|
| `-k, --insecure` | Disable TLS verification |
| `--follow-redirects` | Follow 3xx redirects |
| `-H, --header 'K: V'` | Custom header (repeatable) |
| `-p, --proxy URL` | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--path PATH` | Custom path(s) to test (repeatable) |
| `--user-agent STR` | Override User-Agent |
| `--retries N` | Network retries per request (`1`) |

### Output

| Flag | Description |
|---|---|
| `-o, --output FILE` | JSON output (`.json` → aggregate, `.ndjson` → streaming) |
| `--csv` | Write 6 CSVs |
| `--csv-flat FILE` | Write single flat CSV |
| `--csv-prefix STR` | CSV filename prefix (`php2shell`) |
| `--csv-dir DIR` | CSV output directory (`.`) |
| `--html [FILE]` | Write HTML report (default: `php2shell_report.html`) |
| `--raw-bytes` | Include base64 raw request/response in JSON |
| `--no-summary` | Omit aggregate summary block from JSON |

### Display

| Flag | Description |
|---|---|
| `-q, --quiet` | Only show findings |
| `-v, --verbose` | Increase verbosity (`-v`, `-vv`) |
| `--no-color` | Disable colors |
| `--no-banner` | Skip ASCII banner |
| `--version` | Show version and exit |
| `-h, --help` | Show full help |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean (no vulnerabilities) |
| `1` | Vulnerable found |
| `2` | Error (invalid args, file not found, etc.) |
| `3` | Fatal error (crash) |
| `130` | Interrupted (Ctrl+C) |

---

## 📊 Output Formats

### JSON Schema

```json
{
  "tool": "php2shell",
  "version": "3.1.0",
  "author": "ATHEX BLACK HAT",
  "cves": "CVE-2026-109618 / CVE-2026-109619",
  "schema_version": "1.0",
  "generated_at": "2026-10-23T16:55:12Z",
  "scan_metadata": {
    "total_targets": 1,
    "scan_started_at": "...",
    "scan_ended_at": "..."
  },
  "summary": {
    "total_targets": 1,
    "vulnerable_targets": 1,
    "vulnerable_by_module": {"crash": 1, "takeover": 0, "waf_bypass": 0},
    "waf_detected": 1,
    "waf_vendors": {"Cloudflare": 1},
    "php_vulnerable": 1,
    "tls_grade_distribution": {"A": 1},
    "severity_counts": {"critical": 1, "high": 0, "medium": 3, ...}
  },
  "results": [
    {
      "target": "https://target.com/",
      "fingerprint": {...},
      "headers": {...},
      "tls": {...},
      "waf": {...},
      "bypass": {...},
      "takeover": {...},
      "crash": {...},
      "total_elapsed_ms": 11240.5,
      "error": null
    }
  ]
}
```

### CSV Files

| File | Rows | Key Columns |
|---|---|---|
| `*_summary.csv` | 1 per target | target, server, php_version, waf_name, tls_grade, crash_verdict |
| `*_findings.csv` | 1 per finding | target, module, severity, title, description, cwe |
| `*_endpoints.csv` | 1 per exposed file | target, path, status, severity |
| `*_probes.csv` | 1 per probe | target, probe_index, size_mib, status, elapsed_ms |
| `*_cookies.csv` | 1 per cookie | target, name, secure, httponly, samesite, issues |
| `*_tls.csv` | 1 per target | target, grade, versions, cipher, cert info |

**Excel compatibility:** UTF-8 BOM included — opens cleanly in Excel/Google Sheets.

**Formula injection safe:** cells starting with `=`, `+`, `-`, `@` are prefixed with `'`.

### HTML Report

Self-contained single file with:
- Dark/light theme toggle
- Interactive filtering (search + status buttons)
- Modal detail view (row click)
- Inline severity charts
- Print-friendly (Ctrl+P → clean PDF)
- Zero external dependencies

---

### Data Flow

```
Target URL
    ↓
[core.http] ──── async h11 transport
    ↓           rate limiter (token bucket)
    ↓           retry + backoff
    ↓           HTTP proxy CONNECT
    ↓
[modules/*] ──── detection logic
    ↓           multi-signal analysis
    ↓           confidence scoring
    ↓
[orchestrator] ── per-target result dict
    ↓
[output/*] ────── JSON / CSV / HTML
```

### Performance Notes

- **Thread-local event loops** — 1 loop per thread (10× faster than `asyncio.run()` per request)
- **Streaming upload** — 64 KiB chunks (bade probes RAM mein nahi)
- **Response cap** — 1 MiB body read limit (malformed servers se bachao)
- **Rate limiter** — per-host + global (target DoS nahi)

---

---

## ❓ FAQ

### Q: Is this legal to use?

**A:** Only on systems you **own** or have **explicit written permission** to test. Bug bounty programs — check scope. Otherwise: **illegal** (CFAA, PECA, CMA, etc.). See [Legal Notice](#-legal-notice).

### Q: Can I use this for bug bounty?

**A:** Yes, but **respect scope and rate limits**. Many programs forbid automated scanners. Always:
- Read the program's rules
- Check if WAF bypass testing is in scope
- Use `-t 5` (not `-t 50`)
- Report findings responsibly

### Q: WAF bypass = vulnerability?

**A:** **No** — usually. WAF bypass is a **mitigation weakness**, not a vulnerability. It's only reportable if:
- You **chain it with a real exploit** (SQLi/XSS/RCE)
- You demonstrate **auth bypass** or **cache poisoning**

Alone: vendors usually mark "won't fix" / "informational".

### Q: What's the difference between `--fast` and `--only`?

**A:**
- `--fast` — **same modules**, but fewer requests per module (passive-only WAF, no TLS version enumeration, no passive files)
- `--only` — **fewer modules** (e.g. just fingerprint + takeover)

You can combine: `--only fingerprint,takeover --fast` for ultra-fast recon.

### Q: The scan is slow. How can I speed it up?

**Options:**
1. `--fast` — 3-4× faster
2. `--only fingerprint,takeover` — 10× faster (skip slow modules)
3. `--no-tls-versions` — saves ~4 requests per target
4. `-t 30` — more threads (batch scans)
5. `--no-bypass` — skip 17 bypass requests per target

### Q: My target returns 403 to everything. What now?

**A:** Likely:
- WAF is blocking (see `waf` module output)
- Target requires auth (use `-H "Authorization: Bearer ..."`)
- IP blocked (use `-p` proxy)

### Q: Can I add custom WAF signatures?

**A:** Yes — edit `core/config.py` → `WAF_SIGNATURES` list. Format:
```python
("VendorName", "WAF", [r"^header-regex"], [r"body-regex"], [r"cookie-regex"])
```

### Q: Can I add custom takeover providers?

**A:** Yes — edit `modules/takeover.py` → `PROVIDERS` list. Format:
```python
Provider(
    name="MyProvider",
    cname_patterns=[r"\.myprovider\.com$"],
    fingerprint=[r"not found signature"],
    vulnerable=True,
    claim_url="https://myprovider.com/register",
)
```

### Q: Why does crash test send 20 MiB?

**A:** The CVE trigger requires deep nesting + large body to exhaust PHP's parser memory. The 20 MiB probe is the largest test — smaller ones (1, 8 MiB) often suffice.

### Q: Is the HTML report really self-contained?

**A:** Yes — CSS, JS, and data are all inlined. No external CDN. Open it offline, email it, or print to PDF — everything works.

### Q: How do I get JSON with raw bytes?

**A:** Use `--raw-bytes`:
```bash
python3 php2shell.py -u https://target.com -o scan.json --raw-bytes
```
Bodies are base64-encoded (capped at 8 KiB per field).

---

## 🔧 Troubleshooting

### Error: `ModuleNotFoundError: No module named 'h11'`

```bash
pip install h11 tqdm
# or
pip install -r requirements.txt
```

### Error: `SSL: CERTIFICATE_VERIFY_FAILED`

The target has an invalid cert. Use `-k` to skip verification:
```bash
python3 php2shell.py -u https://target.com -k
```

### Error: `All connection attempts failed`

- Target is down
- Firewall blocking you
- Try `-p` proxy
- Try `--timeout 120`

### Scan hangs on a target

Reduce timeout:
```bash
python3 php2shell.py -u https://slow-target.com --timeout 30
```

Or skip the slow module:
```bash
python3 php2shell.py -u https://slow-target.com --no-bypass
```

### WAF detection says "NO_WAF" but I know there's one

Possible reasons:
- Baseline got 403 (WAF blocks your IP entirely)
- Custom WAF signature not in database (add to `config.py`)
- WAF only triggers on specific payloads (this tool uses benign ones)

Try sending a manual suspicious request through Burp first.

### Takeover check says "not vulnerable" but I know it is

Check:
- DNS resolution — is the CNAME actually dangling?
- Provider in database? (add to `modules/takeover.py`)
- Wait 24-48h for DNS propagation

### CSV opens with weird characters in Excel

The file has UTF-8 BOM — Excel should handle it. If not:
1. Excel → Data → From Text → select file → UTF-8 encoding
2. Or open in Google Sheets / LibreOffice

### Verbose mode isn't showing more

```bash
# -v = INFO (default)
# -vv = DEBUG
python3 php2shell.py -u https://target.com -vv
```

---

## ⚠️ Legal Notice

**This tool is for AUTHORIZED security testing ONLY.**

### You MAY use php2shell on:
- ✅ Systems you **own**
- ✅ Systems you have **explicit written permission** to test
- ✅ Bug bounty programs where automated scanners are **in scope**
- ✅ CTF / lab environments you control

### You MAY NOT use php2shell on:
- ❌ Any third-party system without written permission
- ❌ Bug bounty targets where scanners are **out of scope**
- ❌ Any system you're just "curious" about

### Consequences of misuse

- **United States:** Computer Fraud and Abuse Act (CFAA) — up to 10 years prison
- **United Kingdom:** Computer Misuse Act (CMA) — up to 10 years prison
- **Pakistan:** Prevention of Electronic Crimes Act (PECA) — up to 7 years prison
- **EU:** Directive 2013/40/EU — criminal offense in all member states
- **Everywhere:** Civil liability, account termination, reputation damage

### The tool includes

- Active WAF bypass testing
- Crash-inducing payloads (PHP memory exhaustion)
- Aggressive header manipulation
- Subdomain takeover detection

**These are real attacks.** Treat them accordingly.

### Responsible disclosure

If you find a vulnerability:
1. **Do not** publicly disclose
2. **Do not** claim subdomains / upload files
3. **Report** to the target's security contact (or bug bounty platform)
4. **Give** reasonable time to fix (typically 90 days)

---

## 👤 Author

**ATHEX BLACK HAT**

A security researcher focused on web application vulnerabilities, bug bounty hunting, and offensive tooling development.

- 🐙 GitHub: [@athexx](https://github.com/Athexblackhat2) *(placeholder)*

---


## 📄 License

**Custom license: Authorized Security Testing Only**

This tool may be used freely for authorized security testing. Any use for unauthorized access, data theft, or disruption is prohibited and may be illegal.

The author is not responsible for misuse. Use at your own risk.

---

<div align="center">

**php2shell v3.1.0** · by [ATHEX BLACK HAT](#-author)

*Built for authorized security research*

⚠️ **Test responsibly. Report ethically. Do no harm.** ⚠️

</div>