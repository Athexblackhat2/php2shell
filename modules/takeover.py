#!/usr/bin/env python3
"""
modules/takeover.py — Subdomain takeover detection for php2shell
Author: ATHEX BLACK HAT

Purpose:
  Detect dangling CNAME / unclaimed cloud resources that could be taken over
  by an attacker (aka "subdomain takeover").

Coverage:
  - CNAME chain resolution (dangling record detection)
  - Cloud provider fingerprint database (50+ services)
  - "Not found" page signature matching
  - DNS status classification (unclaimed / claimed / dead / unknown)
  - Per-provider claim-URL hints (for manual verification)

Does NOT claim or create resources. Detection only.

References:
  - https://github.com/EdOverflow/can-i-take-over-xyz
  - https://github.com/indianajson/can-i-take-over-xyz
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.config import DEFAULT_TIMEOUT
from core.http import (
    HTTPResult,
    send_request,
    http_get,
    ProxyConfig,
)
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  PROVIDER FINGERPRINTS
# ═══════════════════════════════════════════════════════════════════════════
#
# Each provider:
#   name          - human name
#   cname_patterns - list of regex to match against the final CNAME target
#   fingerprint   - list of regex to match against HTTP response body
#   vulnerable    - True  → takeable
#                   False → usually NOT takeable (provider protects)
#                   "edge"→ depends on config
#   claim_url     - where the resource would be claimed (for manual check)
#   severity      - impact if taken over
#

@dataclass
class Provider:
    name: str
    cname_patterns: List[str]
    fingerprint: List[str]
    vulnerable: bool | str
    claim_url: str
    severity: str = "high"
    notes: str = ""


PROVIDERS: List[Provider] = [
    # ── AWS S3 ──
    Provider(
        name="AWS S3",
        cname_patterns=[
            r"^[a-z0-9.\-_]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com$",
            r"^[a-z0-9.\-_]+\.s3\.amazonaws\.com$",
            r"^s3[.\-][a-z0-9\-]+\.amazonaws\.com$",
            r"^[a-z0-9.\-_]+\.s3-website[.\-][a-z0-9\-]+\.amazonaws\.com$",
            r"^[a-z0-9.\-_]+\.s3\.dualstack\.[a-z0-9\-]+\.amazonaws\.com$",
        ],
        fingerprint=[
            r"The specified bucket does not exist",
            r"NoSuchBucket",
            r"<Code>NoSuchBucket</Code>",
        ],
        vulnerable=True,
        claim_url="https://s3.console.aws.amazon.com/s3/buckets",
        severity="critical",
        notes="Create bucket with same name in any AWS region",
    ),
    # ── GitHub Pages ──
    Provider(
        name="GitHub Pages",
        cname_patterns=[
            r"^[a-z0-9\-]+\.github\.io$",
        ],
        fingerprint=[
            r"404\s*There\s*isn't\s*a\s*GitHub\s*Pages\s*site\s*here",
            r"There isn't a GitHub Pages site here",
        ],
        vulnerable=True,
        claim_url="https://github.com/settings/pages",
        severity="high",
        notes="Create repo <user>.github.io and set custom domain",
    ),
    # ── Heroku ──
    Provider(
        name="Heroku",
        cname_patterns=[
            r"\.herokuapp\.com$",
            r"\.herokussl\.com$",
            r"\.herokudns\.com$",
        ],
        fingerprint=[
            r"No such app",
            r"heroku \| no such app",
        ],
        vulnerable=True,
        claim_url="https://dashboard.heroku.com/apps",
        severity="critical",
        notes="Create app with same name",
    ),
    # ── Netlify ──
    Provider(
        name="Netlify",
        cname_patterns=[
            r"\.netlify\.app$",
            r"\.netlify\.com$",
        ],
        fingerprint=[
            r"Not Found - Request ID",
            r"site not found",
            r"<title>Netlify</title>.*Not Found",
        ],
        vulnerable=True,
        claim_url="https://app.netlify.com/",
        severity="high",
        notes="Add custom domain to your site",
    ),
    # ── Azure (blob, web apps, cloudapp) ──
    Provider(
        name="Azure",
        cname_patterns=[
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.blob\.core\.windows\.net$",
            r"\.azureedge\.net$",
            r"\.trafficmanager\.net$",
            r"\.azurestaticapps\.net$",
            r"\.azurefd\.net$",
        ],
        fingerprint=[
            r"404 Web Site not found",
            r"Error 404 - Web app not found",
            r"The resource you are looking for has been removed",
            r"BlobNotFound",
            r"<Code>BlobNotFound</Code>",
            r"<Code>ContainerNotFound</Code>",
            r"This Azure Web App is stopped",
        ],
        vulnerable=True,
        claim_url="https://portal.azure.com/",
        severity="high",
        notes="Register resource with same name in any subscription",
    ),
    # ── GCP Cloud Storage / App Engine ──
    Provider(
        name="GCP",
        cname_patterns=[
            r"\.storage\.googleapis\.com$",
            r"\.appspot\.com$",
            r"\.googleapis\.com$",
            r"\.run\.app$",
            r"\.web\.app$",
            r"\.firebaseapp\.com$",
        ],
        fingerprint=[
            r"NoSuchBucket",
            r"The specified bucket does not exist",
            r"404\. That's an error\.",
            r"Site Not Found",
        ],
        vulnerable=True,
        claim_url="https://console.cloud.google.com/",
        severity="high",
        notes="Register bucket/app with same name in your project",
    ),
    # ── Shopify ──
    Provider(
        name="Shopify",
        cname_patterns=[
            r"\.myshopify\.com$",
        ],
        fingerprint=[
            r"Sorry, this shop is currently unavailable",
            r"Only one step left!",
        ],
        vulnerable="edge",
        claim_url="https://www.shopify.com/signup",
        severity="medium",
        notes="Usually protected by ownership verification",
    ),
    # ── Fastly ──
    Provider(
        name="Fastly",
        cname_patterns=[
            r"\.fastly\.net$",
            r"\.fastlylb\.net$",
            r"\.global\.ssl\.fastly\.net$",
        ],
        fingerprint=[
            r"Fastly error: unknown domain",
            r"Fastly error: invalid host",
        ],
        vulnerable=True,
        claim_url="https://manage.fastly.com/",
        severity="high",
        notes="Point CNAME to your Fastly service",
    ),
    # ── Pantheon ──
    Provider(
        name="Pantheon",
        cname_patterns=[
            r"\.pantheonsite\.io$",
        ],
        fingerprint=[
            r"The gods are wise, but do not know of such a site",
            r"404 error unknown site!",
        ],
        vulnerable=True,
        claim_url="https://dashboard.pantheon.io/",
        severity="high",
    ),
    # ── Tumblr ──
    Provider(
        name="Tumblr",
        cname_patterns=[
            r"\.tumblr\.com$",
        ],
        fingerprint=[
            r"Whatever you were looking for doesn't currently exist at this address",
            r"There's nothing here",
        ],
        vulnerable=True,
        claim_url="https://www.tumblr.com/",
        severity="medium",
    ),
    # ── WordPress.com ──
    Provider(
        name="WordPress.com",
        cname_patterns=[
            r"\.wordpress\.com$",
        ],
        fingerprint=[
            r"Do you want to register",
            r"doesn’t exist",
        ],
        vulnerable="edge",
        claim_url="https://wordpress.com/",
        severity="medium",
    ),
    # ── Ghost (Ghost Pro) ──
    Provider(
        name="Ghost",
        cname_patterns=[
            r"\.ghost\.io$",
        ],
        fingerprint=[
            r"The thing you were looking for is no longer here",
        ],
        vulnerable=True,
        claim_url="https://ghost.org/",
        severity="medium",
    ),
    # ── Unbounce ──
    Provider(
        name="Unbounce",
        cname_patterns=[
            r"\.unbouncepages\.com$",
        ],
        fingerprint=[
            r"The requested URL was not found on this server",
        ],
        vulnerable=True,
        claim_url="https://app.unbounce.com/",
        severity="medium",
    ),
    # ── Bitbucket ──
    Provider(
        name="Bitbucket",
        cname_patterns=[
            r"\.bitbucket\.io$",
        ],
        fingerprint=[
            r"Repository not found",
        ],
        vulnerable=True,
        claim_url="https://bitbucket.org/",
        severity="low",
    ),
    # ── AWS Elastic Beanstalk ──
    Provider(
        name="AWS Elastic Beanstalk",
        cname_patterns=[
            r"\.elasticbeanstalk\.com$",
        ],
        fingerprint=[
            r"404 Not Found",
        ],
        vulnerable=True,
        claim_url="https://console.aws.amazon.com/elasticbeanstalk",
        severity="high",
    ),
    # ── Azure Traffic Manager ──
    Provider(
        name="Azure Traffic Manager",
        cname_patterns=[
            r"\.trafficmanager\.net$",
        ],
        fingerprint=[
            r"Not Found",
        ],
        vulnerable=True,
        claim_url="https://portal.azure.com/",
        severity="high",
    ),
    # ── Zendesk ──
    Provider(
        name="Zendesk",
        cname_patterns=[
            r"\.zendesk\.com$",
        ],
        fingerprint=[
            r"Help Center Closed",
        ],
        vulnerable="edge",
        claim_url="https://www.zendesk.com/register",
        severity="low",
    ),
    # ── UserVoice ──
    Provider(
        name="UserVoice",
        cname_patterns=[
            r"\.uservoice\.com$",
        ],
        fingerprint=[
            r"This UserVoice subdomain is currently available!",
        ],
        vulnerable=True,
        claim_url="https://www.uservoice.com/",
        severity="medium",
    ),
    # ── WPEngine ──
    Provider(
        name="WPEngine",
        cname_patterns=[
            r"\.wpengine\.com$",
            r"\.wpenginepowered\.com$",
        ],
        fingerprint=[
            r"The site you were looking for couldn't be found",
        ],
        vulnerable=True,
        claim_url="https://my.wpengine.com/",
        severity="medium",
    ),
    # ── Surge.sh ──
    Provider(
        name="Surge.sh",
        cname_patterns=[
            r"\.surge\.sh$",
        ],
        fingerprint=[
            r"project not found",
        ],
        vulnerable=True,
        claim_url="https://surge.sh/",
        severity="medium",
    ),
    # ── Read the Docs ──
    Provider(
        name="Read the Docs",
        cname_patterns=[
            r"\.readthedocs\.io$",
            r"\.readthedocs\.org$",
        ],
        fingerprint=[
            r"The link you have used to enter the WordPress site",
            r"404",
        ],
        vulnerable=True,
        claim_url="https://readthedocs.org/",
        severity="low",
    ),
    # ── Strikingly ──
    Provider(
        name="Strikingly",
        cname_patterns=[
            r"\.s\.strikingly\.com$",
        ],
        fingerprint=[
            r"page not found",
        ],
        vulnerable=True,
        claim_url="https://www.strikingly.com/",
        severity="medium",
    ),
    # ── Launchrock ──
    Provider(
        name="Launchrock",
        cname_patterns=[
            r"\.launchrock\.com$",
        ],
        fingerprint=[
            r"It looks like you may have taken a wrong turn somewhere",
        ],
        vulnerable=True,
        claim_url="https://www.launchrock.com/",
        severity="low",
    ),
    # ── SmugMug ──
    Provider(
        name="SmugMug",
        cname_patterns=[
            r"\.smugmug\.com$",
        ],
        fingerprint=[
            r"Page Not Found",
        ],
        vulnerable=True,
        claim_url="https://www.smugmug.com/",
        severity="low",
    ),
    # ── Cargo ──
    Provider(
        name="Cargo",
        cname_patterns=[
            r"\.cargocollective\.com$",
        ],
        fingerprint=[
            r"404 Not Found",
        ],
        vulnerable=True,
        claim_url="https://cargocollective.com/",
        severity="low",
    ),
    # ── FeedPress ──
    Provider(
        name="FeedPress",
        cname_patterns=[
            r"\.feedpress\.me$",
        ],
        fingerprint=[
            r"The feed has not been found",
        ],
        vulnerable=True,
        claim_url="https://feedpress.me/",
        severity="low",
    ),
    # ── Fly.io ──
    Provider(
        name="Fly.io",
        cname_patterns=[
            r"\.fly\.dev$",
            r"\.fly\.io$",
        ],
        fingerprint=[
            r"404 Not Found",
            r"<title>404</title>",
        ],
        vulnerable="edge",
        claim_url="https://fly.io/dashboard",
        severity="medium",
    ),
    # ── Vercel ──
    Provider(
        name="Vercel",
        cname_patterns=[
            r"\.vercel\.app$",
            r"\.now\.sh$",
        ],
        fingerprint=[
            r"The deployment could not be found",
            r"DEPLOYMENT_NOT_FOUND",
        ],
        vulnerable="edge",
        claim_url="https://vercel.com/dashboard",
        severity="medium",
    ),
    # ── GitLab Pages ──
    Provider(
        name="GitLab Pages",
        cname_patterns=[
            r"\.gitlab\.io$",
        ],
        fingerprint=[
            r"The page you're looking for could not be found",
            r"404 Not Found",
        ],
        vulnerable=True,
        claim_url="https://gitlab.com/",
        severity="low",
    ),
    # ── DigitalOcean App Platform ──
    Provider(
        name="DigitalOcean",
        cname_patterns=[
            r"\.ondigitalocean\.app$",
            r"\.digitaloceanspaces\.com$",
        ],
        fingerprint=[
            r"404 Not Found",
            r"NoSuchBucket",
        ],
        vulnerable="edge",
        claim_url="https://cloud.digitalocean.com/",
        severity="medium",
    ),
    # ── Plesk ──
    Provider(
        name="Plesk",
        cname_patterns=[
            r"\.plesk\.page$",
        ],
        fingerprint=[
            r"404 Not Found",
        ],
        vulnerable=True,
        claim_url="https://www.plesk.com/",
        severity="low",
    ),
    # ── Tilda ──
    Provider(
        name="Tilda",
        cname_patterns=[
            r"\.tilda\.ws$",
        ],
        fingerprint=[
            r"Please renew your subscription",
        ],
        vulnerable=True,
        claim_url="https://tilda.cc/",
        severity="low",
    ),
    # ── Statuspage ──
    Provider(
        name="Statuspage",
        cname_patterns=[
            r"\.statuspage\.io$",
        ],
        fingerprint=[
            r"You are being redirected",
        ],
        vulnerable="edge",
        claim_url="https://www.statuspage.io/",
        severity="low",
    ),
    # ── JetBrains Space ──
    Provider(
        name="JetBrains Space",
        cname_patterns=[
            r"\.jetbrains\.space$",
        ],
        fingerprint=[
            r"404 Not Found",
        ],
        vulnerable="edge",
        claim_url="https://www.jetbrains.com/space/",
        severity="low",
    ),
    # ── Ngrok ──
    Provider(
        name="Ngrok",
        cname_patterns=[
            r"\.ngrok\.io$",
            r"\.ngrok-free\.app$",
        ],
        fingerprint=[
            r"Tunnel .* not found",
            r"ERR_NGROK_",
        ],
        vulnerable=True,
        claim_url="https://dashboard.ngrok.com/",
        severity="medium",
    ),
    # ── Kong ──
    Provider(
        name="Kong",
        cname_patterns=[
            r"\.kongcloud\.io$",
        ],
        fingerprint=[
            r"404 Not Found",
        ],
        vulnerable="edge",
        claim_url="https://konghq.com/",
        severity="low",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DNSChain:
    """CNAME chain resolution result."""
    hostname: str
    chain: List[str] = field(default_factory=list)
    final_cname: Optional[str] = None
    a_records: List[str] = field(default_factory=list)
    is_dangling: bool = False
    nxdomain: bool = False
    error: Optional[str] = None
    dns_time_ms: float = 0.0


@dataclass
class TakeoverEvidence:
    """Evidence for a takeover finding."""
    provider: str
    confidence: str            # high | medium | low
    cname_matched: bool = False
    fingerprint_matched: bool = False
    status_code: Optional[int] = None
    claim_url: str = ""
    notes: str = ""
    severity: str = "high"
    response_snippet: str = ""


@dataclass
class TakeoverResult:
    """Complete takeover detection result for one hostname."""
    hostname: str = ""
    url: str = ""
    vulnerable: Optional[bool] = None
    confidence: str = "none"
    provider: Optional[str] = None
    severity: str = "info"
    reason: str = ""

    # DNS
    dns: Optional[DNSChain] = None

    # Evidence
    evidence: List[TakeoverEvidence] = field(default_factory=list)

    # HTTP
    http_status: Optional[int] = None
    http_body_snippet: str = ""

    # Meta
    error: Optional[str] = None
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["dns"] = asdict(self.dns) if self.dns else None
        d["evidence"] = [asdict(e) for e in self.evidence]
        return d

    def summary_line(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.vulnerable is True:
            return f"TAKEOVER ({self.provider}, {self.confidence})"
        if self.vulnerable is False:
            return "not vulnerable"
        return f"inconclusive ({self.reason})"


# ═══════════════════════════════════════════════════════════════════════════
#  DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_cname_chain(hostname: str, max_hops: int = 10) -> DNSChain:
    """
    Follow CNAME chain until A record or dead end.

    Uses socket.gethostbyname_ex which returns (hostname, aliases, ips).
    aliases give us the CNAME chain resolution (limited, but works without dnspython).
    """
    result = DNSChain(hostname=hostname)
    t0 = time.perf_counter()

    try:
        canonical, aliases, ips = socket.gethostbyname_ex(hostname)
        result.chain = aliases or []
        result.a_records = ips or []

        # The "canonical name" may differ from the input
        if canonical and canonical != hostname:
            # It's the final A record target
            result.final_cname = aliases[-1] if aliases else canonical

        # If no IPs → dangling
        if not ips:
            result.is_dangling = True

    except socket.gaierror as exc:
        # NXDOMAIN or timeout
        errno_ = getattr(exc, "errno", None)
        if errno_ == socket.EAI_NONAME or "Name or service not known" in str(exc):
            result.nxdomain = True
            result.is_dangling = True
        else:
            result.error = str(exc)
    except Exception as exc:
        result.error = str(exc)

    result.dns_time_ms = round((time.perf_counter() - t0) * 1000, 1)
    return result


def _match_provider_by_cname(cname: str) -> Optional[Provider]:
    """Find provider by CNAME pattern match."""
    if not cname:
        return None
    cname_l = cname.lower().rstrip(".")
    for provider in PROVIDERS:
        for pat in provider.cname_patterns:
            if re.search(pat, cname_l, re.IGNORECASE):
                return provider
    return None


def _match_provider_by_body(body: str) -> Optional[Provider]:
    """Find provider by response body fingerprint match."""
    if not body:
        return None
    for provider in PROVIDERS:
        for pat in provider.fingerprint:
            try:
                if re.search(pat, body, re.IGNORECASE):
                    return provider
            except re.error:
                continue
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def check_takeover(
    hostname: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    proxy: Optional[ProxyConfig] = None,
    scheme: str = "https",
    custom_headers: Optional[Dict[str, str]] = None,
    check_body_fingerprint: bool = True,
) -> TakeoverResult:
    """
    Check a single hostname for subdomain takeover.

    Args:
        hostname: domain (e.g. "sub.example.com")
        scheme: "https" or "http"
        check_body_fingerprint: if True, fetch HTTP and match body patterns
        verify_ssl: TLS verify
        proxy: optional ProxyConfig

    Returns:
        TakeoverResult with verdict.
    """
    started = time.perf_counter()
    result = TakeoverResult(hostname=hostname)
    hostname = hostname.strip().rstrip(".")
    url = f"{scheme}://{hostname}/"
    result.url = url

    # ── Step 1: DNS resolution ──
    Logger.info(f"Resolving CNAME chain for {hostname}", module="takeover")
    dns = _resolve_cname_chain(hostname)
    result.dns = dns

    if dns.error and not dns.nxdomain:
        result.error = f"DNS resolution failed: {dns.error}"
        result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        Logger.warning(result.error, module="takeover")
        return result

    if dns.chain:
        Logger.debug(
            f"CNAME chain: {hostname} → {' → '.join(dns.chain)}",
            module="takeover",
        )
    if dns.final_cname:
        Logger.debug(f"Final CNAME target: {dns.final_cname}", module="takeover")

    # ── Step 2: Provider match by CNAME ──
    candidate_cname = dns.final_cname or (dns.chain[-1] if dns.chain else None)
    provider = _match_provider_by_cname(candidate_cname) if candidate_cname else None

    if provider:
        Logger.info(
            f"CNAME matches provider: {provider.name}",
            module="takeover",
        )
        evidence = TakeoverEvidence(
            provider=provider.name,
            confidence="medium",  # upgraded if body also matches
            cname_matched=True,
            claim_url=provider.claim_url,
            notes=provider.notes,
            severity=provider.severity,
        )
        result.evidence.append(evidence)

    # ── Step 3: HTTP fetch + body fingerprint ──
    if check_body_fingerprint:
        Logger.debug(f"Fetching {url}", module="takeover")
        try:
            response = http_get(
                url,
                timeout=min(timeout, 15),
                verify_ssl=verify_ssl,
                follow_redirects=True,
                proxy=proxy,
                retries=0,
                rate_limit=True,
                headers=dict(custom_headers or {}),
            )
        except Exception as exc:
            Logger.debug(f"HTTP fetch failed: {exc}", module="takeover")
            response = None

        if response and not response.error:
            result.http_status = response.status_code
            result.http_body_snippet = response.body_text[:512]

            body_provider = _match_provider_by_body(response.body_text)
            if body_provider:
                Logger.info(
                    f"Body fingerprint matches provider: {body_provider.name}",
                    module="takeover",
                )
                # If CNAME provider and body provider agree → strong signal
                if provider and provider.name == body_provider.name:
                    evidence = result.evidence[0] if result.evidence else TakeoverEvidence(
                        provider=body_provider.name,
                        confidence="high",
                        claim_url=body_provider.claim_url,
                        notes=body_provider.notes,
                        severity=body_provider.severity,
                    )
                    evidence.fingerprint_matched = True
                    evidence.status_code = response.status_code
                    evidence.response_snippet = response.body_text[:256]
                    evidence.confidence = "high"
                    if evidence not in result.evidence:
                        result.evidence.append(evidence)
                    else:
                        evidence.confidence = "high"
                        evidence.fingerprint_matched = True
                else:
                    # Body matches but CNAME doesn't → maybe mid-migration
                    result.evidence.append(TakeoverEvidence(
                        provider=body_provider.name,
                        confidence="medium",
                        fingerprint_matched=True,
                        status_code=response.status_code,
                        claim_url=body_provider.claim_url,
                        notes=body_provider.notes,
                        severity=body_provider.severity,
                        response_snippet=response.body_text[:256],
                    ))
                    if provider is None:
                        provider = body_provider

    # ── Step 4: Verdict computation ──
    result.total_elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    # 4a: NXDOMAIN + known provider CNAME = very strong takeover signal
    if dns.nxdomain and provider:
        result.vulnerable = True
        result.confidence = "high"
        result.provider = provider.name
        result.severity = provider.severity
        result.reason = (
            f"NXDOMAIN on {hostname} but CNAME points to {provider.name} "
            f"({candidate_cname or '?'}) — likely dangling"
        )
        if provider.vulnerable == False:
            result.vulnerable = False
            result.confidence = "high"
            result.reason = f"Provider {provider.name} protects against takeover"
        elif provider.vulnerable == "edge":
            result.vulnerable = None
            result.confidence = "low"
            result.reason = (
                f"{provider.name} may or may not be takeover-able — "
                "manual verification required"
            )
        Logger.vuln(result.reason, module="takeover")
        return result

    # 4b: Body fingerprint matched + provider matched
    if any(e.fingerprint_matched for e in result.evidence):
        e = next(ev for ev in result.evidence if ev.fingerprint_matched)
        if e.confidence == "high":
            result.vulnerable = True
            result.confidence = "high"
            result.provider = e.provider
            result.severity = e.severity
            result.reason = (
                f"Provider page confirms unclaimed resource: {e.provider}"
            )
            Logger.vuln(result.reason, module="takeover")
            return result
        elif e.confidence == "medium":
            result.vulnerable = None
            result.confidence = "medium"
            result.provider = e.provider
            result.severity = e.severity
            result.reason = (
                f"Response body matches {e.provider} not-found page — "
                "likely takeover-able, verify manually"
            )
            Logger.warning(result.reason, module="takeover")
            return result

    # 4c: Provider matched but no body confirmation
    if provider:
        if provider.vulnerable == False:
            result.vulnerable = False
            result.confidence = "medium"
            result.provider = provider.name
            result.reason = f"{provider.name} protects against takeover"
        else:
            result.vulnerable = None
            result.confidence = "low"
            result.provider = provider.name
            result.reason = (
                f"CNAME points to {provider.name} but no not-found page seen — "
                "may require manual verification"
            )
            if dns.is_dangling:
                result.vulnerable = True
                result.confidence = "medium"
                result.reason = (
                    f"DNS appears dangling (no A records) and CNAME → "
                    f"{provider.name}"
                )
        if result.vulnerable:
            Logger.vuln(result.reason, module="takeover")
        else:
            Logger.info(result.reason, module="takeover")
        return result

    # 4d: No provider match, no fingerprint
    if dns.is_dangling:
        result.vulnerable = None
        result.confidence = "low"
        result.reason = (
            "DNS dangling (no A records) but unknown provider — "
            "manual investigation required"
        )
        Logger.warning(result.reason, module="takeover")
    else:
        result.vulnerable = False
        result.confidence = "high"
        result.reason = "Hostname resolves normally, no takeover signal"
        Logger.info(result.reason, module="takeover")

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  BATCH
# ═══════════════════════════════════════════════════════════════════════════

def check_takeover_batch(
    hostnames: List[str],
    max_workers: int = 10,
    **kwargs,
) -> List[TakeoverResult]:
    """Parallel takeover check."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[TakeoverResult] = []
    progress = Logger.progress(
        total=len(hostnames), desc="Takeover", unit="host"
    )
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(check_takeover, h, **kwargs): h for h in hostnames}
            for fut in as_completed(futures):
                h = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    Logger.error(
                        f"Takeover check error on {h}: {exc}",
                        module="takeover",
                    )
                    r = TakeoverResult(hostname=h)
                    r.error = str(exc)
                    results.append(r)
                progress.update(1)
    finally:
        progress.close()
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  PROVIDER INFO (for reports)
# ═══════════════════════════════════════════════════════════════════════════

def list_providers() -> List[Dict]:
    """Return provider database (for docs/reports)."""
    return [
        {
            "name": p.name,
            "severity": p.severity,
            "claim_url": p.claim_url,
            "vulnerable": p.vulnerable,
            "notes": p.notes,
        }
        for p in PROVIDERS
    ]


def get_provider(name: str) -> Optional[Dict]:
    """Look up a provider by name."""
    for p in PROVIDERS:
        if p.name.lower() == name.lower():
            return {
                "name": p.name,
                "severity": p.severity,
                "claim_url": p.claim_url,
                "vulnerable": p.vulnerable,
                "notes": p.notes,
            }
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "TakeoverResult",
    "TakeoverEvidence",
    "DNSChain",
    "Provider",
    "PROVIDERS",
    "check_takeover",
    "check_takeover_batch",
    "list_providers",
    "get_provider",
]