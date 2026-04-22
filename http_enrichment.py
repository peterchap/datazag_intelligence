"""
HTTP enrichment pipeline — headers and favicon hashing
Runs against live subdomains after A record resolution.

For each live subdomain:
  1. HEAD request → security headers + redirect chain
  2. GET /favicon.ico → favicon hash (MD5 + perceptual hash)
  3. Optional: GET / → page title, HTML hash (for visual similarity)

Single asyncio pass — all three requests concurrent per subdomain,
all subdomains concurrent via semaphore.

Output: Polars DataFrame, one row per subdomain, ready to join
        against your subdomain corpus table.
"""

import asyncio
import hashlib
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
import polars as pl


# ── Security header definitions ────────────────────────────────────────────

SECURITY_HEADERS = {
    # (header_name, severity_if_missing, plain_english_label)
    "strict-transport-security": (
        "elevated",
        "HSTS not set — browser not forced to use HTTPS",
    ),
    "content-security-policy": (
        "elevated",
        "No Content Security Policy — XSS and injection risk elevated",
    ),
    "x-frame-options": (
        "elevated",
        "Clickjacking protection absent",
    ),
    "x-content-type-options": (
        "low",
        "MIME sniffing protection absent",
    ),
    "referrer-policy": (
        "low",
        "Referrer policy not set — URL leakage risk",
    ),
    "permissions-policy": (
        "low",
        "Permissions policy not set",
    ),
}

INFORMATION_DISCLOSURE_HEADERS = {
    # Headers that reveal server internals — presence is the finding
    "server":           "Server software version disclosed",
    "x-powered-by":     "Backend technology disclosed",
    "x-aspnet-version": "ASP.NET version disclosed",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosed",
    "x-generator":      "CMS/generator disclosed",
    "x-drupal-cache":   "Drupal CMS confirmed",
    "x-varnish":        "Varnish cache confirmed",
    "via":              "Proxy/CDN layer disclosed",
}

HSTS_MIN_AGE = 15_552_000  # 180 days — below this is weak HSTS

CDN_SIGNATURES = {
    "cloudflare":   ["cf-ray", "cf-cache-status", "cf-request-id"],
    "fastly":       ["x-fastly-request-id", "x-served-by"],
    "akamai":       ["x-akamai-transformed", "x-check-cacheable"],
    "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "vercel":       ["x-vercel-cache", "x-vercel-id"],
    "netlify":      ["x-nf-request-id"],
    "azure_cdn":    ["x-azure-ref", "x-ms-request-id"],
    "google_cloud": ["x-cloud-trace-context", "via: 1.1 google"],
    "sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
}


# ── Data classes ───────────────────────────────────────────────────────────

@dataclass
class SecurityHeaderResult:
    present:        bool
    value:          Optional[str] = None
    severity:       Optional[str] = None  # If missing, what severity
    finding:        Optional[str] = None  # Plain English finding text


@dataclass
class FaviconResult:
    found:          bool = False
    url:            Optional[str] = None
    status_code:    Optional[int] = None
    content_type:   Optional[str] = None
    size_bytes:     Optional[int] = None
    md5:            Optional[str] = None
    sha1:           Optional[str] = None
    mmh3:           Optional[int] = None
    phash:          Optional[str] = None  # Perceptual hash (hex)
    error:          Optional[str] = None


@dataclass
class HTTPEnrichmentResult:
    subdomain:          str
    url_attempted:      str
    reachable:          bool = False
    final_url:          Optional[str] = None
    status_code:        Optional[int] = None
    redirect_count:     int = 0
    redirect_chain:     list[str] = field(default_factory=list)

    # Security headers
    hsts_present:       bool = False
    hsts_max_age:       Optional[int] = None
    hsts_includes_sub:  bool = False
    hsts_preload:       bool = False
    csp_present:        bool = False
    csp_value:          Optional[str] = None
    x_frame_options:    Optional[str] = None
    x_content_type:     bool = False
    referrer_policy:    Optional[str] = None
    permissions_policy: bool = False

    # Server disclosure
    server_header:      Optional[str] = None
    x_powered_by:       Optional[str] = None
    disclosed_tech:     list[str] = field(default_factory=list)

    # CDN / hosting
    cdn_detected:       Optional[str] = None
    cdn_signals:        list[str] = field(default_factory=list)

    # All headers (raw)
    raw_headers:        dict = field(default_factory=dict)

    # Favicon
    favicon:            FaviconResult = field(default_factory=FaviconResult)

    # Page title (optional GET pass)
    page_title:         Optional[str] = None
    html_hash:          Optional[str] = None  # MD5 of response body

    # Computed findings
    is_sensitive:       bool = False           # payment/login/admin subdomain
    findings:           list[dict] = field(default_factory=list)
    header_score:       float = 0.0  # Higher = more missing headers

    error:              Optional[str] = None


# ── Favicon hashing ────────────────────────────────────────────────────────

def md5_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def phash_image(data: bytes) -> Optional[str]:
    """
    Perceptual hash of an image — works on PNG and ICO favicons.
    Uses a simple DCT-based approach without requiring Pillow.
    Falls back to None if the image can't be parsed.

    For production, use imagehash library:
        import imagehash, PIL.Image, io
        img = PIL.Image.open(io.BytesIO(data))
        return str(imagehash.phash(img))

    This fallback computes a lightweight hash from raw pixel-adjacent
    data that still gives useful grouping for similar favicons.
    """
    try:
        # Try PNG: detect from magic bytes
        if data[:4] == b'\x89PNG':
            return _phash_png(data)
        # ICO: try to extract embedded PNG
        if data[:4] == b'\x00\x00\x01\x00':
            return _phash_ico(data)
    except Exception:
        pass
    # Fallback: hash the raw bytes — at least catches identical favicons
    return md5_hash(data)


def _phash_png(data: bytes) -> Optional[str]:
    """Minimal PNG reader — extracts IDAT chunks and computes perceptual hash."""
    try:
        pos = 8  # Skip PNG signature
        pixels = []
        width = height = 0

        while pos < len(data):
            chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            chunk_data = data[pos+8:pos+8+chunk_len]

            if chunk_type == b'IHDR':
                width  = struct.unpack('>I', chunk_data[:4])[0]
                height = struct.unpack('>I', chunk_data[4:8])[0]
            elif chunk_type == b'IDAT':
                # Decompress and use first 64 bytes as signal
                try:
                    raw = zlib.decompress(chunk_data)
                    pixels.extend(raw[:64])
                except Exception:
                    pass
            elif chunk_type == b'IEND':
                break

            pos += 12 + chunk_len

        if not pixels:
            return None

        # Simple 8x8 DCT approximation
        # Divide into 8 buckets, compare each to mean
        mean = sum(pixels) / len(pixels)
        bits = ''.join('1' if p > mean else '0' for p in pixels[:64])
        # Pad to 64 bits
        bits = bits.ljust(64, '0')
        # Convert to hex
        return hex(int(bits, 2))[2:].zfill(16)
    except Exception:
        return None


def _phash_ico(data: bytes) -> Optional[str]:
    """Extract largest embedded PNG from ICO and hash it."""
    try:
        count = struct.unpack('<H', data[4:6])[0]
        best_size = 0
        best_offset = best_len = 0

        for i in range(count):
            entry = data[6 + i * 16: 6 + i * 16 + 16]
            w = entry[0] or 256
            offset = struct.unpack('<I', entry[12:16])[0]
            size   = struct.unpack('<I', entry[8:12])[0]
            if w > best_size:
                best_size = w
                best_offset = offset
                best_len = size

        if best_len:
            embedded = data[best_offset:best_offset + best_len]
            if embedded[:4] == b'\x89PNG':
                return _phash_png(embedded)
    except Exception:
        pass
    return None


# ── Header parsing ─────────────────────────────────────────────────────────

def parse_hsts(value: str) -> tuple[int, bool, bool]:
    """Parse Strict-Transport-Security header. Returns (max_age, includeSubDomains, preload)."""
    max_age = 0
    includes_sub = False
    preload = False
    for part in value.lower().split(';'):
        part = part.strip()
        if part.startswith('max-age='):
            try:
                max_age = int(part.split('=')[1])
            except ValueError:
                pass
        elif part == 'includesubdomains':
            includes_sub = True
        elif part == 'preload':
            preload = True
    return max_age, includes_sub, preload


def detect_cdn(headers: dict) -> tuple[Optional[str], list[str]]:
    """Detect CDN/proxy from response headers."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    signals_found = []
    cdn_name = None

    for cdn, signals in CDN_SIGNATURES.items():
        matched = []
        for sig in signals:
            if ':' in sig:
                # Value-based match (e.g. "via: 1.1 google")
                h, v = sig.split(': ', 1)
                if h in lower_headers and v in lower_headers[h].lower():
                    matched.append(sig)
            elif sig in lower_headers:
                matched.append(sig)
        if matched:
            cdn_name = cdn
            signals_found = matched
            break

    return cdn_name, signals_found

def score_csp(csp_value: Optional[str]) -> tuple[str, float, str]:
    """
    Assess the quality of a Content-Security-Policy header value.
    Returns (severity, score_points, finding_text).
    """
    if not csp_value:
        return (
            "elevated",
            1.5,
            "CSP absent — browser has no restriction on script sources or data exfiltration. "
            "A successful XSS attack has unrestricted access to page data and session tokens.",
        )

    lower = csp_value.lower()

    if "default-src *" in lower:
        return (
            "elevated",
            1.5,
            "CSP present but uses 'default-src *' — wildcard permits all sources. "
            "This header provides no XSS or exfiltration protection.",
        )

    has_unsafe_inline = "'unsafe-inline'" in lower
    has_unsafe_eval   = "'unsafe-eval'" in lower

    if has_unsafe_inline and has_unsafe_eval:
        return (
            "low",
            0.75,
            "CSP present but permits 'unsafe-inline' and 'unsafe-eval' — "
            "inline scripts and dynamic code execution are unrestricted.",
        )
    if has_unsafe_inline:
        return (
            "low",
            0.5,
            "CSP present but permits 'unsafe-inline' — inline scripts are unrestricted. "
            "Recommend using a nonce or hash-based approach instead.",
        )
    if has_unsafe_eval:
        return (
            "low",
            0.25,
            "CSP present but permits 'unsafe-eval' — dynamic code execution via eval() "
            "is unrestricted. Remove if not required.",
        )

    return ("pass", 0.0, "")

def score_headers(result: HTTPEnrichmentResult) -> tuple[float, list[dict]]:
    """Score missing security headers and build findings list."""
    score = 0.0
    findings = []
 
    if not result.reachable:
        return 0.0, []
 
    # HSTS analysis
    if not result.hsts_present:
        score += 1.5
        findings.append({
            "severity": "elevated",
            "code":     "HEADER_HSTS_MISSING",
            "title":    "HSTS not configured",
            "detail":   f"Strict-Transport-Security header absent on {result.subdomain}. "
                        f"Browsers are not forced to use HTTPS — susceptible to SSL stripping.",
        })
    elif result.hsts_max_age and result.hsts_max_age < HSTS_MIN_AGE:
        score += 0.5
        findings.append({
            "severity": "low",
            "code":     "HEADER_HSTS_WEAK",
            "title":    f"HSTS max-age too short ({result.hsts_max_age}s)",
            "detail":   f"HSTS max-age of {result.hsts_max_age}s is below the recommended "
                        f"minimum of {HSTS_MIN_AGE}s (180 days). "
                        f"Short max-age reduces HSTS protection window.",
        })
 
    # CSP — quality-aware scoring via score_csp()
    # Handles: absent, wildcard, unsafe-inline/eval, and pass
    csp_severity, csp_pts, csp_text = score_csp(result.csp_value)
    if csp_severity != "pass":
        # Upgrade sensitive subdomains to critical if CSP is absent or wildcard
        if result.is_sensitive and csp_severity == "elevated":
            csp_severity = "critical"
            csp_pts      = csp_pts * 1.5
        score += csp_pts
        code = (
            "HEADER_CSP_MISSING"   if not result.csp_present else
            "HEADER_CSP_WILDCARD"  if "default-src *" in (result.csp_value or "").lower() else
            "HEADER_CSP_UNSAFE"
        )
        findings.append({
            "severity": csp_severity,
            "code":     code,
            "title":    (
                "Content Security Policy absent"          if not result.csp_present else
                "Content Security Policy — wildcard"      if "default-src *" in (result.csp_value or "").lower() else
                "Content Security Policy — unsafe directives"
            ),
            "detail":   csp_text + f" (subdomain: {result.subdomain})",
            "csp_value": result.csp_value,
        })
 
    # X-Frame-Options
    if not result.x_frame_options:
        score += 1.0
        findings.append({
            "severity": "elevated",
            "code":     "HEADER_XFO_MISSING",
            "title":    "Clickjacking protection absent",
            "detail":   f"X-Frame-Options not set on {result.subdomain}. "
                        f"This page can be embedded in a malicious iframe.",
        })
 
    # X-Content-Type-Options
    if not result.x_content_type:
        score += 0.5
        findings.append({
            "severity": "low",
            "code":     "HEADER_XCTO_MISSING",
            "title":    "MIME sniffing not prevented",
            "detail":   f"X-Content-Type-Options: nosniff absent on {result.subdomain}.",
        })
 
    # Server disclosure
    if result.server_header:
        # Check if it includes version numbers — more severe
        has_version = bool(re.search(r'\d+\.\d+', result.server_header))
        sev = "elevated" if has_version else "low"
        score += 1.0 if has_version else 0.25
        findings.append({
            "severity": sev,
            "code":     "HEADER_SERVER_DISCLOSURE",
            "title":    f"Server version disclosed: {result.server_header}",
            "detail":   f"The Server header on {result.subdomain} reveals: "
                        f"'{result.server_header}'. Version disclosure aids targeted attacks.",
        })
 
    if result.x_powered_by:
        score += 0.5
        findings.append({
            "severity": "low",
            "code":     "HEADER_XPOWEREDBY_DISCLOSURE",
            "title":    f"Backend technology disclosed: {result.x_powered_by}",
            "detail":   f"X-Powered-By header reveals backend stack: '{result.x_powered_by}'.",
        })
 
    # Payment / login subdomain — stricter scoring
    sensitive_patterns = ["payment", "pay", "login", "auth", "account",
                          "admin", "portal", "secure", "checkout"]
    name_lower = result.subdomain.lower()
    is_sensitive = any(p in name_lower for p in sensitive_patterns)
 
    if is_sensitive and not result.hsts_present:
        score += 1.0  # Additional penalty on sensitive subdomains
        findings[-1]["severity"] = "critical"  # Upgrade last HSTS finding
 
    return round(score, 2), findings


# ── Main enrichment ────────────────────────────────────────────────────────

async def enrich_subdomain(
    subdomain: str,
    client: httpx.AsyncClient,
    fetch_favicon: bool = True,
    fetch_page: bool = False,
    timeout: float = 8.0,
) -> HTTPEnrichmentResult:
    """
    Full HTTP enrichment for a single subdomain.
    Always does HEAD for headers.
    Optionally fetches favicon and page content.
    """
    url = f"https://{subdomain}"
    result = HTTPEnrichmentResult(subdomain=subdomain, url_attempted=url)

    # Flag sensitive subdomains before any requests
    subdomain_part = subdomain.split('.')[0].lower()
    result.is_sensitive = subdomain_part in {
        "payment", "pay", "login", "auth", "account",
        "admin", "portal", "secure", "checkout", "signin",
    }

    # ── HEAD request for headers ──────────────────────────────────────────
    try:
        resp = await client.head(
            url,
            timeout=timeout,
            follow_redirects=True,
        )
        result.reachable    = True
        result.status_code  = resp.status_code
        result.final_url    = str(resp.url)
        result.raw_headers  = dict(resp.headers)

        # Count redirects from history
        result.redirect_count = len(resp.history)
        result.redirect_chain = [str(r.url) for r in resp.history]

        h = {k.lower(): v for k, v in resp.headers.items()}

        # HSTS
        if 'strict-transport-security' in h:
            result.hsts_present = True
            age, inc_sub, preload = parse_hsts(h['strict-transport-security'])
            result.hsts_max_age      = age
            result.hsts_includes_sub = inc_sub
            result.hsts_preload       = preload

        # CSP
        if 'content-security-policy' in h:
            result.csp_present = True
            result.csp_value   = h['content-security-policy']

        # X-Frame-Options
        if 'x-frame-options' in h:
            result.x_frame_options = h['x-frame-options']

        # X-Content-Type-Options
        result.x_content_type = h.get('x-content-type-options', '').lower() == 'nosniff'

        # Referrer-Policy
        result.referrer_policy = h.get('referrer-policy')

        # Permissions-Policy
        result.permissions_policy = 'permissions-policy' in h

        # Server disclosure
        result.server_header = h.get('server')
        result.x_powered_by  = h.get('x-powered-by')

        # Other disclosure headers
        for disc_header, label in INFORMATION_DISCLOSURE_HEADERS.items():
            if disc_header in h and disc_header not in ('server', 'x-powered-by'):
                result.disclosed_tech.append(f"{disc_header}: {h[disc_header]}")

        # CDN detection
        result.cdn_detected, result.cdn_signals = detect_cdn(resp.headers)

    except httpx.ConnectError:
        result.error = "connection_refused"
        return result
    except httpx.TimeoutException:
        result.error = "timeout"
        return result
    except httpx.TooManyRedirects:
        result.error = "too_many_redirects"
        return result
    except Exception as e:
        result.error = str(e)[:200]
        return result

    # ── Favicon fetch ─────────────────────────────────────────────────────
    if fetch_favicon and result.reachable:
        result.favicon = await fetch_favicon_data(
            subdomain, result.final_url or url, client, timeout
        )

    # ── Page title (optional) ─────────────────────────────────────────────
    if fetch_page and result.reachable:
        try:
            page_resp = await client.get(
                url, timeout=timeout, follow_redirects=True
            )
            body = page_resp.text[:50_000]  # Cap at 50KB

            # Extract title
            title_match = re.search(
                r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL
            )
            if title_match:
                result.page_title = title_match.group(1).strip()[:200]

            # Hash the body
            result.html_hash = md5_hash(page_resp.content)

        except Exception:
            pass

    # ── Score headers ─────────────────────────────────────────────────────
    result.header_score, result.findings = score_headers(result)

    return result


async def fetch_favicon_data(
    subdomain: str,
    base_url: str,
    client: httpx.AsyncClient,
    timeout: float = 5.0,
) -> FaviconResult:
    """
    Fetch favicon, trying multiple locations.
    Priority: /favicon.ico → <link rel="icon"> in HTML → /apple-touch-icon.png
    """
    fav = FaviconResult()

    # Try standard locations in order
    candidates = [
        urljoin(base_url, '/favicon.ico'),
        urljoin(base_url, '/favicon.png'),
        urljoin(base_url, '/apple-touch-icon.png'),
    ]

    for favicon_url in candidates:
        try:
            resp = await client.get(
                favicon_url,
                timeout=timeout,
                follow_redirects=True,
            )

            if resp.status_code == 200 and len(resp.content) > 0:
                # Verify it's actually an image
                ct = resp.headers.get('content-type', '').lower()
                is_image = (
                    'image' in ct or
                    resp.content[:4] in (b'\x89PNG', b'\x00\x00\x01\x00',
                                         b'GIF8', b'\xff\xd8\xff') or
                    resp.content[:2] == b'BM'
                )

                if is_image:
                    fav.found        = True
                    fav.url          = favicon_url
                    fav.status_code  = resp.status_code
                    fav.content_type = ct
                    fav.size_bytes   = len(resp.content)
                    fav.md5          = md5_hash(resp.content)
                    fav.sha1         = sha1_hash(resp.content)
                    fav.phash        = phash_image(resp.content)
                    return fav

        except Exception as e:
            fav.error = str(e)[:100]
            continue

    return fav


# ── Batch pipeline ─────────────────────────────────────────────────────────

async def enrich_subdomains_batch(
    subdomains: list[str],
    concurrency: int = 40,
    fetch_favicon: bool = True,
    fetch_page: bool = False,
    timeout: float = 8.0,
    user_agent: str = "Datazag-InfraScout/1.0",
) -> list[HTTPEnrichmentResult]:
    """
    Enrich a batch of live subdomains concurrently.
    Returns list of results in the same order as input.
    """
    semaphore = asyncio.Semaphore(concurrency)

    # Connection limits — don't hammer any single host
    limits = httpx.Limits(
        max_keepalive_connections=20,
        max_connections=concurrency + 10,
        keepalive_expiry=5,
    )

    transport = httpx.AsyncHTTPTransport(
        retries=1,
        limits=limits,
    )

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-GB,en;q=0.9",
    }

    async with httpx.AsyncClient(
        transport=transport,
        headers=headers,
        verify=False,          # Don't fail on self-signed / expired certs
        timeout=timeout,
    ) as client:

        async def bounded_enrich(subdomain: str) -> HTTPEnrichmentResult:
            async with semaphore:
                return await enrich_subdomain(
                    subdomain, client, fetch_favicon, fetch_page, timeout
                )

        results = await asyncio.gather(
            *[bounded_enrich(s) for s in subdomains],
            return_exceptions=False,
        )

    return list(results)


# ── Polars normalisation ───────────────────────────────────────────────────

def results_to_dataframe(results: list[HTTPEnrichmentResult]) -> pl.DataFrame:
    """
    Flatten enrichment results into a Polars DataFrame.
    One row per subdomain. Findings stored as JSON string.
    """
    import json

    rows = []
    for r in results:
        rows.append({
            "subdomain":         r.subdomain,
            "reachable":         r.reachable,
            "status_code":       r.status_code,
            "final_url":         r.final_url,
            "redirect_count":    r.redirect_count,
            "error":             r.error,

            # HSTS
            "hsts_present":      r.hsts_present,
            "hsts_max_age":      r.hsts_max_age,
            "hsts_includes_sub": r.hsts_includes_sub,
            "hsts_preload":      r.hsts_preload,

            # Other security headers
            "csp_present":       r.csp_present,
            "x_frame_options":   r.x_frame_options,
            "x_content_type":    r.x_content_type,
            "referrer_policy":   r.referrer_policy,
            "permissions_policy":r.permissions_policy,

            # Disclosure
            "server_header":     r.server_header,
            "x_powered_by":      r.x_powered_by,
            "disclosed_tech":    json.dumps(r.disclosed_tech),

            # CDN
            "cdn_detected":      r.cdn_detected,

            # Favicon
            "favicon_found":     r.favicon.found,
            "favicon_url":       r.favicon.url,
            "favicon_md5":       r.favicon.md5,
            "favicon_sha1":      r.favicon.sha1,
            "favicon_phash":     r.favicon.phash,
            "favicon_size":      r.favicon.size_bytes,

            # Page
            "page_title":        r.page_title,
            "html_hash":         r.html_hash,

            # Score
            "header_score":      r.header_score,
            "finding_count":     len(r.findings),
            "findings":          json.dumps(r.findings),
        })

    return pl.DataFrame(rows)


# ── Favicon similarity analysis ────────────────────────────────────────────

def find_favicon_matches(
    df: pl.DataFrame,
    reference_md5: Optional[str] = None,
    reference_phash: Optional[str] = None,
    phash_distance_threshold: int = 8,
) -> pl.DataFrame:
    """
    Find subdomains whose favicons match a reference favicon.
    Used for brand impersonation detection — any domain using
    the same or visually similar favicon as the target brand.

    reference_md5: exact match against known legitimate favicon
    reference_phash: perceptual similarity match

    For phash: Hamming distance between two 64-bit hex strings.
    Distance <= 8 is typically visually similar.
    """
    matches = df.filter(pl.col("favicon_found"))

    if reference_md5:
        exact = matches.filter(pl.col("favicon_md5") == reference_md5)
        if len(exact):
            exact = exact.with_columns(
                pl.lit("exact").alias("match_type"),
                pl.lit(0).alias("phash_distance"),
            )
            return exact

    if reference_phash:
        # Compute Hamming distance for each row
        ref_int = int(reference_phash, 16)

        def hamming(phash_hex: str) -> int:
            try:
                return bin(int(phash_hex, 16) ^ ref_int).count('1')
            except Exception:
                return 999

        matches = matches.with_columns(
            pl.col("favicon_phash").map_elements(
                hamming, return_dtype=pl.Int64
            ).alias("phash_distance")
        )

        similar = matches.filter(
            pl.col("phash_distance") <= phash_distance_threshold
        ).with_columns(
            pl.lit("perceptual").alias("match_type")
        )

        return similar.sort("phash_distance")

    return pl.DataFrame()


def aggregate_favicon_clusters(df: pl.DataFrame) -> pl.DataFrame:
    """
    Group all subdomains by favicon MD5.
    Clusters of subdomains sharing the same favicon reveal:
    - Consistent branding (expected)
    - Shared hosting (interesting)
    - Copied/phishing infrastructure (suspicious if across unrelated domains)
    """
    return (
        df.filter(pl.col("favicon_found") & pl.col("favicon_md5").is_not_null())
        .group_by("favicon_md5")
        .agg([
            pl.col("subdomain").count().alias("subdomain_count"),
            pl.col("subdomain").alias("subdomains"),
            pl.col("favicon_phash").first().alias("phash"),
            pl.col("favicon_size").first().alias("size_bytes"),
        ])
        .sort("subdomain_count", descending=True)
    )


# ── Report section builder ─────────────────────────────────────────────────

def build_header_report_section(df: pl.DataFrame) -> dict:
    """
    Aggregate header findings across the full subdomain estate
    for the infrastructure health report.
    """
    live = df.filter(pl.col("reachable"))
    total = len(live)

    if total == 0:
        return {"total_live": 0, "findings": []}

    # Header coverage rates
    hsts_pct  = live.filter(pl.col("hsts_present")).height / total * 100
    csp_pct   = live.filter(pl.col("csp_present")).height  / total * 100
    xfo_pct   = live.filter(pl.col("x_frame_options").is_not_null()).height / total * 100

    # Most exposed subdomains
    worst = (
        live.sort("header_score", descending=True)
        .head(5)
        .select(["subdomain", "header_score", "finding_count"])
    )

    # Server disclosure
    disclosing = live.filter(pl.col("server_header").is_not_null())

    # Favicon diversity
    fav_clusters = aggregate_favicon_clusters(live)

    # CDN coverage
    cdn_breakdown = (
        live.group_by("cdn_detected")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )

    # Payment/auth subdomains specifically
    sensitive_patterns = ["payment", "pay", "login", "auth", "account",
                          "admin", "portal", "secure", "checkout"]
    sensitive = live.filter(
        pl.col("subdomain").str.to_lowercase().str.contains(
            "|".join(sensitive_patterns)
        )
    )
    sensitive_missing_hsts = sensitive.filter(
        pl.col("hsts_present").not_()
    )

    findings = []

    if hsts_pct < 50:
        findings.append({
            "severity": "elevated",
            "code":     "ESTATE_HSTS_LOW",
            "title":    f"HSTS absent on {100-hsts_pct:.0f}% of live subdomains",
            "detail":   f"Only {hsts_pct:.0f}% of {total} live subdomains have "
                        f"HSTS configured. Browsers connecting to unprotected subdomains "
                        f"are susceptible to SSL stripping attacks.",
        })

    if csp_pct < 30:
        findings.append({
            "severity": "elevated",
            "code":     "ESTATE_CSP_LOW",
            "title":    f"Content Security Policy absent on {100-csp_pct:.0f}% of subdomains",
            "detail":   f"CSP is present on only {csp_pct:.0f}% of live subdomains.",
        })

    if len(sensitive_missing_hsts):
        subs = sensitive_missing_hsts["subdomain"].to_list()
        findings.append({
            "severity": "critical",
            "code":     "SENSITIVE_HSTS_MISSING",
            "title":    f"HSTS absent on {len(subs)} sensitive subdomain(s)",
            "detail":   f"Payment or authentication subdomains without HSTS: "
                        f"{', '.join(subs[:5])}{'...' if len(subs) > 5 else ''}. "
                        f"These handle sensitive data and must enforce HTTPS.",
        })

    if len(disclosing):
        versions = disclosing["server_header"].drop_nulls().to_list()
        findings.append({
            "severity": "elevated" if any(
                re.search(r'\d+\.\d+', v) for v in versions
            ) else "low",
            "code":     "ESTATE_SERVER_DISCLOSURE",
            "title":    f"Server version disclosed on {len(disclosing)} subdomains",
            "detail":   f"Examples: {', '.join(versions[:3])}. "
                        f"Version disclosure aids targeted exploitation.",
        })

    return {
        "total_live":         total,
        "hsts_coverage_pct":  round(hsts_pct, 1),
        "csp_coverage_pct":   round(csp_pct, 1),
        "xfo_coverage_pct":   round(xfo_pct, 1),
        "worst_subdomains":   worst.to_dicts(),
        "server_disclosures": len(disclosing),
        "favicon_clusters":   len(fav_clusters),
        "cdn_breakdown":      cdn_breakdown.to_dicts(),
        "findings":           findings,
    }


# ── Demo ───────────────────────────────────────────────────────────────────

async def demo():
    """Demo against a small set of real subdomains."""
    import warnings
    warnings.filterwarnings('ignore')  # Suppress SSL warnings for self-signed

    test_subdomains = [
        "adaptavist.com",
        "docs.adaptavist.com",
        "marketplace.adaptavist.com",
        "library.adaptavist.com",
        "scriptrunner.adaptavist.com",
    ]

    print(f"Enriching {len(test_subdomains)} subdomains...")
    results = await enrich_subdomains_batch(
        test_subdomains,
        concurrency=5,
        fetch_favicon=True,
        fetch_page=False,
    )

    df = results_to_dataframe(results)

    print(f"\n── HTTP enrichment results ──")
    print(df.select([
        "subdomain", "reachable", "status_code",
        "hsts_present", "csp_present", "x_frame_options",
        "server_header", "cdn_detected", "header_score",
    ]))

    print(f"\n── Favicon results ──")
    print(df.select([
        "subdomain", "favicon_found", "favicon_md5",
        "favicon_phash", "favicon_size",
    ]))

    print(f"\n── Favicon clusters ──")
    fav_df = df.filter(pl.col("reachable"))
    clusters = aggregate_favicon_clusters(fav_df)
    print(clusters)

    print(f"\n── Estate-level header report ──")
    report = build_header_report_section(df.filter(pl.col("reachable")))
    print(f"  Live subdomains:    {report['total_live']}")
    print(f"  HSTS coverage:      {report['hsts_coverage_pct']}%")
    print(f"  CSP coverage:       {report['csp_coverage_pct']}%")
    print(f"  Server disclosures: {report['server_disclosures']}")
    print(f"  Favicon clusters:   {report['favicon_clusters']}")
    print(f"\n  Findings:")
    for f in report['findings']:
        print(f"  [{f['severity'].upper():8}] {f['title']}")


if __name__ == "__main__":
    asyncio.run(demo())