"""Traffic Interception — MITM proxy setup, traffic capture analysis, and TLS/SSL analysis.

Generates mitmproxy addon scripts for traffic interception, analyzes captured
traffic (HAR format) for security issues, and examines TLS certificates.

Usage:
    from mobilesentry.traffic_intercept import InterceptionSetup
    from mobilesentry.traffic_intercept import TrafficAnalyzer
    from mobilesentry.traffic_intercept import TlsAnalyzer

    # Generate addon scripts
    setup = InterceptionSetup(output_dir="./mitmproxy_config")
    setup.generate_addon(addon_type="full")  # full, minimal, auth-only

    # Analyze captured traffic (HAR file)
    analyzer = TrafficAnalyzer()
    result = analyzer.analyze_har("capture.har")
    result.summarize()

    # Analyze TLS certificates
    tls = TlsAnalyzer()
    certs = tls.analyze_har("capture.har")
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ══════════════════════════════════════════════
# Data Models
# ══════════════════════════════════════════════


@dataclass
class MitmproxyAddon:
    """Metadata for a mitmproxy addon script."""

    name: str
    description: str
    filename: str
    code: str
    output_path: str = ""

    @property
    def size_bytes(self) -> int:
        return len(self.code.encode("utf-8"))


@dataclass
class CapturedRequest:
    """A single HTTP request captured from traffic."""

    url: str
    method: str
    host: str
    path: str
    scheme: str  # http or https
    status_code: int
    response_size: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body: str | None = None
    response_body: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    timestamp: float = 0.0
    duration_ms: float = 0.0


@dataclass
class TrafficFinding:
    """A security finding discovered during traffic analysis."""

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # auth, crypto, privacy, config, data_exposure
    url: str
    recommendation: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class TrafficAnalysisResult:
    """Complete traffic analysis result."""

    total_requests: int = 0
    total_domains: list[str] = field(default_factory=list)
    http_urls: list[str] = field(default_factory=list)
    findings: list[TrafficFinding] = field(default_factory=list)
    cookie_stats: dict[str, int] = field(default_factory=lambda: {"total": 0, "missing_secure": 0, "missing_httponly": 0, "missing_samesite": 0})
    auth_header_stats: dict[str, int] = field(default_factory=lambda: {"total": 0, "bearer": 0, "basic": 0, "api_key": 0})
    tls_stats: dict[str, list[str]] = field(default_factory=lambda: {"tls_versions": [], "ciphers": []})
    sensitive_data_findings: list[str] = field(default_factory=list)
    analysis_time_ms: float = 0.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[TrafficFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[TrafficFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium_findings(self) -> list[TrafficFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def has_https_only(self) -> bool:
        return len(self.http_urls) == 0 and self.total_requests > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "unique_domains": len(self.total_domains),
            "http_urls": len(self.http_urls),
            "https_ratio": f"{((self.total_requests - len(self.http_urls)) / max(self.total_requests, 1)) * 100:.1f}%",
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "url": f.url,
                }
                for f in self.findings
            ],
            "cookie_issues": {
                "missing_secure": self.cookie_stats["missing_secure"],
                "missing_httponly": self.cookie_stats["missing_httponly"],
                "missing_samesite": self.cookie_stats["missing_samesite"],
            },
            "auth_headers": self.auth_header_stats,
            "tls_versions": list(set(self.tls_stats["tls_versions"])),
            "ciphers": list(set(self.tls_stats["ciphers"])),
        }


@dataclass
class TlsCertificateInfo:
    """Information about an analyzed TLS certificate."""

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0
    key_algorithm: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    subject_alt_names: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_wildcard: bool = False
    chain_length: int = 0
    hostname: str = ""
    tls_version: str = ""
    cipher_suite: str = ""


@dataclass
class TlsAnalysisResult:
    """Overall TLS analysis result."""

    certificates: list[TlsCertificateInfo] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    expired_certs: list[str] = field(default_factory=list)
    weak_key_sizes: list[str] = field(default_factory=list)
    self_signed_certs: list[str] = field(default_factory=list)
    tls_versions: dict[str, int] = field(default_factory=dict)
    findings: list[TrafficFinding] = field(default_factory=list)

    @property
    def total_certs(self) -> int:
        return len(self.certificates)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_certificates": self.total_certs,
            "tls_versions": self.tls_versions,
            "weak_ciphers": self.weak_ciphers,
            "expired_certificates": self.expired_certs,
            "weak_key_sizes": self.weak_key_sizes,
            "self_signed_certificates": self.self_signed_certs,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "hostname": f.url,
                }
                for f in self.findings
            ],
        }


# ══════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════

SENSITIVE_PATTERNS: dict[str, str] = {
    "password": r"(?i)password[=:]\s*\S+",
    "token": r"(?i)(access_token|refresh_token|id_token)[=:]\s*\S+",
    "api_key": r"(?i)(api[_-]?key|x-api-key|apikey)[=:]\s*\S+",
    "jwt": r"(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})",
    "ssn": r"\b(\d{3}-\d{2}-\d{4})\b",
    "credit_card": r"\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(\+?\d{1,2}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
}

INSECURE_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "Missing HSTS header",
        "Add Strict-Transport-Security header to enforce HTTPS connections.",
    ),
    "content-security-policy": (
        "Missing CSP header",
        "Add Content-Security-Policy header to prevent XSS and data injection.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options header",
        "Add X-Frame-Options: DENY to prevent clickjacking.",
    ),
    "x-xss-protection": (
        "Missing X-XSS-Protection header",
        "Add X-XSS-Protection header for legacy browser protection.",
    ),
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "SHA1", "SHA-1",
    "NULL", "EXPORT", "ANON", "aNULL", "eNULL",
    "TLS_RSA_WITH", "TLS_DH_anon", "TLS_ECDH_anon",
    "SSLv3", "TLSv1.0", "TLSv1",
]

WEAK_KEY_SIZES = [512, 1024]

# ══════════════════════════════════════════════
# MITMproxy Addon Scripts
# ══════════════════════════════════════════════

FULL_ADDON_SCRIPT = r'''"""MobileSentry Traffic Interception Addon — Full Mode.

A comprehensive mitmproxy addon that intercepts HTTP/HTTPS traffic,
logs requests and responses, detects security issues in real-time,
and saves captured data for post-capture analysis.

Installation:
    1. Save this script to a file (e.g., mobilesentry_addon.py)
    2. Run mitmproxy with:
       mitmproxy -s mobilesentry_addon.py
       mitmdump -s mobilesentry_addon.py
    3. Or use the config file: mitmproxy -s mobilesentry_addon.py --set block_global=false

Output:
    - Captures all HTTP/HTTPS traffic
    - Logs security findings to console (color-coded)
    - Saves HAR file to mobilesentry_capture_<timestamp>.har
    - Saves JSON findings report

Device Setup:
    Android:  adb shell settings put global http_proxy <proxy_ip>:8080
    iOS:      Settings > Wi-Fi > (i) > HTTP Proxy > Manual
    Cert:     Navigate to http://mitm.it on device to install CA certificate

Author: MobileSentry
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from mitmproxy import http
from mitmproxy import ctx


class MobileSentryInterceptor:
    """MobileSentry mitmproxy addon for traffic interception and security analysis."""

    def __init__(self):
        self.start_time = time.time()
        self.flows = []
        self.findings = []
        self.request_count = 0
        self.har_entries = []
        self.output_dir = os.environ.get("MOBILESENTRY_OUTPUT", ".")

        # Stats
        self.stats = {
            "total_requests": 0,
            "https_count": 0,
            "http_count": 0,
            "unique_hosts": set(),
            "methods": {},
            "status_codes": {},
            "content_types": {},
        }

        # Sensitive data patterns
        self.sensitive_patterns = {
            "password": rb"(?i)(password|passwd|pwd)[=:]\s*\S+",
            "token": rb"(?i)(access_token|refresh_token|id_token|csrf_token)[=:]\s*\S+",
            "api_key": rb"(?i)(api[_-]?key|x-api-key|apikey|api_secret)[=:]\s*\S+",
            "jwt": rb"(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})",
            "ssn": rb"\b(\d{3}-\d{2}-\d{4})\b",
            "credit_card": rb"\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b",
            "email": rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",
            "private_key": rb"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            "aws_key": rb"(?i)(AKIA[0-9A-Z]{16})",
            "github_token": rb"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36}",
        }

        # Insecure headers to check
        self.insecure_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
        ]

        ctx.log.info("[MobileSentry] Interceptor loaded — monitoring traffic")

    def _sanitize_body(self, body: bytes, max_len: int = 2000) -> str:
        """Sanitize body for display: truncate and mask sensitive fields."""
        if not body:
            return ""
        text = body.decode("utf-8", errors="replace")
        # Mask common sensitive patterns
        text = re.sub(
            r'(?i)(password|secret|token|api_key|api-key|apikey)[=:]\s*\S+',
            r'\1=***REDACTED***',
            text,
        )
        if len(text) > max_len:
            text = text[:max_len] + "\n... [truncated]"
        return text

    def _check_sensitive_data(self, body: bytes, url: str, source: str) -> None:
        """Check for sensitive data in request/response bodies."""
        if not body:
            return
        for name, pattern in self.sensitive_patterns.items():
            try:
                matches = re.findall(pattern, body)
                if matches:
                    finding = {
                        "type": name,
                        "source": source,
                        "url": url,
                        "count": len(matches),
                        "preview": matches[0].decode("utf-8", errors="replace")[:60]
                        if isinstance(matches[0], bytes)
                        else str(matches[0])[:60],
                    }
                    self.findings.append(finding)
                    ctx.log.warn(
                        f"[!] SENSITIVE DATA [{name.upper()}]: {finding['preview']}"
                    )
            except Exception:
                pass

    def _check_security_headers(self, headers: dict, url: str) -> None:
        """Check response headers for security best practices."""
        for header in self.insecure_headers:
            if header not in headers:
                ctx.log.warn(
                    f"[!] MISSING HEADER: {header} — {url}"
                )
                self.findings.append({
                    "type": "missing_header",
                    "header": header,
                    "url": url,
                    "severity": "medium",
                })

    def _check_cookies(self, cookies: list, url: str) -> None:
        """Check cookies for security attributes."""
        for cookie in cookies:
            issues = []
            name = cookie.get("name", "unknown")
            if not cookie.get("secure", False):
                issues.append("missing Secure flag")
            if not cookie.get("httponly", False):
                issues.append("missing HttpOnly flag")
            if not cookie.get("same_site", ""):
                issues.append("missing SameSite attribute")
            if issues:
                ctx.log.warn(
                    f"[!] COOKIE ISSUE [{name}]: {', '.join(issues)} — {url}"
                )
                self.findings.append({
                    "type": "insecure_cookie",
                    "cookie": name,
                    "issues": issues,
                    "url": url,
                    "severity": "medium",
                })

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each intercepted request."""
        self.request_count += 1
        req = flow.request

        # Update stats
        self.stats["total_requests"] += 1
        scheme = req.scheme
        if scheme == "https":
            self.stats["https_count"] += 1
        else:
            self.stats["http_count"] += 1

        host = req.host
        self.stats["unique_hosts"].add(host)
        self.stats["methods"][req.method] = self.stats["methods"].get(req.method, 0) + 1

        # Check for HTTP (non-TLS) URLs
        if scheme != "https" and req.pretty_url:
            ctx.log.warn(f"[!] HTTP REQUEST (no TLS): {req.pretty_url}")
            self.findings.append({
                "type": "http_request",
                "url": req.pretty_url,
                "severity": "high",
            })

        # Check for sensitive data in query parameters
        if req.query:
            for key in req.query:
                if any(
                    pattern in key.lower()
                    for pattern in ["token", "secret", "api", "key", "password", "auth"]
                ):
                    ctx.log.warn(
                        f"[!] SENSITIVE PARAM in URL: {key}={req.query[key]} — {req.pretty_url}"
                    )
                    self.findings.append({
                        "type": "sensitive_url_param",
                        "parameter": key,
                        "url": req.pretty_url,
                        "severity": "high",
                    })

        # Check auth headers
        auth_header = req.headers.get("Authorization", "")
        if auth_header:
            if auth_header.startswith("Bearer "):
                ctx.log.info(f"[i] Auth: Bearer token in request to {host}")
            elif auth_header.startswith("Basic "):
                ctx.log.warn(f"[!] Auth: Basic auth (base64) in request to {host}")
                self.findings.append({
                    "type": "basic_auth",
                    "url": req.pretty_url,
                    "severity": "medium",
                })

        # Check for sensitive data in request body
        if req.content and len(req.content) > 0:
            self._check_sensitive_data(req.content, req.pretty_url, "request")

    def response(self, flow: http.HTTPFlow) -> None:
        """Process each intercepted response."""
        resp = flow.response

        # Update status codes
        status_group = f"{resp.status_code // 100}xx"
        self.stats["status_codes"][status_group] = (
            self.stats["status_codes"].get(status_group, 0) + 1
        )

        # Check content types
        content_type = resp.headers.get("Content-Type", "unknown")
        self.stats["content_types"][content_type] = (
            self.stats["content_types"].get(content_type, 0) + 1
        )

        # Check security headers
        resp_headers = dict(resp.headers)
        self._check_security_headers(resp_headers, flow.request.pretty_url)

        # Check cookies
        cookies = []
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie":
                cookie_parts = {}
                parts = [p.strip() for p in value.split(";")]
                cookie_parts["name"] = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
                for part in parts[1:]:
                    if part.lower() == "secure":
                        cookie_parts["secure"] = True
                    elif part.lower() == "httponly":
                        cookie_parts["httponly"] = True
                    elif part.lower().startswith("samesite"):
                        cookie_parts["same_site"] = part.split("=")[1] if "=" in part else "true"
                cookies.append(cookie_parts)
        if cookies:
            self._check_cookies(cookies, flow.request.pretty_url)

        # Check for sensitive data in response body
        if resp.content and len(resp.content) > 0:
            self._check_sensitive_data(resp.content, flow.request.pretty_url, "response")

        # Build HAR entry
        self._build_har_entry(flow)

    def _build_har_entry(self, flow: http.HTTPFlow) -> None:
        """Build a HAR (HTTP Archive) entry from a flow."""
        req = flow.request
        resp = flow.response

        entry = {
            "startedDateTime": datetime.fromtimestamp(
                flow.request.timestamp_start, tz=timezone.utc
            ).isoformat(),
            "time": int((resp.timestamp_end or 0) - (req.timestamp_start or 0)) * 1000,
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "httpVersion": req.http_version,
                "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                "queryString": [
                    {"name": k, "value": v} for k, v in req.query.items()
                ],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(req.content) if req.content else -1,
            },
            "response": {
                "status": resp.status_code,
                "statusText": resp.reason,
                "httpVersion": resp.http_version,
                "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
                "cookies": [
                    {
                        "name": c.get("name", ""),
                        "value": c.get("value", ""),
                        "secure": c.get("secure", False),
                        "httponly": c.get("httponly", False),
                    }
                    for c in self._parse_cookies(resp.headers)
                ],
                "content": {
                    "size": len(resp.content) if resp.content else 0,
                    "mimeType": resp.headers.get("Content-Type", "application/octet-stream"),
                    "text": self._sanitize_body(resp.content) if resp.content else "",
                },
                "headersSize": -1,
                "bodySize": len(resp.content) if resp.content else -1,
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": 0,
                "receive": 0,
            },
        }

        # Add TLS info if available
        if hasattr(flow, "server_conn") and flow.server_conn:
            sc = flow.server_conn
            if hasattr(sc, "tls_version") and sc.tls_version:
                entry["response"]["_tls_version"] = sc.tls_version
            if hasattr(sc, "cipher") and sc.cipher:
                entry["response"]["_tls_cipher"] = sc.cipher
            if hasattr(sc, "certificate_list") and sc.certificate_list:
                entry["response"]["_tls_certificates"] = [
                    {
                        "subject": cert.get("subject", ""),
                        "issuer": cert.get("issuer", ""),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                    }
                    for cert in sc.certificate_list
                ]

        self.har_entries.append(entry)

    def _parse_cookies(self, headers) -> list[dict]:
        """Parse Set-Cookie headers into structured cookie objects."""
        cookies = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                parts = [p.strip() for p in value.split(";")]
                first = parts[0]
                name = first.split("=")[0] if "=" in first else first
                val = "=".join(first.split("=")[1:]) if "=" in first else ""
                cookie = {"name": name, "value": val}
                for part in parts[1:]:
                    pl = part.lower()
                    if pl == "secure":
                        cookie["secure"] = True
                    elif pl == "httponly":
                        cookie["httponly"] = True
                    elif pl.startswith("samesite"):
                        cookie["sameSite"] = part.split("=")[1] if "=" in part else "true"
                    elif pl.startswith("domain"):
                        cookie["domain"] = part.split("=")[1] if "=" in part else ""
                    elif pl.startswith("path"):
                        cookie["path"] = part.split("=")[1] if "=" in part else ""
                    elif pl.startswith("max-age"):
                        cookie["maxAge"] = int(part.split("=")[1]) if "=" in part else 0
                    elif pl.startswith("expires"):
                        cookie["expires"] = part.split("=", 1)[1] if "=" in part else ""
                cookies.append(cookie)
        return cookies

    def done(self) -> None:
        """Called when mitmproxy shuts down — save results."""
        elapsed = time.time() - self.start_time
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save HAR file
        har_file = os.path.join(self.output_dir, f"mobilesentry_capture_{timestamp}.har")
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "MobileSentry", "version": "0.4.0"},
                "entries": self.har_entries,
            }
        }

        os.makedirs(self.output_dir, exist_ok=True)
        with open(har_file, "w", encoding="utf-8") as f:
            json.dump(har_data, f, indent=2, default=str)

        # Save findings report
        findings_file = os.path.join(
            self.output_dir, f"mobilesentry_findings_{timestamp}.json"
        )
        report = {
            "timestamp": timestamp,
            "duration_seconds": elapsed,
            "stats": {
                "total_requests": self.stats["total_requests"],
                "https_requests": self.stats["https_count"],
                "http_requests": self.stats["http_count"],
                "unique_hosts": len(self.stats["unique_hosts"]),
                "methods": dict(self.stats["methods"]),
                "status_codes": dict(self.stats["status_codes"]),
            },
            "findings": self.findings,
        }
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        # Final summary
        ctx.log.info("=" * 60)
        ctx.log.info("[MobileSentry] Interception Complete")
        ctx.log.info(f"  Duration: {elapsed:.1f}s")
        ctx.log.info(f"  Requests: {self.stats['total_requests']}")
        ctx.log.info(f"  HTTPS:    {self.stats['https_count']}")
        ctx.log.info(f"  HTTP:     {self.stats['http_count']}")
        ctx.log.info(f"  Hosts:    {len(self.stats['unique_hosts'])}")
        ctx.log.info(f"  Findings: {len(self.findings)}")
        ctx.log.info(f"  HAR file: {har_file}")
        ctx.log.info(f"  Report:   {findings_file}")
        ctx.log.info("=" * 60)


addons = [MobileSentryInterceptor()]
'''

MINIMAL_ADDON_SCRIPT = r'''"""MobileSentry Traffic Interception Addon — Minimal Mode.

Lightweight mitmproxy addon that captures traffic to HAR files
with minimal overhead. No real-time security analysis.

Usage:
    mitmproxy -s mobilesentry_minimal_addon.py
    mitmdump -s mobilesentry_minimal_addon.py

Output:
    Saves HAR file to mobilesentry_capture_<timestamp>.har

Author: MobileSentry
"""

import json
import os
import time
from datetime import datetime, timezone

from mitmproxy import http, ctx


class MobileSentryMinimalInterceptor:
    """Minimal traffic capture addon."""

    def __init__(self):
        self.start_time = time.time()
        self.entries = []
        self.count = 0

    def response(self, flow: http.HTTPFlow) -> None:
        self.count += 1
        req = flow.request
        resp = flow.response

        sanitized_body = ""
        if resp.content:
            text = resp.content.decode("utf-8", errors="replace")
            sanitized_body = (text[:1000] + "\n... [truncated]") if len(text) > 1000 else text

        entry = {
            "startedDateTime": datetime.fromtimestamp(
                flow.request.timestamp_start, tz=timezone.utc
            ).isoformat(),
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "httpVersion": req.http_version,
                "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                "queryString": [{"name": k, "value": v} for k, v in req.query.items()],
            },
            "response": {
                "status": resp.status_code,
                "statusText": resp.reason,
                "httpVersion": resp.http_version,
                "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
                "content": {
                    "size": len(resp.content) if resp.content else 0,
                    "mimeType": resp.headers.get("Content-Type", ""),
                    "text": sanitized_body,
                },
            },
        }
        self.entries.append(entry)

    def done(self):
        elapsed = time.time() - self.start_time
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        har_file = f"mobilesentry_capture_{timestamp}.har"

        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "MobileSentry", "version": "0.4.0"},
                "entries": self.entries,
            }
        }
        with open(har_file, "w", encoding="utf-8") as f:
            json.dump(har_data, f, indent=2)

        ctx.log.info(f"[MobileSentry] Captured {self.count} requests to {har_file} ({elapsed:.1f}s)")


addons = [MobileSentryMinimalInterceptor()]
'''

AUTH_CAPTURE_ADDON_SCRIPT = r'''"""MobileSentry Traffic Interception Addon — Auth Focus Mode.

Focused on capturing authentication tokens, session cookies, and
OAuth/OIDC traffic. Ideal for authentication security assessment.

Usage:
    mitmproxy -s mobilesentry_auth_addon.py
    mitmdump -s mobilesentry_auth_addon.py

Output:
    - Logs all auth-related flows to console
    - Saves auth tokens found in traffic
    - HAR file with all captured traffic

Author: MobileSentry
"""

import json
import os
import re
import time
from datetime import datetime, timezone

from mitmproxy import http, ctx


class AuthCaptureInterceptor:
    """Auth-focused traffic interceptor."""

    def __init__(self):
        self.start_time = time.time()
        self.auth_flows = []
        self.tokens_found = []
        self.all_entries = []

    def response(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        url = req.pretty_url

        # Check for OAuth/OIDC endpoints
        is_auth_endpoint = any(
            p in url.lower()
            for p in ["/oauth", "/authorize", "/token", "/login", "/auth",
                       "/connect", "/saml", "/openid", "/logout", "/callback"]
        )
        is_auth_header = bool(req.headers.get("Authorization", ""))

        if is_auth_endpoint or is_auth_header:
            entry = {
                "timestamp": datetime.fromtimestamp(
                    flow.request.timestamp_start, tz=timezone.utc
                ).isoformat(),
                "url": url,
                "method": req.method,
                "status": resp.status_code,
                "auth_header": req.headers.get("Authorization", "")[:80],
            }

            # Extract tokens from response
            if resp.content:
                body = resp.content.decode("utf-8", errors="replace")
                tokens = re.findall(
                    r'(?i)(access_token|refresh_token|id_token|bearer)\s*[:=]\s*["\']?([^"\'&\s,;]+)',
                    body,
                )
                for token_type, token_value in tokens:
                    display = token_value[:40] + "..." if len(token_value) > 40 else token_value
                    self.tokens_found.append({"type": token_type, "value": display, "url": url})
                    entry["token_found"] = {"type": token_type, "preview": display}

            # Check cookies for session tokens
            cookies = resp.headers.get_all("set-cookie")
            for cookie in cookies:
                if any(s in cookie.lower() for s in ["session", "token", "auth", "jwt"]):
                    cookie_name = cookie.split("=")[0]
                    ctx.log.info(f"[+] Session Cookie: {cookie_name} from {url}")
                    entry["session_cookie"] = cookie_name

            self.auth_flows.append(entry)

        # Build full HAR entry
        sanitized = ""
        if resp.content:
            text = resp.content.decode("utf-8", errors="replace")
            sanitized = (text[:500] + "\n...") if len(text) > 500 else text

        self.all_entries.append({
            "startedDateTime": datetime.fromtimestamp(
                flow.request.timestamp_start, tz=timezone.utc
            ).isoformat(),
            "request": {
                "method": req.method,
                "url": url,
                "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
            },
            "response": {
                "status": resp.status_code,
                "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
                "content": {"text": sanitized, "size": len(resp.content) if resp.content else 0},
            },
        })

    def done(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        elapsed = time.time() - self.start_time

        # Save auth report
        auth_file = f"mobilesentry_auth_{timestamp}.json"
        report = {
            "auth_flows": len(self.auth_flows),
            "tokens_found": self.tokens_found,
            "flows": self.auth_flows,
        }
        with open(auth_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # Save full HAR
        har_file = f"mobilesentry_capture_{timestamp}.har"
        har_data = {"log": {"version": "1.2", "creator": {"name": "MobileSentry-Auth", "version": "0.4.0"}, "entries": self.all_entries}}
        with open(har_file, "w", encoding="utf-8") as f:
            json.dump(har_data, f, indent=2)

        # Summary
        ctx.log.info(f"[MobileSentry] Auth Capture Complete")
        ctx.log.info(f"  Auth flows: {len(self.auth_flows)}")
        ctx.log.info(f"  Tokens found: {len(self.tokens_found)}")
        for t in self.tokens_found:
            ctx.log.info(f"    [{t['type']}] {t['preview']}")
        ctx.log.info(f"  HAR file: {har_file}")
        ctx.log.info(f"  Auth report: {auth_file}")


addons = [AuthCaptureInterceptor()]
'''

ADDONS: dict[str, tuple[str, str, str, str]] = {
    "full": ("full", "Full-featured interceptor with real-time security analysis and HAR capture", "mobilesentry_addon.py", FULL_ADDON_SCRIPT),
    "minimal": ("minimal", "Lightweight HAR capture with minimal overhead", "mobilesentry_minimal_addon.py", MINIMAL_ADDON_SCRIPT),
    "auth": ("auth", "Auth-focused capture for OAuth/OIDC/token analysis", "mobilesentry_auth_addon.py", AUTH_CAPTURE_ADDON_SCRIPT),
}


# ══════════════════════════════════════════════
# Device Setup Instructions
# ══════════════════════════════════════════════

DEVICE_SETUP_GUIDE = """
╔══════════════════════════════════════════════════════════════╗
║            MITM Proxy — Device Setup Guide                   ║
╚══════════════════════════════════════════════════════════════╝

Prerequisites:
  1. Install mitmproxy on your host machine:
     pip install mitproxy
     # Or: brew install mitmproxy (macOS)

  2. Start the proxy with a MobileSentry addon:
     mitmproxy -s mobilesentry_addon.py
     # Or for headless: mitmdump -s mobilesentry_addon.py

  3. Note your host machine's IP address:
     ifconfig | grep inet  (or ipconfig on Windows)

─────────────────────────────────────────────
ANDROID — Proxy Configuration
─────────────────────────────────────────────

  Option A — ADB (requires USB debugging):
    $ adb shell settings put global http_proxy <HOST_IP>:8080

  Option B — Wi-Fi Settings:
    Settings > Wi-Fi > Long-press network > Modify Network
    > Advanced Options > Proxy > Manual
    > Host: <HOST_IP>  |  Port: 8080

  Install CA Certificate:
    $ adb shell am start -a android.intent.action.VIEW \\
        -d "http://mitm.it"
    # Download and install the certificate
    # Settings > Security > Install from storage > mitmproxy-ca-cert.cer

  For Android 7+ (user certs not trusted by default):
    $ adb push mitmproxy-ca-cert.cer /sdcard/
    $ adb shell
    $ su  # requires rooted device
    # cp /sdcard/mitmproxy-ca-cert.cer /system/etc/security/cacerts/
    # chmod 644 /system/etc/security/cacerts/mitmproxy-ca-cert.cer
    # reboot

  Or use a Magisk module:
    https://github.com/nccgroup/mitmproxy_certificate_transparency

─────────────────────────────────────────────
iOS — Proxy Configuration
─────────────────────────────────────────────

  Option A — Wi-Fi Settings:
    Settings > Wi-Fi > (i) next to your network
    > HTTP Proxy > Manual
    > Server: <HOST_IP>  |  Port: 8080

  Install CA Certificate:
    1. Open Safari on the device
    2. Navigate to http://mitm.it
    3. Download and install the iOS profile
    4. Settings > General > About > Certificate Trust Settings
    5. Enable full trust for "mitmproxy" root certificate

  For iOS 10.3+:
    1. Settings > General > Profiles
    2. Tap the mitmproxy profile > Install
    3. Settings > General > About > Certificate Trust Settings
    4. Toggle ON for "mitmproxy" root CA

─────────────────────────────────────────────
Disable Proxy (Cleanup)
─────────────────────────────────────────────

  Android:  adb shell settings delete global http_proxy
  iOS:      Settings > Wi-Fi > (i) > HTTP Proxy > Off

  Stop mitmproxy:  Ctrl+C in the terminal window
"""


# ══════════════════════════════════════════════
# Interception Setup — Generator
# ══════════════════════════════════════════════


class InterceptionSetup:
    """Generates mitmproxy addon scripts for traffic interception.

    Args:
        output_dir: Directory where generated addons will be saved.
    """

    def __init__(self, output_dir: str = "./mitmproxy_config") -> None:
        self.output_dir = Path(output_dir)

    def list_addons(self) -> list[dict[str, str]]:
        """List available addon types."""
        return [
            {
                "name": name,
                "description": info[1],
                "filename": info[2],
            }
            for name, info in ADDONS.items()
        ]

    def generate_addon(self, addon_type: str = "full") -> MitmproxyAddon | None:
        """Generate a single addon script.

        Args:
            addon_type: Type of addon ('full', 'minimal', 'auth').

        Returns:
            MitmproxyAddon if found, None otherwise.
        """
        if addon_type not in ADDONS:
            return None

        name, desc, filename, code = ADDONS[addon_type]
        output_path = str(self.output_dir / filename)

        return MitmproxyAddon(
            name=name,
            description=desc,
            filename=filename,
            code=code,
            output_path=output_path,
        )

    def generate_all(self) -> list[MitmproxyAddon]:
        """Generate all addon types.

        Returns:
            List of MitmproxyAddon objects.
        """
        addons_list: list[MitmproxyAddon] = []
        for addon_type in ADDONS:
            addon = self.generate_addon(addon_type)
            if addon:
                addons_list.append(addon)
        return addons_list

    def write_addons(self, addons_list: list[MitmproxyAddon]) -> list[str]:
        """Write addon scripts to disk.

        Args:
            addons_list: List of addons to write.

        Returns:
            List of written file paths.
        """
        written: list[str] = []
        for addon in addons_list:
            path = Path(addon.output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(addon.code.strip() + "\n", encoding="utf-8")
            written.append(str(path))
        return written

    def write_all(self) -> list[str]:
        """Generate and write all addon scripts.

        Returns:
            List of written file paths.
        """
        addons_list = self.generate_all()
        return self.write_addons(addons_list)

    def write_addon(self, addon_type: str) -> str | None:
        """Generate and write a single addon script.

        Args:
            addon_type: Type of addon ('full', 'minimal', 'auth').

        Returns:
            Path to written file, or None if not found.
        """
        addon = self.generate_addon(addon_type)
        if addon is None:
            return None
        paths = self.write_addons([addon])
        return paths[0] if paths else None

    def write_setup_guide(self) -> str:
        """Write the device setup guide to disk.

        Returns:
            Path to the written guide file.
        """
        path = self.output_dir / "DEVICE_SETUP.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEVICE_SETUP_GUIDE.strip() + "\n", encoding="utf-8")
        return str(path)


# ══════════════════════════════════════════════
# Traffic Analyzer — HAR Parsing & Security Analysis
# ══════════════════════════════════════════════


class TrafficAnalyzer:
    """Analyzes captured HTTP/HTTPS traffic from HAR files.

    Parses HAR (HTTP Archive) files and performs security analysis on
    the captured traffic, including:
    - HTTPS vs HTTP ratio
    - Cookie security attributes (Secure, HttpOnly, SameSite)
    - Authentication header analysis
    - Security header presence (HSTS, CSP, etc.)
    - Sensitive data exposure in URLs and bodies
    - TLS version and cipher analysis
    """

    def __init__(self) -> None:
        self.analyzer_version = "0.4.0"

    def analyze_har(self, har_path: str) -> TrafficAnalysisResult:
        """Analyze a HAR file for security issues.

        Args:
            har_path: Path to the HAR file.

        Returns:
            TrafficAnalysisResult with findings.
        """
        start = time.time()

        with open(har_path, encoding="utf-8") as f:
            har_data = json.load(f)

        entries = har_data.get("log", {}).get("entries", [])
        if not entries:
            # Try alternate HAR structure (some variants)
            entries = har_data.get("entries", [])

        result = TrafficAnalysisResult()
        result.total_requests = len(entries)

        seen_hosts: set[str] = set()

        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})

            url = request.get("url", "")
            request.get("method", "GET")
            response.get("status", 0)

            parsed = urlparse(url)
            host = parsed.hostname or ""
            scheme = parsed.scheme or "https"

            if host:
                seen_hosts.add(host)

            # Build request headers dict
            req_headers: dict[str, str] = {}
            for h in request.get("headers", []):
                req_headers[h.get("name", "").lower()] = h.get("value", "")

            # Build response headers dict
            resp_headers: dict[str, str] = {}
            for h in response.get("headers", []):
                resp_headers[h.get("name", "").lower()] = h.get("value", "")

            # Get TLS info
            tls_version = response.get("_tls_version", "")
            tls_cipher = response.get("_tls_cipher", "")

            # Get body sizes
            content = response.get("content", {})
            content.get("size", 0)
            body_text = content.get("text", "")

            # ── 1. HTTP (non-TLS) check ──
            if scheme != "https":
                result.http_urls.append(url)
                result.findings.append(TrafficFinding(
                        title="HTTP Request (No TLS)",
                        description="Request made over unencrypted HTTP instead of HTTPS.",
                    severity="high",
                    category="crypto",
                    url=url,
                    recommendation="Ensure all traffic uses HTTPS. Redirect HTTP to HTTPS at the server level.",
                    evidence=[url],
                ))

            # ── 2. Cookie security analysis ──
            for cookie in response.get("cookies", []):
                result.cookie_stats["total"] += 1
                cookie_name = cookie.get("name", "unknown")
                if not cookie.get("secure", False):
                    result.cookie_stats["missing_secure"] += 1
                    result.findings.append(TrafficFinding(
                        title="Cookie Missing Secure Flag",
                        description=f"Cookie '{cookie_name}' is missing the Secure flag.",
                        severity="medium",
                        category="auth",
                        url=url,
                        recommendation="Set the Secure flag on all cookies to ensure they are only sent over HTTPS.",
                        evidence=[f"Cookie: {cookie_name}"],
                    ))
                if not cookie.get("httponly", False):
                    result.cookie_stats["missing_httponly"] += 1
                    result.findings.append(TrafficFinding(
                        title="Cookie Missing HttpOnly Flag",
                        description=f"Cookie '{cookie_name}' is missing the HttpOnly flag.",
                        severity="medium",
                        category="auth",
                        url=url,
                        recommendation="Set the HttpOnly flag on cookies to prevent access via JavaScript.",
                        evidence=[f"Cookie: {cookie_name}"],
                    ))
                if not cookie.get("sameSite", ""):
                    result.cookie_stats["missing_samesite"] += 1
                    result.findings.append(TrafficFinding(
                        title="Cookie Missing SameSite Attribute",
                        description=f"Cookie '{cookie_name}' is missing the SameSite attribute.",
                        severity="low",
                        category="auth",
                        url=url,
                        recommendation="Add SameSite=Lax or SameSite=Strict to cookies for CSRF protection.",
                        evidence=[f"Cookie: {cookie_name}"],
                    ))

            # ── 3. Security headers check ──
            for header, (title, recommendation) in INSECURE_HEADERS.items():
                if header not in resp_headers:
                    result.findings.append(TrafficFinding(
                        title=title,
                        description=f"Response is missing the '{header}' security header.",
                        severity="medium" if header == "strict-transport-security" else "low",
                        category="config",
                        url=url,
                        recommendation=recommendation,
                        evidence=[f"Missing header: {header}"],
                    ))

            # ── 4. Auth header analysis ──
            auth = req_headers.get("authorization", "")
            if auth:
                result.auth_header_stats["total"] += 1
                if auth.startswith("Bearer "):
                    result.auth_header_stats["bearer"] += 1
                    token = auth[7:]
                    # Check for JWT-like tokens in auth
                    if len(token) > 20:
                        parts = token.split(".")
                        if len(parts) == 3:
                            try:
                                # Try to decode JWT payload
                                import base64
                                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                                decoded = base64.urlsafe_b64decode(padded)
                                result.findings.append(TrafficFinding(
                                    title="JWT Token Found in Authorization Header",
                                    description="A JWT token was found in the Authorization header.",
                                    severity="info",
                                    category="auth",
                                    url=url,
                                    recommendation="Ensure JWTs have short expiration times and are properly validated.",
                                    evidence=[f"JWT payload preview: {decoded[:200]!s}"],
                                ))
                            except Exception:
                                pass
                elif auth.startswith("Basic "):
                    result.auth_header_stats["basic"] += 1
                    result.findings.append(TrafficFinding(
                        title="Basic Authentication Used",
                        description="Basic auth sends credentials as base64-encoded (not encrypted).",
                        severity="medium",
                        category="auth",
                        url=url,
                        recommendation="Use token-based authentication (Bearer tokens, OAuth2) instead of Basic auth.",
                        evidence=[f"Auth header present for: {url}"],
                    ))

            # ── 5. API key in URL params ──
            query_string = request.get("queryString", [])
            for param in query_string:
                param_name = param.get("name", "").lower()
                if any(p in param_name for p in ["token", "secret", "api", "key", "password", "auth"]):
                    result.findings.append(TrafficFinding(
                        title="Sensitive Data in URL Parameters",
                        description=f"Sensitive parameter '{param_name}' found in URL.",
                        severity="high",
                        category="data_exposure",
                        url=url,
                        recommendation="Move sensitive parameters to request headers or body. URLs are logged by proxies and servers.",
                        evidence=[f"Parameter: {param_name}"],
                    ))

            # ── 6. TLS version tracking ──
            if tls_version:
                result.tls_stats["tls_versions"].append(tls_version)
                if any(w in tls_version for w in ["SSLv3", "TLSv1.0", "TLSv1.0"]):
                    result.findings.append(TrafficFinding(
                        title="Outdated TLS Version",
                        description=f"Using outdated TLS version: {tls_version}",
                        severity="high",
                        category="crypto",
                        url=url,
                        recommendation="Upgrade to TLS 1.2 or TLS 1.3. Deprecate TLS 1.0 and TLS 1.1.",
                        evidence=[f"TLS version: {tls_version}"],
                    ))
            if tls_cipher:
                result.tls_stats["ciphers"].append(tls_cipher)
                for weak in WEAK_CIPHERS:
                    if weak.lower() in tls_cipher.lower():
                        result.findings.append(TrafficFinding(
                            title="Weak TLS Cipher Suite",
                            description=f"Weak cipher suite detected: {tls_cipher}",
                            severity="high",
                            category="crypto",
                            url=url,
                            recommendation="Disable weak ciphers. Use TLS 1.2+ with AEAD ciphers (GCM, CHACHA20).",
                            evidence=[f"Cipher: {tls_cipher}"],
                        ))
                        break

            # ── 7. Sensitive data in response bodies ──
            if body_text:
                for dtype, pattern in SENSITIVE_PATTERNS.items():
                    try:
                        matches = re.findall(pattern, body_text)
                        if matches:
                            result.sensitive_data_findings.append(f"{dtype}: {url}")
                            result.findings.append(TrafficFinding(
                                title="Sensitive Data Exposure in Response Body",
                                description=f"Potential {dtype} found in response body.",
                                severity="high",
                                category="data_exposure",
                                url=url,
                                recommendation="Review API responses to ensure sensitive data is not leaked.",
                                evidence=[f"Pattern: {dtype}", f"Matches: {len(matches)}"],
                            ))
                            break  # One finding per request
                    except re.error:
                        pass

        result.total_domains = sorted(seen_hosts)

        # Summary finding if no HSTS on HTTPS responses
        hsts_missing_count = sum(
            1 for f in result.findings if f.title == "Missing HSTS header"
        )
        if hsts_missing_count > 0:
            result.findings.append(TrafficFinding(
                title="HSTS Not Configured",
                description=f"{hsts_missing_count} HTTPS responses are missing the HSTS header.",
                severity="medium",
                category="config",
                url="",
                recommendation="Enable HSTS (Strict-Transport-Security) header across all HTTPS responses.",
                evidence=[f"Missing on {hsts_missing_count} responses"],
            ))

        result.analysis_time_ms = (time.time() - start) * 1000
        return result

    def analyze_har_summary(self, har_path: str) -> dict[str, Any]:
        """Quick summary of HAR file without detailed analysis.

        Args:
            har_path: Path to the HAR file.

        Returns:
            Dict with summary statistics.
        """
        with open(har_path, encoding="utf-8") as f:
            har_data = json.load(f)

        entries = har_data.get("log", {}).get("entries", [])
        if not entries:
            entries = har_data.get("entries", [])

        hosts: dict[str, int] = {}
        methods: dict[str, int] = {}
        status_codes: dict[str, int] = {}
        https_count = 0
        http_count = 0

        for entry in entries:
            req = entry.get("request", {})
            res = entry.get("response", {})

            url = req.get("url", "")
            parsed = urlparse(url)

            host = parsed.hostname or "unknown"
            hosts[host] = hosts.get(host, 0) + 1

            method = req.get("method", "UNKNOWN")
            methods[method] = methods.get(method, 0) + 1

            status = res.get("status", 0)
            group = f"{status // 100}xx"
            status_codes[group] = status_codes.get(group, 0) + 1

            if parsed.scheme == "https":
                https_count += 1
            else:
                http_count += 1

        content_types: dict[str, int] = {}
        for entry in entries:
            ct = entry.get("response", {}).get("content", {}).get("mimeType", "unknown")
            content_types[ct] = content_types.get(ct, 0) + 1

        return {
            "total_requests": len(entries),
            "https_requests": https_count,
            "http_requests": http_count,
            "unique_hosts": len(hosts),
            "hosts": dict(sorted(hosts.items(), key=lambda x: x[1], reverse=True)[:20]),
            "methods": methods,
            "status_codes": status_codes,
            "content_types": dict(sorted(content_types.items(), key=lambda x: x[1], reverse=True)[:10]),
            "https_percentage": round((https_count / max(len(entries), 1)) * 100, 1),
        }


# ══════════════════════════════════════════════
# TLS Analyzer — Certificate & Cipher Analysis
# ══════════════════════════════════════════════


class TlsAnalyzer:
    """Analyzes TLS certificates and cipher information from captured traffic.

    Parses TLS metadata embedded in HAR files by MobileSentry addons and
    performs certificate security analysis.
    """

    def __init__(self) -> None:
        pass

    def analyze_har(self, har_path: str) -> TlsAnalysisResult:
        """Analyze TLS certificates from a HAR file.

        Args:
            har_path: Path to the HAR file.

        Returns:
            TlsAnalysisResult with certificate info and findings.
        """
        result = TlsAnalysisResult()

        with open(har_path, encoding="utf-8") as f:
            har_data = json.load(f)

        entries = har_data.get("log", {}).get("entries", [])
        if not entries:
            entries = har_data.get("entries", [])

        for entry in entries:
            response = entry.get("response", {})
            request = entry.get("request", {})
            url = request.get("url", "")
            parsed = urlparse(url)
            host = parsed.hostname or ""

            tls_version = response.get("_tls_version", "")
            tls_cipher = response.get("_tls_cipher", "")

            # Track TLS versions
            if tls_version:
                result.tls_versions[tls_version] = result.tls_versions.get(tls_version, 0) + 1

                if any(w in tls_version for w in ["SSLv3", "TLSv1.0", "TLSv1.1"]):
                    result.findings.append(TrafficFinding(
                        title="Deprecated TLS Version",
                        description=f"Connection uses deprecated {tls_version}",
                        severity="high",
                        category="crypto",
                        url=url,
                        recommendation="Upgrade to TLS 1.2 or TLS 1.3.",
                        evidence=[f"TLS version: {tls_version}", f"Host: {host}"],
                    ))

            # Track weak ciphers
            if tls_cipher:
                for weak in WEAK_CIPHERS:
                    if weak.lower() in tls_cipher.lower():
                        result.weak_ciphers.append(tls_cipher)
                        result.findings.append(TrafficFinding(
                            title="Weak Cipher Suite Detected",
                            description=f"Weak cipher in use: {tls_cipher}",
                            severity="high",
                            category="crypto",
                            url=url,
                            recommendation="Disable weak ciphers. Use AEAD ciphers only.",
                            evidence=[f"Cipher: {tls_cipher}", f"Host: {host}"],
                        ))
                        break

            # Parse certificate info from HAR
            certs_data = response.get("_tls_certificates", [])
            for cert_data in certs_data:
                cert = TlsCertificateInfo(
                    subject=cert_data.get("subject", {}),
                    issuer=cert_data.get("issuer", {}),
                    serial_number=cert_data.get("serialNumber", ""),
                    not_before=cert_data.get("notBefore", ""),
                    not_after=cert_data.get("notAfter", ""),
                    hostname=host,
                    tls_version=tls_version,
                    cipher_suite=tls_cipher,
                )

                # Check expiry
                if cert.not_after:
                    try:
                        not_after = datetime.fromisoformat(cert.not_after.replace("Z", "+00:00"))
                        now = datetime.now(not_after.tzinfo)
                        if not_after < now:
                            cert.is_expired = True
                            result.expired_certs.append(host)
                            result.findings.append(TrafficFinding(
                                title="Expired TLS Certificate",
                                description=f"Certificate for {host} has expired.",
                                severity="high",
                                category="crypto",
                                url=url,
                                recommendation="Renew the TLS certificate immediately.",
                                evidence=[f"Expired: {cert.not_after}", f"Host: {host}"],
                            ))
                        else:
                            cert.days_until_expiry = (not_after - now).days
                    except (ValueError, TypeError):
                        pass

                # Check self-signed
                subj = str(cert.subject)
                iss = str(cert.issuer)
                if subj and iss and subj == iss:
                    cert.is_self_signed = True
                    result.self_signed_certs.append(host)
                    result.findings.append(TrafficFinding(
                        title="Self-Signed TLS Certificate",
                        description=f"Self-signed certificate detected for {host}.",
                        severity="high",
                        category="crypto",
                        url=url,
                        recommendation="Replace self-signed certificates with ones from a trusted CA.",
                        evidence=[f"Host: {host}"],
                    ))

                # Check wildcard
                sans = cert_data.get("subjectAltNames", [])
                for san in sans:
                    if san.startswith("*."):
                        cert.is_wildcard = True

                result.certificates.append(cert)

        # Check for missing TLS info
        total_with_tls = sum(1 for e in entries if e.get("response", {}).get("_tls_version"))
        if total_with_tls == 0 and len(entries) > 0:
            https_count = sum(
                1 for e in entries
                if urlparse(e.get("request", {}).get("url", "")).scheme == "https"
            )
            if https_count > 0:
                result.findings.append(TrafficFinding(
                    title="TLS Metadata Not Available",
                    description="No TLS information found. The HAR file may not include TLS metadata.",
                    severity="info",
                    category="crypto",
                    url="",
                    recommendation="Use the full MobileSentry mitmproxy addon to capture TLS information.",
                    evidence=[f"HTTPS requests: {https_count}"],
                ))

        return result


# ══════════════════════════════════════════════
# Validate Helpers
# ══════════════════════════════════════════════


def validate_addon(addon: MitmproxyAddon) -> list[str]:
    """Validate a generated addon script.

    Args:
        addon: The addon to validate.

    Returns:
        List of validation issues (empty if valid).
    """
    issues: list[str] = []
    if not addon.code.strip():
        issues.append(f"❌ {addon.filename}: Script is empty")
        return issues
    if '"""' not in addon.code and "'''" not in addon.code:
        issues.append(f"⚠️  {addon.filename}: Missing docstring")
    if "from mitmproxy" not in addon.code:
        issues.append(f"⚠️  {addon.filename}: Missing mitmproxy import")
    if "addons = [" not in addon.code:
        issues.append(f"⚠️  {addon.filename}: Missing 'addons' list declaration")
    if addon.size_bytes > 500_000:
        issues.append(f"⚠️  {addon.filename}: Large script ({addon.size_bytes / 1024:.1f} KB)")
    return issues
