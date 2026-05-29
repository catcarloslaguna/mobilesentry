"""Unified Report Generator — Combine all MobileSentry analysis results into HTML, JSON, or Markdown reports.

Usage:
    from mobilesentry.report_generator import ReportGenerator

    gen = ReportGenerator()
    report = gen.load_json("apk", "./output/com.example_analysis.json")

    # Or load multiple at once
    gen.load_all(
        apk_path="./output/com.example_analysis.json",
        owasp_path="./output/com.example_owasp.json",
    )

    # Generate outputs
    gen.write_html("./report.html")
    gen.write_json("./report.json")
    gen.write_markdown("./REPORT.md")
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ══════════════════════════════════════════════
# Data Models
# ══════════════════════════════════════════════


@dataclass
class ReportSource:
    """Metadata about a data source loaded into the report."""

    name: str  # e.g. "apk", "ipa", "owasp", "obfuscation", "dynamic", "traffic", "tls"
    label: str  # Human-readable label e.g. "APK Analysis"
    loaded: bool
    file_path: str | None = None
    error: str | None = None
    timestamp: str | None = None


@dataclass
class SeverityCount:
    """Count of findings by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


@dataclass
class FindingEntry:
    """Normalized finding entry from any analyzer."""

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # e.g. "permissions", "secrets", "obfuscation", "tls", "owasp"
    source: str  # Which analyzer produced this
    recommendation: str = ""
    file: str | None = None
    line: int | None = None
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    cwe: str | None = None
    platform: str | None = None  # "android", "ios", "both"


@dataclass
class UnifiedReport:
    """Complete unified report combining all analyzer results."""

    # Metadata
    generated_at: str = ""
    mobilesentry_version: str = "0.7.0"
    analysis_duration_ms: int = 0

    # Overall assessment
    overall_risk: str = "info"
    overall_score: int = 0

    # Sources
    sources: list[ReportSource] = field(default_factory=list)

    # Severity distribution
    severity_counts: SeverityCount = field(default_factory=SeverityCount)

    # All findings (normalized)
    findings: list[FindingEntry] = field(default_factory=list)

    # Source-specific raw data (for detailed sections)
    raw_apk: dict[str, Any] = field(default_factory=dict)
    raw_ipa: dict[str, Any] = field(default_factory=dict)
    raw_owasp: dict[str, Any] = field(default_factory=dict)
    raw_obfuscation: dict[str, Any] = field(default_factory=dict)
    raw_dynamic: dict[str, Any] = field(default_factory=dict)
    raw_traffic: dict[str, Any] = field(default_factory=dict)
    raw_tls: dict[str, Any] = field(default_factory=dict)

    # App metadata
    app_name: str = ""
    app_version: str = ""
    platform: str = ""  # "android", "ios", "both"


# ══════════════════════════════════════════════
# Severity Helpers
# ══════════════════════════════════════════════


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": ("#dc2626", "#fef2f2"),
    "high": ("#ea580c", "#fff7ed"),
    "medium": ("#ca8a04", "#fefce8"),
    "low": ("#2563eb", "#eff6ff"),
    "info": ("#6b7280", "#f9fafb"),
}
SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",
}


def _severity_score(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def _risk_from_score(score: int, max_score: int = 100) -> str:
    if max_score == 0:
        return "info"
    ratio = score / max_score
    if ratio >= 0.8:
        return "critical"
    if ratio >= 0.6:
        return "high"
    if ratio >= 0.4:
        return "medium"
    if ratio >= 0.2:
        return "low"
    return "info"


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _sanitize_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# ══════════════════════════════════════════════
# Report Generator
# ══════════════════════════════════════════════


class ReportGenerator:
    """Unified report generator combining results from all MobileSentry analyzers."""

    def __init__(self) -> None:
        self.report = UnifiedReport(generated_at=_now_str())

    def load_all(
        self,
        apk_path: str | None = None,
        ipa_path: str | None = None,
        owasp_path: str | None = None,
        obfuscation_path: str | None = None,
        dynamic_path: str | None = None,
        traffic_path: str | None = None,
        tls_path: str | None = None,
    ) -> UnifiedReport:
        """Load all available JSON report files at once."""
        if apk_path:
            self.load_json("apk", apk_path)
        if ipa_path:
            self.load_json("ipa", ipa_path)
        if owasp_path:
            self.load_json("owasp", owasp_path)
        if obfuscation_path:
            self.load_json("obfuscation", obfuscation_path)
        if dynamic_path:
            self.load_json("dynamic", dynamic_path)
        if traffic_path:
            self.load_json("traffic", traffic_path)
        if tls_path:
            self.load_json("tls", tls_path)
        self._compute_overall()
        return self.report

    def load_json(self, source_type: str, file_path: str) -> bool:
        """Load a single JSON report file from a given analyzer type.

        Args:
            source_type: One of "apk", "ipa", "owasp", "obfuscation", "dynamic", "traffic", "tls"
            file_path: Path to the JSON file.

        Returns:
            True if loaded successfully, False otherwise.
        """
        if not os.path.isfile(file_path):
            self.report.sources.append(
                ReportSource(
                    name=source_type,
                    label=self._source_label(source_type),
                    loaded=False,
                    file_path=file_path,
                    error=f"File not found: {file_path}",
                )
            )
            return False

        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.report.sources.append(
                ReportSource(
                    name=source_type,
                    label=self._source_label(source_type),
                    loaded=False,
                    file_path=file_path,
                    error=str(e),
                )
            )
            return False

        loader = getattr(self, f"_load_{source_type}", None)
        if loader:
            loader(data, file_path)
        else:
            self.report.sources.append(
                ReportSource(
                    name=source_type,
                    label=self._source_label(source_type),
                    loaded=True,
                    file_path=file_path,
                )
            )
        return True

    def _source_label(self, source_type: str) -> str:
        labels = {
            "apk": "APK Analysis",
            "ipa": "IPA Analysis",
            "owasp": "OWASP Mobile Top 10",
            "obfuscation": "Code Obfuscation Detection",
            "dynamic": "Dynamic Analysis",
            "traffic": "Traffic Analysis",
            "tls": "TLS Certificate Analysis",
        }
        return labels.get(source_type, source_type.replace("_", " ").title())

    # ── Loaders for each analyzer type ──

    def _load_apk(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_apk = data
        self.report.sources.append(
            ReportSource(
                name="apk",
                label="APK Analysis",
                loaded=True,
                file_path=file_path,
            )
        )
        self.report.platform = "android"

        # App metadata
        apk_info = data.get("apk_info", {})
        if isinstance(apk_info, dict):
            self.report.app_name = apk_info.get("package_name", "")
            self.report.app_version = f'{apk_info.get("version_name", "")} ({apk_info.get("version_code", "")})'

        # Normalize findings
        for issue in data.get("security_issues", []):
            if isinstance(issue, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=issue.get("title", "Security Issue"),
                        description=issue.get("description", ""),
                        severity=issue.get("severity", "medium"),
                        category="security",
                        source="APK Analysis",
                        recommendation=issue.get("recommendation", ""),
                        evidence=issue.get("evidence", []),
                    )
                )

        for secret in data.get("secrets", []):
            if isinstance(secret, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=f"Hardcoded {secret.get('secret_type', 'Secret')}",
                        description=f"Hardcoded {secret.get('secret_type', 'secret')} found: {secret.get('value', '')}",
                        severity=secret.get("severity", "high"),
                        category="secrets",
                        source="APK Analysis",
                        file=secret.get("file"),
                        line=secret.get("line"),
                        evidence=[f"Value: {secret.get('value', '')}"],
                    )
                )

        # Permissions as findings
        for perm in data.get("permissions", []):
            if isinstance(perm, dict) and perm.get("severity") == "dangerous":
                self.report.findings.append(
                    FindingEntry(
                        title=f"Permission: {perm.get('name', 'Unknown')}",
                        description=f"Dangerous permission declared: {perm.get('name', '')}",
                        severity="medium",
                        category="permissions",
                        source="APK Analysis",
                    )
                )

    def _load_ipa(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_ipa = data
        self.report.sources.append(
            ReportSource(
                name="ipa",
                label="IPA Analysis",
                loaded=True,
                file_path=file_path,
            )
        )
        self.report.platform = "ios"

        ipa_info = data.get("ipa_info", {})
        if isinstance(ipa_info, dict):
            self.report.app_name = ipa_info.get("bundle_id", "")
            self.report.app_version = f'{ipa_info.get("version", "")} (build {ipa_info.get("build", "")})'

        # Normalize findings
        for issue in data.get("security_issues", []):
            if isinstance(issue, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=issue.get("title", "Security Issue"),
                        description=issue.get("description", ""),
                        severity=issue.get("severity", "medium"),
                        category="security",
                        source="IPA Analysis",
                        recommendation=issue.get("recommendation", ""),
                    )
                )

        for secret in data.get("secrets", []):
            if isinstance(secret, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=f"Hardcoded {secret.get('secret_type', 'Secret')}",
                        description=f"Hardcoded {secret.get('secret_type', 'secret')} found: {secret.get('value', '')}",
                        severity=secret.get("severity", "high"),
                        category="secrets",
                        source="IPA Analysis",
                        file=secret.get("file"),
                        line=secret.get("line"),
                    )
                )

        # Permissions as findings
        for perm in data.get("permissions", []):
            if isinstance(perm, dict) and perm.get("severity") == "high":
                self.report.findings.append(
                    FindingEntry(
                        title=f"iOS Permission: {perm.get('key', 'Unknown')}",
                        description=f"High-risk permission: {perm.get('key', '')} — {perm.get('purpose', '')[:80]}",
                        severity="medium",
                        category="permissions",
                        source="IPA Analysis",
                    )
                )

    def _load_owasp(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_owasp = data
        self.report.sources.append(
            ReportSource(
                name="owasp",
                label="OWASP Mobile Top 10",
                loaded=True,
                file_path=file_path,
            )
        )

        if not self.report.platform:
            self.report.platform = data.get("platform", "")

        # Normalize findings
        for finding in data.get("findings", []):
            if isinstance(finding, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=finding.get("title", "OWASP Finding"),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "medium"),
                        category=finding.get("category_id", "owasp"),
                        source="OWASP Mobile Top 10",
                        recommendation=finding.get("recommendation", ""),
                        evidence=finding.get("evidence", []),
                        cwe=finding.get("cwe"),
                        platform=finding.get("platform"),
                    )
                )

    def _load_obfuscation(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_obfuscation = data
        self.report.sources.append(
            ReportSource(
                name="obfuscation",
                label="Code Obfuscation Detection",
                loaded=True,
                file_path=file_path,
            )
        )

        if not self.report.platform:
            self.report.platform = data.get("platform", "")

        for finding in data.get("findings", []):
            if isinstance(finding, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=finding.get("technique", "Obfuscation Technique"),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "medium"),
                        category="obfuscation",
                        source="Code Obfuscation Detection",
                        evidence=finding.get("evidence", []),
                        details=finding.get("details", {}),
                        platform=finding.get("platform"),
                    )
                )

    def _load_dynamic(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_dynamic = data
        self.report.sources.append(
            ReportSource(
                name="dynamic",
                label="Dynamic Analysis",
                loaded=True,
                file_path=file_path,
            )
        )

        for finding in data.get("findings", []):
            if isinstance(finding, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=finding.get("title", "Behavioral Finding"),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "medium"),
                        category="dynamic",
                        source="Dynamic Analysis",
                        evidence=finding.get("evidence", []),
                    )
                )

    def _load_traffic(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_traffic = data
        self.report.sources.append(
            ReportSource(
                name="traffic",
                label="Traffic Analysis",
                loaded=True,
                file_path=file_path,
            )
        )

        for finding in data.get("findings", []):
            if isinstance(finding, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=finding.get("title", "Traffic Finding"),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "medium"),
                        category="traffic",
                        source="Traffic Analysis",
                        evidence=finding.get("evidence", []),
                    )
                )

    def _load_tls(self, data: dict[str, Any], file_path: str) -> None:
        self.report.raw_tls = data
        self.report.sources.append(
            ReportSource(
                name="tls",
                label="TLS Certificate Analysis",
                loaded=True,
                file_path=file_path,
            )
        )

        for finding in data.get("findings", []):
            if isinstance(finding, dict):
                self.report.findings.append(
                    FindingEntry(
                        title=finding.get("title", "TLS Finding"),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "medium"),
                        category="tls",
                        source="TLS Certificate Analysis",
                    )
                )

    # ── Overall computation ──

    def _compute_overall(self) -> None:
        """Compute overall severity counts, risk score, and sort findings."""
        counts = SeverityCount()
        for f in self.report.findings:
            sev = f.severity.lower()
            if sev == "critical":
                counts.critical += 1
            elif sev == "high":
                counts.high += 1
            elif sev == "medium":
                counts.medium += 1
            elif sev == "low":
                counts.low += 1
            else:
                counts.info += 1
        self.report.severity_counts = counts

        # Overall score: weighted sum normalized to 0-100
        weighted = (
            counts.critical * 10
            + counts.high * 5
            + counts.medium * 2
            + counts.low * 1
        )
        max_possible = max(1, counts.total * 10)
        self.report.overall_score = min(100, int((weighted / max_possible) * 100))
        self.report.overall_risk = _risk_from_score(self.report.overall_score)

        # Sort findings by severity (critical first)
        self.report.findings.sort(
            key=lambda f: (SEVERITY_ORDER.get(f.severity.lower(), 99), f.title)
        )

    # ══════════════════════════════════════════════
    # HTML Report Generation
    # ══════════════════════════════════════════════

    def generate_html(self) -> str:
        """Generate a self-contained HTML report."""
        self._compute_overall()
        r = self.report
        # Severity bar chart
        max_count = max(
            r.severity_counts.critical,
            r.severity_counts.high,
            r.severity_counts.medium,
            r.severity_counts.low,
            r.severity_counts.info,
            1,
        )

        severity_bars = ""
        for sev in ("critical", "high", "medium", "low", "info"):
            count = getattr(r.severity_counts, sev)
            color, _ = SEVERITY_COLORS[sev]
            icon = SEVERITY_ICONS[sev]
            pct = (count / max_count) * 100
            severity_bars += f"""
            <div class="severity-row">
                <span class="severity-label">{icon} {sev.title()}</span>
                <div class="severity-bar-bg">
                    <div class="severity-bar" style="width:{pct:.1f}%;background:{color};">{count}</div>
                </div>
                <span class="severity-count">{count}</span>
            </div>"""

        # Sources summary
        sources_html = ""
        for src in r.sources:
            status_icon = "✅" if src.loaded else "❌"
            status_color = "var(--green)" if src.loaded else "var(--red)"
            error_str = f'<span class="dim"> — {_sanitize_html(src.error)}</span>' if src.error else ""
            sources_html += f"""
            <div class="source-row">
                <span class="source-icon" style="color:{status_color}">{status_icon}</span>
                <span class="source-label">{_sanitize_html(src.label)}</span>
                <span class="source-file">{_sanitize_html(src.file_path or "")}</span>
                {error_str}
            </div>"""

        # Findings table rows
        findings_rows = ""
        for i, f in enumerate(r.findings, 1):
            if i > 200:
                break  # Limit to 200 findings in HTML to keep size manageable
            color, _ = SEVERITY_COLORS.get(f.severity.lower(), SEVERITY_COLORS["info"])
            icon = SEVERITY_ICONS.get(f.severity.lower(), "▪️")
            file_str = f"<br><span class='dim'>File: {_sanitize_html(f.file)}{' line ' + str(f.line) if f.line else ''}</span>" if f.file else ""
            rec_str = f"<br><span class='rec'>{_sanitize_html(f.recommendation[:200])}</span>" if f.recommendation else ""
            evidence_str = ""
            if f.evidence:
                ev_items = "".join(f"<li>{_sanitize_html(e[:120])}</li>" for e in f.evidence[:5])
                evidence_str = f"<ul class='evidence'>{ev_items}</ul>"

            findings_rows += f"""
            <tr>
                <td><span class="sev-badge" style="background:{color};color:white;">{icon} {f.severity.upper()}</span></td>
                <td><strong>{_sanitize_html(f.title)}</strong><br><span class="dim">{_sanitize_html(f.description[:150])}</span>{file_str}{rec_str}{evidence_str}</td>
                <td>{_sanitize_html(f.category)}</td>
                <td>{_sanitize_html(f.source)}</td>
            </tr>"""

        # Source-specific sections
        apk_section = self._html_apk_section()
        ipa_section = self._html_ipa_section()
        obfuscation_section = self._html_obfuscation_section()
        dynamic_section = self._html_dynamic_section()
        traffic_section = self._html_traffic_section()
        owasp_section = self._html_owasp_section()

        risk_color, _ = SEVERITY_COLORS.get(r.overall_risk, SEVERITY_COLORS["info"])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MobileSentry Security Report — {_sanitize_html(r.app_name or "Mobile App")}</title>
<style>
:root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface2: #334155;
    --text: #e2e8f0;
    --text2: #94a3b8;
    --green: #22c55e;
    --red: #ef4444;
    --accent: #38bdf8;
    --radius: 8px;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }}
.container {{ max-width:1100px; margin:0 auto; padding:24px 16px; }}
h1 {{ font-size:1.8rem; margin-bottom:4px; }}
h2 {{ font-size:1.3rem; margin:24px 0 12px; padding-bottom:8px; border-bottom:2px solid var(--surface2); }}
h3 {{ font-size:1.1rem; margin:16px 0 8px; }}
.header {{ display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px; margin-bottom:24px; }}
.header-meta {{ color:var(--text2); font-size:0.85rem; }}
.risk-badge {{ display:inline-block; padding:4px 16px; border-radius:20px; font-weight:700; font-size:1.1rem; }}
.score-ring {{ width:120px; height:120px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:1.8rem; font-weight:700; border:6px solid; flex-shrink:0; }}
.score-section {{ display:flex; align-items:center; gap:24px; flex-wrap:wrap; margin:16px 0; }}
.severity-row {{ display:flex; align-items:center; gap:8px; margin:4px 0; }}
.severity-label {{ width:100px; font-size:0.85rem; }}
.severity-bar-bg {{ flex:1; height:24px; background:var(--surface2); border-radius:4px; overflow:hidden; }}
.severity-bar {{ height:100%; min-width:24px; display:flex; align-items:center; justify-content:center; font-size:0.75rem; font-weight:600; color:white; transition:width 0.3s; }}
.severity-count {{ width:40px; text-align:right; font-size:0.85rem; }}
.card {{ background:var(--surface); border-radius:var(--radius); padding:20px; margin:12px 0; }}
.card-header {{ display:flex; justify-content:space-between; align-items:center; cursor:pointer; user-select:none; }}
.card-header:hover {{ opacity:0.8; }}
.card-content {{ padding-top:12px; }}
.dim {{ color:var(--text2); font-size:0.85rem; }}
table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
th {{ text-align:left; padding:8px 6px; border-bottom:2px solid var(--surface2); color:var(--text2); font-weight:600; }}
td {{ padding:8px 6px; border-bottom:1px solid var(--surface2); vertical-align:top; }}
tr:hover {{ background:var(--surface2); }}
.sev-badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; white-space:nowrap; }}
.evidence {{ margin:4px 0 0 16px; font-size:0.8rem; color:var(--text2); }}
.evidence li {{ margin:2px 0; }}
.rec {{ color:var(--accent); font-size:0.8rem; }}
.source-row {{ display:flex; align-items:center; gap:8px; padding:4px 0; font-size:0.85rem; }}
.source-icon {{ font-size:1rem; }}
.source-file {{ color:var(--text2); font-size:0.8rem; }}
.grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
.stat-box {{ background:var(--surface2); padding:12px; border-radius:var(--radius); text-align:center; }}
.stat-value {{ font-size:1.5rem; font-weight:700; }}
.stat-label {{ font-size:0.8rem; color:var(--text2); }}
.collapsible {{ display:none; }}
.collapsible.open {{ display:block; }}
.toggle-icon {{ transition:transform 0.2s; }}
.toggle-icon.open {{ transform:rotate(90deg); }}
.tag {{ display:inline-block; padding:1px 6px; border-radius:3px; font-size:0.7rem; font-weight:600; margin:0 2px; background:var(--surface2); }}
@media (max-width:768px) {{ .grid-2 {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
    <div>
        <h1>📱 MobileSentry Security Report</h1>
        <div class="header-meta">
            Generated: {_sanitize_html(r.generated_at)} &middot;
            v{r.mobilesentry_version} &middot;
            Platform: <strong>{r.platform.upper() if r.platform else "N/A"}</strong>
        </div>
    </div>
    <div class="score-ring" style="border-color:{risk_color};color:{risk_color};">
        {r.overall_score}
    </div>
</div>

<!-- App Info -->
<div class="card">
    <strong>{_sanitize_html(r.app_name or "Unknown App")}</strong>
    <span class="dim"> &middot; {_sanitize_html(r.app_version)}</span>
    <br>
    <span class="risk-badge" style="background:{risk_color};color:white;">
        {SEVERITY_ICONS.get(r.overall_risk, '')} {r.overall_risk.upper()} Risk
    </span>
    <span class="dim"> &middot; {r.severity_counts.total} total findings</span>
</div>

<!-- Severity Distribution -->
<h2>📊 Severity Distribution</h2>
<div class="card">
    {severity_bars}
</div>

<!-- Executive Summary Stats -->
<h2>📋 Analysis Summary</h2>
<div class="grid-2">
    <div class="stat-box"><div class="stat-value" style="color:{SEVERITY_COLORS['critical'][0]}">{r.severity_counts.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-box"><div class="stat-value" style="color:{SEVERITY_COLORS['high'][0]}">{r.severity_counts.high}</div><div class="stat-label">High</div></div>
    <div class="stat-box"><div class="stat-value" style="color:{SEVERITY_COLORS['medium'][0]}">{r.severity_counts.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-box"><div class="stat-value" style="color:{SEVERITY_COLORS['low'][0]}">{r.severity_counts.low}</div><div class="stat-label">Low</div></div>
    <div class="stat-box"><div class="stat-value" style="color:var(--text2)">{r.severity_counts.info}</div><div class="stat-label">Info</div></div>
    <div class="stat-box"><div class="stat-value">{len(r.sources)}</div><div class="stat-label">Data Sources</div></div>
</div>

<!-- Data Sources -->
<h2>📦 Data Sources</h2>
<div class="card">
    {sources_html or '<div class="dim">No data sources loaded.</div>'}
</div>

<!-- Findings Table -->
<h2>🔍 Findings ({len(r.findings)})</h2>
<div class="card">
    {f'''<table>
        <thead><tr><th style="width:100px">Severity</th><th>Finding</th><th style="width:100px">Category</th><th style="width:140px">Source</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>''' if findings_rows else '<div class="dim">No findings detected. ✅</div>'}
    {'<div class="dim" style="margin-top:8px">Showing up to 200 findings.</div>' if len(r.findings) > 200 else ''}
</div>

<!-- APK Analysis Section -->
{apk_section}

<!-- IPA Analysis Section -->
{ipa_section}

<!-- OWASP Section -->
{owasp_section}

<!-- Obfuscation Section -->
{obfuscation_section}

<!-- Dynamic Analysis Section -->
{dynamic_section}

<!-- Traffic Analysis Section -->
{traffic_section}

<!-- Footer -->
<div class="card" style="text-align:center;margin-top:32px;">
    <div class="dim">
        Generated by <strong>MobileSentry v{r.mobilesentry_version}</strong> &middot;
        Mobile Application Security Testing Framework<br>
        <a href="https://github.com/Yash-Patil-1/mobilesentry" style="color:var(--accent);">github.com/Yash-Patil-1/mobilesentry</a>
    </div>
</div>

</div>

<script>
// Toggle collapsible sections
document.querySelectorAll('.card-header').forEach(header => {{
    header.addEventListener('click', () => {{
        const content = header.nextElementSibling;
        const icon = header.querySelector('.toggle-icon');
        content.classList.toggle('open');
        if (icon) icon.classList.toggle('open');
    }});
}});
</script>

</body>
</html>"""

    def _html_apk_section(self) -> str:
        data = self.report.raw_apk
        if not data:
            return ""
        info = data.get("apk_info", {})
        if not isinstance(info, dict):
            info = {}
        perm_count = len(data.get("permissions", []))
        comp_count = len(data.get("components", []))
        secret_count = len(data.get("secrets", []))
        issue_count = len(data.get("security_issues", []))

        # Permissions table
        perm_rows = ""
        for perm in data.get("permissions", []):
            if isinstance(perm, dict):
                sev = perm.get("severity", "normal")
                color, _ = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
                perm_rows += f"<tr><td>{_sanitize_html(perm.get('name', ''))}</td><td><span class='sev-badge' style='background:{color};color:white;'>{sev.upper()}</span></td></tr>"

        return f"""
<h2>🤖 APK Analysis</h2>
<div class="card">
    <div class="card-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <strong>APK Metadata &amp; Findings</strong>
        <span class="toggle-icon">▶</span>
    </div>
    <div class="card-content collapsible open">
        <table>
            <tr><td><strong>Package</strong></td><td>{_sanitize_html(info.get('package_name', 'N/A'))}</td></tr>
            <tr><td><strong>Version</strong></td><td>{_sanitize_html(info.get('version_name', ''))} ({_sanitize_html(str(info.get('version_code', '')))})</td></tr>
            <tr><td><strong>Min SDK</strong></td><td>{_sanitize_html(str(info.get('min_sdk', '')))}</td></tr>
            <tr><td><strong>Target SDK</strong></td><td>{_sanitize_html(str(info.get('target_sdk', '')))}</td></tr>
            <tr><td><strong>Size</strong></td><td>{info.get('file_size_kb', 0):.1f} KB</td></tr>
            <tr><td><strong>Debuggable</strong></td><td>{"⚠️ Yes" if info.get('debuggable') else "✅ No"}</td></tr>
            <tr><td><strong>Allow Backup</strong></td><td>{"⚠️ Enabled" if info.get('allow_backup') else "✅ Disabled"}</td></tr>
            <tr><td><strong>Network Security</strong></td><td>{"✅ Present" if info.get('has_network_security_config') else "⚠️ Missing"}</td></tr>
            <tr><td><strong>Signed</strong></td><td>{"✅ Yes" if info.get('is_signed') else "❌ No"}</td></tr>
        </table>
        <div class="dim" style="margin-top:12px">
            {perm_count} permissions &middot; {comp_count} components &middot;
            {secret_count} secrets &middot; {issue_count} security issues
        </div>
        {f'''<h3 style="margin-top:12px">Permissions</h3>
        <table><thead><tr><th>Permission</th><th>Severity</th></tr></thead><tbody>{perm_rows}</tbody></table>''' if perm_rows else ''}
    </div>
</div>"""

    def _html_ipa_section(self) -> str:
        data = self.report.raw_ipa
        if not data:
            return ""
        info = data.get("ipa_info", {})
        if not isinstance(info, dict):
            info = {}
        return f"""
<h2>🍎 IPA Analysis</h2>
<div class="card">
    <div class="card-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <strong>IPA Metadata &amp; Findings</strong>
        <span class="toggle-icon">▶</span>
    </div>
    <div class="card-content collapsible">
        <table>
            <tr><td><strong>Bundle ID</strong></td><td>{_sanitize_html(info.get('bundle_id', 'N/A'))}</td></tr>
            <tr><td><strong>Version</strong></td><td>{_sanitize_html(info.get('version', ''))} (build {_sanitize_html(str(info.get('build', '')))})</td></tr>
            <tr><td><strong>Min OS</strong></td><td>{_sanitize_html(str(info.get('min_os', '')))}</td></tr>
            <tr><td><strong>SDK</strong></td><td>{_sanitize_html(info.get('sdk_name', ''))}</td></tr>
            <tr><td><strong>Size</strong></td><td>{info.get('file_size_kb', 0):.1f} KB</td></tr>
        </table>
        <div class="dim" style="margin-top:12px">
            {len(data.get('permissions', []))} permissions &middot;
            {len(data.get('entitlements', []))} entitlements &middot;
            {len(data.get('sdks', []))} SDKs &middot;
            {len(data.get('secrets', []))} secrets &middot;
            {len(data.get('security_issues', []))} security issues
        </div>
    </div>
</div>"""

    def _html_obfuscation_section(self) -> str:
        data = self.report.raw_obfuscation
        if not data:
            return ""
        obs_score = data.get("obfuscation_score", 0)
        protected = data.get("obfuscated", False)
        status = "🛡️ Protected" if protected else "⚠️ Not Protected"
        status_color = "var(--green)" if protected else "var(--red)"

        findings_html = ""
        for finding in data.get("findings", []):
            if isinstance(finding, dict):
                sev = finding.get("severity", "info")
                color, _ = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
                icon = SEVERITY_ICONS.get(sev, "▪️")
                evidence_items = ""
                if finding.get("evidence"):
                    ev = "".join(f"<li>{_sanitize_html(e[:120])}</li>" for e in finding["evidence"][:5])
                    evidence_items = f"<ul class='evidence'>{ev}</ul>"
                findings_html += f"""
                <div style="margin:8px 0;padding:8px;background:var(--surface2);border-radius:4px;">
                    <span class="sev-badge" style="background:{color};color:white;">{icon} {finding.get('technique', 'Unknown')}</span>
                    <span style="font-size:0.85rem;color:var(--text2)"> — {_sanitize_html(finding.get('description', '')[:120])}</span>
                    {evidence_items}
                </div>"""

        return f"""
<h2>🛡️ Code Obfuscation</h2>
<div class="card">
    <div class="card-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <strong>Obfuscation Score: {obs_score}/100 &middot; <span style="color:{status_color}">{status}</span></strong>
        <span class="toggle-icon">▶</span>
    </div>
    <div class="card-content collapsible">
        <div class="dim">Platform: {data.get('platform', 'N/A')} &middot; Findings: {data.get('total_findings', 0)}</div>
        {findings_html or '<div class="dim" style="margin-top:8px">No obfuscation techniques detected.</div>'}
    </div>
</div>"""

    def _html_dynamic_section(self) -> str:
        data = self.report.raw_dynamic
        if not data:
            return ""
        events = data.get("total_events", 0)
        findings_count = data.get("total_findings", 0)
        etypes = data.get("events_by_type", {})
        etypes_str = ", ".join(f"{k}: {v}" for k, v in sorted(etypes.items(), key=lambda x: x[1], reverse=True)[:5]) if etypes else ""

        return f"""
<h2>⚡ Dynamic Analysis</h2>
<div class="card">
    <div class="card-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <strong>Runtime Behavior Analysis</strong>
        <span class="toggle-icon">▶</span>
    </div>
    <div class="card-content collapsible">
        <div class="dim">
            Events: {events} &middot; Findings: {findings_count}
            {f'&middot; Event types: {etypes_str}' if etypes_str else ''}
        </div>
    </div>
</div>"""

    def _html_traffic_section(self) -> str:
        data = self.report.raw_traffic
        if not data:
            return ""
        reqs = data.get("total_requests", 0)
        domains = data.get("total_domains", [])
        http_urls = data.get("http_urls", [])
        https_pct = ((reqs - len(http_urls)) / max(reqs, 1)) * 100

        domain_list = ""
        if domains:
            items = "".join(f"<li>{_sanitize_html(d)}</li>" for d in sorted(domains)[:10])
            domain_list = f"<ul class='evidence'>{items}</ul>"

        return f"""
<h2>🌐 Traffic Analysis</h2>
<div class="card">
    <div class="card-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <strong>Network Security Analysis</strong>
        <span class="toggle-icon">▶</span>
    </div>
    <div class="card-content collapsible">
        <div class="dim">
            Requests: {reqs} &middot; HTTPS: {https_pct:.1f}% &middot; Domains: {len(domains)} &middot; HTTP: {len(http_urls)}
        </div>
        {f'<h3 style="margin-top:8px">Domains</h3>{domain_list}' if domain_list else ''}
    </div>
</div>"""

    def _html_owasp_section(self) -> str:
        data = self.report.raw_owasp
        if not data:
            return ""
        score = data.get("overall_score", 0)
        risk = data.get("overall_risk", "info")
        color, _ = SEVERITY_COLORS.get(risk, SEVERITY_COLORS["info"])

        summaries = data.get("summaries", [])
        summary_rows = ""
        for s in summaries:
            if isinstance(s, dict):
                sev_color, _ = SEVERITY_COLORS.get(s.get("risk_label", "info"), SEVERITY_COLORS["info"])
                summary_rows += f"<tr><td>{_sanitize_html(s.get('category', ''))}</td><td>{s.get('total_findings', 0)}</td><td><span class='sev-badge' style='background:{sev_color};color:white;'>{s.get('risk_label', 'info').upper()}</span></td><td>{s.get('score', 0)}</td></tr>"

        return f"""
<h2>📋 OWASP Mobile Top 10</h2>
<div class="card">
    <div class="card-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <strong>OWASP Assessment &middot; Score: {score}/100 &middot; <span style="color:{color}">{risk.upper()}</span></strong>
        <span class="toggle-icon">▶</span>
    </div>
    <div class="card-content collapsible">
        <div class="dim">Findings: {data.get('total_findings', 0)} &middot; Platform: {_sanitize_html(str(data.get('platform', '')))}</div>
        {f'''<table style="margin-top:8px"><thead><tr><th>Category</th><th>Findings</th><th>Risk</th><th>Score</th></tr></thead><tbody>{summary_rows}</tbody></table>''' if summary_rows else ''}
    </div>
</div>"""

    # ══════════════════════════════════════════════
    # JSON Report Generation
    # ══════════════════════════════════════════════

    def generate_json(self) -> dict[str, Any]:
        """Generate a structured JSON report."""
        self._compute_overall()
        r = self.report
        return {
            "meta": {
                "generated_at": r.generated_at,
                "mobilesentry_version": r.mobilesentry_version,
                "app_name": r.app_name,
                "app_version": r.app_version,
                "platform": r.platform,
            },
            "overall": {
                "risk": r.overall_risk,
                "score": r.overall_score,
                "total_findings": r.severity_counts.total,
            },
            "severity_counts": {
                "critical": r.severity_counts.critical,
                "high": r.severity_counts.high,
                "medium": r.severity_counts.medium,
                "low": r.severity_counts.low,
                "info": r.severity_counts.info,
            },
            "sources": [
                {
                    "name": s.name,
                    "label": s.label,
                    "loaded": s.loaded,
                    "file_path": s.file_path,
                    "error": s.error,
                }
                for s in r.sources
            ],
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "category": f.category,
                    "source": f.source,
                    "recommendation": f.recommendation,
                    "file": f.file,
                    "line": f.line,
                    "evidence": f.evidence,
                    "cwe": f.cwe,
                    "platform": f.platform,
                }
                for f in r.findings
            ],
            "raw_data": {
                "apk": r.raw_apk or None,
                "ipa": r.raw_ipa or None,
                "owasp": r.raw_owasp or None,
                "obfuscation": r.raw_obfuscation or None,
                "dynamic": r.raw_dynamic or None,
                "traffic": r.raw_traffic or None,
                "tls": r.raw_tls or None,
            },
        }

    # ══════════════════════════════════════════════
    # Markdown Report Generation
    # ══════════════════════════════════════════════

    def generate_markdown(self) -> str:
        """Generate a Markdown report."""
        self._compute_overall()
        r = self.report

        lines = [
            "# 📱 MobileSentry Security Report",
            "",
            f"**App:** {r.app_name or 'Unknown'} — {r.app_version}",
            f"**Platform:** {r.platform.upper() if r.platform else 'N/A'}",
            f"**Generated:** {r.generated_at}",
            f"**Version:** v{r.mobilesentry_version}",
            "",
            "## Overall Assessment",
            "",
            f"- **Risk Level:** {r.overall_risk.upper()}",
            f"- **Security Score:** {r.overall_score}/100",
            f"- **Total Findings:** {r.severity_counts.total}",
            "",
            "### Severity Distribution",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {r.severity_counts.critical} |",
            f"| 🟠 High | {r.severity_counts.high} |",
            f"| 🟡 Medium | {r.severity_counts.medium} |",
            f"| 🔵 Low | {r.severity_counts.low} |",
            f"| ℹ️ Info | {r.severity_counts.info} |",
            "",
        ]

        # Data Sources
        if r.sources:
            lines.extend([
                "## Data Sources",
                "",
            ])
            for s in r.sources:
                status = "✅" if s.loaded else "❌"
                lines.append(f"- {status} **{s.label}**: {s.file_path or 'N/A'}{' (' + s.error + ')' if s.error else ''}")
            lines.append("")

        # Findings
        if r.findings:
            lines.extend([
                f"## Findings ({len(r.findings)})",
                "",
                "| # | Severity | Finding | Category | Source |",
                "|---|----------|---------|----------|--------|",
            ])
            for i, f in enumerate(r.findings[:200], 1):
                icon = SEVERITY_ICONS.get(f.severity.lower(), "▪️")
                short_desc = f.description[:80].replace("\n", " ")
                lines.append(f"| {i} | {icon} {f.severity.upper()} | {f.title} — {short_desc} | {f.category} | {f.source} |")
            if len(r.findings) > 200:
                lines.append(f"| ... | ... | *Showing 200 of {len(r.findings)} findings* | ... | ... |")
            lines.append("")

        # Raw data summaries
        if r.raw_apk:
            lines.extend(self._md_apk_summary())
        if r.raw_ipa:
            lines.extend(self._md_ipa_summary())
        if r.raw_obfuscation:
            lines.extend(self._md_obfuscation_summary())
        if r.raw_dynamic:
            lines.extend(self._md_dynamic_summary())
        if r.raw_traffic:
            lines.extend(self._md_traffic_summary())
        if r.raw_owasp:
            lines.extend(self._md_owasp_summary())

        lines.extend([
            "---",
            "",
            f"*Generated by MobileSentry v{r.mobilesentry_version}*",
            "",
        ])

        return "\n".join(lines)

    def _md_apk_summary(self) -> list[str]:
        data = self.report.raw_apk
        info = data.get("apk_info", {})
        if not isinstance(info, dict):
            info = {}
        return [
            "### APK Analysis",
            "",
            f"- Package: {info.get('package_name', 'N/A')}",
            f"- Version: {info.get('version_name', '')} ({info.get('version_code', '')})",
            f"- Min SDK: {info.get('min_sdk', 'N/A')}",
            f"- Target SDK: {info.get('target_sdk', 'N/A')}",
            f"- Size: {info.get('file_size_kb', 0):.1f} KB",
            f"- Debuggable: {'⚠️ Yes' if info.get('debuggable') else '✅ No'}",
            f"- Allow Backup: {'⚠️ Enabled' if info.get('allow_backup') else '✅ Disabled'}",
            "",
        ]

    def _md_ipa_summary(self) -> list[str]:
        data = self.report.raw_ipa
        info = data.get("ipa_info", {})
        if not isinstance(info, dict):
            info = {}
        return [
            "### IPA Analysis",
            "",
            f"- Bundle ID: {info.get('bundle_id', 'N/A')}",
            f"- Version: {info.get('version', '')} (build {info.get('build', '')})",
            f"- Min OS: {info.get('min_os', 'N/A')}",
            f"- SDK: {info.get('sdk_name', 'N/A')}",
            f"- Size: {info.get('file_size_kb', 0):.1f} KB",
            "",
        ]

    def _md_obfuscation_summary(self) -> list[str]:
        data = self.report.raw_obfuscation
        return [
            "### Code Obfuscation Detection",
            "",
            f"- Obfuscation Score: {data.get('obfuscation_score', 0)}/100",
            f"- Protected: {'✅ Yes' if data.get('obfuscated') else '⚠️ No'}",
            f"- Findings: {data.get('total_findings', 0)}",
            f"- Platform: {data.get('platform', 'N/A')}",
            "",
        ]

    def _md_dynamic_summary(self) -> list[str]:
        data = self.report.raw_dynamic
        return [
            "### Dynamic Analysis",
            "",
            f"- Events: {data.get('total_events', 0)}",
            f"- Findings: {data.get('total_findings', 0)}",
            f"- Duration: {data.get('duration_seconds', 0):.1f}s",
            "",
        ]

    def _md_traffic_summary(self) -> list[str]:
        data = self.report.raw_traffic
        reqs = data.get("total_requests", 0)
        http = len(data.get("http_urls", []))
        https_pct = ((reqs - http) / max(reqs, 1)) * 100
        return [
            "### Traffic Analysis",
            "",
            f"- Total Requests: {reqs}",
            f"- HTTPS: {https_pct:.1f}%",
            f"- Domains: {len(data.get('total_domains', []))}",
            f"- Findings: {data.get('total_findings', 0)}",
            "",
        ]

    def _md_owasp_summary(self) -> list[str]:
        data = self.report.raw_owasp
        return [
            "### OWASP Mobile Top 10",
            "",
            f"- Score: {data.get('overall_score', 0)}/100",
            f"- Risk: {data.get('overall_risk', 'info').upper()}",
            f"- Findings: {data.get('total_findings', 0)}",
            f"- Platform: {data.get('platform', 'N/A')}",
            "",
        ]

    # ══════════════════════════════════════════════
    # File Writers
    # ══════════════════════════════════════════════

    def write_html(self, output_path: str) -> str:
        """Generate and write HTML report to a file. Returns the path."""
        html = self.generate_html()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html)
        return str(path)

    def write_json(self, output_path: str) -> str:
        """Generate and write JSON report to a file. Returns the path."""
        data = self.generate_json()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    def write_markdown(self, output_path: str) -> str:
        """Generate and write Markdown report to a file. Returns the path."""
        md = self.generate_markdown()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md)
        return str(path)
