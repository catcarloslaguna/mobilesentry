"""Static Analysis Engine — OWASP Mobile Top 10 (2024) automated checks.

Consumes results from both the APK Analyzer (Phase 1) and IPA Analyzer (Phase 2)
to produce structured vulnerability findings mapped to the OWASP Mobile Top 10.

Usage:
    from mobilesentry.static_analyzer import analyze, AnalysisContext

    # From APK analysis
    result = analyze(AnalysisContext.from_apk(apk_result))

    # From IPA analysis
    result = analyze(AnalysisContext.from_ipa(ipa_result))

    # Print findings
    for finding in result.findings:
        print(f"[{finding.category}] {finding.title}")
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mobilesentry.apk_analyzer import (
        ApkAnalysisResult,
    )
    from mobilesentry.ipa_analyzer import (
        IpaAnalysisResult,
    )

# ──────────────────────────────────────────────
# OWASP Mobile Top 10 — Categories
# ──────────────────────────────────────────────


class OwaspCategory(str, enum.Enum):
    """OWASP Mobile Top 10 (2024) categories."""

    M1_IMPROPER_CREDENTIAL_USAGE = "M1"
    M2_INADEQUATE_SUPPLY_CHAIN = "M2"
    M3_INSECURE_AUTH = "M3"
    M4_INSUFFICIENT_INPUT_VALIDATION = "M4"
    M5_INSECURE_COMMUNICATION = "M5"
    M6_INADEQUATE_PRIVACY = "M6"
    M7_INSUFFICIENT_BINARY_PROTECTION = "M7"
    M8_SECURITY_MISCONFIGURATION = "M8"
    M9_INSECURE_DATA_STORAGE = "M9"
    M10_INSUFFICIENT_CRYPTOGRAPHY = "M10"

    @property
    def category_title(self) -> str:
        titles = {
            "M1": "Improper Credential Usage",
            "M2": "Inadequate Supply Chain Security",
            "M3": "Insecure Authentication / Authorization",
            "M4": "Insufficient Input / Output Validation",
            "M5": "Insecure Communication",
            "M6": "Inadequate Privacy Controls",
            "M7": "Insufficient Binary Protections",
            "M8": "Security Misconfiguration",
            "M9": "Insecure Data Storage",
            "M10": "Insufficient Cryptography",
        }
        return titles.get(self.value, self.value)

    @property
    def category_description(self) -> str:
        descs = {
            "M1": "The app handles credentials (passwords, tokens, keys) in ways that expose them to unauthorized access, including hardcoding, weak storage, or transmission over insecure channels.",
            "M2": "The app uses third-party libraries, frameworks, or SDKs that may contain vulnerabilities, are outdated, or introduce supply chain risks.",
            "M3": "The app implements authentication or authorization mechanisms that can be bypassed, including weak session management, missing MFA, or insecure token handling.",
            "M4": "The app fails to properly validate input from external sources (intents, deep links, URL schemes, file providers), leading to injection or unauthorized access.",
            "M5": "The app communicates over insecure channels, disables transport security protections, or fails to validate server certificates.",
            "M6": "The app collects or processes personal data without adequate consent, transparency, or user control, or collects more data than necessary.",
            "M7": "The app lacks binary-level protections, including code obfuscation, anti-tampering, stack canaries, PIE, ARC, or FairPlay encryption.",
            "M8": "The app is misconfigured for production, including debug flags, backup settings, insecure component exports, or development-only features.",
            "M9": "The app stores sensitive data (credentials, tokens, PII) on the device in ways that can be accessed by other apps or attackers with physical access.",
            "M10": "The app uses weak or deprecated cryptographic algorithms, manages keys insecurely, or relies on custom cryptography.",
        }
        return descs.get(self.value, "")


# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────


@dataclass
class OwaspFinding:
    """A single OWASP Mobile Top 10 finding with evidence and remediation."""

    title: str
    description: str
    category: OwaspCategory
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    recommendation: str
    cwe: str = ""  # CWE identifier, e.g. "CWE-312"
    owasp_link: str = ""
    evidence: list[str] = field(default_factory=list)  # Specific evidence strings
    platform: str = ""  # "android", "ios", "both"

    @property
    def score(self) -> int:
        """Return a numeric severity score for sorting (higher = more severe)."""
        scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return scores.get(self.severity, 0)


@dataclass
class OwaspSummary:
    """Summary of OWASP analysis findings by category."""

    category: OwaspCategory
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    score: int = 0  # 0-10 risk score for this category

    @property
    def risk_label(self) -> str:
        if self.score >= 8:
            return "critical"
        if self.score >= 5:
            return "high"
        if self.score >= 3:
            return "medium"
        if self.score >= 1:
            return "low"
        return "info"


@dataclass
class StaticAnalysisResult:
    """Complete result from an OWASP Mobile Top 10 static analysis run."""

    platform: str = ""  # "android", "ios", "both"
    findings: list[OwaspFinding] = field(default_factory=list)
    summaries: list[OwaspSummary] = field(default_factory=list)
    overall_score: int = 0
    overall_risk: str = "info"
    analysis_time_ms: int = 0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[OwaspFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[OwaspFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium_findings(self) -> list[OwaspFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def low_findings(self) -> list[OwaspFinding]:
        return [f for f in self.findings if f.severity == "low"]

    def get_findings_by_category(self, category: OwaspCategory) -> list[OwaspFinding]:
        return [f for f in self.findings if f.category == category]


# ──────────────────────────────────────────────
# Analysis Context
# ──────────────────────────────────────────────


@dataclass
class AnalysisContext:
    """Unified context wrapping APK and/or IPA analysis data for OWASP checks."""

    # Platform identification
    platform: str = ""  # "android", "ios", "both"

    # Android-specific data
    apk_info: Any = None  # ApkInfo
    apk_permissions: list = field(default_factory=list)  # list[PermissionInfo]
    apk_components: list = field(default_factory=list)  # list[ComponentInfo]
    apk_secrets: list = field(default_factory=list)  # list[SecretFinding]
    apk_security_issues: list = field(default_factory=list)  # list[SecurityIssue]
    apk_has_native_code: bool = False
    apk_has_obfuscation: bool = False
    apk_decompiled: bool = False
    apk_statistics: dict = field(default_factory=dict)  # Extra stats

    # iOS-specific data
    ipa_info: Any = None  # IpaInfo
    ipa_permissions: list = field(default_factory=list)  # list[IosPermission]
    ipa_entitlements: list = field(default_factory=list)  # list[EntitlementInfo]
    ipa_binary_info: Any = None  # BinaryInfo
    ipa_sdks: list = field(default_factory=list)  # list[SdkFinding]
    ipa_url_schemes: list = field(default_factory=list)  # list[UrlScheme]
    ipa_secrets: list = field(default_factory=list)  # list[SecretFinding]
    ipa_security_issues: list = field(default_factory=list)  # list[SecurityIssue]
    ipa_statistics: dict = field(default_factory=dict)

    @classmethod
    def from_apk(cls, result: ApkAnalysisResult) -> AnalysisContext:
        """Create an AnalysisContext from an ApkAnalysisResult."""
        ctx = cls(platform="android")
        ctx.apk_info = result.apk_info
        ctx.apk_permissions = result.permissions
        ctx.apk_components = result.components
        ctx.apk_secrets = result.secrets
        ctx.apk_security_issues = result.security_issues
        ctx.apk_has_native_code = result.has_native_code
        ctx.apk_has_obfuscation = result.has_obfuscation
        ctx.apk_decompiled = result.decompiled
        ctx.apk_statistics = {
            "package_name": result.apk_info.package_name,
            "version_name": result.apk_info.version_name,
            "min_sdk": result.apk_info.min_sdk,
            "target_sdk": result.apk_info.target_sdk,
            "debuggable": result.apk_info.debuggable,
            "allow_backup": result.apk_info.allow_backup,
        }
        return ctx

    @classmethod
    def from_ipa(cls, result: IpaAnalysisResult) -> AnalysisContext:
        """Create an AnalysisContext from an IpaAnalysisResult."""
        ctx = cls(platform="ios")
        ctx.ipa_info = result.ipa_info
        ctx.ipa_permissions = result.permissions
        ctx.ipa_entitlements = result.entitlements
        ctx.ipa_binary_info = result.binary_info
        ctx.ipa_sdks = result.sdks
        ctx.ipa_url_schemes = result.url_schemes
        ctx.ipa_secrets = result.secrets
        ctx.ipa_security_issues = result.security_issues
        ctx.ipa_statistics = {
            "bundle_id": result.ipa_info.bundle_id,
            "version": result.ipa_info.version,
            "min_os": result.ipa_info.min_os,
        }
        return ctx

    @classmethod
    def from_both(cls, apk_result: ApkAnalysisResult, ipa_result: IpaAnalysisResult) -> AnalysisContext:
        """Create an AnalysisContext from both APK and IPA results."""
        ctx = cls(platform="both")
        # Load both
        apk_ctx = cls.from_apk(apk_result)
        ipa_ctx = cls.from_ipa(ipa_result)
        for field_name in apk_ctx.__dataclass_fields__:
            if field_name != "platform":
                setattr(ctx, field_name, getattr(apk_ctx if field_name.startswith("apk_") else ipa_ctx, field_name))
        return ctx

    @property
    def is_android(self) -> bool:
        return self.platform in ("android", "both")

    @property
    def is_ios(self) -> bool:
        return self.platform in ("ios", "both")


# ══════════════════════════════════════════════
# OWASP Mobile Top 10 — Individual Checks
# ══════════════════════════════════════════════


def _check_m1_credential_usage(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M1: Improper Credential Usage — hardcoded secrets, weak credential storage."""
    findings: list[OwaspFinding] = []

    # Collect all secrets from both platforms
    all_secrets: list = []
    if ctx.is_android:
        all_secrets.extend(getattr(ctx, "apk_secrets", []))
    if ctx.is_ios:
        all_secrets.extend(getattr(ctx, "ipa_secrets", []))

    # Group secrets by severity
    critical_secrets = [s for s in all_secrets if getattr(s, "severity", "") == "critical"]
    high_secrets = [s for s in all_secrets if getattr(s, "severity", "") == "high"]
    total_secrets = len(all_secrets)

    if critical_secrets:
        evidence = [f"{s.secret_type}: {s.value}" for s in critical_secrets[:10]]
        if len(critical_secrets) > 10:
            evidence.append(f"... and {len(critical_secrets) - 10} more critical secrets")
        findings.append(
            OwaspFinding(
                title=f"Hardcoded Critical Credentials ({len(critical_secrets)} found)",
                description=f"The app contains {len(critical_secrets)} hardcoded critical secrets (passwords, tokens, private keys, JWTs). Hardcoded credentials can be extracted via static analysis and reused by attackers to access backend systems or impersonate users.",
                category=OwaspCategory.M1_IMPROPER_CREDENTIAL_USAGE,
                severity="critical",
                confidence="high",
                cwe="CWE-798",
                recommendation="Remove all hardcoded credentials from source code. Use a secrets management solution (e.g., Android Keystore, iOS Keychain, or a remote configuration service) to inject credentials at build time or runtime.",
                evidence=evidence,
                platform=ctx.platform,
            )
        )

    if high_secrets:
        findings.append(
            OwaspFinding(
                title=f"High-Risk Credentials in Source ({len(high_secrets)} found)",
                description=f"The app contains {len(high_secrets)} high-severity hardcoded credentials including API keys, tokens, and secrets. These could allow unauthorized access to third-party services.",
                category=OwaspCategory.M1_IMPROPER_CREDENTIAL_USAGE,
                severity="high",
                confidence="high",
                cwe="CWE-798",
                recommendation="Move all API keys and tokens to server-side proxy endpoints or use runtime credential injection. Never embed keys in client-side source code or version control.",
                evidence=[f"{s.secret_type}: {s.value}" for s in high_secrets[:5]],
                platform=ctx.platform,
            )
        )

    if total_secrets > 0 and not critical_secrets and not high_secrets:
        findings.append(
            OwaspFinding(
                title=f"Credentials Detected ({total_secrets} total)",
                description=f"The app contains {total_secrets} potential credential or secret references in source code. While none are critical severity, they should still be reviewed and removed.",
                category=OwaspCategory.M1_IMPROPER_CREDENTIAL_USAGE,
                severity="medium",
                confidence="medium",
                cwe="CWE-200",
                recommendation="Review each detected secret reference. Use a secrets scanning tool in CI/CD to prevent credentials from being committed.",
                platform=ctx.platform,
            )
        )

    return findings


def _check_m2_supply_chain(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M2: Inadequate Supply Chain Security — risky SDKs, frameworks, libraries."""
    findings: list[OwaspFinding] = []

    if ctx.is_ios:
        sdks = getattr(ctx, "ipa_sdks", [])
        if not sdks:
            return findings

        # Identify high-risk SDKs
        high_risk_sdks = [s for s in sdks if getattr(s, "risk", "") == "high"]
        medium_risk_sdks = [s for s in sdks if getattr(s, "risk", "") == "medium"]

        if high_risk_sdks:
            findings.append(
                OwaspFinding(
                    title=f"High-Risk Third-Party SDKs ({len(high_risk_sdks)})",
                    description=f"The app includes {len(high_risk_sdks)} third-party SDKs rated as high risk: {', '.join(s.name for s in high_risk_sdks)}. These SDKs may collect sensitive data, introduce attack surface, or have compliance implications.",
                    category=OwaspCategory.M2_INADEQUATE_SUPPLY_CHAIN,
                    severity="high",
                    confidence="high",
                    cwe="CWE-1104",
                    recommendation="Review the privacy and security posture of each high-risk SDK. Consider alternatives with better security practices. Ensure all SDKs are updated to latest versions.",
                    evidence=[f"{s.name} ({s.type_}) — risk: {s.risk}" for s in high_risk_sdks],
                    platform="ios",
                )
            )

        if medium_risk_sdks:
            findings.append(
                OwaspFinding(
                    title=f"Third-Party SDK Audit ({len(medium_risk_sdks)} medium-risk)",
                    description=f"The app includes {len(medium_risk_sdks)} third-party SDKs with medium risk: {', '.join(s.name for s in medium_risk_sdks)}. These SDKs may have data collection practices or vulnerabilities worth reviewing.",
                    category=OwaspCategory.M2_INADEQUATE_SUPPLY_CHAIN,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-1104",
                    recommendation="Maintain an inventory of all third-party dependencies. Enable automatic dependency updates. Review each SDK's data handling practices.",
                    evidence=[f"{s.name} ({s.type_})" for s in medium_risk_sdks[:8]],
                    platform="ios",
                )
            )

        cross_platform_sdks = [s for s in sdks if getattr(s, "type_", "") == "cross_platform"]
        if cross_platform_sdks:
            findings.append(
                OwaspFinding(
                    title=f"Cross-Platform Framework Detected ({cross_platform_sdks[0].name})",
                    description=f"The app uses {cross_platform_sdks[0].name}, a cross-platform framework. These frameworks can introduce platform-specific security issues and may not fully leverage native security features.",
                    category=OwaspCategory.M2_INADEQUATE_SUPPLY_CHAIN,
                    severity="low",
                    confidence="medium",
                    recommendation="Ensure the cross-platform framework is configured securely for each target platform. Review framework-specific security best practices and known vulnerabilities.",
                    platform="ios",
                )
            )

    # Android supply chain checks
    if ctx.is_android:
        has_native = getattr(ctx, "apk_has_native_code", False)
        if has_native:
            findings.append(
                OwaspFinding(
                    title="Native Code Libraries Detected",
                    description="The APK contains native (.so) libraries. Native code is harder to audit and may introduce memory corruption vulnerabilities like buffer overflows, use-after-free, and format string bugs.",
                    category=OwaspCategory.M2_INADEQUATE_SUPPLY_CHAIN,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-119",
                    recommendation="Audit all native libraries for known vulnerabilities. Use AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) during testing. Keep native dependencies updated.",
                    platform="android",
                )
            )

    return findings


def _check_m3_insecure_auth(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M3: Insecure Authentication / Authorization."""
    findings: list[OwaspFinding] = []

    # Android checks
    if ctx.is_android:
        apk_info = getattr(ctx, "apk_info", None)
        if apk_info and getattr(apk_info, "debuggable", False):
            findings.append(
                OwaspFinding(
                    title="Debuggable Application",
                    description="The app is debuggable, which means an attacker can attach a debugger to bypass authentication checks, modify runtime behavior, and extract session tokens or credentials from memory.",
                    category=OwaspCategory.M3_INSECURE_AUTH,
                    severity="high",
                    confidence="high",
                    cwe="CWE-489",
                    recommendation="Disable debugging for release builds. Use build variants (debug vs release) to automatically manage the debuggable flag.",
                    evidence=[f"android:debuggable=true in {getattr(apk_info, 'package_name', 'unknown')}"],
                    platform="android",
                )
            )

        # Check exported auth-related components
        components = getattr(ctx, "apk_components", [])
        auth_keywords = ["login", "auth", "signin", "signin", "token", "session", "password"]
        exported_auth = [c for c in components if getattr(c, "exported", False) and any(kw in getattr(c, "name", "").lower() for kw in auth_keywords)]
        if exported_auth:
            findings.append(
                OwaspFinding(
                    title=f"Exported Authentication Components ({len(exported_auth)})",
                    description=f"The app exports {len(exported_auth)} components with authentication-related names (login, auth, token, etc.). Exported components can be invoked by any app on the device, potentially bypassing authentication flows.",
                    category=OwaspCategory.M3_INSECURE_AUTH,
                    severity="high",
                    confidence="high",
                    cwe="CWE-287",
                    recommendation="Set exported=false on authentication-related components. If they must be exported, implement permission checks and verify caller identity.",
                    evidence=[f"{getattr(c, 'component_type', '?')}: {getattr(c, 'name', '?')}" for c in exported_auth[:5]],
                    platform="android",
                )
            )

    # iOS checks
    if ctx.is_ios:
        # Check for risky entitlements that weaken auth
        entitlements = getattr(ctx, "ipa_entitlements", [])
        risky_debug = [e for e in entitlements if getattr(e, "key", "") == "get-task-allow"]
        if risky_debug:
            findings.append(
                OwaspFinding(
                    title="Development Entitlement (get-task-allow) Present",
                    description="The app includes the get-task-allow entitlement, which allows debugger attachment. This should never be present in production builds as it enables authentication bypass via runtime manipulation.",
                    category=OwaspCategory.M3_INSECURE_AUTH,
                    severity="high",
                    confidence="high",
                    cwe="CWE-489",
                    recommendation="Remove get-task-allow from release builds. Use separate provisioning profiles for development and distribution.",
                    platform="ios",
                )
            )

        # URL schemes could be used for auth callbacks
        schemes = getattr(ctx, "ipa_url_schemes", [])
        auth_schemes = [s for s in schemes if "auth" in getattr(s, "name", "").lower() or "token" in getattr(s, "name", "").lower()]
        if auth_schemes:
            findings.append(
                OwaspFinding(
                    title=f"Authentication URL Scheme ({auth_schemes[0].name})",
                    description=f"The app registers a custom URL scheme '{auth_schemes[0].name}' that could be used for OAuth/SSO callbacks. Custom URL schemes can be intercepted by any app on iOS, potentially leading to token theft.",
                    category=OwaspCategory.M3_INSECURE_AUTH,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-287",
                    recommendation="Use Universal Links (iOS 9+) or Associated Domains instead of custom URL schemes for authentication callbacks. Validate the source of all incoming URLs.",
                    evidence=[f"URL Scheme: {auth_schemes[0].name}"],
                    platform="ios",
                )
            )

    return findings


def _check_m4_input_validation(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M4: Insufficient Input/Output Validation — exported components, deep links, intent injection."""
    findings: list[OwaspFinding] = []

    # Android checks
    if ctx.is_android:
        components = getattr(ctx, "apk_components", [])

        # Exported components without intent filters = direct invocation risk
        exported_no_filter = [c for c in components if getattr(c, "exported", False) and not getattr(c, "has_intent_filters", False) and not getattr(c, "permissions", "")]

        if exported_no_filter:
            findings.append(
                OwaspFinding(
                    title=f"Unprotected Exported Components ({len(exported_no_filter)})",
                    description=f"The app has {len(exported_no_filter)} exported components without intent filters or permission guards. Any app on the device can directly invoke these components with arbitrary intents, potentially triggering injection attacks or unauthorized actions.",
                    category=OwaspCategory.M4_INSUFFICIENT_INPUT_VALIDATION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-20",
                    recommendation="Set exported=false for internal components. For components that must be exported, add permission checks and validate all intent extras and actions. Use Android's pending intent immutability where applicable.",
                    evidence=[f"{getattr(c, 'component_type', '?')}: {getattr(c, 'name', '?')}" for c in exported_no_filter[:8]],
                    platform="android",
                )
            )

        # Content providers especially risky
        providers = [c for c in components if getattr(c, "component_type", "") == "provider" and getattr(c, "exported", False)]
        if providers:
            findings.append(
                OwaspFinding(
                    title=f"Exported Content Providers ({len(providers)})",
                    description=f"The app exports {len(providers)} content providers. Exported content providers can be queried by any app on the device, potentially exposing app-internal data including databases, shared preferences, and files.",
                    category=OwaspCategory.M4_INSUFFICIENT_INPUT_VALIDATION,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-200",
                    recommendation="Set exported=false on content providers that are only used internally. For exported providers, implement URI permissions and validate all incoming URIs.",
                    evidence=[f"Provider: {getattr(c, 'name', '?')}" for c in providers[:5]],
                    platform="android",
                )
            )

    # iOS checks — URL schemes as attack surface
    if ctx.is_ios:
        schemes = getattr(ctx, "ipa_url_schemes", [])
        if schemes:
            findings.append(
                OwaspFinding(
                    title=f"Custom URL Schemes ({len(schemes)} registered)",
                    description=f"The app registers {len(schemes)} custom URL schemes (e.g., {schemes[0].name}). Any app can invoke these schemes and pass arbitrary URLs. Insufficient validation can lead to command injection or unauthorized actions.",
                    category=OwaspCategory.M4_INSUFFICIENT_INPUT_VALIDATION,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-20",
                    recommendation="Validate all incoming URL scheme parameters rigorously. Use Universal Links (iOS 9+) instead of custom schemes where possible. Avoid exposing functionality through URL schemes that could bypass authentication.",
                    evidence=[s.name for s in schemes],
                    platform="ios",
                )
            )

        # Check for risky entitlements that allow code injection
        entitlements = getattr(ctx, "ipa_entitlements", [])
        risky_load = [e for e in entitlements if "disable-library-validation" in getattr(e, "key", "")]
        if risky_load:
            findings.append(
                OwaspFinding(
                    title="Arbitrary Library Loading Allowed",
                    description="The entitlement com.apple.security.cs.disable-library-validation allows loading arbitrary frameworks and libraries. This bypasses code signing validation and allows an attacker to inject malicious code via library hijacking.",
                    category=OwaspCategory.M4_INSUFFICIENT_INPUT_VALIDATION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-114",
                    recommendation="Remove this entitlement for release builds. If dynamic library loading is required, validate library paths and use code signing checks.",
                    platform="ios",
                )
            )

    return findings


def _check_m5_insecure_communication(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M5: Insecure Communication — cleartext traffic, ATS, SSL pinning."""
    findings: list[OwaspFinding] = []

    # Android checks
    if ctx.is_android:
        apk_info = getattr(ctx, "apk_info", None)
        if apk_info and not getattr(apk_info, "has_network_security_config", False):
            findings.append(
                OwaspFinding(
                    title="Missing Network Security Configuration",
                    description="The app does not declare an android:networkSecurityConfig. Without explicit configuration, cleartext HTTP traffic may be permitted depending on the Android version. This exposes sensitive data to man-in-the-middle attacks.",
                    category=OwaspCategory.M5_INSECURE_COMMUNICATION,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-319",
                    recommendation="Add a network_security_config.xml that pins certificates, restricts cleartext traffic (usesCleartextTraffic=false), and defines trusted Certificate Authorities.",
                    evidence=[f"Package: {getattr(apk_info, 'package_name', 'unknown')}"],
                    platform="android",
                )
            )

        # Check for low target SDK (cleartext allowed by default before API 28)
        try:
            target_sdk = int(getattr(apk_info, "target_sdk", 0)) if apk_info else 0
        except (ValueError, TypeError):
            target_sdk = 0
        if 0 < target_sdk < 28:
            findings.append(
                OwaspFinding(
                    title=f"Cleartext Traffic May Be Allowed (targetSdk={target_sdk})",
                    description=f"The app targets API {target_sdk}, which is below Android 9 (API 28). On these versions, cleartext HTTP traffic is allowed by default, exposing data to interception.",
                    category=OwaspCategory.M5_INSECURE_COMMUNICATION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-319",
                    recommendation="Increase targetSdkVersion to at least 28 (Android 9) and set usesCleartextTraffic=false in the network security configuration.",
                    evidence=[f"targetSdkVersion={target_sdk}"],
                    platform="android",
                )
            )

    # iOS checks
    if ctx.is_ios:
        # ATS check is already done in ipa_analyzer, but we map to OWASP here
        ipa_security = getattr(ctx, "ipa_security_issues", [])
        ats_issues = [i for i in ipa_security if "NSAllowsArbitraryLoads" in getattr(i, "title", "")]
        if ats_issues:
            findings.append(
                OwaspFinding(
                    title="App Transport Security Disabled (NSAllowsArbitraryLoads)",
                    description="The app disables App Transport Security (ATS), allowing unencrypted HTTP connections. All network traffic is vulnerable to man-in-the-middle attacks.",
                    category=OwaspCategory.M5_INSECURE_COMMUNICATION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-319",
                    recommendation="Remove NSAllowsArbitraryLoads or restrict it to specific trusted domains using NSExceptionDomains. Use HTTPS exclusively for all network communications.",
                    platform="ios",
                )
            )

        # Check for insecure HTTP exceptions
        http_exception_issues = [i for i in ipa_security if "Insecure HTTP" in getattr(i, "title", "")]
        if http_exception_issues:
            findings.append(
                OwaspFinding(
                    title="Insecure HTTP Exceptions Configured",
                    description="The app allows cleartext HTTP connections to specific domains via NSExceptionAllowsInsecureHTTPLoads. These connections are vulnerable to interception and tampering.",
                    category=OwaspCategory.M5_INSECURE_COMMUNICATION,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-319",
                    recommendation="Migrate all HTTP endpoints to HTTPS. If HTTPS is not available, consider the security implications and limit to specific necessary domains.",
                    platform="ios",
                )
            )

    return findings


def _check_m6_privacy(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M6: Inadequate Privacy Controls — excessive permissions, data collection."""
    findings: list[OwaspFinding] = []

    # Android privacy checks
    if ctx.is_android:
        permissions = getattr(ctx, "apk_permissions", [])
        dangerous = [p for p in permissions if getattr(p, "severity", "") == "dangerous"]

        if len(dangerous) > 8:
            findings.append(
                OwaspFinding(
                    title=f"Excessive Dangerous Permissions ({len(dangerous)})",
                    description=f"The app requests {len(dangerous)} dangerous permissions, which is well above average. Excessive permissions increase the privacy attack surface and may violate the principle of least privilege.",
                    category=OwaspCategory.M6_INADEQUATE_PRIVACY,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-272",
                    recommendation="Review each dangerous permission critically. Remove permissions not essential to core app functionality. Request permissions at runtime (Android 6.0+) with clear justification.",
                    evidence=[getattr(p, "name", "") for p in dangerous[:10]],
                    platform="android",
                )
            )

        # Check for specific sensitive permissions
        sensitive_perms = {
            "android.permission.CAMERA": "Camera access allows capturing photos/video without user awareness",
            "android.permission.RECORD_AUDIO": "Microphone access allows recording audio conversations",
            "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location tracking",
            "android.permission.ACCESS_BACKGROUND_LOCATION": "Location tracking even when app is in background",
            "android.permission.READ_CONTACTS": "Access to user's contact database",
            "android.permission.READ_CALL_LOG": "Access to call history and phone numbers",
            "android.permission.READ_SMS": "Access to SMS messages and potentially 2FA codes",
        }
        perm_names = {getattr(p, "name", "") for p in dangerous}
        sensitive_found = [(key, desc) for key, desc in sensitive_perms.items() if key in perm_names]
        if len(sensitive_found) >= 3:
            findings.append(
                OwaspFinding(
                    title=f"Sensitive Privacy Permissions ({len(sensitive_found)})",
                    description=f"The app requests {len(sensitive_found)} highly sensitive permissions including: {', '.join(k.split('.')[-1] for k, _ in sensitive_found)}. Each of these permissions grants access to significant personal data.",
                    category=OwaspCategory.M6_INADEQUATE_PRIVACY,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-359",
                    recommendation="Implement runtime permission requests with clear user-facing justifications. Provide privacy settings to let users opt out of non-essential data collection.",
                    evidence=[f"{k.split('.')[-1]}: {desc}" for k, desc in sensitive_found],
                    platform="android",
                )
            )

    # iOS privacy checks
    if ctx.is_ios:
        permissions = getattr(ctx, "ipa_permissions", [])
        high_risk_perms = [p for p in permissions if getattr(p, "severity", "") == "high"]

        if len(high_risk_perms) >= 4:
            findings.append(
                OwaspFinding(
                    title=f"High-Risk iOS Permissions ({len(high_risk_perms)})",
                    description=f"The app requests {len(high_risk_perms)} high-risk iOS permissions: {', '.join(getattr(p, 'key', '') for p in high_risk_perms)}. High-risk permissions include camera, microphone, location, contacts, health, and tracking.",
                    category=OwaspCategory.M6_INADEQUATE_PRIVACY,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-359",
                    recommendation="Ensure each high-risk permission has a corresponding purpose string in Info.plist that clearly explains why the permission is needed. Implement Privacy Nutrition Labels (required since iOS 14).",
                    evidence=[f"{getattr(p, 'key', '')}: {getattr(p, 'purpose', '')[:50]}" for p in high_risk_perms],
                    platform="ios",
                )
            )

        # Check for NSUserTrackingUsageDescription (App Tracking Transparency)
        tracking_perms = [p for p in permissions if getattr(p, "key", "") == "UserTracking"]
        if tracking_perms:
            findings.append(
                OwaspFinding(
                    title="App Tracking Transparency Requested",
                    description="The app requests user tracking permission (NSUserTrackingUsageDescription). The app may share user data with third parties for tracking purposes across apps and websites.",
                    category=OwaspCategory.M6_INADEQUATE_PRIVACY,
                    severity="low",
                    confidence="medium",
                    cwe="CWE-359",
                    recommendation="Only request tracking if essential to app functionality. Provide clear disclosure of how tracking data is used and shared. Respect user choice if they opt out via ATT.",
                    platform="ios",
                )
            )

    return findings


def _check_m7_binary_protection(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M7: Insufficient Binary Protections — PIE, ARC, stack canary, obfuscation, encryption."""
    findings: list[OwaspFinding] = []

    # Android checks
    if ctx.is_android:
        has_obfuscation = getattr(ctx, "apk_has_obfuscation", False)
        if not has_obfuscation:
            findings.append(
                OwaspFinding(
                    title="No Code Obfuscation Detected",
                    description="The app does not appear to use ProGuard/R8 code obfuscation. Without obfuscation, the app's Java/Kotlin code can be easily decompiled and reverse engineered, exposing business logic and API structures.",
                    category=OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-656",
                    recommendation="Enable ProGuard or R8 minification and obfuscation in the release build configuration. Configure comprehensive obfuscation rules to protect sensitive code paths.",
                    platform="android",
                )
            )

        decompiled = getattr(ctx, "apk_decompiled", False)
        if decompiled:
            findings.append(
                OwaspFinding(
                    title="APK Decompilable (apktool)",
                    description="The APK was successfully decompiled to smali using apktool. This means the app's resources, manifest, and bytecode are easily accessible for analysis and tampering without any anti-tampering protections.",
                    category=OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-656",
                    recommendation="Implement anti-tampering checks (e.g., APK signature verification at runtime, integrity checks on DEX files, certificate pinning validation).",
                    platform="android",
                )
            )

    # iOS checks
    if ctx.is_ios:
        binfo = getattr(ctx, "ipa_binary_info", None)
        if not binfo:
            return findings

        missing_pie = not getattr(binfo, "is_pie", True) and bool(getattr(binfo, "architectures", []))
        if missing_pie:
            findings.append(
                OwaspFinding(
                    title="Position Independent Executable (PIE) Not Enabled",
                    description="The binary is not position-independent, making it significantly more vulnerable to ROP (Return-Oriented Programming) attacks and memory corruption exploits.",
                    category=OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-695",
                    recommendation='Enable PIE in Xcode build settings. Add "-fPIE" and "-pie" flags to the linker. (Enabled by default since Xcode 4.6.)',
                    platform="ios",
                )
            )

        missing_canary = not getattr(binfo, "has_stack_canary", True) and bool(getattr(binfo, "architectures", []))
        if missing_canary:
            findings.append(
                OwaspFinding(
                    title="Stack Canary Not Enabled",
                    description="Stack canaries (buffer overflow protection) were not detected in the binary. This makes the app highly vulnerable to stack buffer overflow attacks that can lead to arbitrary code execution.",
                    category=OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-693",
                    recommendation='Enable stack canaries in Xcode: add "-fstack-protector-all" to Other C Flags in build settings.',
                    platform="ios",
                )
            )

        missing_arc = not getattr(binfo, "has_arc", True) and bool(getattr(binfo, "architectures", []))
        if missing_arc:
            findings.append(
                OwaspFinding(
                    title="Automatic Reference Counting (ARC) Not Enabled",
                    description="ARC (Automatic Reference Counting) was not detected in the binary. Without ARC, the app is more susceptible to memory corruption vulnerabilities including use-after-free, double-free, and retain-release bugs.",
                    category=OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-693",
                    recommendation="Enable ARC in Xcode project settings (CLANG_ENABLE_OBJC_ARC = YES). ARC is enabled by default for new projects.",
                    platform="ios",
                )
            )

        # Check encryption status only if check was performed
        encryption_performed = getattr(binfo, "encryption_check_performed", False)
        if encryption_performed and not getattr(binfo, "is_encrypted", True):
            findings.append(
                OwaspFinding(
                    title="Binary Not FairPlay Encrypted",
                    description="The binary does not appear to be FairPlay encrypted (cryptid=0). App Store builds should be encrypted to prevent static analysis and binary tampering. An unencrypted binary can be disassembled and patched.",
                    category=OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-656",
                    recommendation="Ensure the app is distributed through the App Store, which applies FairPlay encryption automatically. For enterprise builds, consider additional obfuscation and integrity checks.",
                    platform="ios",
                )
            )

    return findings


def _check_m8_misconfiguration(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M8: Security Misconfiguration — debug flags, backup, exported components."""
    findings: list[OwaspFinding] = []

    # Android checks
    if ctx.is_android:
        apk_info = getattr(ctx, "apk_info", None)

        if apk_info:
            debuggable = getattr(apk_info, "debuggable", False)
            if debuggable:
                findings.append(
                    OwaspFinding(
                        title="Production Build is Debuggable",
                        description="The APK is compiled with android:debuggable=true. Debug builds should never be distributed as they allow debugger attachment, increase attack surface, and often expose sensitive logging.",
                        category=OwaspCategory.M8_SECURITY_MISCONFIGURATION,
                        severity="high",
                        confidence="high",
                        cwe="CWE-489",
                        recommendation="Ensure release builds have debuggable=false. Use Gradle build variants to automatically manage this: debuggable=true for debug, false for release.",
                        platform="android",
                    )
                )

            backup = getattr(apk_info, "allow_backup", True)
            if backup:
                findings.append(
                    OwaspFinding(
                        title="Backup Enabled (allowBackup)",
                        description="The app has android:allowBackup=true (or default), which allows full ADB backup. An attacker with USB access can extract all app data including shared preferences, databases, and files.",
                        category=OwaspCategory.M8_SECURITY_MISCONFIGURATION,
                        severity="medium",
                        confidence="high",
                        cwe="CWE-200",
                        recommendation='Set android:allowBackup="false" or configure a custom backup rule via android:fullBackupContent that excludes sensitive data.',
                        platform="android",
                    )
                )

    # iOS checks
    if ctx.is_ios:
        ipa_security = getattr(ctx, "ipa_security_issues", [])
        file_sharing = [i for i in ipa_security if "File Sharing" in getattr(i, "title", "")]
        if file_sharing:
            findings.append(
                OwaspFinding(
                    title="iTunes File Sharing Enabled",
                    description="The app enables UIFileSharingEnabled, making its Documents directory accessible via USB. Sensitive data stored in the Documents directory can be exfiltrated by anyone with physical access to the device.",
                    category=OwaspCategory.M8_SECURITY_MISCONFIGURATION,
                    severity="medium",
                    confidence="high",
                    cwe="CWE-200",
                    recommendation="Set UIFileSharingEnabled to NO (false) in Info.plist unless file sharing is a core feature. Store sensitive data in the Keychain or NSLibraryDirectory with NSFileProtectionComplete.",
                    platform="ios",
                )
            )

        # Risky entitlements as misconfigurations
        entitlements = getattr(ctx, "ipa_entitlements", [])
        risky_ents = [e for e in entitlements if getattr(e, "is_risky", False)]
        if risky_ents:
            risky_keys = [getattr(e, "key", "") for e in risky_ents]
            findings.append(
                OwaspFinding(
                    title=f"Risky Entitlements Configured ({len(risky_ents)})",
                    description=f"The app includes {len(risky_ents)} entitlements that increase attack surface: {', '.join(risky_keys[:5])}. These entitlements may allow debugger attachment, library injection, or unsigned code execution.",
                    category=OwaspCategory.M8_SECURITY_MISCONFIGURATION,
                    severity="high",
                    confidence="high",
                    cwe="CWE-16",
                    recommendation="Review each entitlement and remove those not essential for production. Use separate entitlements files for development and distribution builds.",
                    evidence=risky_keys,
                    platform="ios",
                )
            )

    return findings


def _check_m9_insecure_storage(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M9: Insecure Data Storage — backup, file sharing, local data exposure."""
    findings: list[OwaspFinding] = []

    # Android checks
    if ctx.is_android:
        apk_info = getattr(ctx, "apk_info", None)

        if apk_info:
            backup = getattr(apk_info, "allow_backup", True)
            if backup:
                findings.append(
                    OwaspFinding(
                        title="Sensitive Data Vulnerable to Backup Extraction",
                        description="With allowBackup enabled, an attacker with USB debugging access can use 'adb backup' to extract all app data, including databases, shared preferences, cached tokens, and files from internal storage.",
                        category=OwaspCategory.M9_INSECURE_DATA_STORAGE,
                        severity="high",
                        confidence="high",
                        cwe="CWE-312",
                        recommendation='Set android:allowBackup="false" for release builds. If backup is required, implement android:fullBackupContent with a rule that excludes sensitive files and databases. Encrypt sensitive data before storing it on disk.',
                        platform="android",
                    )
                )

        # Check for secrets that indicate insecure storage
        secrets = getattr(ctx, "apk_secrets", [])
        storage_relevant = [
            s for s in secrets if getattr(s, "secret_type", "") in ("Password / Passphrase", "Private Key (PEM)", "Hardcoded Certificate", "SQL Connection String", "MongoDB Connection String")
        ]
        if storage_relevant:
            findings.append(
                OwaspFinding(
                    title=f"Sensitive Data Stored Insecurely ({len(storage_relevant)} findings)",
                    description=f"The app contains {len(storage_relevant)} instances of sensitive data (passwords, keys, connection strings) stored in plaintext within the APK. These can be extracted via static analysis and used to access backend systems.",
                    category=OwaspCategory.M9_INSECURE_DATA_STORAGE,
                    severity="critical",
                    confidence="high",
                    cwe="CWE-312",
                    recommendation="Use the Android Keystore system to securely store cryptographic keys. Store secrets server-side and retrieve them at runtime via authenticated API calls. Never store passwords or API keys in shared preferences, SQLite databases, or configuration files.",
                    evidence=[f"{getattr(s, 'secret_type', '?')}: {getattr(s, 'value', '')[:50]}" for s in storage_relevant[:5]],
                    platform="android",
                )
            )

    # iOS checks
    if ctx.is_ios:
        ipa_info = getattr(ctx, "ipa_info", None)

        # File sharing = data exposure
        ipa_security = getattr(ctx, "ipa_security_issues", [])
        file_sharing = [i for i in ipa_security if "File Sharing" in getattr(i, "title", "")]
        if file_sharing:
            findings.append(
                OwaspFinding(
                    title="Documents Directory Accessible via USB",
                    description="UIFileSharingEnabled allows apps to expose their Documents directory through iTunes. Any sensitive files in this directory — including cached responses, downloaded documents, or user data — can be exfiltrated via USB connection.",
                    category=OwaspCategory.M9_INSECURE_DATA_STORAGE,
                    severity="high",
                    confidence="high",
                    cwe="CWE-312",
                    recommendation="Disable UIFileSharingEnabled unless file sharing is required. Store sensitive data in the Keychain or NSLibraryDirectory with NSFileProtectionComplete encryption level.",
                    platform="ios",
                )
            )

        # Check Keychain accessibility (entitlements related)
        entitlements = getattr(ctx, "ipa_entitlements", [])
        if not entitlements:
            findings.append(
                OwaspFinding(
                    title="No Entitlements Found — Keychain Usage Uncertain",
                    description="The app does not have detectable entitlements, which may indicate it does not use the iOS Keychain for secure credential storage. Without Keychain, sensitive data may be stored insecurely (UserDefaults, flat files, Core Data without encryption).",
                    category=OwaspCategory.M9_INSECURE_DATA_STORAGE,
                    severity="medium",
                    confidence="low",
                    cwe="CWE-312",
                    recommendation="Use the iOS Keychain for all sensitive data. Set appropriate kSecAttrAccessible protection levels (e.g., kSecAttrAccessibleWhenUnlockedThisDeviceOnly). Avoid storing credentials in UserDefaults or plaintext files.",
                    platform="ios",
                )
            )

        # Check for unprotected data protection
        if ipa_info:
            min_os = str(getattr(ipa_info, "min_os", ""))
            if min_os and "NSFileProtectionComplete" not in str(ipa_security):
                findings.append(
                    OwaspFinding(
                        title="Data Protection Class Not Enforced",
                        description=f"The app targets iOS {min_os} but does not appear to enforce NSFileProtectionComplete for sensitive files. Without file-level encryption, data written to disk may be accessible if the device is lost or stolen.",
                        category=OwaspCategory.M9_INSECURE_DATA_STORAGE,
                        severity="medium",
                        confidence="medium",
                        cwe="CWE-312",
                        recommendation="Set NSFileProtectionComplete on all files containing sensitive data. Use the Keychain for credentials. Enable complete protection in the Capabilities section of your Xcode project.",
                        platform="ios",
                    )
                )

    return findings


def _check_m10_cryptography(ctx: AnalysisContext) -> list[OwaspFinding]:
    """M10: Insufficient Cryptography — weak crypto, hardcoded certs, custom implementations."""
    findings: list[OwaspFinding] = []

    # Collect all secrets and issues from both platforms
    all_secrets: list = []
    if ctx.is_android:
        all_secrets.extend(getattr(ctx, "apk_secrets", []))
    if ctx.is_ios:
        all_secrets.extend(getattr(ctx, "ipa_secrets", []))

    # Check for hardcoded certificates and keys
    certs_and_keys = [s for s in all_secrets if getattr(s, "secret_type", "") in ("Hardcoded Certificate", "Private Key (PEM)", "P12/PFX Certificate")]
    if certs_and_keys:
        findings.append(
            OwaspFinding(
                title=f"Hardcoded Certificates/Keys ({len(certs_and_keys)} found)",
                description=f"The app embeds {len(certs_and_keys)} hardcoded certificates and private keys. Embedded certificates can be extracted and used for man-in-the-middle attacks if private keys are included, or for unauthorized service access.",
                category=OwaspCategory.M10_INSUFFICIENT_CRYPTOGRAPHY,
                severity="high",
                confidence="high",
                cwe="CWE-321",
                recommendation="Do not embed certificates with private keys in app bundles. Use certificate pinning correctly. Store cryptographic keys in hardware-backed keystores (Android Keystore, iOS Secure Enclave).",
                evidence=[f"{getattr(s, 'secret_type', '?')}: {getattr(s, 'file', '')}" for s in certs_and_keys[:5]],
                platform=ctx.platform,
            )
        )

    # Android-specific crypto checks
    if ctx.is_android:
        apk_info = getattr(ctx, "apk_info", None)
        if apk_info:
            try:
                min_sdk = int(getattr(apk_info, "min_sdk", 0))
            except (ValueError, TypeError):
                min_sdk = 0
            if 0 < min_sdk < 23:
                findings.append(
                    OwaspFinding(
                        title=f"Weak Crypto Support (minSdk={min_sdk} < API 23)",
                        description=f"The app supports Android API {min_sdk}, which lacks modern cryptographic APIs like the Android Keystore (introduced in API 18, but no proper key attestation until API 28). Older platforms lack hardware-backed key storage and modern cipher suites.",
                        category=OwaspCategory.M10_INSUFFICIENT_CRYPTOGRAPHY,
                        severity="medium",
                        confidence="high",
                        cwe="CWE-327",
                        recommendation="Increase minSdkVersion to at least 23 (Android 6.0) for proper Keystore support. Use the Android Keystore for key generation and storage. Avoid using deprecated crypto algorithms (DES, RC4, MD5, SHA1 for signatures).",
                        platform="android",
                    )
                )

    # iOS-specific crypto checks
    if ctx.is_ios:
        binfo = getattr(ctx, "ipa_binary_info", None)
        if binfo and getattr(binfo, "encryption_check_performed", False) and not getattr(binfo, "is_encrypted", True):
            findings.append(
                OwaspFinding(
                    title="Missing FairPlay Encryption",
                    description="The binary lacks FairPlay encryption (cryptid=0), which is Apple's application-level encryption. Without it, the binary can be disassembled and analyzed statically to extract cryptographic algorithms and keys.",
                    category=OwaspCategory.M10_INSUFFICIENT_CRYPTOGRAPHY,
                    severity="medium",
                    confidence="medium",
                    cwe="CWE-656",
                    recommendation="Ensure the app is distributed through the App Store for automatic FairPlay encryption. Consider adding runtime encryption verification checks as an additional layer.",
                    platform="ios",
                )
            )

    # Check for base64-encoded data (potential crypto misuse)
    base64_secrets = [s for s in all_secrets if getattr(s, "secret_type", "") == "Base64-Encoded Key (suspicious)"]
    if len(base64_secrets) > 5:
        findings.append(
            OwaspFinding(
                title=f"Suspicious Encoded Data ({len(base64_secrets)} base64 findings)",
                description=f"The app contains {len(base64_secrets)} instances of base64-encoded data that may represent obfuscated credentials, tokens, or cryptographic material. Base64 is encoding, not encryption, and provides no actual security.",
                category=OwaspCategory.M10_INSUFFICIENT_CRYPTOGRAPHY,
                severity="low",
                confidence="low",
                cwe="CWE-327",
                recommendation="Use proper cryptographic operations instead of simple encoding for sensitive data. Use Android Keystore / iOS Keychain for storing credentials. Never rely on base64 encoding alone for data protection.",
                platform=ctx.platform,
            )
        )

    # Check for hardcoded JWT tokens (potential crypto misuse)
    jwt_secrets = [s for s in all_secrets if getattr(s, "secret_type", "") == "JWT / OAuth Token"]
    if jwt_secrets:
        findings.append(
            OwaspFinding(
                title=f"Hardcoded Authentication Tokens ({len(jwt_secrets)} JWT/OAuth)",
                description=f"The app contains {len(jwt_secrets)} hardcoded JSON Web Tokens (JWT) or OAuth tokens. These tokens can grant persistent unauthorized access to backend services. Embedding tokens violates the principle of secure token management.",
                category=OwaspCategory.M10_INSUFFICIENT_CRYPTOGRAPHY,
                severity="critical",
                confidence="high",
                cwe="CWE-798",
                recommendation="Remove hardcoded tokens and implement proper OAuth 2.0 token exchange flows. Store refresh tokens in the Android Keystore or iOS Keychain with biometric protection when available.",
                evidence=[f"Token prefix: {getattr(s, 'value', '')[:30]}..." for s in jwt_secrets[:3]],
                platform=ctx.platform,
            )
        )

    return findings


# ══════════════════════════════════════════════
# Orchestrator
# ══════════════════════════════════════════════


OWASP_CHECKS: list[tuple[str, Callable[..., list[OwaspFinding]]]] = [
    ("M1: Improper Credential Usage", _check_m1_credential_usage),
    ("M2: Inadequate Supply Chain Security", _check_m2_supply_chain),
    ("M3: Insecure Authentication / Authorization", _check_m3_insecure_auth),
    ("M4: Insufficient Input / Output Validation", _check_m4_input_validation),
    ("M5: Insecure Communication", _check_m5_insecure_communication),
    ("M6: Inadequate Privacy Controls", _check_m6_privacy),
    ("M7: Insufficient Binary Protections", _check_m7_binary_protection),
    ("M8: Security Misconfiguration", _check_m8_misconfiguration),
    ("M9: Insecure Data Storage", _check_m9_insecure_storage),
    ("M10: Insufficient Cryptography", _check_m10_cryptography),
]


def _run_single_check(
    check_fn: Callable[..., list[OwaspFinding]],
    name: str,
    ctx: AnalysisContext,
) -> list[OwaspFinding]:
    """Run a single OWASP check with error isolation."""
    try:
        return check_fn(ctx)
    except Exception as exc:
        return [
            OwaspFinding(
                title=f"Check failed: {name}",
                description=f"An error occurred while running this OWASP check: {exc!s}",
                category=_category_from_name(name),
                severity="info",
                confidence="low",
                recommendation="Review the check implementation. This is a tool issue, not an app vulnerability.",
                platform=ctx.platform,
            )
        ]


def analyze(ctx: AnalysisContext) -> StaticAnalysisResult:
    """Run all OWASP Mobile Top 10 checks against an AnalysisContext.

    Args:
        ctx: Unified context with APK and/or IPA analysis data.

    Returns:
        StaticAnalysisResult with all findings, summaries, and overall score.
    """
    import time

    start = time.time()
    result = StaticAnalysisResult(platform=ctx.platform)
    all_findings: list[OwaspFinding] = []

    # Run each OWASP check
    for name, check_fn in OWASP_CHECKS:
        all_findings.extend(_run_single_check(check_fn, name, ctx))

    result.findings = all_findings

    # Build category summaries
    for cat in OwaspCategory:
        cat_findings = [f for f in all_findings if f.category == cat]
        if not cat_findings:
            continue
        summary = OwaspSummary(category=cat, total_findings=len(cat_findings))
        for f in cat_findings:
            if f.severity == "critical":
                summary.critical_count += 1
            elif f.severity == "high":
                summary.high_count += 1
            elif f.severity == "medium":
                summary.medium_count += 1
            elif f.severity == "low":
                summary.low_count += 1
        # Calculate category score (0-10)
        summary.score = min(10, summary.critical_count * 4 + summary.high_count * 2 + summary.medium_count * 1)
        result.summaries.append(summary)

    # Calculate overall score
    total_score = sum(s.score for s in result.summaries)
    max_score = len(OwaspCategory) * 10
    result.overall_score = min(100, round((total_score / max_score) * 100)) if max_score > 0 else 0

    # Overall risk label
    if result.overall_score >= 70:
        result.overall_risk = "critical"
    elif result.overall_score >= 45:
        result.overall_risk = "high"
    elif result.overall_score >= 20:
        result.overall_risk = "medium"
    elif result.overall_score >= 5:
        result.overall_risk = "low"
    else:
        result.overall_risk = "info"

    result.analysis_time_ms = int((time.time() - start) * 1000)
    return result


def _category_from_name(name: str) -> OwaspCategory:
    """Map a check name back to an OwaspCategory."""
    mapping = {
        "M1": OwaspCategory.M1_IMPROPER_CREDENTIAL_USAGE,
        "M2": OwaspCategory.M2_INADEQUATE_SUPPLY_CHAIN,
        "M3": OwaspCategory.M3_INSECURE_AUTH,
        "M4": OwaspCategory.M4_INSUFFICIENT_INPUT_VALIDATION,
        "M5": OwaspCategory.M5_INSECURE_COMMUNICATION,
        "M6": OwaspCategory.M6_INADEQUATE_PRIVACY,
        "M7": OwaspCategory.M7_INSUFFICIENT_BINARY_PROTECTION,
        "M8": OwaspCategory.M8_SECURITY_MISCONFIGURATION,
        "M9": OwaspCategory.M9_INSECURE_DATA_STORAGE,
        "M10": OwaspCategory.M10_INSUFFICIENT_CRYPTOGRAPHY,
    }
    for prefix, cat in mapping.items():
        if name.startswith(prefix):
            return cat
    return OwaspCategory.M8_SECURITY_MISCONFIGURATION


# ──────────────────────────────────────────────
# JSON Serialization
# ──────────────────────────────────────────────


def format_owasp_result(result: StaticAnalysisResult) -> dict:
    """Format OWASP analysis result into a serializable dict.

    Args:
        result: The StaticAnalysisResult to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    return {
        "platform": result.platform,
        "analysis_time_ms": result.analysis_time_ms,
        "overall_score": result.overall_score,
        "overall_risk": result.overall_risk,
        "total_findings": result.total_findings,
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "category": f.category.value,
                "category_title": f.category.category_title,
                "severity": f.severity,
                "confidence": f.confidence,
                "recommendation": f.recommendation,
                "cwe": f.cwe,
                "evidence": f.evidence,
                "platform": f.platform,
            }
            for f in result.findings
        ],
        "summaries": [
            {
                "category": s.category.value,
                "category_title": s.category.category_title,
                "total_findings": s.total_findings,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
                "medium_count": s.medium_count,
                "low_count": s.low_count,
                "score": s.score,
                "risk_label": s.risk_label,
            }
            for s in result.summaries
        ],
    }
