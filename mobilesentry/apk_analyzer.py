"""APK Analyzer — Android application analysis module.

Supports:
- Manifest parsing (package, version, SDK, debuggable, backup, etc.)
- Permission extraction with severity classification
- Component enumeration (activities, services, receivers, providers) with export status
- Security misconfiguration checks
- Hardcoded secrets detection via regex on decompiled source
- APK file structure listing
- Comprehensive JSON + Rich terminal output
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────


@dataclass
class ApkInfo:
    """Basic APK metadata from AndroidManifest.xml."""

    package_name: str = ""
    version_code: str = ""
    version_name: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    has_network_security_config: bool = False
    is_signed: bool = False
    signature_name: str = ""
    file_size_kb: float = 0.0


@dataclass
class ComponentInfo:
    """An Android component (activity, service, receiver, provider)."""

    name: str
    component_type: str
    exported: bool
    has_intent_filters: bool
    permissions: str = ""


@dataclass
class PermissionInfo:
    """A declared permission with severity classification."""

    name: str
    severity: str  # dangerous, normal, signature, unknown


@dataclass
class SecretFinding:
    """A hardcoded secret discovered in decompiled source."""

    secret_type: str
    value: str
    file: str
    line: int
    severity: str  # critical, high, medium, low


@dataclass
class SecurityIssue:
    """A security misconfiguration or concern."""

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    recommendation: str = ""


@dataclass
class ApkAnalysisResult:
    """Complete result from an APK analysis run."""

    apk_path: str
    apk_info: ApkInfo = field(default_factory=ApkInfo)
    permissions: list[PermissionInfo] = field(default_factory=list)
    components: list[ComponentInfo] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    security_issues: list[SecurityIssue] = field(default_factory=list)
    file_count: int = 0
    dex_count: int = 0
    has_native_code: bool = False
    has_obfuscation: bool = False
    decompiled: bool = False
    decompile_path: str = ""
    error: str = ""
    analysis_time_ms: int = 0


# ──────────────────────────────────────────────
# Permission Severity Mapping
# ──────────────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    # Calendar
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # Camera
    "android.permission.CAMERA",
    # Contacts
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    # Microphone
    "android.permission.RECORD_AUDIO",
    # Phone
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_PHONE_NUMBERS",
    # SMS
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.SMS_FINANCIAL_TRANSACTIONS",
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    # Bluetooth
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    # Body sensors
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    # Activity recognition
    "android.permission.ACTIVITY_RECOGNITION",
    # Nearby devices
    "android.permission.NEARBY_WIFI_DEVICES",
    # Notifications
    "android.permission.POST_NOTIFICATIONS",
}

SIGNATURE_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}

# ──────────────────────────────────────────────
# Hardcoded Secrets Regex Patterns
# ──────────────────────────────────────────────

SECRETS_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Access Key", r"(?i)aws[_-]?(secret|access)[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']", "critical"),
    ("Google API / Firebase Key", r"AIza[0-9A-Za-z_-]{35}", "high"),
    ("Firebase Database URL", r"https://[a-zA-Z0-9-]+\.firebaseio\.com", "medium"),
    ("Firebase Project ID", r"(?i)firebase[_-]?project[_-]?\w*\s*[:=]\s*[\"'][a-zA-Z0-9-]+[\"']", "medium"),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,50}[\"']", "high"),
    ("Password / Passphrase", r"(?i)(password|passwd|pwd|passphrase)\s*[:=]\s*[\"'][^\"']{4,100}[\"']", "critical"),
    ("Secret / Token", r"(?i)(secret|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{8,}[\"']", "high"),
    ("JWT / OAuth Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "critical"),
    ("Private Key (PEM)", r"-----BEGIN\s*(RSA|DSA|EC|OPENSSH|PRIVATE)\s*KEY-----", "critical"),
    ("Slack Token", r"xox[baprsr]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}", "critical"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}", "critical"),
    ("GitHub OAuth / Fine-Grained", r"github[_-]?(pat|token|key|secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']", "high"),
    ("Heroku API Key", r"(?i)heroku[a-z_]*\s*[:=]\s*[\"'][A-Za-z0-9\-]{20,}[\"']", "high"),
    ("NPM / npmrc Token", r"(?i)_auth\s*[:=]\s*[\"'][A-Za-z0-9+/=]{20,}[\"']", "high"),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high"),
    ("Twitter / X API Key", r"(?i)(twitter|x)[_-]?(api|consumer)[_-]?(key|secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']", "high"),
    ("SQL Connection String", r"(?i)(jdbc|mysql|postgresql|mssql|sqlite):[^\s'\"]{10,}", "critical"),
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s'\"]{10,}", "critical"),
    ("Redis Connection String", r"redis://[^\s'\"]{10,}", "high"),
    ("Generic Connection String", r"(?i)(connection[_-]?string|conn[_-]?string)\s*[:=]\s*[\"'][^\"]{10,}[\"']", "high"),
    ("Hardcoded Certificate", r"-----BEGIN\s+CERTIFICATE-----", "medium"),
    ("OAuth Client Secret", r"(?i)(client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']", "critical"),
    ("Base64-Encoded Key (suspicious)", r"[A-Za-z0-9+/]{40,}={0,2}", "low"),
]

# ──────────────────────────────────────────────
# Security Check Helpers
# ──────────────────────────────────────────────


def _classify_permission(perm: str) -> str:
    """Classify a permission by severity level."""
    if perm in DANGEROUS_PERMISSIONS:
        return "dangerous"
    if perm in SIGNATURE_PERMISSIONS:
        return "signature"
    if perm.startswith("android.permission."):
        known_normal = {
            "ACCESS_NETWORK_STATE",
            "ACCESS_WIFI_STATE",
            "CHANGE_NETWORK_STATE",
            "CHANGE_WIFI_STATE",
            "CHANGE_WIFI_MULTICAST_STATE",
            "INTERNET",
            "ACCESS_LOCATION_EXTRA_COMMANDS",
            "ACCESS_NOTIFICATION_POLICY",
            "ACCESS_MEDIA_LOCATION",
            "BATTERY_STATS",
            "BLUETOOTH",
            "BROADCAST_STICKY",
            "EXPAND_STATUS_BAR",
            "FLASHLIGHT",
            "FOREGROUND_SERVICE",
            "FOREGROUND_SERVICE_DATA_SYNC",
            "FOREGROUND_SERVICE_MEDIA_PLAYBACK",
            "FOREGROUND_SERVICE_LOCATION",
            "FOREGROUND_SERVICE_CONNECTED_DEVICE",
            "FOREGROUND_SERVICE_CAMERA",
            "FOREGROUND_SERVICE_MICROPHONE",
            "GET_PACKAGE_SIZE",
            "KILL_BACKGROUND_PROCESSES",
            "MANAGE_OWN_CALLS",
            "MODIFY_AUDIO_SETTINGS",
            "NFC",
            "NFC_TRANSACTION_EVENT",
            "QUERY_ALL_PACKAGES",
            "READ_SYNC_SETTINGS",
            "RECEIVE_BOOT_COMPLETED",
            "REORDER_TASKS",
            "REQUEST_COMPANION_RUN_IN_BACKGROUND",
            "REQUEST_COMPANION_SELF_MANAGED",
            "REQUEST_COMPANION_START_FOREGROUND_SERVICES_GRANT",
            "REQUEST_COMPANION_USE_DATA_IN_BACKGROUND",
            "REQUEST_DELETE_PACKAGES",
            "REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE",
            "SET_ALARM",
            "SET_WALLPAPER",
            "SET_WALLPAPER_HINTS",
            "TRANSMIT_IR",
            "UNINSTALL_SHORTCUT",
            "USE_BIOMETRIC",
            "USE_FINGERPRINT",
            "USE_FULL_SCREEN_INTENT",
            "VIBRATE",
            "WAKE_LOCK",
            "WRITE_SYNC_SETTINGS",
        }
        perm_name = perm.split(".")[-1]
        if perm_name in known_normal:
            return "normal"
        return "unknown"
    if perm.startswith(("com.", "org.", "io.")):
        return "custom"
    return "unknown"


def _check_debuggable(apk_info: ApkInfo) -> SecurityIssue | None:
    """Check if the app is debuggable."""
    if apk_info.debuggable:
        return SecurityIssue(
            title="App is Debuggable",
            description=('The AndroidManifest.xml declares `android:debuggable="true"`. Debug builds expose the app to debugger attachment, allowing runtime code injection and data inspection.'),
            severity="high",
            recommendation='Set `android:debuggable="false"` in the <application> tag for release builds. Use build variants (debug/release) to manage this flag automatically.',
        )
    return None


def _check_allow_backup(apk_info: ApkInfo) -> SecurityIssue | None:
    """Check if allowBackup is enabled."""
    if apk_info.allow_backup:
        return SecurityIssue(
            title="Backup Enabled (allowBackup)",
            description=('The app allows full ADB backups via `android:allowBackup="true"`. Attackers with USB access can exfiltrate app data including shared preferences, databases, and files.'),
            severity="medium",
            recommendation='Set `android:allowBackup="false"` or use `android:fullBackupContent` with a restrictive backup rules XML file.',
        )
    return None


def _check_network_security(apk_info: ApkInfo) -> SecurityIssue | None:
    """Check network security config."""
    if not apk_info.has_network_security_config:
        return SecurityIssue(
            title="No Network Security Configuration",
            description=(
                "The app does not declare a `android:networkSecurityConfig`. "
                "Without explicit configuration, the app relies on platform defaults, "
                "which may allow cleartext traffic (HTTP) on older Android versions."
            ),
            severity="low",
            recommendation="Add a `network_security_config.xml` that pins certificates and "
            "restricts cleartext traffic. Reference it via "
            '`android:networkSecurityConfig="@xml/network_security_config"`.',
        )
    return None


def _check_exported_components(components: list[ComponentInfo]) -> list[SecurityIssue]:
    """Check for unnecessarily exported components."""
    return [
        SecurityIssue(
            title=f"Exported Component: {comp.name.split('.')[-1]}",
            description=f"The {comp.component_type} `{comp.name}` is exported without intent filters or permission guards. Any app on the device can launch this component.",
            severity="medium",
            recommendation=f'Set `android:exported="false"` on this {comp.component_type} if it is only used internally, or add a custom permission via `android:permission`.',
        )
        for comp in components
        if comp.exported and not comp.has_intent_filters and not comp.permissions
    ]


def _check_min_sdk(apk_info: ApkInfo) -> SecurityIssue | None:
    """Check if minSdkVersion is too low."""
    try:
        min_sdk = int(apk_info.min_sdk) if apk_info.min_sdk else 0
    except ValueError:
        return None
    if 0 < min_sdk < 21:
        return SecurityIssue(
            title=f"Low minSdkVersion ({min_sdk})",
            description=(
                f"The app targets Android API {min_sdk} as minimum, which is "
                f"below Android 5.0 (API 21). Older platforms lack security "
                f"features like ART runtime improvements, multi-user support, "
                f"and SELinux enforcement."
            ),
            severity="medium",
            recommendation="Set `minSdkVersion` to at least 21 (Android 5.0) or ideally 26 (Android 8.0) for modern security features.",
        )
    if 21 <= min_sdk < 26:
        return SecurityIssue(
            title=f"Moderate minSdkVersion ({min_sdk})",
            description=(f"The app targets API {min_sdk}. Consider raising to at least API 26 (Android 8.0) for better security defaults."),
            severity="low",
            recommendation="Set `minSdkVersion` to at least 26 (Android 8.0) for automatic runtime permission management and improved security.",
        )
    return None


def _check_excessive_permissions(permissions: list[PermissionInfo]) -> list[SecurityIssue]:
    """Flag excessive or unusual permission combinations."""
    issues: list[SecurityIssue] = []
    dangerous = [p for p in permissions if p.severity == "dangerous"]
    dangerous_names = {p.name for p in dangerous}

    if len(dangerous) > 10:
        issues.append(
            SecurityIssue(
                title=f"Excessive Permissions ({len(dangerous)} dangerous)",
                description=(f"The app requests {len(dangerous)} dangerous permissions. Each dangerous permission should be justified and used only for core functionality."),
                severity="medium",
                recommendation="Review each dangerous permission and remove any that are not essential to the app's core functionality. Follow the principle of least privilege.",
            )
        )

    # Check for sensitive combinations
    sensitive_combo = {
        ("android.permission.CAMERA", "android.permission.RECORD_AUDIO"): "Camera + Microphone",
        ("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"): "Fine Location + Background Location",
        ("android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG"): "Contacts + Call Log",
        ("android.permission.READ_SMS", "android.permission.SEND_SMS"): "Read + Send SMS",
    }
    for (perm1, perm2), label in sensitive_combo.items():
        if perm1 in dangerous_names and perm2 in dangerous_names:
            issues.append(
                SecurityIssue(
                    title=f"Sensitive Permission Combo: {label}",
                    description=(f"The app requests both `{perm1.split('.')[-1]}` and `{perm2.split('.')[-1]}`. This combination enables powerful surveillance capabilities."),
                    severity="low",
                    recommendation="Ensure both permissions are truly needed and follow runtime permission best practices.",
                )
            )

    return issues


# ──────────────────────────────────────────────
# Core Analysis Functions
# ──────────────────────────────────────────────


def _parse_manifest_xml(manifest_str: str) -> tuple[ApkInfo, list[PermissionInfo], list[ComponentInfo], list[SecurityIssue]]:
    """Parse AndroidManifest.xml string into structured data."""
    root = ET.fromstring(manifest_str)

    apk_info = ApkInfo()
    permissions: list[PermissionInfo] = []
    components: list[ComponentInfo] = []
    security_issues: list[SecurityIssue] = []

    # ── Package & version info ──
    apk_info.package_name = root.get("package", "")
    apk_info.version_code = root.get("{http://schemas.android.com/apk/res/android}versionCode", "")
    apk_info.version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "")

    # ── Application tag ──
    app_tag = root.find("application")
    if app_tag is not None:
        debuggable_str = app_tag.get("{http://schemas.android.com/apk/res/android}debuggable", "false")
        apk_info.debuggable = debuggable_str.lower() == "true"
        backup_str = app_tag.get("{http://schemas.android.com/apk/res/android}allowBackup", "true")
        apk_info.allow_backup = backup_str.lower() != "false"
        ns_config = app_tag.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig", "")
        apk_info.has_network_security_config = bool(ns_config)

    # ── SDK versions from <uses-sdk> ──
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        apk_info.min_sdk = uses_sdk.get("{http://schemas.android.com/apk/res/android}minSdkVersion", "")
        apk_info.target_sdk = uses_sdk.get("{http://schemas.android.com/apk/res/android}targetSdkVersion", "")
        apk_info.max_sdk = uses_sdk.get("{http://schemas.android.com/apk/res/android}maxSdkVersion", "")

    # ── Permissions ──
    for perm_elem in root.findall("uses-permission"):
        perm_name = perm_elem.get("{http://schemas.android.com/apk/res/android}name", "")
        if perm_name:
            severity = _classify_permission(perm_name)
            permissions.append(PermissionInfo(name=perm_name, severity=severity))

    # ── Components ──
    if app_tag is not None:
        for comp_type in ("activity", "service", "receiver", "provider"):
            for comp_elem in app_tag.findall(comp_type):
                comp_name = comp_elem.get("{http://schemas.android.com/apk/res/android}name", "")
                if not comp_name:
                    continue
                exported_str = comp_elem.get("{http://schemas.android.com/apk/res/android}exported", "")
                has_intent = comp_elem.find("intent-filter") is not None
                # Default export status: true if has intent-filter, false otherwise
                if exported_str.lower() == "true":
                    exported = True
                elif exported_str.lower() == "false":
                    exported = False
                else:
                    exported = has_intent
                perm_attr = comp_elem.get("{http://schemas.android.com/apk/res/android}permission", "")
                components.append(
                    ComponentInfo(
                        name=comp_name,
                        component_type=comp_type,
                        exported=exported,
                        has_intent_filters=has_intent,
                        permissions=perm_attr,
                    )
                )

    # ── Security checks ──
    if issue := _check_debuggable(apk_info):
        security_issues.append(issue)
    if issue := _check_allow_backup(apk_info):
        security_issues.append(issue)
    if issue := _check_network_security(apk_info):
        security_issues.append(issue)
    if issue := _check_min_sdk(apk_info):
        security_issues.append(issue)
    security_issues.extend(_check_exported_components(components))
    security_issues.extend(_check_excessive_permissions(permissions))

    return apk_info, permissions, components, security_issues


def _scan_decompiled_source(decompile_dir: str) -> list[SecretFinding]:
    """Scan decompiled source files for hardcoded secrets."""
    findings: list[SecretFinding] = []
    source_extensions = {".smali", ".java", ".kt", ".xml", ".json", ".properties", ".txt", ".gradle", ".yml", ".yaml", ".config", ".env"}

    for root_str, _dirs, files in os.walk(decompile_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in source_extensions:
                continue
            fpath = os.path.join(root_str, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    for line_num, line in enumerate(fh, 1):
                        for secret_type, pattern, severity in SECRETS_PATTERNS:
                            # Skip low-severity base64 matches if too common
                            if severity == "low" and len(line) > 200:
                                continue
                            match = re.search(pattern, line)
                            if match:
                                value = match.group(0)[:80]
                                rel_path = os.path.relpath(fpath, decompile_dir)
                                findings.append(
                                    SecretFinding(
                                        secret_type=secret_type,
                                        value=value,
                                        file=rel_path,
                                        line=line_num,
                                        severity=severity,
                                    )
                                )
                                # Only first match per line per pattern
                                break
            except (OSError, UnicodeDecodeError):
                continue

    # Deduplicate: keep first occurrence of each (type, value, file) triple
    seen: set[tuple[str, str, str]] = set()
    unique: list[SecretFinding] = []
    for f in findings:
        key = (f.secret_type, f.value, f.file)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _detect_obfuscation(decompile_dir: str) -> bool:
    """Detect if the app uses code obfuscation (ProGuard/R8)."""
    obfuscation_indicators = [
        "proguard",
        "r8",
        "mapping.txt",
        "seed.txt",
        "usage.txt",
        "a.a.a",
        "b.b.b",  # common obfuscated package patterns
    ]
    for root_str, _dirs, files in os.walk(decompile_dir):
        for fname in files:
            f_lower = fname.lower()
            for indicator in obfuscation_indicators:
                if indicator in f_lower:
                    return True
    return False


# ──────────────────────────────────────────────
# Main Analysis Entry Point
# ──────────────────────────────────────────────


def analyze_apk(
    apk_path: str,
    decompile: bool = True,
    output_dir: str = "./mobilesentry_output",
    skip_decompile: bool = False,
) -> ApkAnalysisResult:
    """Analyze an APK file and return structured results.

    Args:
        apk_path: Path to the APK file.
        decompile: Whether to attempt decompilation for secrets scanning.
        output_dir: Base output directory.
        skip_decompile: Force skip decompilation even if tools are available.

    Returns:
        ApkAnalysisResult with all findings.
    """
    start_time = time.time()
    result = ApkAnalysisResult(apk_path=apk_path)

    if not os.path.isfile(apk_path):
        result.error = f"File not found: {apk_path}"
        return result

    # File size
    apk_size = os.path.getsize(apk_path)
    result.apk_info.file_size_kb = round(apk_size / 1024, 1)

    # ── Load with androguard ──
    try:
        from androguard.misc import AnalyzeAPK  # type: ignore[import-untyped]

        a, _d, _dx = AnalyzeAPK(apk_path)

        # Get manifest as XML string
        manifest_xml = a.get_android_manifest_axml().get_xml()

        # Parse manifest
        info, perms, comps, issues = _parse_manifest_xml(manifest_xml)
        result.apk_info = info
        result.permissions = perms
        result.components = comps
        result.security_issues = issues

        # Signing info
        try:
            result.apk_info.is_signed = a.is_signed()
            sig_name = a.get_signature_name()
            if sig_name:
                result.apk_info.signature_name = sig_name
        except Exception:
            pass

        # File & dex info
        result.file_count = len(a.get_files())
        dex_files = [f for f in a.get_files() if f.endswith(".dex")]
        result.dex_count = len(dex_files) if dex_files else 1

        # Detect native code
        native_extensions = {".so", ".dll", ".dylib", ".bin"}
        result.has_native_code = any(os.path.splitext(f)[1].lower() in native_extensions for f in a.get_files())

    except ImportError:
        result.error = "androguard is not installed. Run: pip install androguard"
        return result
    except Exception as e:
        result.error = f"Error analyzing APK: {e!s}"
        return result

    # ── Decompilation & Secrets Scanning ──
    if decompile and not skip_decompile:
        decompile_dir = os.path.join(output_dir, "decompiled", result.apk_info.package_name or "unknown")
        result.decompile_path = decompile_dir
        os.makedirs(decompile_dir, exist_ok=True)

        try:
            # Prefer apktool for decompilation (produces smali + resources)
            subprocess.run(
                ["apktool", "d", "-f", "-o", decompile_dir, apk_path],
                capture_output=True,
                timeout=120,
            )
            result.decompiled = True

            # Detect obfuscation
            result.has_obfuscation = _detect_obfuscation(decompile_dir)

            # Scan for secrets
            result.secrets = _scan_decompiled_source(decompile_dir)

        except FileNotFoundError:
            # Fallback: extract and search resources only
            result.decompiled = False
        except subprocess.TimeoutExpired:
            result.decompiled = False
        except Exception:
            result.decompiled = False

    result.analysis_time_ms = int((time.time() - start_time) * 1000)
    return result


def format_analysis_summary(result: ApkAnalysisResult) -> dict:
    """Format analysis result into a serializable dict for JSON output."""
    return {
        "apk_path": result.apk_path,
        "error": result.error or None,
        "analysis_time_ms": result.analysis_time_ms,
        "apk_info": {
            "package_name": result.apk_info.package_name,
            "version_code": result.apk_info.version_code,
            "version_name": result.apk_info.version_name,
            "min_sdk": result.apk_info.min_sdk,
            "target_sdk": result.apk_info.target_sdk,
            "max_sdk": result.apk_info.max_sdk,
            "debuggable": result.apk_info.debuggable,
            "allow_backup": result.apk_info.allow_backup,
            "has_network_security_config": result.apk_info.has_network_security_config,
            "is_signed": result.apk_info.is_signed,
            "signature_name": result.apk_info.signature_name,
            "file_size_kb": result.apk_info.file_size_kb,
        },
        "permissions": [{"name": p.name, "severity": p.severity} for p in result.permissions],
        "components": [
            {
                "name": c.name,
                "type": c.component_type,
                "exported": c.exported,
                "has_intent_filters": c.has_intent_filters,
                "permissions": c.permissions or None,
            }
            for c in result.components
        ],
        "secrets": [
            {
                "type": s.secret_type,
                "value": s.value,
                "file": s.file,
                "line": s.line,
                "severity": s.severity,
            }
            for s in result.secrets
        ],
        "security_issues": [
            {
                "title": s.title,
                "description": s.description,
                "severity": s.severity,
                "recommendation": s.recommendation,
            }
            for s in result.security_issues
        ],
        "statistics": {
            "file_count": result.file_count,
            "dex_count": result.dex_count,
            "has_native_code": result.has_native_code,
            "has_obfuscation": result.has_obfuscation,
            "decompiled": result.decompiled,
            "total_permissions": len(result.permissions),
            "dangerous_permissions": sum(1 for p in result.permissions if p.severity == "dangerous"),
            "total_components": len(result.components),
            "exported_components": sum(1 for c in result.components if c.exported),
            "total_secrets": len(result.secrets),
            "critical_secrets": sum(1 for s in result.secrets if s.severity == "critical"),
            "high_secrets": sum(1 for s in result.secrets if s.severity == "high"),
            "security_issues_count": len(result.security_issues),
        },
    }
