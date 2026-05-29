"""IPA Analyzer — iOS application analysis module.

Supports:
- IPA unpacking (ZIP extraction)
- Info.plist parsing (bundle ID, version, permissions, URL schemes)
- Entitlements extraction
- Binary architecture detection (arm64, arm64e, x86_64)
- Third-party SDK detection
- Security misconfiguration checks
- Hardcoded secrets detection via decompiled/binary search
- Comprehensive JSON + Rich terminal output
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field

# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────


@dataclass
class IpaInfo:
    """Metadata extracted from IPA/Info.plist."""

    bundle_id: str = ""
    bundle_name: str = ""
    display_name: str = ""
    version: str = ""
    build: str = ""
    min_os: str = ""
    sdk_name: str = ""
    platform_version: str = ""
    executable: str = ""
    app_folder: str = ""
    file_size_kb: float = 0.0


@dataclass
class IosPermission:
    """An iOS permission (NSCameraUsageDescription, etc.)."""

    key: str
    purpose: str  # The description string
    severity: str = "medium"  # high, medium, low, info


@dataclass
class UrlScheme:
    """A custom URL scheme registered by the app."""

    name: str
    role: str = "Editor"  # Viewer, Editor, Contributor, etc.


@dataclass
class EntitlementInfo:
    """An entitlement with its value."""

    key: str
    value: str
    is_risky: bool = False


@dataclass
class BinaryInfo:
    """Information about the Mach-O binary."""

    architectures: list[str] = field(default_factory=list)
    is_encrypted: bool = False
    encryption_check_performed: bool = False
    is_pie: bool = False
    has_stack_canary: bool = False
    has_arc: bool = False
    is_64bit: bool = False
    file_type: str = ""


@dataclass
class SdkFinding:
    """A detected third-party SDK or library."""

    name: str
    type_: str  # framework, library, service
    version: str = ""
    risk: str = "info"  # critical, high, medium, low, info


@dataclass
class SecretFinding:
    """A hardcoded secret discovered in the IPA."""

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
class IpaAnalysisResult:
    """Complete result from an IPA analysis run."""

    ipa_path: str
    ipa_info: IpaInfo = field(default_factory=IpaInfo)
    permissions: list[IosPermission] = field(default_factory=list)
    url_schemes: list[UrlScheme] = field(default_factory=list)
    entitlements: list[EntitlementInfo] = field(default_factory=list)
    binary_info: BinaryInfo = field(default_factory=BinaryInfo)
    sdks: list[SdkFinding] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    security_issues: list[SecurityIssue] = field(default_factory=list)
    file_count: int = 0
    framework_count: int = 0
    error: str = ""
    analysis_time_ms: int = 0


# ──────────────────────────────────────────────
# iOS Permission Mapping
# ──────────────────────────────────────────────

# Maps Info.plist permission keys to severity
IOS_PERMISSION_KEYS: dict[str, str] = {
    "NSCameraUsageDescription": "high",
    "NSMicrophoneUsageDescription": "high",
    "NSPhotoLibraryUsageDescription": "medium",
    "NSPhotoLibraryAddUsageDescription": "medium",
    "NSLocationWhenInUseUsageDescription": "medium",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "high",
    "NSLocationAlwaysUsageDescription": "high",
    "NSBluetoothAlwaysUsageDescription": "medium",
    "NSBluetoothPeripheralUsageDescription": "low",
    "NSContactsUsageDescription": "high",
    "NSCalendarsUsageDescription": "medium",
    "NSRemindersUsageDescription": "medium",
    "NSSpeechRecognitionUsageDescription": "medium",
    "NSFaceIDUsageDescription": "high",
    "NSHealthShareUsageDescription": "high",
    "NSHealthUpdateUsageDescription": "high",
    "NSHomeKitUsageDescription": "high",
    "NSAppleMusicUsageDescription": "medium",
    "NFSAllowUseForEnterprise": "low",
    "NSMotionUsageDescription": "low",
    "NSLocalNetworkUsageDescription": "medium",
    "NSNearbyInteractionAllowOnceUsageDescription": "medium",
    "NSUserTrackingUsageDescription": "high",
    "NSSiriUsageDescription": "medium",
    "NSFocusStatusUsageDescription": "low",
    "NSSensorKitUsageDescription": "high",
    "NSCalendarsFullAccessUsageDescription": "high",
    "NSPhotoLibraryPrivacyMigrationUsageDescription": "info",
}

# ──────────────────────────────────────────────
# Third-party SDK Detection
# ──────────────────────────────────────────────

KNOWN_SDKS: dict[str, tuple[str, str]] = {
    # Crash reporting & analytics
    "Firebase": ("analytics", "medium"),
    "GoogleAnalytics": ("analytics", "low"),
    "Crashlytics": ("crash_reporting", "low"),
    "Fabric": ("crash_reporting", "low"),
    "Sentry": ("crash_reporting", "low"),
    "Mixpanel": ("analytics", "low"),
    "Amplitude": ("analytics", "low"),
    "Flurry": ("analytics", "low"),
    "Adjust": ("analytics", "medium"),
    "AppsFlyer": ("analytics", "medium"),
    "Branch": ("deeplinking", "low"),
    # Advertising
    "GoogleMobileAds": ("advertising", "medium"),
    "AdMob": ("advertising", "medium"),
    "FacebookAudienceNetwork": ("advertising", "high"),
    "AppLovin": ("advertising", "medium"),
    "UnityAds": ("advertising", "medium"),
    # Social
    "FacebookSDK": ("social", "medium"),
    "FBSDKCoreKit": ("social", "medium"),
    "TwitterKit": ("social", "low"),
    "GoogleSignIn": ("social", "medium"),
    # Payments
    "Stripe": ("payments", "medium"),
    "Braintree": ("payments", "medium"),
    "PayPal": ("payments", "medium"),
    "RevenueCat": ("payments", "low"),
    # Maps
    "GoogleMaps": ("maps", "low"),
    "Mapbox": ("maps", "low"),
    # Chat & Messaging
    "Intercom": ("chat", "low"),
    "Zendesk": ("support", "low"),
    "Freshchat": ("chat", "low"),
    "Twilio": ("messaging", "low"),
    "SendBird": ("chat", "low"),
    # Performance
    "NewRelic": ("performance", "low"),
    "Datadog": ("performance", "low"),
    "Instabug": ("bug_reporting", "low"),
    # Auth
    "Auth0": ("authentication", "low"),
    "Okta": ("authentication", "low"),
    "MSAL": ("authentication", "low"),
    "AWSCognito": ("authentication", "medium"),
    # AWS
    "AWSCore": ("cloud", "low"),
    "AWSS3": ("cloud", "low"),
    "AWSAPIGateway": ("cloud", "low"),
    "AWSLambda": ("cloud", "low"),
    # Other cloud
    "Alamofire": ("networking", "low"),
    "AFNetworking": ("networking", "low"),
    "Realm": ("database", "medium"),
    "CoreData": ("database", "low"),
    "RxSwift": ("reactive", "low"),
    "Combine": ("reactive", "low"),
    "SwiftUI": ("ui_framework", "info"),
    "React Native": ("cross_platform", "medium"),
    "Flutter": ("cross_platform", "medium"),
    "Xamarin": ("cross_platform", "medium"),
    "Cordova": ("cross_platform", "high"),
    "UnityFramework": ("cross_platform", "medium"),
    # Security
    "Valet": ("security", "low"),
    "KeychainAccess": ("security", "low"),
    "SAMKeychain": ("security", "low"),
    "TheKeychain": ("security", "low"),
    # Utils
    "SwiftyJSON": ("utility", "info"),
    "Kingfisher": ("image_caching", "info"),
    "SDWebImage": ("image_caching", "info"),
    "AlamofireImage": ("image_caching", "info"),
    "CocoaLumberjack": ("logging", "info"),
    "SVProgressHUD": ("ui", "info"),
    "MBProgressHUD": ("ui", "info"),
    "SnapKit": ("ui", "info"),
    "lottie-ios": ("animation", "info"),
}

# ──────────────────────────────────────────────
# Hardcoded Secrets Regex Patterns
# ──────────────────────────────────────────────

SECRETS_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Access Key", r"(?i)aws[_-]?(secret|access)[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']", "critical"),
    ("Google API / Firebase Key", r"AIza[0-9A-Za-z_-]{35}", "high"),
    ("Firebase Database URL", r"https://[a-zA-Z0-9-]+\.firebaseio\.com", "medium"),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,50}[\"']", "high"),
    ("Password / Passphrase", r"(?i)(password|passwd|pwd|passphrase)\s*[:=]\s*[\"'][^\"']{4,100}[\"']", "critical"),
    ("Secret / Token", r"(?i)(secret|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{8,}[\"']", "high"),
    ("JWT / OAuth Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "critical"),
    ("Private Key (PEM)", r"-----BEGIN\s*(RSA|DSA|EC|OPENSSH|PRIVATE)\s*KEY-----", "critical"),
    ("Slack Token", r"xox[baprsr]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}", "critical"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}", "critical"),
    ("Heroku API Key", r"(?i)heroku[a-z_]*\s*[:=]\s*[\"'][A-Za-z0-9\-]{20,}[\"']", "high"),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high"),
    ("SQL Connection String", r"(?i)(jdbc|mysql|postgresql|mssql|sqlite):[^\s'\"]{10,}", "critical"),
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s'\"]{10,}", "critical"),
    ("Generic Connection String", r"(?i)(connection[_-]?string|conn[_-]?string)\s*[:=]\s*[\"'][^\"]{10,}[\"']", "high"),
    ("Hardcoded Certificate", r"-----BEGIN\s+CERTIFICATE-----", "medium"),
    ("OAuth Client Secret", r"(?i)(client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']", "critical"),
    ("Base64-Encoded Key (suspicious)", r"[A-Za-z0-9+/]{40,}={0,2}", "low"),
    ("iOS API Hardcoded", r"(?i)(apiKey|apikey|api_secret|appSecret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']", "high"),
    ("P12/PFX Certificate", r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "critical"),
    ("Apple Push Key", r"(?i)(apns|push)[_-]?(key|cert|secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']", "high"),
]

# ──────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────


def _get_ipa_tempdir() -> str:
    """Create a temp directory for IPA extraction."""
    return tempfile.mkdtemp(prefix="mobilesentry_ipa_")


def _cleanup_tempdir(path: str) -> None:
    """Remove a temp directory."""
    shutil.rmtree(path, ignore_errors=True)


def _find_app_bundle(extract_dir: str) -> str | None:
    """Find the .app bundle inside an extracted IPA."""
    payload_dir = os.path.join(extract_dir, "Payload")
    if not os.path.isdir(payload_dir):
        return None
    for item in os.listdir(payload_dir):
        if item.endswith(".app"):
            app_path = os.path.join(payload_dir, item)
            if os.path.isdir(app_path):
                return app_path
    return None


def _find_binary(app_folder: str, executable_name: str | None = None) -> str | None:
    """Find the Mach-O binary inside the .app bundle."""
    if executable_name:
        candidate = os.path.join(app_folder, executable_name)
        if os.path.isfile(candidate):
            return candidate
    # Fallback: scan for Mach-O binaries
    for item in os.listdir(app_folder):
        item_path = os.path.join(app_folder, item)
        if os.path.isfile(item_path) and not item.endswith((".plist", ".png", ".jpg", ".jpeg", ".gif", ".json", ".xml", ".strings", ".lproj", ".storyboardc", ".nib", ".car", ".dylib")):
            try:
                output = subprocess.run(["file", "-b", item_path], capture_output=True, text=True, timeout=5)
                if "Mach-O" in output.stdout:
                    return item_path
            except (OSError, subprocess.SubprocessError):
                continue
    return None


# ──────────────────────────────────────────────
# Info.plist Parsing
# ──────────────────────────────────────────────


def _parse_info_plist(app_folder: str) -> tuple[IpaInfo, list[IosPermission], list[UrlScheme], list[EntitlementInfo]]:
    """Parse Info.plist from an iOS app bundle."""
    info = IpaInfo(app_folder=app_folder)
    permissions: list[IosPermission] = []
    schemes: list[UrlScheme] = []
    entitlements: list[EntitlementInfo] = []

    # Find Info.plist — may be binary XML or XML
    plist_path = os.path.join(app_folder, "Info.plist")
    if not os.path.isfile(plist_path):
        return info, permissions, schemes, entitlements

    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)
    except Exception:
        # Try plutil to convert binary plist to XML first
        try:
            xml_path = plist_path + ".xml"
            subprocess.run(["plutil", "-convert", "xml1", "-o", xml_path, plist_path], capture_output=True, timeout=15)
            with open(xml_path, "rb") as f:
                plist_data = plistlib.load(f)
            os.unlink(xml_path)
        except Exception:
            return info, permissions, schemes, entitlements

    if not isinstance(plist_data, dict):
        return info, permissions, schemes, entitlements

    # ── Basic Info ──
    info.bundle_id = str(plist_data.get("CFBundleIdentifier", ""))
    info.bundle_name = str(plist_data.get("CFBundleName", ""))
    info.display_name = str(plist_data.get("CFBundleDisplayName", info.bundle_name))
    info.version = str(plist_data.get("CFBundleShortVersionString", ""))
    info.build = str(plist_data.get("CFBundleVersion", ""))
    info.min_os = str(plist_data.get("MinimumOSVersion", ""))
    info.sdk_name = str(plist_data.get("DTSDKName", ""))
    info.platform_version = str(plist_data.get("DTPlatformVersion", ""))
    info.executable = str(plist_data.get("CFBundleExecutable", ""))

    # ── Permissions (usage descriptions) ──
    for key, severity in IOS_PERMISSION_KEYS.items():
        if key in plist_data:
            purpose = str(plist_data.get(key, ""))
            permissions.append(IosPermission(key=key.replace("NS", "").replace("UsageDescription", ""), purpose=purpose, severity=severity))

    # ── URL Schemes ──
    url_types = plist_data.get("CFBundleURLTypes", [])
    if isinstance(url_types, list):
        for url_type in url_types:
            if isinstance(url_type, dict):
                role = str(url_type.get("CFBundleURLRole", "Editor"))
                scheme_list = url_type.get("CFBundleURLSchemes", [])
                if isinstance(scheme_list, list):
                    schemes.extend(UrlScheme(name=str(scheme), role=role) for scheme in scheme_list)

    # ── Embedded entitlements ──
    # Try from _CodeSignature/CodeResources first, then embedded.mobileprovision
    entitlements_paths = [
        os.path.join(app_folder, "embedded.mobileprovision"),
        os.path.join(app_folder, "archived-expanded-entitlements.xcent"),
    ]
    for epath in entitlements_paths:
        if os.path.isfile(epath):
            try:
                with open(epath, "rb") as f:
                    data = f.read()
                # mobileprovision is a CMS signed plist; try to extract the plist portion
                try:
                    ent_plist = plistlib.loads(data)
                except Exception:
                    # Try to find plist content between <?xml and </plist>
                    text = data.decode("utf-8", errors="replace")
                    xml_match = re.search(r"<\?xml.*?</plist>", text, re.DOTALL)
                    if xml_match:
                        try:
                            ent_plist = plistlib.loads(xml_match.group(0).encode("utf-8"))
                        except Exception:
                            ent_plist = {}
                    else:
                        ent_plist = {}
                if isinstance(ent_plist, dict):
                    # Extract entitlements if inside a wrapper dict
                    ent_source = ent_plist.get("Entitlements", ent_plist)
                    if isinstance(ent_source, dict):
                        _extract_entitlements(ent_source, entitlements)
            except Exception:
                continue

    return info, permissions, schemes, entitlements


_RISKY_ENTITLEMENTS: dict[str, str] = {
    "get-task-allow": "Allows debugger attachment (development only). Should not be present in release builds.",
    "com.apple.security.cs.disable-library-validation": "Allows loading arbitrary frameworks/libraries (code injection risk).",
    "com.apple.security.cs.disable-executable-page-protection": "Disables NX protection, allowing writable+executable memory pages.",
    "com.apple.security.cs.allow-unsigned-executable-memory": "Allows JIT compilation, can be abused for code injection.",
    "com.apple.security.cs.allow-dyld-environment-variables": "Allows DYLD_INSERT_LIBRARIES which enables library injection.",
    "com.apple.security.network.client": "Allows outbound network connections (risky when combined with data exfiltration).",
    "com.apple.security.network.server": "Allows listening on network ports (attack surface increase).",
    "com.apple.security.device.camera": "Access to camera hardware.",
    "com.apple.security.device.microphone": "Access to microphone hardware.",
    "com.apple.security.device.usb": "Access to USB devices.",
    "com.apple.security.personal-information.addressbook": "Access to Address Book data.",
    "com.apple.security.personal-information.calendars": "Access to Calendar data.",
    "com.apple.security.personal-information.photos": "Access to Photos library.",
    "com.apple.security.personal-information.location": "Access to location services.",
    "com.apple.application-identifier": "App identifier (standard entitlement).",
}


def _extract_entitlements(ent_source: dict, entitlements: list[EntitlementInfo]) -> None:
    """Extract entitlements from a plist dict."""
    for key, value in ent_source.items():
        val_str = str(value)
        is_risky = key in _RISKY_ENTITLEMENTS and not key.endswith("application-identifier")
        entitlements.append(
            EntitlementInfo(
                key=key,
                value=val_str[:100] if len(val_str) > 100 else val_str,
                is_risky=is_risky,
            )
        )


# ──────────────────────────────────────────────
# Binary Analysis
# ──────────────────────────────────────────────


def _analyze_binary(binary_path: str) -> BinaryInfo:
    """Analyze a Mach-O binary for architecture and security features."""
    binfo = BinaryInfo()

    if not binary_path or not os.path.isfile(binary_path):
        return binfo

    # File type detection
    try:
        output = subprocess.run(["file", "-b", binary_path], capture_output=True, text=True, timeout=5)
        binfo.file_type = output.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass

    # Check for 64-bit in file type
    if "arm64" in binfo.file_type or "x86_64" in binfo.file_type:
        binfo.is_64bit = True

    # Architecture detection from file output
    arch_patterns = {
        "arm64": "arm64",
        "arm64e": "arm64e",
        "x86_64": "x86_64",
        "i386": "i386",
        "armv7": "armv7",
        "armv7s": "armv7s",
    }
    for arch_key, arch_label in arch_patterns.items():
        if arch_key in binfo.file_type.lower():
            binfo.architectures.append(arch_label)

    if not binfo.architectures:
        binfo.architectures.append(binfo.file_type.split(",")[0].strip() if binfo.file_type else "unknown")

    # Check PIE (Position Independent Executable)
    if "pie" in binfo.file_type.lower() or "position-independent" in binfo.file_type.lower():
        binfo.is_pie = True

    # Check encryption via otool (if available)
    try:
        otool_out = subprocess.run(["otool", "-l", binary_path], capture_output=True, text=True, timeout=10)
        binfo.encryption_check_performed = True
        if "cryptid 1" in otool_out.stdout:
            binfo.is_encrypted = True
    except (OSError, subprocess.SubprocessError):
        # otool may not be available on non-macOS
        pass

    # Stack canary detection via strings on binary
    try:
        strings_out = subprocess.run(["strings", binary_path], capture_output=True, text=True, timeout=30)
        # Stack canary presence: __stack_chk_fail or __stack_chk_guard
        if "__stack_chk_fail" in strings_out.stdout or "__stack_chk_guard" in strings_out.stdout:
            binfo.has_stack_canary = True
        # ARC: _objc_release, _objc_retainAutoreleasedReturnValue
        if "_objc_retainAutoreleasedReturnValue" in strings_out.stdout:
            binfo.has_arc = True
    except (OSError, subprocess.SubprocessError):
        pass

    return binfo


# ──────────────────────────────────────────────
# SDK Detection
# ──────────────────────────────────────────────


def _detect_sdks(app_folder: str) -> tuple[list[SdkFinding], int]:
    """Detect third-party SDKs and frameworks in the app bundle."""
    detected: list[SdkFinding] = []
    found_names: set[str] = set()

    # Check Frameworks directory
    frameworks_dir = os.path.join(app_folder, "Frameworks")
    if os.path.isdir(frameworks_dir):
        for fw_name in os.listdir(frameworks_dir):
            if fw_name.endswith(".framework"):
                sdk_name = fw_name.replace(".framework", "")
                # Check against known SDKs
                for known_name, (type_, risk) in KNOWN_SDKS.items():
                    if known_name.lower() in sdk_name.lower():
                        if known_name not in found_names:
                            detected.append(SdkFinding(name=known_name, type_=type_, risk=risk))
                            found_names.add(known_name)
                        break
                else:
                    # Unknown framework
                    detected.append(SdkFinding(name=sdk_name, type_="framework", risk="info"))

    # Count frameworks
    framework_count = 0
    if os.path.isdir(frameworks_dir):
        framework_count = len([f for f in os.listdir(frameworks_dir) if f.endswith(".framework")])

    # Check .dylib files in Frameworks
    if os.path.isdir(frameworks_dir):
        for fname in os.listdir(frameworks_dir):
            if fname.endswith(".dylib"):
                for known_name, (type_, risk) in KNOWN_SDKS.items():
                    if known_name.lower() in fname.lower() and known_name not in found_names:
                        detected.append(SdkFinding(name=known_name, type_=type_, risk=risk))
                        found_names.add(known_name)

    # Also check Info.plist for SDK references
    plist_path = os.path.join(app_folder, "Info.plist")
    if os.path.isfile(plist_path):
        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)
        except Exception:
            try:
                xml_path = plist_path + ".xml"
                subprocess.run(["plutil", "-convert", "xml1", "-o", xml_path, plist_path], capture_output=True, timeout=15)
                with open(xml_path, "rb") as f:
                    plist_data = plistlib.load(f)
                os.unlink(xml_path)
            except Exception:
                plist_data = {}

        if isinstance(plist_data, dict):
            # Check UIRequiredDeviceCapabilities
            capabilities = plist_data.get("UIRequiredDeviceCapabilities", [])
            if isinstance(capabilities, list):
                cap_str = " ".join(str(c).lower() for c in capabilities)
                if "arkit" in cap_str and "ARKit" not in found_names:
                    detected.append(SdkFinding(name="ARKit", type_="framework", risk="info"))
                    found_names.add("ARKit")

    return detected, framework_count


# ──────────────────────────────────────────────
# Security Checks
# ──────────────────────────────────────────────


def _check_http_transport(info: IpaInfo) -> SecurityIssue | None:
    """Check for NSAppTransportSecurity settings."""
    plist_path = os.path.join(info.app_folder, "Info.plist")
    if not os.path.isfile(plist_path):
        return None
    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)
    except Exception:
        return None
    if not isinstance(plist_data, dict):
        return None

    ats = plist_data.get("NSAppTransportSecurity", {})
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        return SecurityIssue(
            title="NSAllowsArbitraryLoads Enabled",
            description="The app disables App Transport Security (ATS), allowing arbitrary HTTP connections. This exposes sensitive data to man-in-the-middle attacks over cleartext HTTP.",
            severity="high",
            recommendation="Remove NSAllowsArbitraryLoads or scope specific exceptions via NSExceptionDomains for trusted endpoints only.",
        )

    # Check for specific insecure domains
    if isinstance(ats, dict):
        exceptions = ats.get("NSExceptionDomains", {})
        if isinstance(exceptions, dict):
            insecure_domains = []
            for domain, config in exceptions.items():
                if isinstance(config, dict) and config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    insecure_domains.append(domain)
            if insecure_domains:
                return SecurityIssue(
                    title=f"Insecure HTTP Exceptions ({len(insecure_domains)} domains)",
                    description=f"The app allows HTTP loads for: {', '.join(insecure_domains[:5])}",
                    severity="medium",
                    recommendation="Remove NSExceptionAllowsInsecureHTTPLoads or use HTTPS for these domains.",
                )
    return None


def _check_local_data_protection(info: IpaInfo) -> SecurityIssue | None:
    """Check for NSDocumentsFolderUsageDescription or related."""
    plist_path = os.path.join(info.app_folder, "Info.plist")
    if not os.path.isfile(plist_path):
        return None
    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)
    except Exception:
        return None
    if not isinstance(plist_data, dict):
        return None

    # Check for UIFileSharingEnabled
    if plist_data.get("UIFileSharingEnabled"):
        return SecurityIssue(
            title="File Sharing Enabled (UIFileSharingEnabled)",
            description="The app enables iTunes file sharing, making its Documents directory accessible via USB. Sensitive data stored in Documents can be exfiltrated.",
            severity="medium",
            recommendation="Set UIFileSharingEnabled to NO (false) in Info.plist unless file sharing is a required feature. Store sensitive data in the Keychain or NSLibraryDirectory with NSFileProtectionComplete.",
        )

    # Check LSSupportsOpeningDocumentsInPlace
    if plist_data.get("LSSupportsOpeningDocumentsInPlace"):
        return SecurityIssue(
            title="Supports Opening Documents In Place",
            description="The app supports opening documents in place, which may expose file URLs to other apps on the system.",
            severity="low",
            recommendation="Review if LSSupportsOpeningDocumentsInPlace is necessary, and ensure document scope is properly restricted.",
        )
    return None


def _check_encryption(binary_info: BinaryInfo) -> SecurityIssue | None:
    """Check if the binary appears encrypted (App Store build)."""
    if not binary_info.is_encrypted:
        return SecurityIssue(
            title="Binary Not Encrypted (No FairPlay Encryption)",
            description="The app binary does not appear to be FairPlay encrypted. App Store builds should have cryptid=1, indicating encryption. An unencrypted binary is easier to reverse engineer.",
            severity="medium",
            recommendation="Ensure the app is distributed through the App Store with FairPlay encryption enabled. For enterprise distribution, consider additional obfuscation.",
        )
    return None


def _check_no_pie(binary_info: BinaryInfo) -> SecurityIssue | None:
    """Check if PIE is enabled."""
    if binary_info.architectures and not binary_info.is_pie:
        return SecurityIssue(
            title="Position Independent Executable (PIE) Not Enabled",
            description="The binary is not position-independent. This makes it more vulnerable to ROP attacks and buffer overflow exploitation.",
            severity="high",
            recommendation='Add "-fPIE" and "-pie" flags to the linker settings in Xcode build settings. (Enabled by default since Xcode 4.6 for iOS.)',
        )
    return None


def _check_no_arc(binary_info: BinaryInfo) -> SecurityIssue | None:
    """Check if ARC is enabled."""
    if binary_info.architectures and not binary_info.has_arc:
        return SecurityIssue(
            title="Automatic Reference Counting (ARC) Not Detected",
            description="The binary does not appear to use ARC, making it more susceptible to memory corruption vulnerabilities like use-after-free and retain-release bugs.",
            severity="medium",
            recommendation="Enable ARC in Xcode build settings (CLANG_ENABLE_OBJC_ARC = YES) for all Objective-C files.",
        )
    return None


def _check_no_stack_canary(binary_info: BinaryInfo) -> SecurityIssue | None:
    """Check if stack canary is present."""
    if binary_info.architectures and not binary_info.has_stack_canary:
        return SecurityIssue(
            title="Stack Canary Not Detected",
            description="Stack canaries (__stack_chk_fail/__stack_chk_guard) were not found in the binary. This makes the app more vulnerable to stack buffer overflow attacks.",
            severity="high",
            recommendation='Enable stack canaries in Xcode build settings: set "-fstack-protector-all" in Other C Flags.',
        )
    return None


def _check_excessive_permissions(permissions: list[IosPermission]) -> list[SecurityIssue]:
    """Flag excessive permission requests."""
    issues: list[SecurityIssue] = []
    high_count = sum(1 for p in permissions if p.severity == "high")
    total = len(permissions)

    if high_count >= 5:
        issues.append(
            SecurityIssue(
                title=f"Excessive Permissions ({high_count} high-risk)",
                description=f"The app requests {total} permissions of which {high_count} are high-risk (camera, microphone, location, contacts, health, etc.). Each permission should be justified for the app's core functionality.",
                severity="medium",
                recommendation="Review each high-risk permission and remove any that are not essential. Consider using purpose strings that clearly explain why each permission is needed.",
            )
        )
    elif total >= 8:
        issues.append(
            SecurityIssue(
                title=f"Many Permissions Requested ({total})",
                description=f"The app requests {total} iOS permissions. Excessive permissions increase the attack surface and user privacy concerns.",
                severity="low",
                recommendation="Review each permission and remove those not essential to core functionality.",
            )
        )

    return issues


# ──────────────────────────────────────────────
# Secrets Scanning
# ──────────────────────────────────────────────


def _scan_for_secrets(app_folder: str) -> list[SecretFinding]:
    """Scan the app bundle for hardcoded secrets in source-like files."""
    findings: list[SecretFinding] = []
    source_extensions = {
        ".swift",
        ".m",
        ".h",
        ".mm",
        ".cpp",
        ".c",
        ".hpp",
        ".plist",
        ".json",
        ".xml",
        ".strings",
        ".txt",
        ".yml",
        ".yaml",
        ".config",
        ".env",
        ".js",
        ".ts",
    }

    for root_str, _dirs, files in os.walk(app_folder):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in source_extensions:
                continue
            if ".framework" in root_str and ext in (".m", ".h", ".c", ".cpp", ".swift"):
                # Skip source files inside frameworks (third-party code)
                continue
            fpath = os.path.join(root_str, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    for line_num, line in enumerate(fh, 1):
                        for secret_type, pattern, severity in SECRETS_PATTERNS:
                            if severity == "low" and len(line) > 200:
                                continue
                            match = re.search(pattern, line)
                            if match:
                                value = match.group(0)[:80]
                                rel_path = os.path.relpath(fpath, app_folder)
                                findings.append(
                                    SecretFinding(
                                        secret_type=secret_type,
                                        value=value,
                                        file=rel_path,
                                        line=line_num,
                                        severity=severity,
                                    )
                                )
                                break
            except (OSError, UnicodeDecodeError):
                continue

    # Deduplicate
    seen: set[tuple[str, str, str]] = set()
    unique: list[SecretFinding] = []
    for f in findings:
        key = (f.secret_type, f.value, f.file)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ──────────────────────────────────────────────
# Main Analysis Entry Point
# ──────────────────────────────────────────────


def analyze_ipa(
    ipa_path: str,
    extract: bool = True,
    scan_secrets: bool = True,
    cleanup_temp: bool = True,
) -> IpaAnalysisResult:
    """Analyze an IPA file and return structured results.

    Args:
        ipa_path: Path to the IPA file.
        extract: Whether to extract the IPA for deep analysis.
        scan_secrets: Whether to scan for hardcoded secrets.
        cleanup_temp: Whether to remove temp extraction directory.

    Returns:
        IpaAnalysisResult with all findings.
    """
    start_time = time.time()
    result = IpaAnalysisResult(ipa_path=ipa_path)

    if not os.path.isfile(ipa_path):
        result.error = f"File not found: {ipa_path}"
        return result

    # File size
    ipa_size = os.path.getsize(ipa_path)
    result.ipa_info.file_size_kb = round(ipa_size / 1024, 1)

    # ── Validate IPA format ──
    if not zipfile.is_zipfile(ipa_path):
        result.error = "Not a valid IPA file (not a ZIP archive)"
        return result

    # ── Extract ──
    temp_dir = None
    app_folder: str | None = None

    if extract:
        temp_dir = _get_ipa_tempdir()
        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                zf.extractall(temp_dir)
        except zipfile.BadZipFile as e:
            result.error = f"Corrupt IPA archive: {e!s}"
            return result

        app_folder = _find_app_bundle(temp_dir)
        if app_folder is None:
            result.error = "No .app bundle found in IPA (missing Payload/ directory)"
            # Check what's in the extract
            payload = os.path.join(temp_dir, "Payload")
            if os.path.isdir(payload):
                contents = os.listdir(payload)
                result.error += f" Contents: {contents[:5]}"
            return result

        # Count files
        file_count = 0
        for _root_str, _dirs, files in os.walk(app_folder):
            file_count += len(files)
        result.file_count = file_count
        result.ipa_info.app_folder = app_folder

    # ── Parse Info.plist ──
    if app_folder:
        info, permissions, schemes, entitlements = _parse_info_plist(app_folder)
        result.ipa_info = info
        result.permissions = permissions
        result.url_schemes = schemes
        result.entitlements = entitlements

    # ── Detect SDKs ──
    if app_folder:
        sdks, fw_count = _detect_sdks(app_folder)
        result.sdks = sdks
        result.framework_count = fw_count

    # ── Analyze Binary ──
    if app_folder:
        binary_path = _find_binary(app_folder, info.executable or None)
        if binary_path:
            result.binary_info = _analyze_binary(binary_path)

    # ── Security Checks ──
    if app_folder:
        issues: list[SecurityIssue] = []

        if issue := _check_http_transport(info):
            issues.append(issue)
        if issue := _check_local_data_protection(info):
            issues.append(issue)
        if issue := _check_no_pie(result.binary_info):
            issues.append(issue)
        if issue := _check_no_arc(result.binary_info):
            issues.append(issue)
        if issue := _check_no_stack_canary(result.binary_info):
            issues.append(issue)
        if result.binary_info.encryption_check_performed and not result.binary_info.is_encrypted and (issue := _check_encryption(result.binary_info)):
            issues.append(issue)
        issues.extend(_check_excessive_permissions(permissions))

        # Check for risky entitlements
        for ent in entitlements:
            if ent.is_risky:
                risk_desc = _RISKY_ENTITLEMENTS.get(ent.key, "Potentially risky entitlement.")
                issues.append(
                    SecurityIssue(
                        title=f"Risky Entitlement: {ent.key}",
                        description=risk_desc,
                        severity="high" if "get-task-allow" in ent.key or "disable-library" in ent.key or "unsigned-executable" in ent.key else "medium",
                        recommendation="Remove this entitlement unless it is essential for the app's functionality. Review Apple's entitlement documentation for alternatives.",
                    )
                )

        result.security_issues = issues

    # ── Secrets Scanning ──
    if app_folder and scan_secrets:
        result.secrets = _scan_for_secrets(app_folder)

    # ── Cleanup ──
    if cleanup_temp and temp_dir:
        _cleanup_tempdir(temp_dir)

    result.analysis_time_ms = int((time.time() - start_time) * 1000)
    return result


# ──────────────────────────────────────────────
# JSON Serialization
# ──────────────────────────────────────────────


def format_analysis_summary(result: IpaAnalysisResult) -> dict:
    """Format analysis result into a serializable dict for JSON output."""
    return {
        "ipa_path": result.ipa_path,
        "error": result.error or None,
        "analysis_time_ms": result.analysis_time_ms,
        "ipa_info": {
            "bundle_id": result.ipa_info.bundle_id,
            "bundle_name": result.ipa_info.bundle_name,
            "display_name": result.ipa_info.display_name,
            "version": result.ipa_info.version,
            "build": result.ipa_info.build,
            "min_os": result.ipa_info.min_os,
            "sdk_name": result.ipa_info.sdk_name,
            "platform_version": result.ipa_info.platform_version,
            "executable": result.ipa_info.executable,
            "file_size_kb": result.ipa_info.file_size_kb,
        },
        "permissions": [{"key": p.key, "purpose": p.purpose, "severity": p.severity} for p in result.permissions],
        "url_schemes": [{"name": s.name, "role": s.role} for s in result.url_schemes],
        "entitlements": [{"key": e.key, "value": e.value, "is_risky": e.is_risky} for e in result.entitlements],
        "binary_info": {
            "architectures": result.binary_info.architectures,
            "is_encrypted": result.binary_info.is_encrypted,
            "is_pie": result.binary_info.is_pie,
            "has_stack_canary": result.binary_info.has_stack_canary,
            "has_arc": result.binary_info.has_arc,
            "is_64bit": result.binary_info.is_64bit,
            "file_type": result.binary_info.file_type,
        },
        "sdks": [{"name": s.name, "type": s.type_, "version": s.version, "risk": s.risk} for s in result.sdks],
        "secrets": [{"type": s.secret_type, "value": s.value, "file": s.file, "line": s.line, "severity": s.severity} for s in result.secrets],
        "security_issues": [{"title": s.title, "description": s.description, "severity": s.severity, "recommendation": s.recommendation} for s in result.security_issues],
        "statistics": {
            "file_count": result.file_count,
            "framework_count": result.framework_count,
            "total_permissions": len(result.permissions),
            "high_risk_permissions": sum(1 for p in result.permissions if p.severity == "high"),
            "total_sdks": len(result.sdks),
            "url_schemes": len(result.url_schemes),
            "entitlements": len(result.entitlements),
            "risky_entitlements": sum(1 for e in result.entitlements if e.is_risky),
            "total_secrets": len(result.secrets),
            "critical_secrets": sum(1 for s in result.secrets if s.severity == "critical"),
            "high_secrets": sum(1 for s in result.secrets if s.severity == "high"),
            "security_issues_count": len(result.security_issues),
        },
    }
