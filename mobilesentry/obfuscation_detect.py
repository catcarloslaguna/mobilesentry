"""Code Obfuscation Detection — ProGuard, DexGuard, OLLVM, string encryption, reflection, packers, and more.

Detects a wide range of obfuscation techniques used in Android and iOS applications
by analyzing decompiled source code, binary metadata, and behavioral patterns.

Platforms:
    - Android: ProGuard/R8, DexGuard, OLLVM, string encryption, reflection hiding, packers, resource obfuscation
    - iOS: Symbol obfuscation, OLLVM, string encryption, ObjC metadata obfuscation

Usage:
    from mobilesentry.obfuscation_detect import ObfuscationDetector

    detector = ObfuscationDetector()
    report = detector.analyze_apk(decompile_dir="/path/to/decompiled")

    for finding in report.findings:
        print(f"[{finding.severity}] {finding.technique} — {finding.description}")
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ══════════════════════════════════════════════
# Data Models
# ══════════════════════════════════════════════


@dataclass
class ObfuscationTechnique:
    """Description of an obfuscation technique and how to detect it."""

    name: str
    platform: str  # "android", "ios", "both"
    description: str
    severity: str  # "info", "low", "medium", "high", "critical"
    indicators: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class ObfuscationFinding:
    """A single obfuscation detection finding with evidence."""

    technique: str
    platform: str
    description: str
    severity: str  # "info", "low", "medium", "high", "critical"
    confidence: str  # "low", "medium", "high", "certain"
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return scores.get(self.severity, 0)


@dataclass
class ObfuscationReport:
    """Complete obfuscation detection report."""

    platform: str  # "android", "ios", "both"
    findings: list[ObfuscationFinding] = field(default_factory=list)
    total_score: int = 0
    risk_level: str = "info"  # "info", "low", "medium", "high", "critical"
    analysis_time_ms: int = 0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[ObfuscationFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[ObfuscationFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium_findings(self) -> list[ObfuscationFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def protected(self) -> bool:
        """True if meaningful obfuscation was detected."""
        return len([f for f in self.findings if f.confidence in ("high", "certain")]) > 0

    @property
    def obfuscation_score(self) -> int:
        """Score 0-100 indicating how obfuscated the app is."""
        if not self.findings:
            return 0
        # Normalize: critical=20pts, high=12pts, medium=6pts, low=3pts, info=1pt
        weighted = 0
        for f in self.findings:
            if f.severity == "critical":
                weighted += 20
            elif f.severity == "high":
                weighted += 12
            elif f.severity == "medium":
                weighted += 6
            elif f.severity == "low":
                weighted += 3
            else:
                weighted += 1
            # Half-weight for low confidence
            if f.confidence == "low":
                weighted -= int(weighted * 0.4)
        return min(100, weighted)


# ══════════════════════════════════════════════
# Technique Definitions
# ══════════════════════════════════════════════


ANDROID_OBFUSCATION_TECHNIQUES: list[ObfuscationTechnique] = [
    ObfuscationTechnique(
        name="ProGuard/R8",
        platform="android",
        description="ProGuard or R8 minification and obfuscation. Detects renamed classes, fields, and methods with short meaningless names, indicating standard Android obfuscation.",
        severity="medium",
        indicators=[
            "Class names like a.a.a, b.c.d (single-letter package/class names)",
            "mapping.txt file present in APK",
            "proguard configuration strings in decompiled code",
            "BuildConfig.MINIFIED = true",
            "R$ classes with obfuscated field names",
        ],
        recommendation="ProGuard/R8 obfuscation is the baseline for Android app protection. Consider enabling full obfuscation rules (not just minification) and adding DexGuard for enhanced protection.",
    ),
    ObfuscationTechnique(
        name="DexGuard",
        platform="android",
        description="DexGuard — commercial-grade obfuscation built on ProGuard with additional protections: string encryption, class encryption, reflection hiding, and anti-tampering.",
        severity="high",
        indicators=[
            "Encrypted string constants in DEX bytecode",
            "DexGuard-specific manifest entries or assets",
            "Reflection-based class loading patterns",
            "Anti-tampering integrity checks",
            "Resources encrypted or embedded in non-standard locations",
        ],
        recommendation="DexGuard provides strong protection. Verify that all sensitive strings and classes are encrypted, and that anti-tampering checks are tested on rooted devices.",
    ),
    ObfuscationTechnique(
        name="String Encryption",
        platform="android",
        description="String encryption — sensitive strings are encrypted in the binary and decrypted at runtime via XOR, AES, or custom algorithms. Prevents static analysis of strings.",
        severity="high",
        indicators=[
            "XOR decryption loops (char[] XOR with key)",
            "String decryption helper methods (decrypt, getString, decode)",
            "Character array building patterns",
            "Suspicious byte-to-string conversions",
            "AES decryption setup in code",
        ],
        recommendation="String encryption protects API endpoints, tokens, and error messages from static analysis. Ensure the decryption keys are not easily extracted (e.g., hardcoded nearby).",
    ),
    ObfuscationTechnique(
        name="Reflection-Based Hiding",
        platform="android",
        description="Reflection-based API hiding — class names and method names are constructed at runtime using string manipulation and passed to Class.forName() and Method.invoke() to hide static references.",
        severity="high",
        indicators=[
            "Excessive Class.forName() calls with non-constant strings",
            "Method.invoke() with dynamically constructed method names",
            "getDeclaredMethod() patterns",
            "String concatenation for class/method names",
            "Dynamic class loading via DexClassLoader",
        ],
        recommendation="Reflection hiding makes static analysis significantly harder. Ensure reflection is not bypassable by simply logging method invocations via Frida.",
    ),
    ObfuscationTechnique(
        name="Obfuscator-LLVM (OLLVM)",
        platform="android",
        description="Obfuscator-LLVM applied to native (.so) libraries. Uses control flow flattening, bogus control flow, and instruction substitution to make reverse engineering of native code extremely difficult.",
        severity="critical",
        indicators=[
            "Control flow flattening patterns (switch-based dispatchers)",
            "Bogus control flow with opaque predicates",
            "String encryption in JNI native code",
            "LLVM obfuscation pass signatures",
            "Extremely high branch count relative to function size",
        ],
        recommendation="OLLVM provides strong native code protection. Combine with white-box cryptography for maximum protection of cryptographic operations in native code.",
    ),
    ObfuscationTechnique(
        name="Packer / DEX Protection",
        platform="android",
        description="Application packer or DEX protector. The original DEX bytecode is encrypted or compressed and loaded dynamically at runtime, preventing static analysis of the app bytecode.",
        severity="critical",
        indicators=[
            "UPX signature in native libraries (UPX! markers)",
            "DexClassLoader or InMemoryDexClassLoader usage",
            "Suspicious .init_array or JNI_OnLoad in native libs",
            "Very small shell DEX loading main payload",
            "Encrypted/compressed DEX stored in assets or native libs",
            "Anti-debugging and anti-VM checks present",
        ],
        recommendation="Packers provide strong protection but are often detectable by Google Play Protect. Use reputable packers like DexProtector, Arxan, or Tencent Legu. Test on actual devices.",
    ),
    ObfuscationTechnique(
        name="Resource Obfuscation",
        platform="android",
        description="Resource name and ID obfuscation. Resource names (strings.xml keys, layout names, drawable names) are shortened or randomized to hide the purpose of UI elements and string resources.",
        severity="low",
        indicators=[
            "Resource names are single characters or short random strings",
            "R$id fields with non-descriptive names",
            "Resources with base64-encoded or hashed names",
            "String resources with cryptic names",
        ],
        recommendation="Resource obfuscation prevents trivial identification of UI flows. Combined with string encryption, it is a useful additional layer.",
    ),
    ObfuscationTechnique(
        name="Arithmetic Obfuscation",
        platform="android",
        description="Arithmetic obfuscation — constant values are encoded using mathematical expressions (multiplication, XOR, addition chains) to hide magic numbers, sizes, and flags from static analysis.",
        severity="medium",
        indicators=[
            "Complex constant expressions computing simple values",
            "XOR chains for integer constants",
            "Expression trees for magic numbers",
            "Float/double encoding of integer constants",
        ],
        recommendation="Arithmetic obfuscation hinders trivial patching. Combine with DexGuard's constant encryption for stronger protection.",
    ),
]

IOS_OBFUSCATION_TECHNIQUES: list[ObfuscationTechnique] = [
    ObfuscationTechnique(
        name="Symbol Obfuscation",
        platform="ios",
        description="Symbol obfuscation — function names, class names, and global symbols in the Mach-O binary are renamed to short random strings, making disassembly and debugging much harder.",
        severity="high",
        indicators=[
            "High proportion of short (1-3 char) symbol names",
            "Symbol names appear randomized (no readable patterns)",
            "C++ symbol demangling shows obfuscated identifiers",
            "Large number of anonymous or stripped symbols",
            "Function names do not correspond to known API patterns",
        ],
        recommendation="Symbol obfuscation is a strong first line of defense for iOS binaries. Combine with OLLVM or other binary-level obfuscation for comprehensive protection.",
    ),
    ObfuscationTechnique(
        name="Objective-C Metadata Obfuscation",
        platform="ios",
        description="Objective-C runtime metadata (class names, selectors, protocols) are obfuscated to prevent easy identification of classes and methods via class-dump or runtime introspection.",
        severity="high",
        indicators=[
            "ObjC class names are single letters or short random strings",
            "Selector names do not match method implementations",
            "Proto/class name stripping detected",
            "Reduced ObjC metadata section size relative to code size",
            "Custom objc-runtime hooks for name resolution",
        ],
        recommendation="ObjC metadata obfuscation prevents trivial class-dump analysis. Verify that Apple's app review does not flag the obfuscation (some techniques may cause rejection).",
    ),
    ObfuscationTechnique(
        name="String Encryption (iOS)",
        platform="ios",
        description="String encryption in iOS native code — strings are encrypted in the Mach-O __text section and decrypted at runtime via XOR or custom algorithms.",
        severity="high",
        indicators=[
            "Character-by-character string building loops",
            "XOR decryption patterns in ARM64 assembly",
            "Encrypted string sections or obfuscated cstring sections",
            "Suspicious byte array initialization before string usage",
            "Decryption helper functions with key material",
        ],
        recommendation="String encryption is essential for protecting API keys and URLs. Ensure decryption happens at the latest possible moment and keys are not stored adjacent to ciphertexts.",
    ),
    ObfuscationTechnique(
        name="Obfuscator-LLVM (OLLVM) — iOS",
        platform="ios",
        description="Obfuscator-LLVM applied to iOS native code. Uses control flow flattening, bogus control flow, and instruction substitution at the LLVM IR level before compilation.",
        severity="critical",
        indicators=[
            "Control flow flattening (switch-based dispatchers in ARM64)",
            "Bogus control flow — unreachable code blocks with opaque predicates",
            "Extremely high cyclomatic complexity relative to function purpose",
            "Instruction substitution patterns (e.g., ADD replaced with multiple operations)",
            "LLVM obfuscation pass signatures in binary",
        ],
        recommendation="OLLVM provides very strong protection for iOS native code. Consider using it with Hikari or other LLVM-based obfuscators that include additional passes.",
    ),
    ObfuscationTechnique(
        name="Control Flow Flattening",
        platform="ios",
        description="Standalone control flow flattening (not OLLVM) — the function's control flow graph is flattened into a switch-dispatch pattern, making it extremely difficult to trace execution paths.",
        severity="high",
        indicators=[
            "Functions with a single entry and large switch dispatcher",
            "State variable manipulation before switch",
            "Basic blocks reordered with jump table dispatch",
            "No natural if/else or loop structure in decompiled output",
        ],
        recommendation="Control flow flattening is effective against manual static analysis. Combine with other techniques like opaque predicates for maximum impact.",
    ),
    ObfuscationTechnique(
        name="Anti-Hooking / Anti-Debugging",
        platform="ios",
        description="Anti-debugging and anti-hooking protections — ptrace() calls, sysctl() checks for debugger, symbolic breakpoint detection, and library injection detection.",
        severity="medium",
        indicators=[
            "ptrace(PT_DENY_ATTACH, ...) or sysctl() debugger checks",
            "svc 0x80 / svc 0x00 syscall instructions",
            "dladdr() or dlsym(RTLD_MAIN_ONLY) for breakpoint detection",
            "Library injection detection via _dyld_get_image_name()",
            "Memory region integrity checks",
        ],
        recommendation="Anti-debugging prevents runtime analysis. Be aware that these checks can be bypassed with Frida's anti-anti-debugging features. Combine with runtime integrity verification.",
    ),
]

ALL_TECHNIQUES: dict[str, list[ObfuscationTechnique]] = {
    "android": ANDROID_OBFUSCATION_TECHNIQUES,
    "ios": IOS_OBFUSCATION_TECHNIQUES,
}


def list_techniques(platform: str = "all") -> list[ObfuscationTechnique]:
    """List available obfuscation detection techniques."""
    if platform == "all":
        return ANDROID_OBFUSCATION_TECHNIQUES + IOS_OBFUSCATION_TECHNIQUES
    return ALL_TECHNIQUES.get(platform, [])


# ══════════════════════════════════════════════
# Detection Helpers
# ══════════════════════════════════════════════


def _walk_smali_files(decompile_dir: str) -> list[str]:
    """Walk decompiled smali directory and return all .smali file paths."""
    base = Path(decompile_dir)
    return [
        os.path.join(root, f)
        for root, _dirs, files in os.walk(base)
        for f in files
        if f.endswith(".smali")
    ]


def _walk_source_files(decompile_dir: str) -> list[str]:
    """Walk decompiled directory and return all relevant source files."""
    base = Path(decompile_dir)
    return [
        os.path.join(root, f)
        for root, _dirs, files in os.walk(base)
        for f in files
        if f.endswith((".smali", ".java", ".kt", ".xml", ".txt", ".properties"))
    ]


def _walk_native_libs(decompile_dir: str) -> list[str]:
    """Find all native (.so) libraries in the decompiled directory."""
    base = Path(decompile_dir)
    return [
        os.path.join(root, f)
        for root, _dirs, files in os.walk(base)
        for f in files
        if f.endswith(".so")
    ]


def _read_file_sample(path: str, max_bytes: int = 50_000) -> str:
    """Read a file sample, returning at most max_bytes as text (best-effort)."""
    try:
        with open(path, errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _count_files_matching(decompile_dir: str, pattern: str) -> int:
    """Count files whose content matches a regex pattern."""
    count = 0
    for root, _dirs, files in os.walk(decompile_dir):
        for f in files:
            if f.endswith((".smali", ".java", ".kt", ".xml", ".txt")):
                try:
                    filepath = os.path.join(root, f)
                    with open(filepath, errors="replace") as fh:
                        content = fh.read(100_000)
                        if re.search(pattern, content, re.IGNORECASE):
                            count += 1
                except Exception:
                    continue
    return count


def _grep_in_files(decompile_dir: str, pattern: str, max_results: int = 20) -> list[str]:
    """Search for a regex pattern across decompiled files."""
    results: list[str] = []
    for root, _dirs, files in os.walk(decompile_dir):
        for f in files:
            if f.endswith((".smali", ".java", ".kt", ".xml", ".txt")):
                try:
                    filepath = os.path.join(root, f)
                    with open(filepath, errors="replace") as fh:
                        content = fh.read(100_000)
                        for i, line in enumerate(content.splitlines(), 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                rel = os.path.relpath(filepath, decompile_dir)
                                results.append(f"{rel}:{i}: {line.strip()[:120]}")
                                if len(results) >= max_results:
                                    return results
                except Exception:
                    continue
    return results


# ══════════════════════════════════════════════
# Android Detection Functions
# ══════════════════════════════════════════════


def _detect_proguard(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect ProGuard/R8 obfuscation."""
    evidence: list[str] = []
    details: dict[str, Any] = {}
    confidence = "low"

    # Check for mapping.txt
    mapping_path = os.path.join(decompile_dir, "mapping.txt")
    if os.path.isfile(mapping_path):
        mapping_content = _read_file_sample(mapping_path)
        evidence.append(f"mapping.txt found ({len(mapping_content)} bytes)")
        confidence = "high"

    # Check for a.a.a style obfuscated class names in smali
    smali_files = _walk_smali_files(decompile_dir)
    obfuscated_classes = set()
    for smali in smali_files:
        content = _read_file_sample(smali, max_bytes=10_000)
        # Look for class definitions with single-letter or very short names
        matches = re.findall(r'\.class\s+.*?([a-z]\.[a-z]\.[a-z])', content)
        for m in matches:
            obfuscated_classes.add(m)
        # Also look for Lx/a/a/a; style references
        matches2 = re.findall(r'L[a-z]/[a-z]/[a-z]/', content)
        for m in matches2:
            obfuscated_classes.add(m.strip("L").rstrip("/"))

    if len(obfuscated_classes) > 5:
        evidence.append(f"Found {len(obfuscated_classes)} obfuscated class references (a.b.c style)")
        if confidence == "low":
            confidence = "high"
    elif len(obfuscated_classes) > 0:
        evidence.append(f"Found {len(obfuscated_classes)} potentially obfuscated class references")
        confidence = "medium"

    # Check for BuildConfig.MINIFIED
    minified_count = _count_files_matching(decompile_dir, r"MINIFIED\s*[:=]\s*true")
    if minified_count > 0:
        evidence.append(f"BuildConfig.MINIFIED=true found in {minified_count} files")
        confidence = "high"

    # Check for proguard configuration references
    proguard_refs = _grep_in_files(decompile_dir, r"proguard", max_results=3)
    if proguard_refs:
        evidence.append(f"ProGuard configuration references: {proguard_refs[0][:80]}")
        if confidence == "low":
            confidence = "medium"

    # Check for R$ obfuscation
    r_files = [f for f in smali_files if "R$" in f]
    obfuscated_r_fields = 0
    for rf in r_files[:20]:
        content = _read_file_sample(rf, max_bytes=5_000)
        # Look for short field names like .field public static final a:I
        if re.search(r'\.field\s+\S+\s+\S+\s+[a-z]:', content):
            obfuscated_r_fields += 1
    if obfuscated_r_fields > 5:
        evidence.append(f"R$ classes have {obfuscated_r_fields} obfuscated field names (a, b, c style)")
        confidence = "high"

    if not evidence:
        return None

    severity = "medium"
    if confidence == "high" and len(obfuscated_classes) > 20:
        severity = "high"

    details = {
        "obfuscated_class_refs": len(obfuscated_classes),
        "has_mapping_txt": os.path.isfile(mapping_path),
        "obfuscated_r_fields": obfuscated_r_fields,
    }

    return ObfuscationFinding(
        technique="ProGuard/R8",
        platform="android",
        description="Standard ProGuard or R8 obfuscation detected. Class, method, and field names have been renamed to short meaningless identifiers.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:8],
        details=details,
    )


def _detect_dexguard(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect DexGuard-specific obfuscation indicators."""
    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Check for encrypted strings (char[] XOR pattern in smali)
    encrypted_string_files = _grep_in_files(
        decompile_dir,
        r"xor|encrypt|decrypt|char\s*\[\s*\]\s*\w+\s*=\s*\{",
        max_results=10,
    )
    if encrypted_string_files:
        evidence.append(f"Potential string encryption patterns found in {len(encrypted_string_files)} locations")
        details["encrypted_string_hits"] = len(encrypted_string_files)

    # Check for DexGuard-specific assets
    assets_dir = os.path.join(decompile_dir, "assets")
    if os.path.isdir(assets_dir):
        dexguard_assets = [f for f in os.listdir(assets_dir) if "dexguard" in f.lower() or "dg" in f.lower()]
        if dexguard_assets:
            evidence.append(f"DexGuard-specific assets: {', '.join(dexguard_assets[:3])}")

    # Check for anti-tampering checks
    tamper_checks = _grep_in_files(
        decompile_dir,
        r"(signature|checksum|integrity|tamper|certificate|hash)\s*\.\s*(verify|check|validate|confirm)",
        max_results=5,
    )
    if tamper_checks:
        evidence.append(f"Anti-tampering integrity checks detected: {len(tamper_checks)} references")
        details["tamper_checks"] = len(tamper_checks)

    if not evidence:
        return None

    severity = "high" if len(evidence) >= 2 else "medium"
    confidence = "medium"

    return ObfuscationFinding(
        technique="DexGuard",
        platform="android",
        description="DexGuard or similar commercial obfuscation detected. Advanced protections including string encryption, class encryption, and anti-tampering are likely in use.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:6],
        details=details,
    )


def _detect_string_encryption(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect string encryption patterns in DEX bytecode."""
    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Look for XOR decryption patterns
    xor_patterns = _grep_in_files(
        decompile_dir,
        r"(xor|XOR)\s*[-:].*?(char|byte|int|key)",
        max_results=5,
    )
    if xor_patterns:
        evidence.append(f"XOR-based string decryption patterns: {len(xor_patterns)} locations")
        details["xor_patterns"] = len(xor_patterns)

    # Look for char[] array building
    char_array_patterns = _grep_in_files(
        decompile_dir,
        r"new-array\s+.*?char|char\s*\[\s*\]\s*\w+\s*=\s*new\s*char",
        max_results=8,
    )
    if char_array_patterns:
        evidence.append(f"Character array building (potential string decryption): {len(char_array_patterns)} usages")
        details["char_arrays"] = len(char_array_patterns)

    # Look for decryption helper method names
    decrypt_methods = _grep_in_files(
        decompile_dir,
        r"\.method\s+.*(decrypt|deobfuscat|getDecode|decodeString|getString)",
        max_results=5,
    )
    if decrypt_methods:
        evidence.append(f"String decryption helper methods: {len(decrypt_methods)}")
        details["decrypt_methods"] = len(decrypt_methods)

    # Check for AES/Cipher references
    cipher_refs = _grep_in_files(
        decompile_dir,
        r"AES|Cipher\.getInstance|SecretKeySpec|DESede",
        max_results=5,
    )
    if cipher_refs and decrypt_methods:
        evidence.append(f"Cipher/AES references: {len(cipher_refs)} (may indicate encrypted strings)")
        details["cipher_refs"] = len(cipher_refs)

    # Look for suspicious byte-to-string conversion
    byte_conv = _grep_in_files(
        decompile_dir,
        r"new\s+String\s*\(\s*[a-z]+\s*,\s*\"[^\"]*\"\s*\)|invoke-direct.*?String.*?\[B|bytes\s*=>\s*string",
        max_results=5,
    )
    if byte_conv:
        evidence.append(f"Suspicious byte-to-String conversions: {len(byte_conv)}")
        details["byte_conversions"] = len(byte_conv)

    if not evidence:
        return None

    severity = "high" if (details.get("xor_patterns", 0) + details.get("decrypt_methods", 0)) >= 3 else "medium"
    confidence = "medium"
    if details.get("xor_patterns", 0) >= 5:
        confidence = "high"

    return ObfuscationFinding(
        technique="String Encryption",
        platform="android",
        description="String encryption detected — sensitive strings are encrypted in the binary and decrypted at runtime using XOR, AES, or custom algorithms.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:6],
        details=details,
    )


def _detect_reflection_hiding(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect reflection-based API hiding."""
    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Count Class.forName() usages
    class_forname = _grep_in_files(
        decompile_dir,
        r"Class\s*\.\s*forName|Ljava/lang/Class;->forName",
        max_results=10,
    )
    if class_forname:
        evidence.append(f"Class.forName() usages: {len(class_forname)}")
        details["class_forname"] = len(class_forname)

    # Count Method.invoke() usages
    method_invoke = _grep_in_files(
        decompile_dir,
        r"Method\s*\.\s*invoke|Ljava/lang/reflect/Method;->invoke",
        max_results=10,
    )
    if method_invoke:
        evidence.append(f"Method.invoke() usages: {len(method_invoke)}")
        details["method_invoke"] = len(method_invoke)

    # Count getDeclaredMethod/getDeclaredField
    declared_ref = _grep_in_files(
        decompile_dir,
        r"getDeclaredMethod|getDeclaredField|getMethod|getField",
        max_results=10,
    )
    if declared_ref:
        evidence.append(f"getDeclared*/get* reflection methods: {len(declared_ref)}")
        details["declared_refs"] = len(declared_ref)

    # Count DexClassLoader usages
    dex_loader = _grep_in_files(
        decompile_dir,
        r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader",
        max_results=5,
    )
    if dex_loader:
        evidence.append(f"Dynamic class loading (DexClassLoader etc.): {len(dex_loader)}")
        details["dex_loaders"] = len(dex_loader)

    # String concatenation for class/method names
    concat_patterns = _grep_in_files(
        decompile_dir,
        r'"[A-Za-z]*"\s*\+\s*"[A-Za-z]*"\s*\+\s*"[A-Za-z]*"',
        max_results=5,
    )
    if concat_patterns:
        evidence.append(f"String concatenation (potential dynamic class/method name building): {len(concat_patterns)}")

    total_reflections = sum(details.values())
    if total_reflections < 5:
        return None

    severity = "high" if total_reflections > 15 else "medium"
    confidence = "medium" if total_reflections > 10 else "low"

    return ObfuscationFinding(
        technique="Reflection-Based Hiding",
        platform="android",
        description=f"Excessive reflection usage detected ({total_reflections} reflection API calls). Class and method names are likely hidden behind runtime reflection, making static analysis significantly harder.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:6],
        details=details,
    )


def _detect_ollvm_android(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect Obfuscator-LLVM in native .so libraries."""
    evidence: list[str] = []
    details: dict[str, Any] = {}
    native_libs = _walk_native_libs(decompile_dir)

    if not native_libs:
        return None

    details["native_lib_count"] = len(native_libs)
    details["native_libs"] = [os.path.basename(lib) for lib in native_libs[:10]]

    # Check for UPX-packed libraries and OLLVM signatures in native libs
    upx_count = 0
    for lib in native_libs:
        if os.path.isfile(lib):
            try:
                with open(lib, "rb") as f:
                    header = f.read(4)
                    if header[:3] == b"UPX" or header == b"\x55\x50\x58\x21":
                        upx_count += 1
                        evidence.append(f"UPX-packed library: {os.path.basename(lib)}")
                    # Read more for OLLVM check
                    content = f.read(200_000)
                    if b"OLLVM" in content or b"ollvm" in content:
                        evidence.append(f"OLLVM signature found in: {os.path.basename(lib)}")
                        details["ollvm_confirmed"] = True
            except Exception:
                continue

    if upx_count > 0:
        details["upx_packed"] = upx_count

    # Check for strings in smali that reference JNI with obfuscated code
    jni_obfuscated = _grep_in_files(
        decompile_dir,
        r"native\s+.*(?:a|b|c|d)\s*\(",  # obfuscated native method declarations
        max_results=5,
    )
    if jni_obfuscated:
        evidence.append(f"Potentially obfuscated JNI native methods: {len(jni_obfuscated)}")
        details["obfuscated_jni_methods"] = len(jni_obfuscated)

    if not evidence:
        return None

    severity = "critical" if details.get("ollvm_confirmed") else "high"
    confidence = "high" if details.get("ollvm_confirmed") else "medium"

    return ObfuscationFinding(
        technique="Obfuscator-LLVM (OLLVM)",
        platform="android",
        description="Obfuscator-LLVM or similar native code obfuscation detected in native libraries. Control flow flattening, bogus control flow, and instruction substitution make native code reverse engineering extremely difficult.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:6],
        details=details,
    )


def _detect_packer(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect application packers and DEX protectors."""
    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Check for dynamic DEX loading
    dex_loader = _grep_in_files(
        decompile_dir,
        r"DexClassLoader|InMemoryDexClassLoader",
        max_results=5,
    )
    if dex_loader:
        evidence.append(f"DexClassLoader/InMemoryDexClassLoader references: {len(dex_loader)}")
        details["dex_loaders"] = len(dex_loader)

    # Check for anti-debugging / anti-VM checks
    anti_debug = _grep_in_files(
        decompile_dir,
        r"android\.os\.Debug|isDebuggerConnected|WaitForDebugger|TracerPid|android_id|ro\.debuggable|ro\.secure|Build\.FINGERPRINT",
        max_results=8,
    )
    if anti_debug:
        evidence.append(f"Anti-debugging/anti-VM checks: {len(anti_debug)}")
        details["anti_debug"] = len(anti_debug)

    # Check for small shell DEX (common in packed apps)
    smali_files = _walk_smali_files(decompile_dir)
    if len(smali_files) < 50:
        evidence.append(f"Very few smali classes ({len(smali_files)}) — possible shell DEX")
        details["small_dex"] = True

    # Check for native packer initialization
    native_init = _grep_in_files(
        decompile_dir,
        r"JNI_OnLoad|\.init\b|__attribute__\(\(constructor",
        max_results=5,
    )
    if native_init and len(native_init) > 3:
        evidence.append(f"Suspicious native initialization patterns: {len(native_init)}")

    # Check for packed native libraries
    native_libs = _walk_native_libs(decompile_dir)
    for lib in native_libs:
        try:
            with open(lib, "rb") as f:
                content = f.read(100_000)
                # Look for common packer signatures
                packer_sigs = [b"UPX!", b"LIEF", b"packed", b"protector"]
                for sig in packer_sigs:
                    if sig in content:
                        evidence.append(f"Packer signature '{sig.decode()}' in: {os.path.basename(lib)}")
                        details["packer_signature"] = sig.decode()
                        break
        except Exception:
            continue

    if not evidence:
        return None

    severity = "critical" if details.get("dex_loaders", 0) > 0 else "high"
    confidence = "high" if len(evidence) >= 2 else "medium"

    return ObfuscationFinding(
        technique="Packer / DEX Protection",
        platform="android",
        description="Application packer or DEX protector detected. The app's bytecode is likely encrypted or compressed and dynamically loaded at runtime.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:6],
        details=details,
    )


def _detect_resource_obfuscation(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect resource name obfuscation."""
    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Check R$ fields for obfuscated names
    smali_files = _walk_smali_files(decompile_dir)
    r_files = [f for f in smali_files if "R$" in os.path.basename(f)]

    obfuscated_resources = 0
    total_resources = 0
    for rf in r_files[:30]:
        content = _read_file_sample(rf, max_bytes=10_000)
        # Count field definitions
        fields = re.findall(r'\.field\s+\S+\s+\S+\s+(\w+):', content)
        total_resources += len(fields)
        # Count single-letter fields
        single_letter = [f for f in fields if len(f) == 1 and f.isalpha()]
        obfuscated_resources += len(single_letter)

    if total_resources > 0 and obfuscated_resources > 0:
        pct = (obfuscated_resources / total_resources) * 100
        if pct > 50:
            evidence.append(f"Resource obfuscation: {obfuscated_resources}/{total_resources} fields are single-letter ({pct:.0f}%)")
            details["obfuscation_pct"] = round(pct, 1)
            details["obfuscated_fields"] = obfuscated_resources
            details["total_fields"] = total_resources

    # Check strings.xml for cryptic name= attributes
    for root, _dirs, files in os.walk(Path(decompile_dir) / "res"):
        for f in files:
            if f == "strings.xml":
                content = _read_file_sample(os.path.join(root, f), max_bytes=50_000)
                cryptic_names = re.findall(r'name="([a-z]{1,3})"', content)
                if len(cryptic_names) > 10:
                    evidence.append(f"String resources with short cryptic names: {len(cryptic_names)} (e.g., '{cryptic_names[0]}', '{cryptic_names[1]}')")
                    details["cryptic_string_names"] = len(cryptic_names)
                break

    if not evidence:
        return None

    return ObfuscationFinding(
        technique="Resource Obfuscation",
        platform="android",
        description="Resource names have been obfuscated. Resource IDs and string names use short or randomized identifiers, making it harder to infer UI flows from resource names alone.",
        severity="low",
        confidence="medium",
        evidence=evidence[:4],
        details=details,
    )


def _detect_arithmetic_obfuscation(decompile_dir: str) -> ObfuscationFinding | None:
    """Detect arithmetic obfuscation of constants."""
    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Look for const operations with XOR chains
    const_xor = _grep_in_files(
        decompile_dir,
        r"const\s+.*?,\s*0x[a-f0-9]+\s*.*?\n.*?xor-int",
        max_results=5,
    )
    if const_xor:
        evidence.append(f"Constant XOR encoding patterns: {len(const_xor)}")
        details["xor_constants"] = len(const_xor)

    # Look for complex arithmetic expressions
    arith_patterns = _grep_in_files(
        decompile_dir,
        r"mul-int.*?\n.*?add-int.*?\n.*?xor-int|xor-int.*?\n.*?xor-int",
        max_results=5,
    )
    if arith_patterns:
        evidence.append(f"Complex arithmetic chains (potential constant obfuscation): {len(arith_patterns)}")
        details["arith_chains"] = len(arith_patterns)

    if not evidence:
        return None

    return ObfuscationFinding(
        technique="Arithmetic Obfuscation",
        platform="android",
        description="Arithmetic obfuscation of constants detected. Integer constants, flags, and sizes are encoded using mathematical expressions to hide their true values from static analysis.",
        severity="medium",
        confidence="low",
        evidence=evidence[:4],
        details=details,
    )


# ══════════════════════════════════════════════
# iOS Detection Functions
# ══════════════════════════════════════════════


def _detect_symbol_obfuscation(binary_data: bytes | None) -> ObfuscationFinding | None:
    """Detect symbol obfuscation in Mach-O binary."""
    if not binary_data:
        return None

    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Extract printable strings from binary
    strings_found: list[str] = []
    current: list[bytes] = []
    for byte in binary_data:
        if 32 <= byte < 127:
            current.append(bytes([byte]))
        else:
            if current:
                s = b"".join(current).decode("ascii", errors="replace")
                if len(s) >= 4:
                    strings_found.append(s)
                current = []
    if current:
        s = b"".join(current).decode("ascii", errors="replace")
        if len(s) >= 4:
            strings_found.append(s)

    details["total_strings"] = len(strings_found)

    # Count short symbols (1-3 chars) that look like obfuscated names
    short_symbols = [s for s in strings_found if 1 <= len(s) <= 3 and s.isascii() and s.isidentifier()]
    if len(short_symbols) > 50:
        pct = (len(short_symbols) / max(len(strings_found), 1)) * 100
        evidence.append(f"High proportion of short (1-3 char) potential symbols: {len(short_symbols)} ({pct:.1f}% of strings)")
        details["short_symbols"] = len(short_symbols)
        details["short_symbol_pct"] = round(pct, 1)

    # Look for randomized-looking function names
    random_pattern = re.compile(r'^[_]?[a-zA-Z0-9]{8,12}$')
    random_symbols = [s for s in strings_found if random_pattern.match(s) and not s.startswith("_OBJC")]
    if len(random_symbols) > 20:
        evidence.append(f"Randomized symbol names detected: {len(random_symbols)} (pattern: 8-12 char alphanumeric)")
        details["random_symbols"] = len(random_symbols)

    # Check for C++ demangled symbol patterns that indicate obfuscation
    cpp_symbols = [s for s in strings_found if s.startswith(("__Z", "_Z"))]
    if cpp_symbols:
        evidence.append(f"C++ symbol count: {len(cpp_symbols)} (some may indicate OLLVM)")
        details["cpp_symbols"] = len(cpp_symbols)

    if not evidence:
        return None

    severity = "high" if details.get("random_symbols", 0) > 50 else "medium"
    confidence = "high" if details.get("random_symbols", 0) > 30 else "medium"

    return ObfuscationFinding(
        technique="Symbol Obfuscation",
        platform="ios",
        description="Symbol obfuscation detected in the Mach-O binary. Function and class names are renamed to short or randomized strings, making disassembly and static analysis significantly harder.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:4],
        details=details,
    )


def _detect_objc_metadata_obfuscation(binary_data: bytes | None, decompile_dir: str | None = None) -> ObfuscationFinding | None:
    """Detect Objective-C metadata obfuscation."""
    if not binary_data:
        return None

    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Look for ObjC class references in binary
    objc_class_pattern = re.compile(rb'_OBJC_CLASS_\$_([a-zA-Z_][a-zA-Z0-9_]*)')
    objc_classes = objc_class_pattern.findall(binary_data)
    details["objc_class_count"] = len(objc_classes)

    # Count single-letter ObjC class names
    class_names = [c.decode("ascii", errors="replace") for c in objc_classes]
    short_classes = [c for c in class_names if 1 <= len(c) <= 3]
    if short_classes and len(class_names) > 5:
        pct = (len(short_classes) / len(class_names)) * 100
        evidence.append(f"Short ObjC class names: {len(short_classes)}/{len(class_names)} ({pct:.0f}%)")
        details["short_objc_classes"] = len(short_classes)
        details["objc_obfuscation_pct"] = round(pct, 1)

    # Look for ObjC protocol/selector metadata
    objc_sel_pattern = re.compile(rb'_OBJC_SELECTOR_REFERENCES_\$|_OBJC_PROTOCOL_\$_')
    sel_refs = objc_sel_pattern.findall(binary_data)
    details["objc_metadata_refs"] = len(sel_refs)

    if details.get("objc_obfuscation_pct", 0) > 30:
        evidence.append(f"ObjC class names are significantly obfuscated ({details['objc_obfuscation_pct']:.0f}% short names)")

    # Check if protocol metadata is stripped
    if details.get("objc_metadata_refs", 100) < 10 and details.get("objc_class_count", 0) > 20:
        evidence.append("ObjC protocol metadata appears stripped or minimal")
        details["metadata_stripped"] = True

    if not evidence:
        return None

    severity = "high" if details.get("objc_obfuscation_pct", 0) > 50 else "medium"
    confidence = "high" if details.get("objc_obfuscation_pct", 0) > 40 else "medium"

    return ObfuscationFinding(
        technique="Objective-C Metadata Obfuscation",
        platform="ios",
        description="Objective-C runtime metadata obfuscation detected. Class names, selectors, and protocol metadata are obfuscated to prevent class-dump and runtime introspection.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:4],
        details=details,
    )


def _detect_ios_string_encryption(binary_data: bytes | None) -> ObfuscationFinding | None:
    """Detect string encryption in iOS Mach-O binary."""
    if not binary_data:
        return None

    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Look for XOR patterns in __text section or cstring section analysis
    # Check if cstrings section is unusually small for the binary size
    cstring_markers = [b"cfstring", b"__cstring", b"__objc_string"]
    cstring_hits = 0
    for marker in cstring_markers:
        cstring_hits += binary_data.count(marker)

    details["cstring_markers"] = cstring_hits

    # Look for character-by-character building patterns (common in string encryption)
    char_build_pattern = re.compile(rb'mov\s+w\d+,\s*#0x[0-9a-f]{2}\s*\n\s*strb\s+w\d+', re.IGNORECASE)
    char_builds = len(char_build_pattern.findall(binary_data[:500_000]))
    if char_builds > 10:
        evidence.append(f"Character-by-character string build patterns: {char_builds} (potential string decryption)")
        details["char_builds"] = char_builds

    # Look for suspicious byte arrays in __text section
    byte_array_pattern = re.compile(rb'\x00[\x20-\x7e]\x00[\x20-\x7e]\x00[\x20-\x7e]')
    byte_arrays = len(byte_array_pattern.findall(binary_data[:500_000]))
    if byte_arrays > 100:
        evidence.append(f"Suspicious interleaved byte arrays (potential encrypted strings): {byte_arrays}")
        details["byte_arrays"] = byte_arrays

    if not evidence:
        return None

    return ObfuscationFinding(
        technique="String Encryption (iOS)",
        platform="ios",
        description="String encryption detected in the iOS binary. Strings appear to be encrypted and decrypted at runtime, protecting sensitive API endpoints, keys, and error messages.",
        severity="high",
        confidence="medium",
        evidence=evidence[:4],
        details=details,
    )


def _detect_ios_ollvm(binary_data: bytes | None) -> ObfuscationFinding | None:
    """Detect Obfuscator-LLVM in iOS binary."""
    if not binary_data:
        return None

    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Look for control flow flattening patterns (switch dispatchers)
    # Common pattern in ARM64: large switch table with state variable
    switch_pattern = re.compile(rb'\xff\x83\x00\xd1|\xe0\x07\x00\xb4|\x1f\x20\x03\xd5')
    switch_hits = len(switch_pattern.findall(binary_data[:500_000]))
    if switch_hits > 100:
        evidence.append(f"High number of function prologue / switch patterns: {switch_hits} (potential CF flattening)")
        details["cf_flattening_hits"] = switch_hits
        if switch_hits > 300:
            severity = "critical"
            confidence = "high"
        elif switch_hits > 150:
            severity = "high"
            confidence = "medium"
        else:
            severity = "medium"
            confidence = "low"

    # Look for bogus control flow (opaque predicates)
    # ARM64: tst w0, #1; b.eq; b.ne (always taken branch patterns)
    opaque_predicates = re.compile(rb'\x20\x00\x00\x36|\x00\x00\x00\x54|\x01\x00\x00\x54')
    opaque_hits = len(opaque_predicates.findall(binary_data[:500_000]))
    details["opaque_predicate_hits"] = opaque_hits

    # Check for high instruction count in small functions (instruction substitution)
    # This is hard to detect statically without disassembly, check for string signatures
    if b"flattening" in binary_data or b"bogus" in binary_data:
        evidence.append("Control flow obfuscation string references found in binary")
        details["ollvm_string_ref"] = True

    if not evidence and opaque_hits < 50:
        return None

    if switch_hits > 100:
        evidence.append(f"Control flow flattening detected ({switch_hits} switch/dispatcher patterns)")

    severity = "critical" if details.get("cf_flattening_hits", 0) > 300 else "high"
    confidence = "high" if details.get("cf_flattening_hits", 0) > 200 else "medium"

    return ObfuscationFinding(
        technique="Obfuscator-LLVM (OLLVM) — iOS",
        platform="ios",
        description="Obfuscator-LLVM or control flow obfuscation detected in the iOS binary. Control flow flattening and opaque predicates make reverse engineering of native code extremely difficult.",
        severity=severity,
        confidence=confidence,
        evidence=evidence[:4],
        details=details,
    )


def _detect_ios_control_flow(decompile_dir: str | None) -> ObfuscationFinding | None:
    """Detect standalone control flow flattening (non-OLLVM)."""
    if not decompile_dir:
        return None
    # For IPA analysis, we check for patterns in extracted binary data
    # This is mainly covered by OLLVM detection above
    return None


def _detect_ios_anti_hooking(ipa_extract_dir: str | None) -> ObfuscationFinding | None:
    """Detect anti-hooking and anti-debugging in iOS binary."""
    if not ipa_extract_dir:
        return None

    evidence: list[str] = []
    details: dict[str, Any] = {}

    # Look for ptrace PT_DENY_ATTACH in binary data
    binary_files: list[str] = []
    for root, _dirs, files in os.walk(ipa_extract_dir):
        for f in files:
            # Only check Mach-O binaries (executables, dylibs, bundles)
            path = os.path.join(root, f)
            if os.path.isfile(path) and os.path.getsize(path) > 1000:
                try:
                    with open(path, "rb") as fh:
                        header = fh.read(4)
                        # Check for Mach-O magic numbers
                        if header in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
                            binary_files.append(path)
                except Exception:
                    continue

    for bf in binary_files:
        if not os.path.isfile(bf):
            continue
        try:
            with open(bf, "rb") as fh:
                content = fh.read(500_000)
        except Exception:
            continue
        # ptrace syscall pattern in ARM64: mov x0, #31; mov x1, #0; mov x2, #0; mov x3, #0; mov x16, #26; svc #0x80
        if b"\x1f\x20\x03\xd5" in content:  # svc #0x80
            evidence.append(f"ptrace syscall detected in: {os.path.basename(bf)}")
            details["ptrace_detected"] = True
        # sysctl for debugger check
        if b"sysctl" in content:
            evidence.append(f"sysctl reference (debugger check) in: {os.path.basename(bf)}")
            details["sysctl_detected"] = True
        # dladdr/dlsym for breakpoint detection
        if b"dladdr" in content or b"dlsym" in content:
            details["dladdr_detected"] = True

    if not evidence:
        return None

    return ObfuscationFinding(
        technique="Anti-Hooking / Anti-Debugging",
        platform="ios",
        description="Anti-debugging and anti-hooking protections detected. The app actively prevents debugger attachment and may detect runtime instrumentation.",
        severity="medium",
        confidence="high",
        evidence=evidence[:4],
        details=details,
    )


# ══════════════════════════════════════════════
# ObfuscationDetector — Main Class
# ══════════════════════════════════════════════


class ObfuscationDetector:
    """Detect code obfuscation techniques in mobile applications.

    Analyzes decompiled APK directories, IPA extractions, and binary data
    to identify a wide range of obfuscation techniques.
    """

    def __init__(self) -> None:
        self._findings: list[ObfuscationFinding] = []

    def analyze_apk(
        self,
        decompile_dir: str | None = None,
        smali_files: list[str] | None = None,
    ) -> ObfuscationReport:
        """Analyze decompiled APK directory for obfuscation.

        Args:
            decompile_dir: Path to decompiled APK directory (from apktool).
            smali_files: Optional pre-read list of smali file paths.

        Returns:
            ObfuscationReport with all findings.
        """
        import time

        start = time.time()
        self._findings = []

        if not decompile_dir or not os.path.isdir(decompile_dir):
            return ObfuscationReport(
                platform="android",
                findings=[],
                analysis_time_ms=int((time.time() - start) * 1000),
            )

        # Run all Android detection checks
        checks = [
            _detect_proguard,
            _detect_dexguard,
            _detect_string_encryption,
            _detect_reflection_hiding,
            _detect_ollvm_android,
            _detect_packer,
            _detect_resource_obfuscation,
            _detect_arithmetic_obfuscation,
        ]

        for check in checks:
            finding = self._run_check(check, decompile_dir, "android")
            if finding:
                self._findings.append(finding)

        return self._build_report("android", start)

    def analyze_ipa(
        self,
        ipa_extract_dir: str | None = None,
        binary_data: bytes | None = None,
    ) -> ObfuscationReport:
        """Analyze extracted IPA directory for obfuscation.

        Args:
            ipa_extract_dir: Path to extracted IPA directory.
            binary_data: Pre-read Mach-O binary data (optional, for analysis without extraction).

        Returns:
            ObfuscationReport with all findings.
        """
        import time

        start = time.time()
        self._findings = []

        # Try to read binary data if not provided but extract dir is given
        if binary_data is None and ipa_extract_dir:
            for root, _dirs, files in os.walk(ipa_extract_dir):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        with open(path, "rb") as fh:
                            header = fh.read(4)
                            if header in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
                                fh.seek(0)
                                binary_data = fh.read(1_000_000)
                                break
                    except Exception:
                        continue

        if not binary_data and not ipa_extract_dir:
            return ObfuscationReport(
                platform="ios",
                findings=[],
                analysis_time_ms=int((time.time() - start) * 1000),
            )

        # Run all iOS detection checks
        checks = [
            lambda d=None: _detect_symbol_obfuscation(binary_data),
            lambda d=None: _detect_objc_metadata_obfuscation(binary_data),
            lambda d=None: _detect_ios_string_encryption(binary_data),
            lambda d=None: _detect_ios_ollvm(binary_data),
            lambda d=None: _detect_ios_control_flow(ipa_extract_dir),
            lambda d=None: _detect_ios_anti_hooking(ipa_extract_dir),
        ]

        for check in checks:
            finding = self._run_check(check, None, "ios")
            if finding:
                self._findings.append(finding)

        return self._build_report("ios", start)

    def _build_report(self, platform: str, start_time: float) -> ObfuscationReport:
        import time

        total_weighted = sum(f.score for f in self._findings)
        if total_weighted >= 15:
            risk = "critical"
        elif total_weighted >= 10:
            risk = "high"
        elif total_weighted >= 5:
            risk = "medium"
        elif total_weighted >= 2:
            risk = "low"
        else:
            risk = "info"

        return ObfuscationReport(
            platform=platform,
            findings=sorted(self._findings, key=lambda f: f.score, reverse=True),
            total_score=total_weighted,
            risk_level=risk,
            analysis_time_ms=int((time.time() - start_time) * 1000),
        )

    def _run_check(self, check_fn: Any, arg: str | None, platform: str) -> ObfuscationFinding | None:
        """Run a detection check safely, returning a finding or error finding."""
        try:
            if arg is None:
                finding = check_fn()
            else:
                finding = check_fn(arg)
            return finding
        except Exception as exc:
            return ObfuscationFinding(
                technique="Detection Error",
                platform=platform,
                description=f"Error running detection check: {exc!s}",
                severity="info",
                confidence="low",
            )


# ══════════════════════════════════════════════
# Serialization
# ══════════════════════════════════════════════


def format_report(report: ObfuscationReport) -> dict[str, Any]:
    """Serialize an ObfuscationReport to a JSON-compatible dict."""
    return {
        "platform": report.platform,
        "total_score": report.total_score,
        "risk_level": report.risk_level,
        "total_findings": report.total_findings,
        "obfuscated": report.protected,
        "obfuscation_score": report.obfuscation_score,
        "analysis_time_ms": report.analysis_time_ms,
        "findings": [
            {
                "technique": f.technique,
                "platform": f.platform,
                "description": f.description,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "details": f.details,
            }
            for f in report.findings
        ],
    }
