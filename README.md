# MobileSentry 📱🔒

**Mobile Application Security Testing Framework** — A comprehensive toolkit for Android (APK) and iOS (IPA) application security analysis, static/dynamic analysis, traffic interception, and automated OWASP Mobile Top 10 checks with bypass techniques.

> ✅ **Status:** Alpha — All 9 phases complete.

---

## Features

### Phase 1 — APK Analyzer ✅
- **APK Decompilation** — Decompile APKs via apktool with directory tree visualization
- **Manifest Analysis** — Extract package name, version, SDK levels, debuggable flag, allowBackup, network security config, signing info
- **Permission Analysis** — List all declared permissions classified by severity (dangerous/normal/signature/custom) with counts
- **Component Enumeration** — Activities, services, receivers, and content providers with export status and intent-filter detection
- **Security Misconfiguration Checks** — 8 automated checks:
  - Debuggable flag detection
  - Backup enabled vulnerability
  - Missing network security config
  - Low minSdkVersion targeting
  - Unnecessarily exported components
  - Excessive permission requests
  - Sensitive permission combinations (Camera+Mic, Location+Background, etc.)
- **Hardcoded Secrets Detection** — 23 regex patterns scanning decompiled source for:
  - AWS keys, GitHub tokens, Slack tokens, JWT tokens
  - Firebase URLs, Google API keys
  - Passwords, connection strings, private keys
  - OAuth secrets, API keys, and more
- **Statistics** — File counts, DEX classes, native code detection, obfuscation detection, analysis timing
- **JSON Export** — Full structured report for integration with other tools
- **Rich Terminal Output** — Color-coded severity badges, formatted tables, panels, and progress spinners

### Completed Phases
| Phase | Module | Status |
|-------|--------|--------|
| 1 | APK Analyzer | ✅ Complete |
| 2 | IPA Analyzer | ✅ Complete |
| 3 | Static Analysis Engine (OWASP Mobile Top 10) | ✅ Complete |
| 4 | SSL Pinning Bypass (Frida) | ✅ Complete |
| 5 | Root/Jailbreak Detection Bypass (Frida) | ✅ Complete |
| 6 | Traffic Interception (MITM, HAR analysis, TLS) | ✅ Complete |
| 7 | Dynamic Analysis | ✅ Complete |
| 8 | Code Obfuscation Detection | ✅ Complete |
| 9 | Report Generation | ✅ Complete |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Yash-Patil-1/mobilesentry.git
cd mobilesentry

# Install with pip (recommended)
pip install -e .

# Or install with extra dependencies
pip install -e ".[analyze]"    # For APK analysis (androguard)
pip install -e ".[all]"        # All extras
```

### System Dependencies

**APK Analyzer** requires:
- **apktool** — For APK decompilation (secrets scanning)
- **Java Runtime** — Required by apktool

**IPA Analyzer** requires:
- **plutil** — macOS utility for plist conversion (or handled gracefully)
- **unzip** — For IPA extraction (ZIP archive)
- **file** — For Mach-O binary detection
- **otool** — Optional, for encryption detection (macOS only)

```bash
# Ubuntu/Debian
sudo apt install apktool default-jre unzip file

# macOS
brew install apktool
```

---

## Usage

### Frida — SSL Pinning Bypass Script Generation
```bash
# List all available bypass techniques
mobilesentry frida list

# List only Android techniques
mobilesentry frida list android

# List only iOS techniques
mobilesentry frida list ios

# Generate all SSL bypass scripts (both platforms)
mobilesentry frida generate

# Generate only Android scripts
mobilesentry frida generate android

# Generate only iOS scripts
mobilesentry frida generate ios

# Specify custom output directory
mobilesentry frida generate all --output ./my_frida_scripts
```

Generated scripts are organized by platform:
```
frida_scripts/
├── android/
│   ├── ssl_universal_android.js       # 🌟 Best — hooks SSLContext, OkHttp, WebView, TrustKit
│   ├── ssl_okhttp_android.js           # 🎯 Targeted — OkHttp3/4 CertificatePinner
│   ├── ssl_trustmanager_android.js     # ✅ Good — Custom TrustManager injection
│   ├── ssl_webview_android.js          # 🎯 Targeted — WebView SSL error bypass
│   ├── ssl_flutter_android.js          # ✅ Good — Flutter SSL bypass (Dart + native)
│   └── ssl_xamarin_android.js          # 🎯 Targeted — Xamarin.Android SSL bypass
└── ios/
    ├── ssl_universal_ios.js            # 🌟 Best — NSURLSession, AFNetworking, TrustKit
    ├── ssl_afnetworking_ios.js         # 🎯 Targeted — AFSecurityPolicy bypass
    ├── ssl_alamofire_ios.js            # 🎯 Targeted — Alamofire ServerTrustManager
    ├── ssl_trustkit_ios.js             # 🎯 Targeted — TrustKit library bypass
    ├── ssl_flutter_ios.js              # ✅ Good — Flutter iOS SSL bypass
    └── ssl_nsurlsession_ios.js         # ✅ Good — Pure NSURLSession/NSURLConnection
```

Quick usage with Frida:
```bash
# Attach to a running Android app
frida -U com.target.app -l frida_scripts/android/ssl_universal_android.js

# Spawn and inject into Android app
frida -U -f com.target.app -l frida_scripts/android/ssl_universal_android.js --no-pause

# Spawn and inject into iOS app
frida -U -f com.target.app -l frida_scripts/ios/ssl_universal_ios.js
```

### Frida — Root/Jailbreak Detection Bypass Script Generation
```bash
# List all available root/jailbreak bypass techniques
mobilesentry frida root-bypass list

# List only Android techniques
mobilesentry frida root-bypass list android

# List only iOS techniques
mobilesentry frida root-bypass list ios

# Generate all root/jailbreak bypass scripts (both platforms)
mobilesentry frida root-bypass generate

# Generate only Android root bypass scripts
mobilesentry frida root-bypass generate android

# Generate only iOS jailbreak bypass scripts
mobilesentry frida root-bypass generate ios

# Specify custom output directory
mobilesentry frida root-bypass generate all --output ./my_bypass_scripts
```

Generated scripts are organized by platform:
```
bypass_scripts/
├── android/
│   ├── root_universal_android.js       # 🌟 Best — Hooks File.exists, Runtime.exec, System.getProperty, Build.TAGS,
│   │                                      ProcessBuilder, native access/stat, RootBeer, Superuser, Magisk
│   ├── root_magisk_android.js           # 🎯 Targeted — Magisk-specific bypass (paths, env, mounts, Zygisk)
│   ├── root_rootbeer_android.js         # 🎯 Targeted — RootBeer library bypass (all methods + native lib)
│   └── root_safetynet_android.js        # 🎯 Targeted — SafetyNet/Play Integrity API bypass
└── ios/
    ├── root_universal_ios.js            # 🌟 Best — Hooks NSFileManager, stat/access/open, fork/system, dlopen,
    │                                      canOpenURL, sysctl, proc_info, sandbox, NSTask
    ├── root_cydia_ios.js                # 🎯 Targeted — Cydia/Substrate app & library detection bypass
    ├── root_liberty_ios.js              # 🎯 Targeted — Libhooker/rootless jailbreak bypass (Dopamine, Xina)
    └── root_rootful_ios.js              # 🎯 Targeted — Rootful jailbreak bypass (unc0ver, checkra1n)
```

Quick usage with Frida:
```bash
# Attach to a running Android app
frida -U com.target.app -l bypass_scripts/android/root_universal_android.js

# Spawn and inject into iOS app
frida -U -f com.target.app -l bypass_scripts/ios/root_universal_ios.js
```

### Frida — Runtime Monitoring Script Generation & Trace Analysis (Dynamic Analysis)
```bash
# List all available runtime monitoring techniques
mobilesentry frida dynamic list

# List only Android techniques
mobilesentry frida dynamic list android

# List only iOS techniques
mobilesentry frida dynamic list ios

# Generate all runtime monitor scripts (both platforms)
mobilesentry frida dynamic generate

# Generate only Android monitor scripts
mobilesentry frida dynamic generate android

# Generate only iOS monitor scripts
mobilesentry frida dynamic generate ios

# Specify custom output directory
mobilesentry frida dynamic generate all --output ./my_monitor_scripts

# Analyze a captured trace file
mobilesentry frida dynamic trace trace.json
```

Generated scripts are organized by platform:
```
monitor_scripts/
├── android/
│   ├── monitor_universal_android.js       # 🌟 Best — method calls, file I/O, crypto, DB, network, permissions
│   ├── monitor_method_tracer_android.js   # ✅ Good — lightweight sensitive API tracing (Telephony, Accounts, Location, Camera, WebView)
│   ├── monitor_crypto_android.js          # 🎯 Targeted — Cipher, KeyGenerator, MessageDigest, KeyStore, Signature
│   ├── monitor_database_android.js        # 🎯 Targeted — SQLiteDatabase, Room, ContentResolver queries
│   ├── monitor_file_io_android.js         # 🎯 Targeted — File, RandomAccessFile, Context directories, FileObserver
│   └── monitor_network_android.js         # 🎯 Targeted — HttpURLConnection, OkHttp, WebSocket, DownloadManager
└── ios/
    ├── monitor_universal_ios.js           # 🌟 Best — NSFileManager, NSUserDefaults, Keychain, NSURLSession, CLLocation
    └── monitor_method_tracer_ios.js       # ✅ Good — UIDevice, UIApplication, AVCaptureDevice, CNContactStore, WKWebView, CommonCrypto
```

Quick usage with Frida:
```bash
# Attach to a running Android app and capture trace output
frida -U com.target.app -l monitor_scripts/android/monitor_universal_android.js 2>&1 | tee trace.json

# Spawn and inject into app
frida -U -f com.target.app -l monitor_scripts/android/monitor_universal_android.js --no-pause 2>&1 | tee trace.json

# Analyze the captured trace
mobilesentry frida dynamic trace trace.json
```

The `DynamicAnalyzer` produces a comprehensive report including:
- Event type breakdown (method_calls, file_io, crypto, db_query, network, permission)
- Top methods called with call counts
- Behavioral security findings (crypto volume, sensitive files, SQL injection risks, HTTP requests)
- Sensitive API usage inventory
- Call graph visualization (nodes and edges)

### Code Obfuscation Detection
```bash
# List all available obfuscation detection techniques (Android + iOS)
mobilesentry obfuscation list

# Analyze an APK for obfuscation
mobilesentry obfuscation analyze app.apk

# Analyze an IPA for obfuscation
mobilesentry obfuscation analyze app.ipa

# Export results as JSON
mobilesentry obfuscation analyze app.apk --json
```

Obfuscation detection techniques by platform:

**Android (8 techniques):**
| Technique | Severity | Description |
|-----------|----------|-------------|
| ProGuard/R8 | 🟡 Medium | Standard class/method/field renaming, minification, mapping.txt checks |
| DexGuard | 🔴 High | Commercial obfuscation — string encryption, class encryption, anti-tampering |
| String Encryption | 🔴 High | XOR/AES-based string decryption, char[] building, decryption helpers |
| Reflection Hiding | 🔴 High | Class.forName(), Method.invoke(), DexClassLoader for dynamic dispatch |
| Obfuscator-LLVM | 🔴 Critical | Native (.so) code obfuscation — CF flattening, bogus control flow, instruction substitution |
| Packer/DEX Protection | 🔴 Critical | UPX packing, DEX encryption, DexClassLoader payloads, anti-debugging |
| Resource Obfuscation | 🔵 Low | Shortened/randomized resource names and IDs |
| Arithmetic Obfuscation | 🟡 Medium | Constant encoding via expressions, XOR chains |

**iOS (6 techniques):**
| Technique | Severity | Description |
|-----------|----------|-------------|
| Symbol Obfuscation | 🔴 High | Random short function/class symbol names preventing disassembly |
| ObjC Metadata Obfuscation | 🔴 High | Obfuscated class names, selectors, protocol metadata |
| String Encryption (iOS) | 🔴 High | Encrypted cstrings, character-by-character decryption in ARM64 |
| OLLVM (iOS) | 🔴 Critical | LLVM-level CF flattening, bogus CF, instruction substitution |
| Control Flow Flattening | 🔴 High | Switch-dispatch pattern flattening of function CFG |
| Anti-Hooking/Anti-Debug | 🟡 Medium | ptrace(), sysctl(), dladdr() debugger/hooking detection |

### Traffic Interception — MITM Proxy Setup & Analysis
```bash
# Generate all mitmproxy addon scripts (full, minimal, auth)
mobilesentry traffic setup

# Generate only the full-featured addon with device setup guide
mobilesentry traffic setup full --guide

# Generate auth-focused addon
mobilesentry traffic setup auth

# Custom output directory
mobilesentry traffic setup all --output ./my_mitmproxy
```

Generated addons are organized by type:
```
mitmproxy_config/
├── mobilesentry_addon.py             # 🌟 Full — Real-time security analysis + HAR capture
├── mobilesentry_minimal_addon.py     # 📦 Minimal — Lightweight HAR capture only
├── mobilesentry_auth_addon.py        # 🔑 Auth — OAuth/OIDC/token focused capture
└── DEVICE_SETUP.md                   # 📋 Device configuration guide
```

Intercept traffic:
```bash
# Start mitmproxy with the full addon
mitmproxy -s mitmproxy_config/mobilesentry_addon.py

# Or headless capture with mitmdump
mitmdump -s mitmproxy_config/mobilesentry_addon.py

# Configure device proxy to <HOST_IP>:8080
# Install CA certificate: open http://mitm.it on device
```

### Traffic Analysis — HAR File Security Analysis
```bash
# Analyze a captured HAR file for security issues
mobilesentry traffic analyze capture.har
```

Analysis checks include:
- HTTPS vs HTTP ratio
- Missing security headers (HSTS, CSP, XFO, etc.)
- Cookie security attributes (Secure, HttpOnly, SameSite)
- Authentication header types (Bearer, Basic, API keys)
- Sensitive data exposure in URLs and response bodies
- TLS version and cipher analysis
- Weak cipher detection (RC4, DES, 3DES, etc.)

### TLS Certificate Analysis
```bash
# Analyze TLS certificates from captured traffic
mobilesentry traffic certs capture.har
```

Certificate analysis checks:
- Expiry dates and days until expiration
- Self-signed certificate detection
- Wildcard certificate detection
- Deprecated TLS versions (SSLv3, TLSv1.0, TLSv1.1)
- Weak cipher suite detection
- Certificate chain length

### Full APK Analysis
```bash
mobilesentry apk analyze app.apk
```

### Analysis with JSON Export
```bash
mobilesentry apk analyze app.apk --json
```

### Quick APK Info
```bash
mobilesentry apk info app.apk
```

### Decompile APK Only
```bash
mobilesentry apk decompile app.apk
```

### Scan for Hardcoded Secrets
```bash
mobilesentry apk secrets app.apk
```

### IPA Analysis
```bash
# Full IPA analysis
mobilesentry ipa analyze app.ipa

# Quick IPA info
mobilesentry ipa info app.ipa

# Extract IPA to .app bundle
mobilesentry ipa decompile app.ipa

# Scan for hardcoded secrets
mobilesentry ipa secrets app.ipa
```

### Unified Report Generation

Combine results from multiple analyzers into a single HTML, JSON, or Markdown report.

```bash
# Generate an HTML report from an APK analysis JSON file
mobilesentry report --apk ./mobilesentry_output/com.example_analysis.json --format html

# Combine APK + OWASP + obfuscation results
mobilesentry report --apk ./output/com.example_analysis.json --owasp ./output/com.example_owasp.json --obfuscation ./output/com.example_obfuscation.json

# Generate a JSON report (for CI/tooling integration)
mobilesentry report --apk ./result.json --format json

# Generate a Markdown report (for documentation)
mobilesentry report --apk ./result.json --format md --output ./REPORT.md
```

The generated HTML report includes:
- Executive summary with risk score (0–100)
- Severity distribution bar chart
- All findings sorted by severity (critical → info)
- Detailed APK metadata section
- Detailed IPA metadata section
- OWASP category breakdown
- Obfuscation detection results
- Dynamic analysis summary
- Traffic analysis overview
- Dark theme, responsive layout, collapsible sections

### Help
```bash
mobilesentry --help
mobilesentry apk --help
mobilesentry ipa --help
```

---

## Example Output

### APK Metadata
```
┌─────────────────────────────────────────────────────┐
│                    APK Metadata                      │
├──────────────────────┬──────────────────────────────┤
│ Package              │ com.example.app              │
│ Version              │ 2.1.0 (42)                   │
│ Min SDK              │ 26                            │
│ Target SDK           │ 34                            │
│ Size                 │ 12.4 MB                       │
│ Debuggable           │ ✅ No                         │
│ Allow Backup         │ ⚠️ Enabled                    │
│ Network Security     │ ⚠️ Missing                    │
│ Signed               │ ✅ Yes                        │
│ Signature            │ APK Signature Scheme v2       │
└──────────────────────┴──────────────────────────────┘
```

### Permission Analysis
Permissions are color-coded by severity:
- 🔴 **DANGEROUS** — Sensitive data access (Camera, Location, SMS, etc.)
- 🟠 **SIGNATURE** — System-level permissions
- 🔵 **UNKNOWN** — Custom or undocumented permissions
- ✅ **NORMAL** — Low-risk permissions (Internet, Network, etc.)

### Security Issues
Each issue is displayed in a bordered panel with:
- Severity badge (CRITICAL/HIGH/MEDIUM/LOW)
- Description explaining the vulnerability
- Actionable recommendation

### Secrets Detection
Hardcoded secrets are displayed in a table with severity, type, truncated value, file path, and line number.

---

## Architecture

```
mobilesentry/
├── mobilesentry/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # Python -m entry point
│   ├── cli.py               # CLI with argparse + Rich formatting
│   ├── apk_analyzer.py      # Android APK analysis engine
│   ├── ipa_analyzer.py      # iOS IPA analysis engine
│   ├── static_analyzer.py   # OWASP Mobile Top 10 static analysis
│   ├── ssl_pinning.py       # Frida SSL pinning bypass script generation
│   ├── root_bypass.py       # Frida root/jailbreak detection bypass script generation
│   ├── traffic_intercept.py   # MITM proxy setup, HAR analysis, TLS cert analysis
│   ├── dynamic_analyzer.py    # Runtime monitoring script gen + trace analysis
│   ├── obfuscation_detect.py  # Code obfuscation detection (ProGuard, OLLVM, packers, etc.)
│   └── config.py              # Configuration constants
├── pyproject.toml           # Package config + ruff rules
├── README.md
└── LICENSE
```

### APK Analysis Pipeline
```
APK File
    │
    ▼
androguard (APK loading)
    │
    ├── Parse AXML Manifest ──► Package, Version, SDK, Permissions, Components
    │
    ├── Security Checks ──► Debuggable, Backup, Exported Components, Permissions
    │
    ▼
apktool (Decompilation)
    │
    └── Source Scanning ──► 23 regex patterns for hardcoded secrets
    │
    ▼
JSON + Rich Terminal Output
```

### IPA Analysis Pipeline
```
IPA File
    │
    ▼
unzip (Extraction)
    │
    ├── Parse Info.plist ──► Bundle ID, Version, Min OS, SDK, Permissions
    │
    ├── Find .app Bundle ──► Frameworks, Entitlements, Binary
    │
    ├── Binary Analysis ──► Architectures, PIE, ARC, Stack Canary, Encryption
    │
    ├── SDK Detection ──► 65+ known frameworks matched
    │
    ├── Security Checks ──► ATS, File Sharing, Permissions, Entitlements
    │
    └── Source Scanning ──► 23 regex patterns for hardcoded secrets
    │
    ▼
JSON + Rich Terminal Output
```

---

## Security Checks

### APK Security Checks
| Check | Description | Severity |
|-------|-------------|----------|
| Debuggable App | `android:debuggable="true"` allows debugger attachment | 🔴 High |
| Backup Enabled | `android:allowBackup="true"` allows ADB data exfiltration | 🟡 Medium |
| Missing Network Config | No `networkSecurityConfig` = platform default cleartext policy | 🔵 Low |
| Low minSdkVersion | Targets outdated API levels lacking security features | 🟡 Medium |
| Exported Components | Components accessible from other apps without permission | 🟡 Medium |
| Excessive Permissions | 10+ dangerous permissions requested | 🟡 Medium |
| Sensitive Combos | Camera+Mic, Location+Background, etc. | 🔵 Low |

### IPA Security Checks
| Check | Description | Severity |
|-------|-------------|----------|
| ATS Disabled | `NSAllowsArbitraryLoads` enables cleartext HTTP | 🔴 High |
| Insecure HTTP Exceptions | Specific domains allowed to load over HTTP | 🟡 Medium |
| File Sharing Enabled | `UIFileSharingEnabled` exposes Documents via USB | 🟡 Medium |
| Missing PIE | Binary not position-independent (ROP vulnerable) | 🔴 High |
| Missing ARC | No Automatic Reference Counting (memory bugs) | 🟡 Medium |
| Missing Stack Canary | No stack overflow protection | 🔴 High |
| Missing Encryption | Binary not FairPlay encrypted (easier to RE) | 🟡 Medium |
| Risky Entitlements | Debugger attach, library injection, unsigned exec | 🔴 High |
| Excessive Permissions | 5+ high-risk permissions (camera, mic, location, etc.) | 🟡 Medium |

---

## License

MIT License — see [LICENSE](LICENSE)

## Author

**Yash Patil** — Cybersecurity Analyst | Penetration Tester

- GitHub: [@Yash-Patil-1](https://github.com/Yash-Patil-1)
- LinkedIn: [Yash Patil](https://www.linkedin.com/in/yash-patil-997357330)
