"""Dynamic Analysis — Runtime app monitoring and behavioral analysis for Android and iOS.

Generates Frida JavaScript (.js) scripts for runtime app monitoring including
method tracing, file I/O monitoring, crypto operation tracking, database query
logging, and network call monitoring. Includes a DynamicAnalyzer class for
parsing trace output and generating behavioral reports.

Usage:
    from mobilesentry.dynamic_analyzer import RuntimeMonitorGenerator
    from mobilesentry.dynamic_analyzer import DynamicAnalyzer

    gen = RuntimeMonitorGenerator(output_dir="./monitor_scripts")
    gen.generate_all()              # Generate all monitor scripts
    gen.generate_platform("android")  # Generate Android scripts only

    analyzer = DynamicAnalyzer()
    report = analyzer.analyze_trace("trace_output.json")
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────


@dataclass
class MonitorTechnique:
    """Metadata for a single runtime monitoring technique."""

    name: str
    platform: str  # "android", "ios"
    description: str
    monitor_targets: list[str]  # What the script monitors (e.g., "method_calls", "file_io", "crypto")
    quality: str  # "best", "good", "targeted"
    min_frida_version: str = "12.0"
    warnings: list[str] = field(default_factory=list)


@dataclass
class GeneratedScript:
    """A generated Frida script with metadata."""

    filename: str
    technique: MonitorTechnique
    code: str
    output_path: str = ""

    @property
    def size_bytes(self) -> int:
        return len(self.code.encode("utf-8"))


@dataclass
class TraceEvent:
    """A single trace event captured during runtime monitoring."""

    timestamp: float = 0.0
    event_type: str = ""  # method_call, file_io, crypto, db_query, network, permission
    thread_id: int = 0
    class_name: str = ""
    method_name: str = ""
    args: list[str] = field(default_factory=list)
    return_value: str = ""
    duration_ms: float = 0.0
    stack_depth: int = 0
    platform: str = ""


@dataclass
class BehavioralFinding:
    """A behavioral security finding detected during dynamic analysis."""

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # crypto, file_io, network, data_access, permission, suspicious
    evidence: list[str] = field(default_factory=list)
    count: int = 0
    recommendation: str = ""


@dataclass
class DynamicAnalysisReport:
    """Complete dynamic analysis report from trace data."""

    app_name: str = ""
    platform: str = ""
    analysis_timestamp: str = ""
    total_events: int = 0
    duration_seconds: float = 0.0
    events_by_type: dict[str, int] = field(default_factory=dict)
    methods_called: dict[str, int] = field(default_factory=dict)
    files_accessed: list[str] = field(default_factory=list)
    crypto_operations: list[dict[str, str]] = field(default_factory=list)
    db_queries: list[str] = field(default_factory=list)
    network_requests: list[dict[str, str]] = field(default_factory=list)
    permission_checks: list[str] = field(default_factory=list)
    sensitive_apis: list[dict[str, Any]] = field(default_factory=list)
    findings: list[BehavioralFinding] = field(default_factory=list)
    call_graph: dict[str, list[str]] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[BehavioralFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[BehavioralFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_name": self.app_name,
            "platform": self.platform,
            "analysis_timestamp": self.analysis_timestamp,
            "total_events": self.total_events,
            "duration_seconds": self.duration_seconds,
            "events_by_type": self.events_by_type,
            "top_methods": dict(
                sorted(self.methods_called.items(), key=lambda x: x[1], reverse=True)[:20]
            ),
            "files_accessed_count": len(self.files_accessed),
            "crypto_operations_count": len(self.crypto_operations),
            "db_queries_count": len(self.db_queries),
            "network_requests_count": len(self.network_requests),
            "permission_checks_count": len(self.permission_checks),
            "total_findings": self.total_findings,
            "critical_findings": len(self.critical_findings),
            "high_findings": len(self.high_findings),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "count": f.count,
                }
                for f in self.findings
            ],
        }


# ══════════════════════════════════════════════
# Constants — Sensitive API Patterns
# ══════════════════════════════════════════════

SENSITIVE_ANDROID_APIS: dict[str, str] = {
    "javax.crypto.Cipher": "Symmetric/Asymmetric encryption operation",
    "javax.crypto.KeyGenerator": "Key generation",
    "javax.crypto.SecretKeyFactory": "Secret key factory",
    "java.security.KeyStore": "Key store access (may leak credentials)",
    "javax.net.ssl.SSLContext": "SSL context initialization",
    "android.location.LocationManager": "Location access",
    "android.telephony.TelephonyManager": "Device identifier access (IMEI/IMSI)",
    "android.accounts.AccountManager": "Account credential access",
    "android.content.ContentResolver": "Content provider data access",
    "android.database.sqlite.SQLiteDatabase": "Database query execution",
    "java.net.HttpURLConnection": "HTTP network request",
    "okhttp3.OkHttpClient": "OkHttp network request",
    "android.webkit.WebView": "WebView usage (potential XSS)",
    "android.hardware.Camera": "Camera access",
    "android.media.MediaRecorder": "Audio recording",
    "android.content.SharedPreferences": "SharedPreferences access (local storage)",
    "java.io.FileInputStream": "File read operation",
    "java.io.FileOutputStream": "File write operation",
    "android.provider.Settings$Secure": "Secure settings access (Android ID, etc.)",
    "android.bluetooth.BluetoothAdapter": "Bluetooth access",
}

SENSITIVE_IOS_APIS: dict[str, str] = {
    "NSFileManager": "File system access",
    "NSUserDefaults": "User defaults access (local storage)",
    "NSKeyedArchiver": "Archiver/unarchiver (potential deserialization)",
    "NSKeyedUnarchiver": "Unarchiver (potential deserialization)",
    "CLLocationManager": "Location access",
    "AVCaptureDevice": "Camera/microphone access",
    "CNContactStore": "Contacts access",
    "PHPhotoLibrary": "Photo library access",
    "ABAddressBook": "Address book access (deprecated)",
    "SecItemCopyMatching": "Keychain access (credential retrieval)",
    "SecItemAdd": "Keychain write (credential storage)",
    "SecItemUpdate": "Keychain update",
    "SecItemDelete": "Keychain delete",
    "NSURLConnection": "Network request",
    "NSURLSession": "Network request",
    "WKWebView": "WebView usage",
    "CommonCrypto": "Cryptographic operation",
    "SecKeyCreatePair": "Key pair generation",
    "SecCertificateCreate": "Certificate creation",
    "sqlite3_exec": "SQLite query execution",
    "sqlite3_prepare_v2": "SQLite prepared statement",
    "CBCentralManager": "Bluetooth access",
    "UIDevice.identifierForVendor": "Device identifier access",
}

SUSPICIOUS_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"(?i)jailbreak|root.?detect|isJailbroken|isRooted", "description": "Jailbreak/root detection check"},
    {"pattern": r"(?i)debugger|isDebuggerConnected|android:debuggable", "description": "Debugger detection"},
    {"pattern": r"(?i)ssl.?pinning|certificate.?pinner|CertificatePinner", "description": "SSL pinning implementation"},
    {"pattern": r"(?i)encrypt|decrypt|cipher|aes|rsa|3des", "description": "Encryption/decryption operation"},
    {"pattern": r"(?i)pasteboard|UIPasteboard|ClipboardManager", "description": "Clipboard access (data leakage risk)"},
    {"pattern": r"(?i)screen.?shot|view.?capture|UIGetScreenImage", "description": "Screen capture detection"},
    {"pattern": r"(?i)keychain|KeyStore|keystore", "description": "Keychain/keystore access"},
    {"pattern": r"(?i)obfuscat|proguard|dexguard", "description": "Code obfuscation detection"},
    {"pattern": r"(?i)emulat|genymotion|bluestacks|nox", "description": "Emulator detection"},
    {"pattern": r"(?i)hook|frida|xposed|substrate|cydia", "description": "Hooking framework detection"},
    {"pattern": r"(?i)runtime.?exec|ProcessBuilder|NSTask", "description": "Runtime command execution"},
    {"pattern": r"(?i)content://|content_provider|ContentResolver\.query", "description": "Content provider data access"},
    {"pattern": r"(?i)base64|encode|decode", "description": "Encoding/decoding operation (may hide data)"},
]


# ══════════════════════════════════════════════
# Android Frida Scripts — Runtime Monitoring
# ══════════════════════════════════════════════


ANDROID_UNIVERSAL_SCRIPT = r"""/*
 * MobileSentry — Android Universal Runtime Monitor
 *
 * Comprehensive runtime monitoring for Android apps. Tracks method calls,
 * file I/O, crypto operations, database queries, network requests,
 * and permission checks. Outputs structured JSON trace logs via Frida's
 * send() API for post-capture analysis.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_universal.js --no-pause
 *        frida -U com.target.app -l monitor_universal.js
 *
 * Output: Captured via frida's send() — pipe to file:
 *   frida -U -f com.target.app -l monitor_universal.js --no-pause 2>&1 | tee trace.json
 */

'use strict';

// ── Configuration ──
var CONFIG = {
    maxDepth: 20,              // Max stack depth for method tracing
    maxArgLength: 150,         // Max length of argument strings
    sampleRate: 1.0,           // Sampling rate (1.0 = all calls)
    redactSecrets: true,       // Redact sensitive values in logs
    trackFileIO: true,         // Track file I/O operations
    trackCrypto: true,         // Track crypto operations
    trackDB: true,             // Track database queries
    trackNetwork: true,        // Track network requests
    trackPermissions: true     // Track permission checks
};

// ── Color-coded logging ──
var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    warn: function (msg) { console.log('[!] ' + msg); },
    detail: function (msg) { console.log('    ' + msg); },
    trace: function (data) {
        // Send structured data for analysis
        send(JSON.stringify(data));
    }
};

log.info('MobileSentry Universal Runtime Monitor loaded');

// ── Helper: Redact sensitive values ──
function redactValue(value) {
    if (!CONFIG.redactSecrets || !value) return value;
    var str = String(value);
    // Redact common sensitive patterns
    str = str.replace(/(?i)(password|secret|token|api[_-]?key|auth)[:=]\s*\S+/g, '$1=***REDACTED***');
    // Redact long strings (potential data)
    if (str.length > CONFIG.maxArgLength) {
        str = str.substring(0, CONFIG.maxArgLength) + '...[truncated]';
    }
    return str;
}

// ── Helper: Truncate string for display ──
function truncate(val, maxLen) {
    if (!val) return 'null';
    var str = String(val);
    return str.length > (maxLen || CONFIG.maxArgLength) ? str.substring(0, maxLen || CONFIG.maxArgLength) + '...' : str;
}

// ── Helper: Get current timestamp ──
function now() { return Date.now() / 1000; }

// ── Helper: Check sampling ──
function shouldSample() {
    return CONFIG.sampleRate >= 1.0 || Math.random() < CONFIG.sampleRate;
}

// ══════════════════════════════════════════════
// 1. Java Method Call Tracing
// ══════════════════════════════════════════════

Java.perform(function () {
    var stackDepth = 0;

    // ── Hook: Sensitive Android APIs ──
    var SENSITIVE_CLASSES = [
        'javax.crypto.Cipher',
        'javax.crypto.KeyGenerator',
        'java.security.KeyStore',
        'javax.net.ssl.SSLContext',
        'android.location.LocationManager',
        'android.telephony.TelephonyManager',
        'android.accounts.AccountManager',
        'android.database.sqlite.SQLiteDatabase',
        'android.webkit.WebView',
        'android.content.SharedPreferences',
        'android.provider.Settings$Secure',
        'android.bluetooth.BluetoothAdapter'
    ];

    SENSITIVE_CLASSES.forEach(function (className) {
        try {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();
            methods.forEach(function (method) {
                try {
                    var methodName = method.getName();
                    var overloadCount = clazz[methodName] ? clazz[methodName].overloads.length : 0;

                    for (var i = 0; i < overloadCount; i++) {
                        try {
                            clazz[methodName].overloads[i].implementation = function () {
                                if (!shouldSample()) return this[methodName].apply(this, arguments);

                                var args = [];
                                for (var a = 0; a < arguments.length; a++) {
                                    args.push(redactValue(truncate(arguments[a], 80)));
                                }

                                var event = {
                                    type: 'method_call',
                                    timestamp: now(),
                                    thread_id: Process.getCurrentThreadId(),
                                    class_name: className,
                                    method_name: methodName,
                                    args: args,
                                    stack_depth: stackDepth,
                                    platform: 'android'
                                };

                                stackDepth++;
                                var start = now();
                                try {
                                    var ret = this[methodName].apply(this, arguments);
                                    event.return_value = redactValue(truncate(ret, 80));
                                    return ret;
                                } catch (e) {
                                    event.return_value = 'ERROR: ' + e.message;
                                    throw e;
                                } finally {
                                    stackDepth--;
                                    event.duration_ms = (now() - start) * 1000;
                                    if (stackDepth <= CONFIG.maxDepth) {
                                        log.trace(event);
                                    }
                                }
                            };
                        } catch (e) {
                            // Skip overloads that can't be hooked
                        }
                    }
                } catch (e) {
                    // Skip methods that can't be hooked
                }
            });
            log.detail('✓ Hooked: ' + className);
        } catch (e) {
            // Class not available in this app
        }
    });

    // ── Hook 2: File I/O Operations ──
    if (CONFIG.trackFileIO) {
        try {
            var FileInputStream = Java.use('java.io.FileInputStream');
            FileInputStream.$init.overload('java.io.File').implementation = function (file) {
                var path = file.getAbsolutePath();
                log.trace({
                    type: 'file_io',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'read',
                    path: path,
                    platform: 'android'
                });
                return this.$init(file);
            };
            log.detail('✓ Hooked FileInputStream');

            var FileOutputStream = Java.use('java.io.FileOutputStream');
            FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
                var path = file.getAbsolutePath();
                log.trace({
                    type: 'file_io',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'write',
                    path: path,
                    platform: 'android'
                });
                return this.$init(file);
            };
            log.detail('✓ Hooked FileOutputStream');
        } catch (e) {
            log.warn('File I/O hooks failed: ' + e.message);
        }
    }

    // ── Hook 3: Crypto Operations ──
    if (CONFIG.trackCrypto) {
        try {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.getInstance.overload('java.lang.String').implementation = function (algorithm) {
                log.trace({
                    type: 'crypto',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'Cipher.getInstance',
                    algorithm: algorithm,
                    platform: 'android'
                });
                return this.getInstance(algorithm);
            };

            Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
                var modeStr = mode === 1 ? 'ENCRYPT_MODE' : mode === 2 ? 'DECRYPT_MODE' : 'WRAP_MODE';
                var algorithm = key.getAlgorithm();
                log.trace({
                    type: 'crypto',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'Cipher.init',
                    mode: modeStr,
                    algorithm: algorithm,
                    platform: 'android'
                });
                return this.init(mode, key);
            };
            log.detail('✓ Hooked javax.crypto.Cipher');

            var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
            KeyGenerator.getInstance.overload('java.lang.String').implementation = function (algorithm) {
                log.trace({
                    type: 'crypto',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'KeyGenerator.getInstance',
                    algorithm: algorithm,
                    platform: 'android'
                });
                return this.getInstance(algorithm);
            };
            var kg = KeyGenerator.$new();
            // Hook generateKey if available
            try {
                KeyGenerator.generateKey.implementation = function () {
                    log.trace({
                        type: 'crypto',
                        timestamp: now(),
                        thread_id: Process.getCurrentThreadId(),
                        operation: 'KeyGenerator.generateKey',
                        platform: 'android'
                    });
                    return this.generateKey();
                };
            } catch (e) { /* OK */ }
            log.detail('✓ Hooked javax.crypto.KeyGenerator');
        } catch (e) {
            log.warn('Crypto hooks failed: ' + e.message);
        }
    }

    // ── Hook 4: Database Operations ──
    if (CONFIG.trackDB) {
        try {
            var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
            SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selectionArgs) {
                log.trace({
                    type: 'db_query',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    query: truncate(sql, 200),
                    platform: 'android'
                });
                return this.rawQuery(sql, selectionArgs);
            };

            SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
                log.trace({
                    type: 'db_query',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    query: truncate(sql, 200),
                    operation: 'exec',
                    platform: 'android'
                });
                return this.execSQL(sql);
            };
            log.detail('✓ Hooked SQLiteDatabase');
        } catch (e) {
            log.warn('Database hooks failed: ' + e.message);
        }
    }

    // ── Hook 5: Network Operations ──
    if (CONFIG.trackNetwork) {
        try {
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            HttpURLConnection.connect.implementation = function () {
                var url = this.getURL();
                log.trace({
                    type: 'network',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'connect',
                    url: truncate(url.toString(), 200),
                    method: this.getRequestMethod(),
                    platform: 'android'
                });
                return this.connect();
            };
            log.detail('✓ Hooked HttpURLConnection');
        } catch (e) {
            log.warn('HttpURLConnection hooks failed: ' + e.message);
        }

        try {
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            OkHttpClient.newCall.implementation = function (request) {
                var url = request.url();
                log.trace({
                    type: 'network',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    operation: 'OkHttp.newCall',
                    url: truncate(url.toString(), 200),
                    method: request.method(),
                    platform: 'android'
                });
                return this.newCall(request);
            };
            log.detail('✓ Hooked OkHttpClient');
        } catch (e) {
            // OkHttp not present
        }
    }

    // ── Hook 6: Permission Checks ──
    if (CONFIG.trackPermissions) {
        try {
            var ContextCompat = Java.use('androidx.core.content.ContextCompat');
            if (ContextCompat) {
                ContextCompat.checkSelfPermission.overload('android.content.Context', 'java.lang.String').implementation = function (context, permission) {
                    log.trace({
                        type: 'permission',
                        timestamp: now(),
                        thread_id: Process.getCurrentThreadId(),
                        permission: permission,
                        platform: 'android'
                    });
                    return this.checkSelfPermission(context, permission);
                };
                log.detail('✓ Hooked ContextCompat.checkSelfPermission');
            }
        } catch (e) {
            // Not using AndroidX
        }

        try {
            var Context = Java.use('android.content.Context');
            Context.checkCallingPermission.overload('java.lang.String').implementation = function (permission) {
                log.trace({
                    type: 'permission',
                    timestamp: now(),
                    thread_id: Process.getCurrentThreadId(),
                    permission: permission,
                    platform: 'android'
                });
                return this.checkCallingPermission(permission);
            };
            log.detail('✓ Hooked Context.checkCallingPermission');
        } catch (e) {
            log.warn('Permission hooks failed: ' + e.message);
        }
    }

    // ── Hook 7: SharedPreferences Access ──
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        var prefMethods = ['getString', 'getInt', 'getBoolean', 'getLong', 'getFloat'];
        prefMethods.forEach(function (methodName) {
            try {
                SharedPreferences[methodName].overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
                    log.trace({
                        type: 'data_access',
                        timestamp: now(),
                        thread_id: Process.getCurrentThreadId(),
                        source: 'SharedPreferences',
                        operation: 'get',
                        key: key,
                        platform: 'android'
                    });
                    return this[methodName](key, defValue);
                };
            } catch (e) { /* overload not found */ }
        });
        log.detail('✓ Hooked SharedPreferences');
    } catch (e) {
        log.detail('SharedPreferences hook failed');
    }

    // ── Hook 8: Runtime.exec (command execution) ──
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
            var cmdStr = cmdArray ? Array.prototype.join.call(cmdArray, ' ') : '';
            log.trace({
                type: 'suspicious',
                timestamp: now(),
                thread_id: Process.getCurrentThreadId(),
                operation: 'Runtime.exec',
                command: truncate(cmdStr, 200),
                platform: 'android'
            });
            return this.exec(cmdArray);
        };
        log.detail('✓ Hooked Runtime.exec');
    } catch (e) {
        log.detail('Runtime.exec hook failed');
    }

    log.info('All Android runtime monitors installed');
});

log.info('Universal runtime monitoring active — use frida send() API for structured output');
"""

ANDROID_METHOD_TRACER_SCRIPT = r"""/*
 * MobileSentry — Android Method Call Tracer
 *
 * Lightweight Java method call tracing for specific sensitive APIs.
 * Hooks a focused set of security-relevant APIs and logs call
 * traces with timing information. Minimal overhead for production use.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_method_tracer.js
 */

'use strict';

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); }
};

log.info('MobileSentry Method Call Tracer loaded');

Java.perform(function () {
    // ── Target APIs for method tracing ──
    var TARGET_APIS = {
        'android.telephony.TelephonyManager': ['getDeviceId', 'getImei', 'getSubscriberId', 'getSimSerialNumber'],
        'android.accounts.AccountManager': ['getAccounts', 'getAccountsByType', 'getPassword', 'getUserData'],
        'android.location.LocationManager': ['getLastKnownLocation', 'requestLocationUpdates'],
        'android.hardware.Camera': ['open', 'takePicture'],
        'android.media.MediaRecorder': ['start', 'stop'],
        'android.content.ContentResolver': ['query', 'insert', 'delete', 'update'],
        'android.provider.Settings$Secure': ['getString', 'getInt', 'getLong'],
        'android.bluetooth.BluetoothAdapter': ['getAddress', 'getName', 'startDiscovery'],
        'android.webkit.WebView': ['loadUrl', 'evaluateJavascript', 'addJavascriptInterface'],
        'java.security.MessageDigest': ['getInstance', 'digest'],
        'javax.crypto.Mac': ['getInstance', 'doFinal'],
        'java.security.Signature': ['getInstance', 'initSign', 'initVerify', 'sign', 'verify'],
        'android.app.ActivityManager': ['getRunningAppProcesses', 'getMemoryInfo'],
        'android.net.wifi.WifiManager': ['getConnectionInfo', 'getScanResults'],
    };

    Object.keys(TARGET_APIS).forEach(function (className) {
        try {
            var clazz = Java.use(className);
            var methods = TARGET_APIS[className];

            methods.forEach(function (methodName) {
                try {
                    if (clazz[methodName] && clazz[methodName].overloads) {
                        for (var i = 0; i < clazz[methodName].overloads.length; i++) {
                            try {
                                clazz[methodName].overloads[i].implementation = function () {
                                    var args = [];
                                    for (var a = 0; a < arguments.length; a++) {
                                        var arg = arguments[a];
                                        args.push(arg !== null ? String(arg).substring(0, 100) : 'null');
                                    }

                                    var start = Date.now();
                                    try {
                                        var ret = this[methodName].apply(this, arguments);
                                        log.trace({
                                            type: 'method_call',
                                            timestamp: Date.now() / 1000,
                                            class_name: className,
                                            method_name: methodName,
                                            args: args,
                                            return_value: ret !== null ? String(ret).substring(0, 100) : 'null',
                                            duration_ms: Date.now() - start,
                                            platform: 'android'
                                        });
                                        return ret;
                                    } catch (e) {
                                        log.trace({
                                            type: 'method_call',
                                            timestamp: Date.now() / 1000,
                                            class_name: className,
                                            method_name: methodName,
                                            args: args,
                                            return_value: 'ERROR',
                                            duration_ms: Date.now() - start,
                                            platform: 'android'
                                        });
                                        throw e;
                                    }
                                };
                            } catch (e) { /* skip overload */ }
                        }
                        log.info('✓ ' + className + '.' + methodName);
                    }
                } catch (e) { /* skip method */ }
            });
        } catch (e) {
            // Class not found
        }
    });
});

log.info('Method call tracer active — logging sensitive API calls');
"""

ANDROID_CRYPTO_SCRIPT = r"""/*
 * MobileSentry — Android Crypto Operation Monitor
 *
 * Monitors all cryptographic operations including encryption, decryption,
 * key generation, hashing, signing, and key store access.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_crypto.js
 */

'use strict';

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); }
};

log.info('MobileSentry Crypto Monitor loaded');

Java.perform(function () {
    // ── Hook 1: Cipher operations ──
    try {
        var Cipher = Java.use('javax.crypto.Cipher');

        Cipher.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            log.trace({
                type: 'crypto',
                operation: 'Cipher.getInstance',
                algorithm: algorithm,
                timestamp: Date.now() / 1000
            });
            return this.getInstance(algorithm);
        };

        Cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (algorithm, provider) {
            log.trace({
                type: 'crypto',
                operation: 'Cipher.getInstance',
                algorithm: algorithm,
                provider: provider,
                timestamp: Date.now() / 1000
            });
            return this.getInstance(algorithm, provider);
        };

        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : mode === 3 ? 'WRAP' : 'UNWRAP';
            log.trace({
                type: 'crypto',
                operation: 'Cipher.init',
                mode: modeStr,
                algorithm: key.getAlgorithm(),
                format: key.getFormat(),
                timestamp: Date.now() / 1000
            });
            return this.init(mode, key);
        };

        Cipher.doFinal.overload('[B').implementation = function (input) {
            log.trace({
                type: 'crypto',
                operation: 'Cipher.doFinal',
                input_size: input ? input.length : 0,
                timestamp: Date.now() / 1000
            });
            return this.doFinal(input);
        };

        log.info('✓ Hooked javax.crypto.Cipher');
    } catch (e) {
        log.warn('Cipher hook failed: ' + e.message);
    }

    // ── Hook 2: Key generation ──
    try {
        var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
        KeyGenerator.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            return this.getInstance(algorithm);
        };

        var kg = Java.use('javax.crypto.KeyGenerator');
        kg.generateKey.implementation = function () {
            var key = this.generateKey();
            log.trace({
                type: 'crypto',
                operation: 'KeyGenerator.generateKey',
                algorithm: key.getAlgorithm(),
                format: key.getFormat(),
                timestamp: Date.now() / 1000
            });
            return key;
        };
        log.info('✓ Hooked KeyGenerator');
    } catch (e) {
        log.warn('KeyGenerator hook failed: ' + e.message);
    }

    // ── Hook 3: MessageDigest (hashing) ──
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            log.trace({
                type: 'crypto',
                operation: 'MessageDigest.getInstance',
                algorithm: algorithm,
                timestamp: Date.now() / 1000
            });
            return this.getInstance(algorithm);
        };

        MessageDigest.digest.overload('[B').implementation = function (input) {
            var result = this.digest(input);
            log.trace({
                type: 'crypto',
                operation: 'MessageDigest.digest',
                input_size: input ? input.length : 0,
                output_size: result ? result.length : 0,
                timestamp: Date.now() / 1000
            });
            return result;
        };
        log.info('✓ Hooked MessageDigest');
    } catch (e) {
        log.warn('MessageDigest hook failed: ' + e.message);
    }

    // ── Hook 4: KeyStore access ──
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (stream, password) {
            log.trace({
                type: 'crypto',
                operation: 'KeyStore.load',
                has_password: password !== null,
                timestamp: Date.now() / 1000
            });
            return this.load(stream, password);
        };

        KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter').implementation = function (alias, protParam) {
            log.trace({
                type: 'crypto',
                operation: 'KeyStore.getEntry',
                alias: alias,
                timestamp: Date.now() / 1000
            });
            return this.getEntry(alias, protParam);
        };

        KeyStore.getKey.overload('java.lang.String', '[C').implementation = function (alias, password) {
            log.trace({
                type: 'crypto',
                operation: 'KeyStore.getKey',
                alias: alias,
                has_password: password !== null,
                timestamp: Date.now() / 1000
            });
            return this.getKey(alias, password);
        };
        log.info('✓ Hooked KeyStore');
    } catch (e) {
        log.warn('KeyStore hook failed: ' + e.message);
    }

    // ── Hook 5: Signature ──
    try {
        var Signature = Java.use('java.security.Signature');
        Signature.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            log.trace({
                type: 'crypto',
                operation: 'Signature.getInstance',
                algorithm: algorithm,
                timestamp: Date.now() / 1000
            });
            return this.getInstance(algorithm);
        };
        log.info('✓ Hooked Signature');
    } catch (e) {
        log.warn('Signature hook failed: ' + e.message);
    }

    // ── Hook 6: SecureRandom ──
    try {
        var SecureRandom = Java.use('java.security.SecureRandom');
        SecureRandom.nextInt.overload().implementation = function () {
            var ret = this.nextInt();
            log.trace({
                type: 'crypto',
                operation: 'SecureRandom.nextInt',
                timestamp: Date.now() / 1000
            });
            return ret;
        };

        SecureRandom.nextBytes.overload('[B').implementation = function (bytes) {
            this.nextBytes(bytes);
            log.trace({
                type: 'crypto',
                operation: 'SecureRandom.nextBytes',
                size: bytes ? bytes.length : 0,
                timestamp: Date.now() / 1000
            });
        };
        log.info('✓ Hooked SecureRandom');
    } catch (e) {
        log.warn('SecureRandom hook failed: ' + e.message);
    }
});

log.info('Crypto monitor active — all crypto operations being logged');
"""

ANDROID_DATABASE_SCRIPT = r"""/*
 * MobileSentry — Android Database Query Monitor
 *
 * Monitors SQLite database operations including queries, inserts,
 * updates, deletes, and content provider access.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_database.js
 */

'use strict';

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); },
    warn: function (msg) { console.log('[!] ' + msg); }
};

log.info('MobileSentry Database Monitor loaded');

Java.perform(function () {
    // ── Hook 1: SQLiteDatabase ──
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selectionArgs) {
            log.trace({
                type: 'db_query',
                operation: 'rawQuery',
                sql: String(sql).substring(0, 300),
                args: selectionArgs ? Array.prototype.map.call(selectionArgs, String).join(', ') : 'none',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.rawQuery(sql, selectionArgs);
        };

        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            log.trace({
                type: 'db_query',
                operation: 'execSQL',
                sql: String(sql).substring(0, 300),
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.execSQL(sql);
        };

        SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function (table, nullColumnHack, values) {
            log.trace({
                type: 'db_query',
                operation: 'insert',
                table: table,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.insert(table, nullColumnHack, values);
        };

        SQLiteDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function (table, values, whereClause, whereArgs) {
            log.trace({
                type: 'db_query',
                operation: 'update',
                table: table,
                where: whereClause || 'none',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.update(table, values, whereClause, whereArgs);
        };

        SQLiteDatabase.delete.overload('java.lang.String', 'java.lang.String', '[Ljava.lang.String;').implementation = function (table, whereClause, whereArgs) {
            log.trace({
                type: 'db_query',
                operation: 'delete',
                table: table,
                where: whereClause || 'none',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.delete(table, whereClause, whereArgs);
        };

        // Open/create database tracking
        try {
            SQLiteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function (path, factory) {
                log.trace({
                    type: 'db_query',
                    operation: 'openOrCreate',
                    path: path,
                    timestamp: Date.now() / 1000,
                    platform: 'android'
                });
                return this.openOrCreateDatabase(path, factory);
            };
        } catch (e) { /* OK */ }

        log.info('✓ Hooked SQLiteDatabase');
    } catch (e) {
        log.warn('SQLiteDatabase hook failed: ' + e.message);
    }

    // ── Hook 2: Room Database (if used) ──
    try {
        var RoomDatabase = Java.use('androidx.room.RoomDatabase');
        if (RoomDatabase) {
            var rdMethods = ['query', 'runInTransaction', 'compileStatement'];
            rdMethods.forEach(function (m) {
                try {
                    RoomDatabase[m].implementation = function () {
                        log.trace({
                            type: 'db_query',
                            operation: 'Room.' + m,
                            timestamp: Date.now() / 1000,
                            platform: 'android'
                        });
                        return this[m].apply(this, arguments);
                    };
                } catch (e) { /* OK */ }
            });
            log.info('✓ Hooked RoomDatabase');
        }
    } catch (e) {
        // Room not used
    }

    // ── Hook 3: ContentResolver (content provider data access) ──
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');

        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            log.trace({
                type: 'db_query',
                operation: 'ContentResolver.query',
                uri: uri ? uri.toString() : 'null',
                selection: selection || 'none',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };

        ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function (uri, values) {
            log.trace({
                type: 'db_query',
                operation: 'ContentResolver.insert',
                uri: uri ? uri.toString() : 'null',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.insert(uri, values);
        };

        log.info('✓ Hooked ContentResolver');
    } catch (e) {
        log.warn('ContentResolver hook failed: ' + e.message);
    }
});

log.info('Database monitor active — all database operations being logged');
"""

ANDROID_FILE_MONITOR_SCRIPT = r"""/*
 * MobileSentry — Android File I/O Monitor
 *
 * Monitors file read/write operations, directory listings, and
 * file permission changes. Identifies sensitive file access patterns
 * including database files, shared preferences, and cache data.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_file_io.js
 */

'use strict';

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); },
    warn: function (msg) { console.log('[!] ' + msg); }
};

log.info('MobileSentry File I/O Monitor loaded');

Java.perform(function () {
    // ── Hook 1: File operations ──
    try {
        var File = Java.use('java.io.File');

        // File constructors
        File.$init.overload('java.lang.String').implementation = function (pathname) {
            log.trace({
                type: 'file_io',
                operation: 'File.open',
                path: pathname,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.$init(pathname);
        };

        // File operations
        File.createNewFile.implementation = function () {
            var path = this.getAbsolutePath();
            log.trace({
                type: 'file_io',
                operation: 'create',
                path: path,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.createNewFile();
        };

        File.delete.implementation = function () {
            var path = this.getAbsolutePath();
            log.trace({
                type: 'file_io',
                operation: 'delete',
                path: path,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.delete();
        };

        File.listFiles.overload().implementation = function () {
            var path = this.getAbsolutePath();
            log.trace({
                type: 'file_io',
                operation: 'listDir',
                path: path,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.listFiles();
        };

        log.info('✓ Hooked java.io.File');
    } catch (e) {
        log.warn('File hooks failed: ' + e.message);
    }

    // ── Hook 2: RandomAccessFile ──
    try {
        var RandomAccessFile = Java.use('java.io.RandomAccessFile');
        RandomAccessFile.$init.overload('java.lang.String', 'java.lang.String').implementation = function (path, mode) {
            log.trace({
                type: 'file_io',
                operation: 'RandomAccessFile',
                path: path,
                mode: mode,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.$init(path, mode);
        };

        RandomAccessFile.read.overload('[B').implementation = function (buffer) {
            var result = this.read(buffer);
            log.trace({
                type: 'file_io',
                operation: 'RandomAccessFile.read',
                size: result,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return result;
        };
        log.info('✓ Hooked RandomAccessFile');
    } catch (e) {
        log.warn('RandomAccessFile hook failed: ' + e.message);
    }

    // ── Hook 3: Application data directory access ──
    try {
        var Context = Java.use('android.content.Context');
        Context.getFilesDir.implementation = function () {
            var result = this.getFilesDir();
            log.trace({
                type: 'file_io',
                operation: 'getFilesDir',
                path: result ? result.getAbsolutePath() : 'null',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return result;
        };

        Context.getCacheDir.implementation = function () {
            var result = this.getCacheDir();
            log.trace({
                type: 'file_io',
                operation: 'getCacheDir',
                path: result ? result.getAbsolutePath() : 'null',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return result;
        };

        Context.getDatabasePath.overload('java.lang.String').implementation = function (name) {
            var result = this.getDatabasePath(name);
            log.trace({
                type: 'file_io',
                operation: 'getDatabasePath',
                name: name,
                path: result ? result.getAbsolutePath() : 'null',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return result;
        };

        log.info('✓ Hooked Context data directory access');
    } catch (e) {
        log.warn('Context hooks failed: ' + e.message);
    }

    // ── Hook 4: FileObserver (if used) ──
    try {
        var FileObserver = Java.use('android.os.FileObserver');
        FileObserver.startWatching.implementation = function () {
            log.trace({
                type: 'file_io',
                operation: 'FileObserver.startWatching',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.startWatching();
        };
        log.info('✓ Hooked FileObserver');
    } catch (e) {
        // FileObserver not available
    }
});

log.info('File I/O monitor active');
"""

ANDROID_NETWORK_SCRIPT = r"""/*
 * MobileSentry — Android Network API Monitor
 *
 * Monitors HTTP/HTTPS network requests via HttpURLConnection,
 * OkHttp, and WebSocket connections. Captures URLs, methods,
 * headers, and response codes.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_network.js
 */

'use strict';

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); }
};

log.info('MobileSentry Network Monitor loaded');

Java.perform(function () {
    // ── Hook 1: HttpURLConnection ──
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');

        HttpURLConnection.connect.implementation = function () {
            var url = this.getURL();
            var method = this.getRequestMethod();
            log.trace({
                type: 'network',
                operation: 'HttpURLConnection.connect',
                url: url ? String(url) : 'null',
                method: method,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.connect();
        };

        HttpURLConnection.getInputStream.implementation = function () {
            var url = this.getURL();
            log.trace({
                type: 'network',
                operation: 'HttpURLConnection.getInputStream',
                url: url ? String(url) : 'null',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.getInputStream();
        };

        HttpURLConnection.getResponseCode.implementation = function () {
            var code = this.getResponseCode();
            var url = this.getURL();
            log.trace({
                type: 'network',
                operation: 'HttpURLConnection.response',
                url: url ? String(url) : 'null',
                response_code: code,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return code;
        };

        log.info('✓ Hooked HttpURLConnection');
    } catch (e) {
        log.warn('HttpURLConnection hook failed: ' + e.message);
    }

    // ── Hook 2: URL class ──
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (url) {
            log.trace({
                type: 'network',
                operation: 'URL.open',
                url: url,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.$init(url);
        };
        log.info('✓ Hooked URL constructor');
    } catch (e) {
        log.warn('URL hook failed: ' + e.message);
    }

    // ── Hook 3: OkHttp client ──
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function (request) {
            var urlObj = request.url();
            var url = urlObj ? urlObj.toString() : 'null';
            var method = request.method();
            var headers = {};
            try {
                var hdrs = request.headers();
                if (hdrs) {
                    var hdrNames = hdrs.names();
                    if (hdrNames) {
                        for (var i = 0; i < hdrNames.size(); i++) {
                            var name = hdrNames.get(i);
                            if (name) {
                                var val = hdrs.get(name);
                                if (name.toLowerCase().indexOf('auth') !== -1 || name.toLowerCase().indexOf('token') !== -1 || name.toLowerCase().indexOf('key') !== -1) {
                                    val = '***REDACTED***';
                                }
                                headers[name] = val;
                            }
                        }
                    }
                }
            } catch (e) { /* headers parse failed */ }

            log.trace({
                type: 'network',
                operation: 'OkHttp.newCall',
                url: String(url).substring(0, 500),
                method: method,
                headers: headers,
                timestamp: Date.now() / 1000,
                platform: 'android'
            });

            return this.newCall(request);
        };

        log.info('✓ Hooked OkHttpClient.newCall');
    } catch (e) {
        // OkHttp not present
    }

    // ── Hook 4: WebSocket (OkHttp) ──
    try {
        var WebSocket = Java.use('okhttp3.WebSocket');
        if (WebSocket) {
            WebSocket.send.overload('java.lang.String').implementation = function (message) {
                log.trace({
                    type: 'network',
                    operation: 'WebSocket.send',
                    message_length: message ? message.length : 0,
                    timestamp: Date.now() / 1000,
                    platform: 'android'
                });
                return this.send(message);
            };
            log.info('✓ Hooked WebSocket');
        }
    } catch (e) {
        // WebSocket not present
    }

    // ── Hook 5: DownloadManager ──
    try {
        var DownloadManager = Java.use('android.app.DownloadManager');
        DownloadManager.enqueue.implementation = function (request) {
            var uri = request.getUri();
            log.trace({
                type: 'network',
                operation: 'DownloadManager.enqueue',
                url: uri ? String(uri) : 'null',
                timestamp: Date.now() / 1000,
                platform: 'android'
            });
            return this.enqueue(request);
        };
        log.info('✓ Hooked DownloadManager');
    } catch (e) {
        // DownloadManager not used
    }
});

log.info('Network monitor active');
"""


# ══════════════════════════════════════════════
# iOS Frida Scripts — Runtime Monitoring
# ══════════════════════════════════════════════


IOS_UNIVERSAL_SCRIPT = r"""/*
 * MobileSentry — iOS Universal Runtime Monitor
 *
 * Comprehensive runtime monitoring for iOS apps. Tracks Objective-C
 * method calls, file I/O via NSFileManager, crypto via Security
 * framework, network requests via NSURLSession, and more.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_universal_ios.js --no-pause
 *        frida -U com.target.app -l monitor_universal_ios.js
 *
 * Output: Captured via frida's send() API — pipe to file:
 *   frida -U -f com.target.app -l monitor_universal_ios.js 2>&1 | tee trace.json
 */

'use strict';

var CONFIG = {
    maxArgLength: 150,
    redactSecrets: true,
    trackFileIO: true,
    trackCrypto: true,
    trackNetwork: true
};

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    warn: function (msg) { console.log('[!] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); }
};

log.info('MobileSentry iOS Universal Runtime Monitor loaded');

function truncate(val, maxLen) {
    if (!val) return 'null';
    var str = String(val);
    return str.length > (maxLen || CONFIG.maxArgLength) ? str.substring(0, maxLen || CONFIG.maxArgLength) + '...' : str;
}

function redactValue(value) {
    if (!CONFIG.redactSecrets || !value) return value;
    var str = String(value);
    str = str.replace(/(?i)(password|secret|token|api[_-]?key)[:=]\s*\S+/g, '$1=***REDACTED***');
    if (str.length > CONFIG.maxArgLength) {
        str = str.substring(0, CONFIG.maxArgLength) + '...[truncated]';
    }
    return str;
}

if (ObjC.available) {
    // ── Hook 1: NSFileManager (file I/O) ──
    if (CONFIG.trackFileIO) {
        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            var fm = NSFileManager.defaultManager();

            try {
                var origFileExists = fm['- fileExistsAtPath:'];
                if (origFileExists) {
                    origFileExists.implementation = function (self, sel, path) {
                        var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
                        log.trace({
                            type: 'file_io',
                            operation: 'fileExistsAtPath',
                            path: pathStr,
                            timestamp: Date.now() / 1000,
                            platform: 'ios'
                        });
                        return ObjC.classes.NSFileManager['- fileExistsAtPath:'](self, sel, path);
                    };
                }
            } catch (e) { /* OK */ }

            try {
                var origContents = fm['- contentsOfDirectoryAtPath:error:'];
                if (origContents) {
                    origContents.implementation = function (self, sel, path, error) {
                        var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
                        log.trace({
                            type: 'file_io',
                            operation: 'listDir',
                            path: pathStr,
                            timestamp: Date.now() / 1000,
                            platform: 'ios'
                        });
                        return ObjC.classes.NSFileManager['- contentsOfDirectoryAtPath:error:'](self, sel, path, error);
                    };
                }
            } catch (e) { /* OK */ }

            try {
                var origRemove = fm['- removeItemAtPath:error:'];
                if (origRemove) {
                    origRemove.implementation = function (self, sel, path, error) {
                        var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
                        log.trace({
                            type: 'file_io',
                            operation: 'removeItem',
                            path: pathStr,
                            timestamp: Date.now() / 1000,
                            platform: 'ios'
                        });
                        return ObjC.classes.NSFileManager['- removeItemAtPath:error:'](self, sel, path, error);
                    };
                }
            } catch (e) { /* OK */ }

            log.info('✓ Hooked NSFileManager');
        } catch (e) {
            log.warn('NSFileManager hook failed: ' + e.message);
        }
    }

    // ── Hook 2: NSUserDefaults (data access) ──
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        var ud = NSUserDefaults.standardUserDefaults();

        try {
            var origString = ud['- stringForKey:'];
            if (origString) {
                origString.implementation = function (self, sel, key) {
                    var keyStr = ObjC.classes.NSString.stringWithString(key).toString();
                    log.trace({
                        type: 'data_access',
                        source: 'NSUserDefaults',
                        operation: 'stringForKey',
                        key: keyStr,
                        timestamp: Date.now() / 1000,
                        platform: 'ios'
                    });
                    return ObjC.classes.NSUserDefaults['- stringForKey:'](self, sel, key);
                };
            }
        } catch (e) { /* OK */ }

        try {
            var origData = ud['- dataForKey:'];
            if (origData) {
                origData.implementation = function (self, sel, key) {
                    var keyStr = ObjC.classes.NSString.stringWithString(key).toString();
                    log.trace({
                        type: 'data_access',
                        source: 'NSUserDefaults',
                        operation: 'dataForKey',
                        key: keyStr,
                        timestamp: Date.now() / 1000,
                        platform: 'ios'
                    });
                    return ObjC.classes.NSUserDefaults['- dataForKey:'](self, sel, key);
                };
            }
        } catch (e) { /* OK */ }

        log.info('✓ Hooked NSUserDefaults');
    } catch (e) {
        log.warn('NSUserDefaults hook failed: ' + e.message);
    }

    // ── Hook 3: Keychain access ──
    if (CONFIG.trackCrypto) {
        try {
            var SecItemCopyMatching = Module.findExportByName('libSecurity.dylib', 'SecItemCopyMatching');
            if (SecItemCopyMatching) {
                Interceptor.attach(SecItemCopyMatching, {
                    onLeave: function (retval) {
                        if (retval.toInt32() === 0) { // errSecSuccess
                            log.trace({
                                type: 'crypto',
                                operation: 'SecItemCopyMatching',
                                description: 'Keychain read access',
                                timestamp: Date.now() / 1000,
                                platform: 'ios'
                            });
                        }
                    }
                });
            }

            var SecItemAdd = Module.findExportByName('libSecurity.dylib', 'SecItemAdd');
            if (SecItemAdd) {
                Interceptor.attach(SecItemAdd, {
                    onLeave: function (retval) {
                        if (retval.toInt32() === 0) {
                            log.trace({
                                type: 'crypto',
                                operation: 'SecItemAdd',
                                description: 'Keychain write (credential storage)',
                                timestamp: Date.now() / 1000,
                                platform: 'ios'
                            });
                        }
                    }
                });
            }

            log.info('✓ Hooked Keychain (Security framework)');
        } catch (e) {
            log.warn('Keychain hooks failed: ' + e.message);
        }
    }

    // ── Hook 4: NSURLSession (network) ──
    if (CONFIG.trackNetwork) {
        try {
            var NSURLSession = ObjC.classes.NSURLSession;

            // Enumerate all classes for auth challenge delegates
            var allClasses = ObjC.enumerateLoadedClassesSync();
            allClasses.forEach(function (className) {
                try {
                    var clazz = ObjC.classes[className];
                    if (!clazz) return;

                    var method = clazz['- URLSession:didReceiveChallenge:completionHandler:'];
                    if (method) {
                        method.implementation = function (self, sel, session, challenge, completion) {
                            var protectionSpace = challenge.protectionSpace();
                            var host = protectionSpace.host();
                            var authMethod = protectionSpace.authenticationMethod();

                            log.trace({
                                type: 'network',
                                operation: 'URLSession.authChallenge',
                                host: ObjC.classes.NSString.stringWithString(host).toString(),
                                authMethod: ObjC.classes.NSString.stringWithString(authMethod).toString(),
                                timestamp: Date.now() / 1000,
                                platform: 'ios'
                            });

                            var block = new ObjC.Block(completion);
                            if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                                var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                                var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                                block.implementation(disposition, credential);
                            } else {
                                block.implementation(0, null);
                            }
                        };
                    }
                } catch (e) { /* class not hookable */ }
            });

            log.info('✓ Hooked NSURLSession delegates');
        } catch (e) {
            log.warn('NSURLSession hooks failed: ' + e.message);
        }
    }

    // ── Hook 5: CLLocationManager (location access) ──
    try {
        var CLLocationManager = ObjC.classes.CLLocationManager;
        if (CLLocationManager) {
            try {
                var origLoc = CLLocationManager['- startUpdatingLocation'];
                if (origLoc) {
                    origLoc.implementation = function (self, sel) {
                        log.trace({
                            type: 'permission',
                            operation: 'CLLocationManager.startUpdatingLocation',
                            description: 'Location access requested',
                            timestamp: Date.now() / 1000,
                            platform: 'ios'
                        });
                        CLLocationManager['- startUpdatingLocation'](self, sel);
                    };
                }
            } catch (e) { /* OK */ }

            try {
                var origMonitor = CLLocationManager['- startMonitoringSignificantLocationChanges'];
                if (origMonitor) {
                    origMonitor.implementation = function (self, sel) {
                        log.trace({
                            type: 'permission',
                            operation: 'startMonitoringSignificantLocationChanges',
                            description: 'Background location monitoring',
                            timestamp: Date.now() / 1000,
                            platform: 'ios'
                        });
                        CLLocationManager['- startMonitoringSignificantLocationChanges'](self, sel);
                    };
                }
            } catch (e) { /* OK */ }

            log.info('✓ Hooked CLLocationManager');
        }
    } catch (e) {
        log.detail('CLLocationManager not found');
    }

    log.info('All iOS runtime monitors installed');
} else {
    log.warn('Objective-C runtime not available');
}

log.info('Universal runtime monitoring active — use frida send() API for structured output');
"""

IOS_METHOD_TRACER_SCRIPT = r"""/*
 * MobileSentry — iOS Objective-C Method Call Tracer
 *
 * Lightweight method call tracing for sensitive iOS APIs.
 * Hooks key security-relevant Objective-C methods and logs
 * call traces with timing information.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l monitor_method_tracer_ios.js
 */

'use strict';

var log = {
    info: function (msg) { console.log('[+] ' + msg); },
    trace: function (data) { send(JSON.stringify(data)); }
};

log.info('MobileSentry iOS Method Call Tracer loaded');

if (ObjC.available) {
    // ── Target classes and methods ──
    var TARGETS = {
        'UIDevice': [
            { sel: '- identifierForVendor', desc: 'Device identifier access' },
            { sel: '- name', desc: 'Device name access' }
        ],
        'UIApplication': [
            { sel: '- canOpenURL:', desc: 'URL scheme check' },
            { sel: '- openURL:', desc: 'URL open' }
        ],
        'AVCaptureDevice': [
            { sel: '+ authorizationStatusForMediaType:', desc: 'Camera/mic permission check' },
            { sel: '+ requestAccessForMediaType:completionHandler:', desc: 'Camera/mic access request' }
        ],
        'CNContactStore': [
            { sel: '- unifiedContactsMatchingPredicate:keysToFetch:error:', desc: 'Contacts read' }
        ],
        'PHPhotoLibrary': [
            { sel: '+ requestAuthorization:', desc: 'Photo library authorization' }
        ],
        'ABAddressBook': [
            { sel: '+ requestAccessWithCompletion:', desc: 'Address book access (deprecated)' }
        ],
        'WKWebView': [
            { sel: '- loadRequest:', desc: 'WebView load request' },
            { sel: '- evaluateJavaScript:completionHandler:', desc: 'JavaScript execution in WebView' }
        ]
    };

    Object.keys(TARGETS).forEach(function (className) {
        try {
            var clazz = ObjC.classes[className];
            if (!clazz) return;

            TARGETS[className].forEach(function (target) {
                try {
                    var method = clazz[target.sel];
                    if (method) {
                        method.implementation = function (self, sel) {
                            var start = Date.now();
                            var args = [];
                            for (var i = 2; i < arguments.length; i++) {
                                args.push(String(arguments[i]).substring(0, 100));
                            }

                            try {
                                var ret = ObjC.classes[className][target.sel].apply(this, arguments);
                                log.trace({
                                    type: 'method_call',
                                    class_name: className,
                                    selector: target.sel,
                                    description: target.desc,
                                    args: args,
                                    return_value: ret ? String(ret).substring(0, 100) : 'null',
                                    duration_ms: Date.now() - start,
                                    timestamp: Date.now() / 1000,
                                    platform: 'ios'
                                });
                                return ret;
                            } catch (e) {
                                log.trace({
                                    type: 'method_call',
                                    class_name: className,
                                    selector: target.sel,
                                    description: target.desc,
                                    error: e.message,
                                    timestamp: Date.now() / 1000,
                                    platform: 'ios'
                                });
                                throw e;
                            }
                        };
                        log.info('✓ ' + className + ' ' + target.sel);
                    }
                } catch (e) { /* selector not found */ }
            });
        } catch (e) { /* class not found */ }
    });

    // ── Hook platform-independent functions ──
    try {
        // SQLite operations
        var sqliteExec = Module.findExportByName('libsqlite3.dylib', 'sqlite3_exec');
        if (sqliteExec) {
            Interceptor.attach(sqliteExec, {
                onEnter: function (args) {
                    var db = args[0];
                    var sql = args[1].readCString();
                    log.trace({
                        type: 'db_query',
                        operation: 'sqlite3_exec',
                        sql: sql ? String(sql).substring(0, 300) : 'null',
                        timestamp: Date.now() / 1000,
                        platform: 'ios'
                    });
                }
            });
            log.info('✓ Hooked sqlite3_exec');
        }
    } catch (e) {
        log.warn('SQLite hook failed: ' + e.message);
    }

    // ── Hook CommonCrypto ──
    try {
        var CCCrypt = Module.findExportByName('libCommonCrypto.dylib', 'CCCrypt');
        if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function (args) {
                    var op = args[0].toInt32(); // kCCEncrypt = 0, kCCDecrypt = 1
                    log.trace({
                        type: 'crypto',
                        operation: op === 0 ? 'CCCrypt (Encrypt)' : op === 1 ? 'CCCrypt (Decrypt)' : 'CCCrypt (Unknown)',
                        timestamp: Date.now() / 1000,
                        platform: 'ios'
                    });
                }
            });
            log.info('✓ Hooked CommonCrypto CCCrypt');
        }
    } catch (e) {
        log.warn('CommonCrypto hook failed: ' + e.message);
    }
}

log.info('iOS method call tracer active');
"""


# ══════════════════════════════════════════════
# Techniques Catalog
# ══════════════════════════════════════════════

ANDROID_TECHNIQUES: list[MonitorTechnique] = [
    MonitorTechnique(
        name="universal",
        platform="android",
        description="Comprehensive runtime monitor — tracks method calls, file I/O, crypto, database queries, network requests, permission checks, and SharedPreferences access. The most comprehensive option.",
        monitor_targets=[
            "method_calls", "file_io", "crypto", "db_queries",
            "network_requests", "permission_checks", "data_access",
            "runtime_exec",
        ],
        quality="best",
        warnings=["Higher overhead due to comprehensive hooking. Use targeted scripts if performance is a concern."],
    ),
    MonitorTechnique(
        name="method_tracer",
        platform="android",
        description="Lightweight method call tracing for specific sensitive APIs. Tracks TelephonyManager, AccountManager, LocationManager, Camera, WebView, crypto, and more.",
        monitor_targets=[
            "method_calls", "sensitive_apis", "device_identifiers",
            "location", "camera", "webview",
        ],
        quality="good",
        warnings=["Only hooks predefined sensitive APIs. Use universal for broader coverage."],
    ),
    MonitorTechnique(
        name="crypto",
        platform="android",
        description="Crypto operation monitor — tracks Cipher (encrypt/decrypt), KeyGenerator, MessageDigest, KeyStore access, Signature, and SecureRandom operations.",
        monitor_targets=[
            "crypto", "encryption", "decryption", "key_generation",
            "hashing", "key_store", "signing",
        ],
        quality="targeted",
        warnings=["Specifically targets cryptographic operations. Does not monitor general app behavior."],
    ),
    MonitorTechnique(
        name="database",
        platform="android",
        description="Database query monitor — tracks SQLiteDatabase (rawQuery, execSQL, insert, update, delete), Room Database, and ContentResolver queries.",
        monitor_targets=[
            "db_queries", "sqlite", "room", "content_provider",
            "data_storage",
        ],
        quality="targeted",
        warnings=["Only monitors database operations. Use universal for broader coverage."],
    ),
    MonitorTechnique(
        name="file_io",
        platform="android",
        description="File I/O monitor — tracks file read/write operations, directory listings, RandomAccessFile access, application data directory access, and FileObserver.",
        monitor_targets=[
            "file_io", "file_read", "file_write", "directory_listing",
            "data_storage",
        ],
        quality="targeted",
        warnings=["Only monitors file system operations. Use universal for broader coverage."],
    ),
    MonitorTechnique(
        name="network",
        platform="android",
        description="Network API monitor — tracks HttpURLConnection connections, URL accesses, OkHttp requests, WebSocket messages, and DownloadManager downloads.",
        monitor_targets=[
            "network_requests", "http", "okhttp", "websocket",
            "download_manager",
        ],
        quality="targeted",
        warnings=["Only monitors network operations. Use universal for broader coverage."],
    ),
]

IOS_TECHNIQUES: list[MonitorTechnique] = [
    MonitorTechnique(
        name="universal",
        platform="ios",
        description="Comprehensive iOS runtime monitor — tracks NSFileManager file I/O, NSUserDefaults access, Keychain (Security framework), NSURLSession network calls, and CLLocationManager.",
        monitor_targets=[
            "file_io", "data_access", "crypto", "network",
            "permission_checks", "keychain", "location",
        ],
        quality="best",
        warnings=["Higher overhead due to comprehensive hooking. Use method_tracer for targeted monitoring."],
    ),
    MonitorTechnique(
        name="method_tracer",
        platform="ios",
        description="Lightweight iOS method call tracer — hooks UIDevice, UIApplication, AVCaptureDevice, CNContactStore, PHPhotoLibrary, WKWebView, SQLite, and CommonCrypto.",
        monitor_targets=[
            "method_calls", "sensitive_apis", "device_identifiers",
            "camera", "contacts", "webview", "sqlite", "crypto",
        ],
        quality="good",
        warnings=["Only hooks predefined target selectors. Use universal for broader coverage."],
    ),
]

TECHNIQUES_BY_PLATFORM: dict[str, list[MonitorTechnique]] = {
    "android": ANDROID_TECHNIQUES,
    "ios": IOS_TECHNIQUES,
}

ALL_TECHNIQUES: list[MonitorTechnique] = ANDROID_TECHNIQUES + IOS_TECHNIQUES

# Scripts by technique name
ANDROID_SCRIPTS: dict[str, str] = {
    "universal": ANDROID_UNIVERSAL_SCRIPT,
    "method_tracer": ANDROID_METHOD_TRACER_SCRIPT,
    "crypto": ANDROID_CRYPTO_SCRIPT,
    "database": ANDROID_DATABASE_SCRIPT,
    "file_io": ANDROID_FILE_MONITOR_SCRIPT,
    "network": ANDROID_NETWORK_SCRIPT,
}

IOS_SCRIPTS: dict[str, str] = {
    "universal": IOS_UNIVERSAL_SCRIPT,
    "method_tracer": IOS_METHOD_TRACER_SCRIPT,
}

SCRIPTS_BY_PLATFORM: dict[str, dict[str, str]] = {
    "android": ANDROID_SCRIPTS,
    "ios": IOS_SCRIPTS,
}


# ══════════════════════════════════════════════
# Generator
# ══════════════════════════════════════════════


class RuntimeMonitorGenerator:
    """Generates Frida scripts for runtime app monitoring.

    Args:
        output_dir: Directory where generated scripts will be saved.
    """

    def __init__(self, output_dir: str = "./monitor_scripts") -> None:
        self.output_dir = Path(output_dir)

    # ── Listing ──

    def list_techniques(self, platform: str | None = None) -> list[MonitorTechnique]:
        """List available monitoring techniques, optionally filtered by platform.

        Args:
            platform: Filter by platform ("android", "ios", or None for all).

        Returns:
            List of MonitorTechnique metadata objects.
        """
        if platform:
            return TECHNIQUES_BY_PLATFORM.get(platform.lower(), [])
        return ALL_TECHNIQUES

    def get_technique(self, name: str, platform: str) -> MonitorTechnique | None:
        """Get a specific technique by name and platform.

        Args:
            name: Technique name (e.g., "universal", "crypto").
            platform: Platform ("android" or "ios").

        Returns:
            MonitorTechnique if found, None otherwise.
        """
        platform_lower = platform.lower()
        if platform_lower not in TECHNIQUES_BY_PLATFORM:
            return None
        for technique in TECHNIQUES_BY_PLATFORM[platform_lower]:
            if technique.name == name:
                return technique
        return None

    # ── Generation ──

    def generate_all(self) -> list[GeneratedScript]:
        """Generate all monitor scripts for both platforms.

        Returns:
            List of GeneratedScript objects with file paths.
        """
        scripts: list[GeneratedScript] = []
        scripts.extend(self.generate_platform("android"))
        scripts.extend(self.generate_platform("ios"))
        return scripts

    def generate_platform(self, platform: str) -> list[GeneratedScript]:
        """Generate all monitor scripts for a specific platform.

        Args:
            platform: "android" or "ios".

        Returns:
            List of GeneratedScript objects with file paths.
        """
        platform_lower = platform.lower()
        if platform_lower not in SCRIPTS_BY_PLATFORM:
            raise ValueError(f"Unknown platform: {platform}. Must be 'android' or 'ios'.")

        scripts: list[GeneratedScript] = []
        scripts_map = SCRIPTS_BY_PLATFORM[platform_lower]

        for technique_name, code in scripts_map.items():
            technique = self.get_technique(technique_name, platform_lower)
            if technique is None:
                continue

            filename = f"monitor_{technique_name}_{platform_lower}.js"
            output_path = str(self.output_dir / platform_lower / filename)

            scripts.append(
                GeneratedScript(
                    filename=filename,
                    technique=technique,
                    code=code,
                    output_path=output_path,
                )
            )

        return scripts

    def generate_script(self, technique_name: str, platform: str) -> GeneratedScript | None:
        """Generate a single monitor script by technique name and platform.

        Args:
            technique_name: Technique name (e.g., "universal", "crypto").
            platform: Platform ("android" or "ios").

        Returns:
            GeneratedScript if found, None otherwise.
        """
        platform_lower = platform.lower()
        if platform_lower not in SCRIPTS_BY_PLATFORM:
            return None

        code = SCRIPTS_BY_PLATFORM[platform_lower].get(technique_name)
        technique = self.get_technique(technique_name, platform_lower)
        if code is None or technique is None:
            return None

        filename = f"monitor_{technique_name}_{platform_lower}.js"
        output_path = str(self.output_dir / platform_lower / filename)

        return GeneratedScript(
            filename=filename,
            technique=technique,
            code=code,
            output_path=output_path,
        )

    # ── Writing ──

    def write_scripts(self, scripts: list[GeneratedScript]) -> list[str]:
        """Write generated scripts to disk.

        Args:
            scripts: List of GeneratedScript objects to write.

        Returns:
            List of successfully written file paths.
        """
        written: list[str] = []
        for script in scripts:
            path = Path(script.output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(script.code.strip() + "\n", encoding="utf-8")
            written.append(str(path))
        return written

    def write_all(self) -> list[str]:
        """Generate and write all scripts to disk.

        Returns:
            List of successfully written file paths.
        """
        scripts = self.generate_all()
        return self.write_scripts(scripts)

    def write_platform(self, platform: str) -> list[str]:
        """Generate and write all scripts for a specific platform.

        Args:
            platform: "android" or "ios".

        Returns:
            List of successfully written file paths.
        """
        scripts = self.generate_platform(platform)
        return self.write_scripts(scripts)

    def write_script(self, technique_name: str, platform: str) -> str | None:
        """Generate and write a single script.

        Args:
            technique_name: Technique name.
            platform: "android" or "ios".

        Returns:
            Path to the written file, or None if technique not found.
        """
        script = self.generate_script(technique_name, platform)
        if script is None:
            return None
        paths = self.write_scripts([script])
        return paths[0] if paths else None

    # ── Validation ──

    def validate_scripts(self, scripts: list[GeneratedScript]) -> list[str]:
        """Validate generated scripts for basic correctness.

        Checks:
        - Script is not empty
        - Script contains 'use strict' for Frida compatibility
        - Script starts with a comment header

        Args:
            scripts: List of scripts to validate.

        Returns:
            List of validation warnings/errors.
        """
        issues: list[str] = []
        for script in scripts:
            if not script.code.strip():
                issues.append(f"❌ {script.filename}: Script is empty")
                continue
            if "'use strict'" not in script.code:
                issues.append(f"⚠️  {script.filename}: Missing 'use strict' directive")
            if not script.code.strip().startswith("/*"):
                issues.append(f"⚠️  {script.filename}: Missing header comment")
            if script.size_bytes > 100_000:
                issues.append(f"⚠️  {script.filename}: Large script ({script.size_bytes / 1024:.1f} KB)")
        return issues


# ══════════════════════════════════════════════
# Dynamic Analyzer — Parse & Analyze Trace Output
# ══════════════════════════════════════════════


class DynamicAnalyzer:
    """Analyzes trace output from runtime monitoring Frida scripts.

    Parses structured JSON trace logs generated by the monitor scripts and
    produces behavioral security analysis reports, including:
    - Sensitive API usage patterns
    - File I/O access patterns
    - Crypto operation inventory
    - Database query logging
    - Network request analysis
    - Permission usage patterns
    - Suspicious behavior detection
    """

    def __init__(self) -> None:
        self.analyzer_version = "0.5.0"

    def analyze_trace(self, trace_path: str) -> DynamicAnalysisReport:
        """Analyze a trace file (JSON-lines format) for behavioral findings.

        Args:
            trace_path: Path to the trace file (one JSON object per line).

        Returns:
            DynamicAnalysisReport with behavioral findings.
        """
        report = DynamicAnalysisReport()
        report.analysis_timestamp = datetime.now(timezone.utc).isoformat()

        start_time: float | None = None
        end_time: float | None = None

        events: list[TraceEvent] = []
        seen_methods: dict[str, int] = {}
        seen_files: list[str] = []
        seen_crypto: list[dict[str, str]] = []
        seen_db: list[str] = []
        seen_network: list[dict[str, str]] = []
        seen_permissions: list[str] = []
        sensitive_apis: list[dict[str, Any]] = []

        with open(trace_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = self._parse_event(data)
                if event is None:
                    continue

                events.append(event)
                event_type = event.event_type
                report.events_by_type[event_type] = report.events_by_type.get(event_type, 0) + 1

                if start_time is None or event.timestamp < start_time:
                    start_time = event.timestamp
                if end_time is None or event.timestamp > end_time:
                    end_time = event.timestamp

                # Track by event type
                if event_type == "method_call" and event.class_name:
                    key = f"{event.class_name}.{event.method_name}"
                    seen_methods[key] = seen_methods.get(key, 0) + 1

                    # Check against sensitive API list
                    self._check_sensitive_api(
                        event.class_name, event.method_name, event.args,
                        seen_methods[key], sensitive_apis,
                    )

                elif event_type == "file_io" and event.args:
                    path = event.args[0] if event.args else ""
                    if path and path not in seen_files:
                        seen_files.append(path)

                elif event_type == "crypto":
                    op = event.method_name or event.args[0] if event.args else ""
                    algo = event.args[1] if len(event.args) > 1 else ""
                    seen_crypto.append({"operation": op, "algorithm": algo})

                elif event_type == "db_query":
                    sql = event.args[0] if event.args else ""
                    if sql:
                        seen_db.append(sql)

                elif event_type == "network":
                    url = event.args[0] if event.args else ""
                    op = event.method_name or ""
                    seen_network.append({"url": url, "operation": op})

                elif event_type == "permission":
                    perm = event.args[0] if event.args else ""
                    if perm and perm not in seen_permissions:
                        seen_permissions.append(perm)

        if not events:
            return report

        report.total_events = len(events)
        if start_time and end_time:
            report.duration_seconds = end_time - start_time
        report.methods_called = seen_methods
        report.files_accessed = seen_files
        report.crypto_operations = seen_crypto
        report.db_queries = seen_db
        report.network_requests = seen_network
        report.permission_checks = seen_permissions
        report.sensitive_apis = sensitive_apis

        # Build call graph
        self._build_call_graph(events, report)

        # Generate behavioral findings
        self._generate_findings(report)

        return report

    def _parse_event(self, data: dict[str, Any]) -> TraceEvent | None:
        """Parse a single event dictionary into a TraceEvent."""
        event_type = data.get("type", "")
        if not event_type:
            return None

        return TraceEvent(
            timestamp=data.get("timestamp", 0.0),
            event_type=event_type,
            thread_id=data.get("thread_id", 0),
            class_name=data.get("class_name", data.get("source", "")),
            method_name=data.get("method_name", data.get("operation", "")),
            args=self._safe_args(data),
            return_value=data.get("return_value", ""),
            duration_ms=data.get("duration_ms", 0.0),
            stack_depth=data.get("stack_depth", 0),
            platform=data.get("platform", ""),
        )

    def _safe_args(self, data: dict[str, Any]) -> list[str]:
        """Extract arguments from event data safely."""
        args = data.get("args", [])
        if isinstance(args, list):
            return [str(a) for a in args]
        # For non-array args (like single string or dict), convert to list
        if isinstance(args, str):
            return [args]
        return [str(args)]

    def _check_sensitive_api(
        self,
        class_name: str,
        method_name: str,
        args: list[str],
        call_count: int,
        sensitive_apis: list[dict[str, Any]],
    ) -> None:
        """Check if a method call matches known sensitive APIs."""
        # Check Android APIs
        if "android" in class_name or "java" in class_name or "okhttp" in class_name or "javax" in class_name:
            for api_class, description in SENSITIVE_ANDROID_APIS.items():
                if api_class in class_name:
                    sensitive_apis.append({
                        "api": f"{class_name}.{method_name}",
                        "description": description,
                        "count": call_count,
                        "platform": "android",
                    })
                    return
        # Check iOS APIs
        if class_name in SENSITIVE_IOS_APIS:
            sensitive_apis.append({
                "api": f"{class_name}.{method_name}",
                "description": SENSITIVE_IOS_APIS[class_name],
                "count": call_count,
                "platform": "ios",
            })
        # Check via description
        for name, desc in SENSITIVE_IOS_APIS.items():
            if name in class_name or name in method_name:
                sensitive_apis.append({
                    "api": f"{class_name}.{method_name}",
                    "description": desc,
                    "count": call_count,
                    "platform": "ios",
                })
                return

    def _build_call_graph(self, events: list[TraceEvent], report: DynamicAnalysisReport) -> None:
        """Build a simple call graph from trace events."""
        if not events:
            return

        # Group by class and method
        graph: dict[str, list[str]] = {}
        for event in events:
            if event.class_name and event.method_name:
                caller_key = f"{event.class_name}.{event.method_name}"
                if caller_key not in graph:
                    graph[caller_key] = []

        # Build call chains from sequential events in same thread
        threads: dict[int, list[TraceEvent]] = {}
        for event in events:
            tid = event.thread_id
            if tid not in threads:
                threads[tid] = []
            threads[tid].append(event)

        for tid, thread_events in threads.items():
            for i in range(len(thread_events) - 1):
                curr = thread_events[i]
                next_ev = thread_events[i + 1]
                curr_key = f"{curr.class_name}.{curr.method_name}"
                next_key = f"{next_ev.class_name}.{next_ev.method_name}"
                if curr_key in graph and next_key != curr_key and next_key not in graph[curr_key]:
                    graph[curr_key].append(next_key)

        report.call_graph = graph

    def _generate_findings(self, report: DynamicAnalysisReport) -> None:
        """Generate behavioral findings based on analyzed trace data."""
        findings: list[BehavioralFinding] = []

        # ── 1. Crypto operations ──
        crypto_count = len(report.crypto_operations)
        if crypto_count > 0:
            if crypto_count > 50:
                findings.append(BehavioralFinding(
                    title="High Volume of Crypto Operations",
                    description=f"The app performed {crypto_count} cryptographic operations during monitoring. Verify all encryption is using strong, standard algorithms.",
                    severity="medium",
                    category="crypto",
                    count=crypto_count,
                    recommendation="Audit all cryptographic operations to ensure they use strong, standard algorithms (AES-256, RSA-2048+).",
                ))
            else:
                findings.append(BehavioralFinding(
                    title="Cryptographic Operations Detected",
                    description=f"The app performed {crypto_count} cryptographic operations. Understand what data is being encrypted and how keys are managed.",
                    severity="low",
                    category="crypto",
                    count=crypto_count,
                    recommendation="Verify key management practices. Keys should be stored in the platform keychain/keystore, not in code or shared prefs.",
                ))

        # ── 2. File I/O patterns ──
        file_count = len(report.files_accessed)
        if file_count > 0:
            sensitive_files = [f for f in report.files_accessed if any(
                kw in f.lower() for kw in ["database", "pref", "cache", "token", "key", ".db", "credential", ".plist", "wallet"]
            )]
            if sensitive_files:
                findings.append(BehavioralFinding(
                    title="Sensitive Files Accessed",
                    description=f"The app accessed {len(sensitive_files)} sensitive files/paths including databases, preferences, or credential stores.",
                    severity="medium",
                    category="file_io",
                    evidence=sensitive_files[:10],
                    count=len(sensitive_files),
                    recommendation="Ensure sensitive files are properly protected with platform encryption (File-Based Encryption on Android, NSFileProtection on iOS).",
                ))

        # ── 3. Database queries ──
        db_count = len(report.db_queries)
        if db_count > 0:
            # Check for SQL injection risk
            dynamic_queries = [q for q in report.db_queries if q and "?" not in q and q.count("'") > 4]
            if dynamic_queries:
                findings.append(BehavioralFinding(
                    title="Dynamic SQL Queries (Potential Injection Risk)",
                    description=f"The app executed {len(dynamic_queries)} SQL queries without parameterized placeholders, which may indicate SQL injection vulnerability.",
                    severity="high",
                    category="data_access",
                    evidence=dynamic_queries[:5],
                    count=len(dynamic_queries),
                    recommendation="Use parameterized queries or prepared statements instead of string concatenation for SQL queries.",
                ))

            if "INSERT" in str(report.db_queries) and "password" in str(report.db_queries).lower():
                findings.append(BehavioralFinding(
                    title="Potential Credential Storage in Database",
                    description="The app appears to store credentials or passwords in a local database.",
                    severity="high",
                    category="data_access",
                    recommendation="Store credentials in the platform keychain/keystore, not in a plaintext database.",
                ))

        # ── 4. Network requests ──
        net_count = len(report.network_requests)
        if net_count > 0:
            http_urls = [req["url"] for req in report.network_requests if req.get("url", "").startswith("http://")]
            if http_urls:
                findings.append(BehavioralFinding(
                    title="HTTP (Non-TLS) Network Requests",
                    description=f"The app made {len(http_urls)} requests over unencrypted HTTP instead of HTTPS.",
                    severity="high",
                    category="network",
                    evidence=http_urls[:5],
                    count=len(http_urls),
                    recommendation="Ensure all network traffic uses HTTPS. Update network security configuration to block cleartext traffic.",
                ))

        # ── 5. Permission checks ──
        perm_count = len(report.permission_checks)
        if perm_count > 0:
            location_perms = [p for p in report.permission_checks if "location" in p.lower()]
            camera_perms = [p for p in report.permission_checks if "camera" in p.lower()]
            [p for p in report.permission_checks if "record_audio" in p.lower() or "microphone" in p.lower()]
            if location_perms and camera_perms:
                findings.append(BehavioralFinding(
                    title="Camera + Location Permission Access",
                    description="The app accessed both camera and location permissions at runtime.",
                    severity="medium",
                    category="permission",
                    evidence=[f"Location: {len(location_perms)}", f"Camera: {len(camera_perms)}"],
                    recommendation="Verify the app has a legitimate reason to access both camera and location simultaneously.",
                ))

        # ── 6. Suspicious API calls ──
        if report.sensitive_apis:
            high_risk_apis = [a for a in report.sensitive_apis if any(
                kw in a.get("api", "").lower() for kw in [
                    "telephonymanager.getdeviceid", "telephonymanager.getimei",
                    "telephonymanager.getsubscriberid", "accountmanager.getpassword",
                    "getinstalledpackages", "runtim.exec", "processbuilder.start",
                ]
            )]
            if high_risk_apis:
                findings.append(BehavioralFinding(
                    title="High-Risk API Calls Detected",
                    description=f"The app called {len(high_risk_apis)} high-risk APIs including device identifier access, command execution, or credential retrieval.",
                    severity="high",
                    category="suspicious",
                    evidence=[f"{a['api']} ({a.get('description', '')})" for a in high_risk_apis[:5]],
                    count=len(high_risk_apis),
                    recommendation="Investigate why the app needs to access device identifiers or execute shell commands. These APIs are often used for fingerprinting or device tracking.",
                ))

        # ── 7. Total method calls ──
        total_methods = len(report.methods_called)
        if total_methods > 0:
            findings.append(BehavioralFinding(
                title="Runtime Behavior Summary",
                description=f"The app invoked {report.total_events} method calls across {total_methods} unique APIs during the monitoring period ({report.duration_seconds:.1f}s).",
                severity="info",
                category="data_access",
                count=report.total_events,
                recommendation="Review the complete method trace for any unexpected API calls or behavioral patterns.",
            ))

        # ── 8. Suspicious pattern matching ──
        suspicious_evidence: list[str] = []
        for pattern in SUSPICIOUS_PATTERNS:
            regex = re.compile(pattern["pattern"])
            suspicious_evidence.extend(
                f"{mk} — {pattern['description']}"
                for mk in report.methods_called
                if regex.search(mk)
            )

        if suspicious_evidence:
            findings.append(BehavioralFinding(
                title="Suspicious Behavioral Patterns Detected",
                description=f"The app exhibits {len(suspicious_evidence)} suspicious behavioral patterns including jailbreak/root detection, debugger checks, or anti-hooking measures.",
                severity="high",
                category="suspicious",
                evidence=suspicious_evidence[:10],
                count=len(suspicious_evidence),
                recommendation="Apps implementing jailbreak/root detection, debugger checks, or anti-hooking may be hiding malicious behavior or violating user privacy.",
            ))

        report.findings = findings

    def analyze_trace_summary(self, trace_path: str) -> dict[str, Any]:
        """Quick summary of trace file without detailed analysis.

        Args:
            trace_path: Path to the trace file.

        Returns:
            Dict with summary statistics.
        """
        event_types: dict[str, int] = {}
        total_lines = 0

        with open(trace_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total_lines += 1
                try:
                    data = json.loads(line)
                    event_type = data.get("type", "unknown")
                    event_types[event_type] = event_types.get(event_type, 0) + 1
                except json.JSONDecodeError:
                    event_types["parse_error"] = event_types.get("parse_error", 0) + 1

        return {
            "total_events": total_lines,
            "event_types": event_types,
            "unique_events": len(event_types),
        }

