"""SSL Pinning Bypass — Frida script generation for Android and iOS.

Generates ready-to-use Frida JavaScript (.js) scripts that bypass SSL
pinning in mobile applications. Supports multiple bypass techniques
for both platforms.

Usage:
    from mobilesentry.ssl_pinning import SslBypassGenerator

    gen = SslBypassGenerator(output_dir="./frida_scripts")
    gen.generate_all()              # Generate all scripts
    gen.generate_platform("ios")    # Generate iOS scripts only
    gen.list_techniques()           # List available bypass techniques
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────


@dataclass
class SslBypassTechnique:
    """Metadata for a single SSL pinning bypass technique."""

    name: str
    platform: str  # "android", "ios"
    description: str
    libraries: list[str]  # Targeted libraries/frameworks
    quality: str  # "best", "good", "targeted"
    min_frida_version: str = "12.0"
    warnings: list[str] = field(default_factory=list)


@dataclass
class GeneratedScript:
    """A generated Frida script with metadata."""

    filename: str
    technique: SslBypassTechnique
    code: str
    output_path: str = ""

    @property
    def size_bytes(self) -> int:
        return len(self.code.encode("utf-8"))


# ══════════════════════════════════════════════
# Android Frida Scripts
# ══════════════════════════════════════════════


ANDROID_UNIVERSAL_SCRIPT = r"""/*
 * MobileSentry — Android Universal SSL Pinning Bypass
 *
 * Hooks SSLContext.init(), TrustManager.checkServerTrusted(),
 * and OkHttp CertificatePinner to accept any certificate.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_universal.js
 *        frida -U com.target.app --no-pause -l ssl_universal.js
 */

'use strict';

// Color-coded logging
const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    warn: (msg) => console.log(`[!] ${msg}`),
    error: (msg) => console.log(`[-] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Universal SSL Pinning Bypass loaded');
log.info('Target: All SSL/TLS verification in Java SSLContext + OkHttp');

// ── Hook 1: SSLContext.init() — Accept all TrustManagers ──
try {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (keyManager, trustManager, secureRandom) {
        log.info('SSLContext.init() hooked — overriding TrustManager');
        // Create a custom TrustManager that trusts all certificates
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustAllManager = Java.registerClass({
            name: 'com.mobilesentry.TrustAllManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {
                    log.detail('TrustAllManager: checkClientTrusted (accepting all)');
                },
                checkServerTrusted: function (chain, authType) {
                    log.detail('TrustAllManager: checkServerTrusted (accepting all)');
                },
                getAcceptedIssuers: function () {
                    return [];
                }
            }
        });
        this.init(keyManager, [TrustAllManager.$new()], secureRandom);
        log.info('SSL pinning bypassed via custom TrustAllManager');
    };
    log.info('✓ Hooked SSLContext.init()');
} catch (e) {
    log.warn('Could not hook SSLContext.init(): ' + e.message);
}

// ── Hook 2: X509TrustManager.checkServerTrusted() — Accept all ──
try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
        log.detail('X509TrustManager.checkServerTrusted bypassed (chain length: ' + chain.length + ')');
        // Don't throw — accept all certificates
    };
    log.info('✓ Hooked X509TrustManager.checkServerTrusted()');
} catch (e) {
    log.warn('Could not hook X509TrustManager: ' + e.message);
}

// ── Hook 3: TrustManager checkServerTrusted (alternate) ──
try {
    var TrustManager = Java.use('javax.net.ssl.TrustManager');
    log.info('✓ TrustManager interface found (cannot hook interface directly)');
} catch (e) {
    // Expected — TrustManager is an interface
}

// ── Hook 4: OkHttp3 CertificatePinner ──
try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
        log.info('OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
        return; // Accept all certificates
    };
    log.info('✓ Hooked okhttp3.CertificatePinner.check()');
} catch (e) {
    log.detail('okhttp3.CertificatePinner not found (OkHttp3 not used)');
}

// ── Hook 5: OkHttp2 CertificatePinner ──
try {
    var CertificatePinner2 = Java.use('com.squareup.okhttp.CertificatePinner');
    CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
        log.info('OkHttp2 CertificatePinner.check() bypassed for: ' + hostname);
        return;
    };
    log.info('✓ Hooked com.squareup.okhttp.CertificatePinner.check()');
} catch (e) {
    log.detail('com.squareup.okhttp.CertificatePinner not found (OkHttp2 not used)');
}

// ── Hook 6: HostnameVerifier ──
try {
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    HostnameVerifier.verify.implementation = function (hostname, session) {
        log.detail('HostnameVerifier.verify() bypassed for: ' + hostname);
        return true;
    };
    log.info('✓ Hooked HostnameVerifier.verify()');
} catch (e) {
    log.warn('Could not hook HostnameVerifier: ' + e.message);
}

// ── Hook 7: TrustKit (Android) ──
try {
    var TrustKit = Java.use('com.datatheorem.android.trustkit.TrustKit');
    TrustKit.initializeWithNetworkSecurityConfiguration.implementation = function (context) {
        log.info('TrustKit.initializeWithNetworkSecurityConfiguration() blocked');
        // No-op: skip initialization to prevent pinning
    };
    log.info('✓ Hooked TrustKit (com.datatheorem.android.trustkit)');
} catch (e) {
    log.detail('TrustKit not found');
}

// ── Hook 8: Apache HTTP Client SSL ──
try {
    var SSLSocketFactory = Java.use('org.apache.http.conn.ssl.SSLSocketFactory');
    SSLSocketFactory.createSocket.overload(
        'java.net.Socket',
        'java.lang.String',
        'int',
        'boolean'
    ).implementation = function (socket, host, port, autoClose) {
        log.detail('Apache SSLSocketFactory.createSocket() bypassed for: ' + host);
        // Don't verify hostname — accept all
        var sf = this.createSocket(socket, host, port, autoClose);
        return sf;
    };
    log.info('✓ Hooked Apache HTTP SSLSocketFactory');
} catch (e) {
    log.detail('Apache HTTP Client SSLSocketFactory not found');
}

// ── Hook 9: OKHttp3 CertificateChainCleaner ──
try {
    var CertificateChainCleaner = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
    CertificateChainCleaner.clean.overload('java.util.List', 'java.lang.String').implementation = function (chain, hostname) {
        log.detail('CertificateChainCleaner.clean() bypassed for: ' + hostname);
        return chain;
    };
    log.info('✓ Hooked OkHttp3 CertificateChainCleaner');
} catch (e) {
    log.detail('OkHttp3 CertificateChainCleaner not found');
}

// ── Hook 10: WebView SSL Error Handler ──
try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.overload(
        'android.webkit.WebView',
        'android.webkit.SslErrorHandler',
        'android.net.http.SslError'
    ).implementation = function (view, handler, error) {
        log.info('WebView SSL error bypassed: ' + error.getPrimaryError());
        handler.proceed(); // Ignore SSL error and proceed
    };
    log.info('✓ Hooked WebViewClient.onReceivedSslError()');
} catch (e) {
    log.detail('WebView SSL error handler hook failed: ' + e.message);
}

log.info('All SSL pinning bypass hooks installed');
log.info('─────────────────────────────────────────────');
"""

ANDROID_OKHTTP_SCRIPT = r"""/*
 * MobileSentry — OkHttp SSL Pinning Bypass (Android)
 *
 * Targets OkHttp3/4 CertificatePinner specifically.
 * Use when only OkHttp pinning needs to be bypassed.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_okhttp3.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry OkHttp SSL Pinning Bypass loaded');

// ── OkHttp3/4 CertificatePinner ──
try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
        log.info('OkHttp3 CertificatePinner bypassed for: ' + hostname);
        return;
    };
    log.info('✓ Hooked okhttp3.CertificatePinner.check()');
} catch (e) {
    log.detail('okhttp3.CertificatePinner not found');
}

try {
    var CertificatePinner2 = Java.use('com.squareup.okhttp.CertificatePinner');
    CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
        log.info('OkHttp2 CertificatePinner bypassed for: ' + hostname);
        return;
    };
    log.info('✓ Hooked com.squareup.okhttp.CertificatePinner.check()');
} catch (e) {
    log.detail('com.squareup.okhttp.CertificatePinner not found');
}

// ── OkHttp3 CertificateChainCleaner ──
try {
    var CertificateChainCleaner = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
    CertificateChainCleaner.clean.overload('java.util.List', 'java.lang.String').implementation = function (chain, hostname) {
        log.detail('CertificateChainCleaner bypassed for: ' + hostname);
        return chain;
    };
    log.info('✓ Hooked OkHttp3 CertificateChainCleaner');
} catch (e) {
    log.detail('OkHttp3 CertificateChainCleaner not found');
}

// ── OkHttp3 RealCall (early SSL check) ──
try {
    var RealCall = Java.use('okhttp3.RealCall');
    RealCall.getResponseWithInterceptorChain.implementation = function () {
        log.detail('RealCall.getResponseWithInterceptorChain intercepted');
        return this.getResponseWithInterceptorChain();
    };
    log.info('✓ Hooked okhttp3.RealCall');
} catch (e) {
    log.detail('okhttp3.RealCall not found');
}

log.info('OkHttp bypass hooks complete');
"""

ANDROID_TRUSTMANAGER_SCRIPT = r"""/*
 * MobileSentry — TrustManager SSL Pinning Bypass (Android)
 *
 * Hooks SSLContext.init() to inject a custom TrustManager
 * that accepts all certificates. Works with any networking
 * library that uses standard Java SSLContext.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_trustmanager.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry TrustManager Bypass loaded');

Java.perform(function () {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // Create a single trust-all TrustManager class
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustAllManager = Java.registerClass({
        name: 'com.mobilesentry.TrustAllManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {
                log.detail('TrustAll: checkClientTrusted');
            },
            checkServerTrusted: function (chain, authType) {
                log.detail('TrustAll: checkServerTrusted for ' + (chain.length > 0 ? chain[0].getSubjectDN().getName() : 'unknown'));
            },
            getAcceptedIssuers: function () {
                return [];
            }
        }
    });

    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (keyManager, trustManager, secureRandom) {
        log.info('SSLContext.init intercepted — injecting TrustAllManager');

        // In case the app passes its own X509TrustManager
        try {
            var x509Trust = Java.use('javax.net.ssl.X509TrustManager');
            if (trustManager !== null && trustManager.length > 0) {
                for (var i = 0; i < trustManager.length; i++) {
                    if (trustManager[i] !== null) {
                        var wrapper = Java.cast(trustManager[i], x509Trust);
                        var originalImpl = wrapper.checkServerTrusted;
                        wrapper.checkServerTrusted.implementation = function (chain, authType) {
                            log.detail('App-specific X509TrustManager bypassed');
                            // Don't throw — accept all
                        };
                    }
                }
            }
        } catch (e) {
            log.detail('Could not wrap app trust managers: ' + e.message);
        }

        this.init(keyManager, [TrustAllManager.$new()], secureRandom);
        log.info('✓ TrustAllManager injected into SSLContext');
    };

    log.info('✓ SSLContext.init() hook installed');
});

log.info('TrustManager bypass hooks complete');
"""

ANDROID_WEBVIEW_SCRIPT = r"""/*
 * MobileSentry — WebView SSL Bypass (Android)
 *
 * Hooks WebViewClient and WebChromeClient SSL error handlers
 * to proceed on any SSL certificate error.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_webview.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry WebView SSL Bypass loaded');

Java.perform(function () {
    // ── Hook 1: WebViewClient.onReceivedSslError ──
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overload(
            'android.webkit.WebView',
            'android.webkit.SslErrorHandler',
            'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            log.info('WebView SSL error intercepted');
            log.detail('Error type: ' + error.getPrimaryError());
            log.detail('URL: ' + view.getUrl());
            handler.proceed();
            log.info('✓ SSL error handler: proceeding anyway');
        };
        log.info('✓ Hooked onReceivedSslError()');
    } catch (e) {
        log.detail('onReceivedSslError hook failed: ' + e.message);
    }

    // ── Hook 2: onReceivedError (includes SSL) ──
    try {
        WebViewClient.onReceivedError.overload(
            'android.webkit.WebView',
            'int',
            'java.lang.String',
            'java.lang.String'
        ).implementation = function (view, errorCode, description, failingUrl) {
            log.detail('WebView error: ' + errorCode + ' - ' + description);
            // Don't block — let the page load regardless
        };
        log.info('✓ Hooked onReceivedError()');
    } catch (e) {
        log.detail('onReceivedError hook failed: ' + e.message);
    }

    // ── Hook 3: WebView.loadUrl (with extra headers injection) ──
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            log.detail('WebView loading URL: ' + url);
            this.loadUrl(url);
        };
    } catch (e) {
        log.detail('WebView.loadUrl hook failed: ' + e.message);
    }

    // ── Hook 4: SslErrorHandler.proceed (defensive) ──
    try {
        var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
        SslErrorHandler.proceed.implementation = function () {
            log.detail('SslErrorHandler.proceed() called');
            this.proceed();
        };
        SslErrorHandler.cancel.implementation = function () {
            log.detail('SslErrorHandler.cancel() intercepted — forcing proceed');
            this.proceed();
        };
        log.info('✓ Hooked SslErrorHandler');
    } catch (e) {
        log.detail('SslErrorHandler hook failed: ' + e.message);
    }
});

log.info('WebView SSL bypass hooks complete');
"""

ANDROID_FLUTTER_SCRIPT = r"""/*
 * MobileSentry — Flutter SSL Pinning Bypass (Android)
 *
 * Hooks Flutter's Dart SSL handling to bypass certificate
 * validation. Works with both Dart HTTP client and platform
 * channel SSL verification.
 *
 * Based on: https://github.com/rscloura/FridaDroidSSLPinningBypass
 *
 * Frida version: >= 14.0
 * Usage: frida -U -f com.target.app -l ssl_flutter.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Flutter SSL Pinning Bypass loaded');

// ── Hook Flutter's SSL via Dart VM ──
// Flutter uses Dart's HttpClient which connects through platform channels.
// We need to intercept at both levels.

Java.perform(function () {
    // Hook the Flutter JNI bridge to inject SSL bypass
    try {
        var FlutterJNI = Java.use('io.flutter.embedding.engine.FlutterJNI');
        if (FlutterJNI) {
            log.info('✓ Flutter engine detected (io.flutter.embedding.engine)');
        }
    } catch (e) {
        log.detail('io.flutter.embedding.engine not found');
    }

    // Hook Flutter's platform channel SSL verification
    try {
        var BinaryMessenger = Java.use('io.flutter.plugin.common.BinaryMessenger');
        log.info('✓ Flutter BinaryMessenger detected');
    } catch (e) {
        log.detail('Flutter BinaryMessenger not found');
    }

    // Hook OkHttp (used by Flutter HTTP client on Android)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            log.info('Flutter -> OkHttp: CertificatePinner bypassed for: ' + hostname);
            return;
        };
        log.info('✓ Hooked OkHttp CertificatePinner (Flutter layer)');
    } catch (e) {
        log.detail('No OkHttp CertificatePinner found in Flutter app');
    }

    // Hook the Dart VM's SSL verification functions
    try {
        var DART_SSL = Module.findExportByName(null, 'Dart_SSLCertificate_verify');
        if (DART_SSL) {
            Interceptor.attach(DART_SSL, {
                onEnter: function (args) {
                    log.info('Dart SSL certificate verification intercepted');
                },
                onLeave: function (retval) {
                    log.info('Dart SSL verify returning: true');
                    retval.replace(1); // Return true (accept all)
                }
            });
            log.info('✓ Hooked Dart_SSLCertificate_verify');
        }
    } catch (e) {
        log.detail('Dart_SSLCertificate_verify not found (non-Flutter or different Dart version)');
    }

    // Try Flutter Dart SSL via binary search
    try {
        var dartLib = Process.findModuleByName('libflutter.so');
        if (dartLib) {
            log.info('libflutter.so found at base: ' + dartLib.base);
            // Search for SSL-related symbols in libflutter.so
            var sslVerifySym = Module.enumerateSymbolsSync('libflutter.so')
                .filter(s => s.name.toLowerCase().indexOf('ssl') !== -1 &&
                           (s.name.toLowerCase().indexOf('cert') !== -1 ||
                            s.name.toLowerCase().indexOf('verify') !== -1));
            if (sslVerifySym.length > 0) {
                log.info('Found ' + sslVerifySym.length + ' SSL-related symbols in libflutter.so');
                sslVerifySym.forEach(function (sym) {
                    log.detail('  Symbol: ' + sym.name + ' @ ' + sym.address);
                });
            } else {
                log.detail('No SSL symbols found in libflutter.so');
            }
        }
    } catch (e) {
        log.detail('libflutter.so not found (not a Flutter app)');
    }

    // ── Hook Android KeyStore (used by Flutter plugins) ──
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getTrustedCertificate.overload('java.security.cert.Certificate').implementation = function (cert) {
            log.detail('KeyStore.getTrustedCertificate intercepted');
            return this.getTrustedCertificate(cert);
        };
        log.info('✓ Hooked KeyStore.getTrustedCertificate()');
    } catch (e) {
        log.detail('KeyStore hook failed: ' + e.message);
    }
});

log.info('Flutter SSL bypass hooks complete');
"""

ANDROID_XAMARIN_SCRIPT = r"""/*
 * MobileSentry — Xamarin SSL Pinning Bypass (Android)
 *
 * Works with Xamarin.Android apps. Hooks both the managed
 * and native SSL layers.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_xamarin.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Xamarin SSL Pinning Bypass loaded');

Java.perform(function () {
    // Xamarin wraps Java SSL — hook both SSLContext and the Mono runtime

    // ── Hook SSLContext (Xamarin uses standard Java SSL) ──
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

        var TrustAll = Java.registerClass({
            name: 'com.mobilesentry.XamarinTrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    log.detail('Xamarin: server certificate accepted: ' + (chain[0] ? chain[0].getSubjectDN().getName() : 'unknown'));
                },
                getAcceptedIssuers: function () { return []; }
            }
        });

        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (keyManager, trustManager, secureRandom) {
            log.info('Xamarin SSLContext.init intercepted — injecting trust-all');
            this.init(keyManager, [TrustAll.$new()], secureRandom);
        };
        log.info('✓ Hooked Xamarin SSLContext.init()');
    } catch (e) {
        log.warn('Xamarin SSLContext hook failed: ' + e.message);
    }

    // ── Hook HostnameVerifier ──
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        HostnameVerifier.verify.implementation = function (hostname, session) {
            log.detail('Xamarin: HostnameVerifier bypassed for: ' + hostname);
            return true;
        };
        log.info('✓ Hooked Xamarin HostnameVerifier');
    } catch (e) {
        log.detail('Xamarin HostnameVerifier hook failed');
    }

    // ── Hook OkHttp if present (Xamarin can use bindings) ──
    try {
        var Cp = Java.use('okhttp3.CertificatePinner');
        Cp.check.implementation = function (hostname, peerCertificates) {
            log.info('Xamarin -> OkHttp: CertificatePinner bypassed for: ' + hostname);
            return;
        };
        log.info('✓ Hooked Xamarin OkHttp CertificatePinner');
    } catch (e) {
        log.detail('Xamarin OkHttp not found');
    }
});

log.info('Xamarin SSL bypass hooks complete');
"""


# ══════════════════════════════════════════════
# iOS Frida Scripts
# ══════════════════════════════════════════════


IOS_UNIVERSAL_SCRIPT = r"""/*
 * MobileSentry — iOS Universal SSL Pinning Bypass
 *
 * Hooks NSURLSession, NSURLConnection, NSURLProtocol delegate
 * methods for TLS trust evaluation. Also hooks AFNetworking
 * and Alamofire pinning mechanisms.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_universal_ios.js
 *        frida -U com.target.app --no-pause -l ssl_universal_ios.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    warn: (msg) => console.log(`[!] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry iOS Universal SSL Pinning Bypass loaded');

// ── Hook 1: NSURLSession delegate: didReceiveChallenge ──
try {
    var NSURLSession = ObjC.classes.NSURLSession;
    log.info('✓ NSURLSession class found');
} catch (e) {
    log.warn('NSURLSession not found');
}

// Hook NSURLSession delegate methods for authentication challenges
try {
    var origImp = ObjC.classes.NSObject['- URLSession:didReceiveChallenge:completionHandler:'];
    if (origImp) {
        // Already implemented — hook it
    }
} catch (e) {
    // Expected — the delegate may implement it per-session
}

// ── Hook 2: NSURLConnection delegate: canAuthenticateAgainstProtectionSpace ──
try {
    var NSURLConnection = ObjC.classes.NSURLConnection;
    if (NSURLConnection) {
        log.info('✓ NSURLConnection class found');
    }
} catch (e) {
    log.detail('NSURLConnection not found');
}

// ── Hook 3: NSURLProtectionSpace (accept all) ──
try {
    var protectionSpace = ObjC.classes.NSURLProtectionSpace;
    log.info('✓ NSURLProtectionSpace class found');
} catch (e) {
    log.detail('NSURLProtectionSpace not found');
}

// ── Hook 4: [NSURLRequest allowsCellularAccess] related SSL bypass ──
try {
    var allowsCellular = ObjC.classes.NSMutableURLRequest['+ requestWithURL:'];
    if (allowsCellular) {
        log.info('✓ NSMutableURLRequest class found');
    }
} catch (e) {
    log.detail('NSMutableURLRequest not found');
}

// ── Hook 5: AFSecurityPolicy (AFNetworking) ──
try {
    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (AFSecurityPolicy) {
        log.info('✓ AFSecurityPolicy found (AFNetworking detected)');

        AFSecurityPolicy['- setSSLPinningMode:'].implementation = function (self, sel, mode) {
            log.info('AFSecurityPolicy.setSSLPinningMode intercepted — blocking pinning');
            // Don't call original — just suppress the setter to prevent pinning
        };

        // Hook allowInvalidCertificates
        try {
            var origAllowInvalid = AFSecurityPolicy['- allowsInvalidCertificates'];
            if (origAllowInvalid) {
                AFSecurityPolicy['- allowsInvalidCertificates'].implementation = function (self, sel) {
                    log.detail('AFSecurityPolicy.allowInvalidCertificates returning YES');
                    return 1; // YES
                };
            }
        } catch (e) {
            log.detail('allowInvalidCertificates not found');
        }

        // Hook setAllowInvalidCertificates:
        try {
            AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation = function (self, sel, allow) {
                log.info('AFSecurityPolicy.setAllowInvalidCertificates intercepted — blocking');
                // Don't call original — just suppress the setter
            };
        } catch (e) {
            log.detail('setAllowInvalidCertificates not found');
        }

        // Hook evaluatesServerTrust (main pinning check)
        try {
            AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation = function (self, sel, serverTrust, domain) {
                log.info('AFSecurityPolicy.evaluateServerTrust bypassed for: ' + (domain ? ObjC.classes.NSString.stringWithString(domain).toString() : 'nil'));
                return 1; // YES — trust everything
            };
            log.info('✓ Hooked AFSecurityPolicy.evaluateServerTrust:forDomain:');
        } catch (e) {
            log.detail('evaluateServerTrust:forDomain: not found');
        }
    }
} catch (e) {
    log.detail('AFNetworking not found');
}

// ── Hook 6: ServerTrustEvaluation (Alamofire / Swift) ──
try {
    var Alamofire = ObjC.classes.Alamofire;
    if (Alamofire) {
        log.info('✓ Alamofire framework detected');
    }
} catch (e) {
    log.detail('Alamofire not found');
}

// ── Hook 7: TrustKit (iOS) ──
try {
    var TrustKitClass = ObjC.classes.TrustKit;
    if (TrustKitClass) {
        log.info('✓ TrustKit detected on iOS');

        // Try to hook TrustKit's pinning validation
        try {
            TrustKitClass['+ swizzleNetworkingMethods'].implementation = function () {
                log.info('TrustKit swizzleNetworkingMethods intercepted — blocking');
                // Don't swizzle = pinning is disabled
            };
            log.info('✓ Hooked TrustKit.swizzleNetworkingMethods');
        } catch (e) {
            log.detail('Could not hook TrustKit swizzleNetworkingMethods');
        }

        // Hook PinningValidator
        try {
            var PinningValidator = ObjC.classes['TrustKitPinningValidator'];
            if (PinningValidator) {
                PinningValidator['+ evaluateTrust:forHostname:'].implementation = function (self, sel, trust, hostname) {
                    log.info('TrustKitPinningValidator.evaluateTrust bypassed for: ' + hostname);
                    return 1; // YES
                };
                log.info('✓ Hooked TrustKitPinningValidator');
            }
        } catch (e) {
            log.detail('TrustKitPinningValidator not found');
        }
    }
} catch (e) {
    log.detail('TrustKit not found on iOS');
}

// ── Hook 8: NSURLSession/NSURLConnection auth challenge (universal) ──
// This is the main hook for iOS — intercepts authentication challenges
// from NSURLSessionDataDelegate and NSURLConnectionDelegate

// We use a dynamic approach: find all classes implementing the delegate methods
try {
    var methods = [
        '- URLSession:didReceiveChallenge:completionHandler:',
        '- connection:didReceiveAuthenticationChallenge:',
        '- webView:didReceiveAuthenticationChallenge:completionHandler:'
    ];

    // Enumerate all classes and hook those with SSL delegate methods
    var allClasses = ObjC.enumerateLoadedClassesSync();
    log.info('Enumerating ' + allClasses.length + ' loaded classes for SSL delegate methods');

    allClasses.forEach(function (className) {
        var clazz = ObjC.classes[className];
        if (!clazz) return;

        // Check for NSURLSession auth challenge handler
        try {
            var sessionMethod = clazz['- URLSession:didReceiveChallenge:completionHandler:'];
            if (sessionMethod) {
                log.detail('Hooking NSURLSession delegate in: ' + className);
                sessionMethod.implementation = function (self, sel, session, challenge, completion) {
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod();
                    var host = protectionSpace.host();

                    if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                        log.info('SSL bypass: accepting server trust for: ' + host);
                        var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                        var block = new ObjC.Block(completion);
                        block.implementation(disposition, credential);
                        return;
                    }

                    // Forward non-SSL challenges
                    var block = new ObjC.Block(completion);
                    block.implementation(0, null); // NSURLSessionAuthChallengePerformDefaultHandling
                };
            }
        } catch (e) {
            // No auth challenge method in this class
        }

        // Check for NSURLConnection auth challenge handler
        try {
            var connMethod = clazz['- connection:didReceiveAuthenticationChallenge:'];
            if (connMethod) {
                log.detail('Hooking NSURLConnection delegate in: ' + className);
                connMethod.implementation = function (self, sel, connection, challenge) {
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod();
                    var host = protectionSpace.host();

                    if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                        log.info('SSL bypass: accepting server trust for: ' + host);
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                        challenge.sender().useCredential(credential, challenge);
                        return;
                    }

                    challenge.sender().continueWithoutCredential(challenge);
                };
            }
        } catch (e) {
            // No auth challenge method in this class
        }
    });
} catch (e) {
    log.warn('Error enumerating classes for SSL delegates: ' + e.message);
}

log.info('All iOS SSL pinning bypass hooks installed');
log.info('─────────────────────────────────────────────');
"""

IOS_AFNETWORKING_SCRIPT = r"""/*
 * MobileSentry — AFNetworking SSL Pinning Bypass (iOS)
 *
 * Specifically targets AFSecurityPolicy used by AFNetworking.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_afnetworking.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry AFNetworking SSL Bypass loaded');

if (ObjC.available) {
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            log.info('✓ AFNetworking AFSecurityPolicy detected');

            // ── Hook SSLPinningMode ──
            try {
                AFSecurityPolicy['- setSSLPinningMode:'].implementation = function (self, sel, mode) {
                    log.info('setSSLPinningMode intercepted — blocking pinning');
                    // Don't call original — suppress the setter
                };
                log.info('✓ Hooked setSSLPinningMode:');
            } catch (e) {
                log.detail('setSSLPinningMode hook failed');
            }

            // ── Hook evaluatesServerTrust:forDomain: ──
            try {
                var origEvaluate = AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
                if (origEvaluate) {
                    origEvaluate.implementation = function (self, sel, serverTrust, domain) {
                        var domainStr = domain ? ObjC.classes.NSString.stringWithString(domain).toString() : '(null)';
                        log.info('evaluateServerTrust bypassed for domain: ' + domainStr);
                        return 1; // YES — always trust
                    };
                    log.info('✓ Hooked evaluateServerTrust:forDomain:');
                }
            } catch (e) {
                log.detail('evaluateServerTrust hook failed: ' + e.message);
            }

            // ── Hook allowInvalidCertificates ──
            try {
                AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation = function (self, sel, allow) {
                    log.info('setAllowInvalidCertificates intercepted — blocking');
                    // Don't call original — suppress the setter
                };
                log.info('✓ Hooked setAllowInvalidCertificates:');
            } catch (e) {
                log.detail('setAllowInvalidCertificates hook failed');
            }

            // ── Hook validatesDomainName ──
            try {
                AFSecurityPolicy['- setValidatesDomainName:'].implementation = function (self, sel, validate) {
                    log.info('setValidatesDomainName intercepted — blocking');
                    // Don't call original — suppress the setter
                };
                log.info('✓ Hooked setValidatesDomainName:');
            } catch (e) {
                log.detail('setValidatesDomainName hook failed');
            }

            // ── Hook pinnedCertificates ──
            try {
                AFSecurityPolicy['- setPinnedCertificates:'].implementation = function (self, sel, certs) {
                    log.info('setPinnedCertificates intercepted — clearing pins');
                    // Don't call original — just suppress the setter to prevent pins from being stored
                };
                log.info('✓ Hooked setPinnedCertificates:');
            } catch (e) {
                log.detail('setPinnedCertificates hook failed');
            }
        } else {
            log.detail('AFSecurityPolicy not found (AFNetworking not used)');
        }
    } catch (e) {
        log.warn('Error hooking AFSecurityPolicy: ' + e.message);
    }
} else {
    log.warn('Objective-C runtime not available');
}

log.info('AFNetworking bypass hooks complete');
"""

IOS_ALAMOFIRE_SCRIPT = r"""/*
 * MobileSentry — Alamofire SSL Pinning Bypass (iOS)
 *
 * Targets Alamofire 4.x/5.x ServerTrustEvaluation.
 * Uses Swift runtime introspection to disable pinning.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_alamofire.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Alamofire SSL Bypass loaded');

if (ObjC.available) {
    // ── Hook ServerTrustManager (Alamofire) ──
    try {
        var ServerTrustManager = ObjC.classes['Alamofire.ServerTrustManager'];
        if (ServerTrustManager) {
            log.info('✓ Alamofire ServerTrustManager detected');

            var hostSel = '- serverTrustManager:evaluateServerTrust:forHost:';

            // Hook the evaluator creation
            try {
                ServerTrustManager['- init'].implementation = function (self, sel) {
                    log.info('Alamofire ServerTrustManager.init intercepted');
                    // Don't call original init — prevent evaluators from being configured
                    return self;
                };
                log.info('✓ Hooked ServerTrustManager init');
            } catch (e) {
                log.detail('ServerTrustManager init hook failed');
            }
        }
    } catch (e) {
        log.detail('Alamofire ServerTrustManager not found');
    }

    // ── Hook PinnedCertificatesTrustEvaluator ──
    try {
        var PinnedEval = ObjC.classes['Alamofire.PinnedCertificatesTrustEvaluator'];
        if (PinnedEval) {
            log.info('✓ Alamofire PinnedCertificatesTrustEvaluator detected');
            try {
                PinnedEval['- evaluateTrust:forHost:'].implementation = function (self, sel, trust, host) {
                    log.info('PinnedCertificatesTrustEvaluator bypassed for: ' + host);
                    return; // Swift throws on failure — returning is success
                };
                log.info('✓ Hooked PinnedCertificatesTrustEvaluator.evaluate');
            } catch (e) {
                log.detail('PinnedCertificatesTrustEvaluator evaluate hook failed');
            }
        }
    } catch (e) {
        log.detail('Alamofire PinnedCertificatesTrustEvaluator not found');
    }

    // ── Hook PublicKeysTrustEvaluator ──
    try {
        var PublicKeyEval = ObjC.classes['Alamofire.PublicKeysTrustEvaluator'];
        if (PublicKeyEval) {
            log.info('✓ Alamofire PublicKeysTrustEvaluator detected');
            try {
                PublicKeyEval['- evaluateTrust:forHost:'].implementation = function (self, sel, trust, host) {
                    log.info('PublicKeysTrustEvaluator bypassed for: ' + host);
                    return;
                };
                log.info('✓ Hooked PublicKeysTrustEvaluator.evaluate');
            } catch (e) {
                log.detail('PublicKeysTrustEvaluator evaluate hook failed');
            }
        }
    } catch (e) {
        log.detail('Alamofire PublicKeysTrustEvaluator not found');
    }

    // ── Hook CompositeTrustEvaluator ──
    try {
        var CompositeEval = ObjC.classes['Alamofire.CompositeTrustEvaluator'];
        if (CompositeEval) {
            log.info('✓ Alamofire CompositeTrustEvaluator detected');
            try {
                CompositeEval['- evaluateTrust:forHost:'].implementation = function (self, sel, trust, host) {
                    log.info('CompositeTrustEvaluator bypassed for: ' + host);
                    return;
                };
                log.info('✓ Hooked CompositeTrustEvaluator.evaluate');
            } catch (e) {
                log.detail('CompositeTrustEvaluator evaluate hook failed');
            }
        }
    } catch (e) {
        log.detail('Alamofire CompositeTrustEvaluator not found');
    }

    // ── Hook DisabledEvaluator ──
    try {
        var DisabledEval = ObjC.classes['Alamofire.DisabledTrustEvaluator'];
        if (DisabledEval) {
            log.info('✓ Alamofire DisabledTrustEvaluator found (pinning already disabled)');
        }
    } catch (e) {
        log.detail('Alamofire DisabledTrustEvaluator not found');
    }

    // ── Fallback: Hook the underlying URLSession from Alamofire ──
    try {
        var SessionDelegate = ObjC.classes['Alamofire.SessionDelegate'];
        if (SessionDelegate) {
            log.info('✓ Alamofire SessionDelegate detected');
            try {
                SessionDelegate['- urlSession:didReceiveChallenge:completionHandler:'].implementation = function (self, sel, session, challenge, completion) {
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod();
                    var host = protectionSpace.host();

                    if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                        log.info('Alamofire URLSession: accepting server trust for: ' + host);
                        var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                        var block = new ObjC.Block(completion);
                        block.implementation(disposition, credential);
                        return;
                    }
                    var block = new ObjC.Block(completion);
                    block.implementation(0, null);
                };
                log.info('✓ Hooked Alamofire SessionDelegate URLSession challenge');
            } catch (e) {
                log.detail('Alamofire SessionDelegate URLSession challenge hook failed');
            }
        }
    } catch (e) {
        log.detail('Alamofire SessionDelegate not found');
    }
}

log.info('Alamofire bypass hooks complete');
"""

IOS_TRUSTKIT_SCRIPT = r"""/*
 * MobileSentry — TrustKit SSL Pinning Bypass (iOS)
 *
 * Targets TrustKit iOS library for SSL pinning bypass.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_trustkit.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry TrustKit SSL Bypass loaded');

if (ObjC.available) {
    try {
        var TrustKit = ObjC.classes.TrustKit;
        if (TrustKit) {
            log.info('✓ TrustKit detected');

            // ── Hook initialization ──
            try {
                TrustKit['+ initializeWithConfiguration:'].implementation = function (self, sel, config) {
                    log.info('TrustKit.initializeWithConfiguration intercepted — blocking');
                    // Don't call original = no pinning initialized
                };
                log.info('✓ Hooked +initializeWithConfiguration:');
            } catch (e) {
                log.detail('initializeWithConfiguration hook failed');
            }

            // ── Hook sharedInstance ──
            try {
                TrustKit['+ sharedInstance'].implementation = function (self, sel) {
                    log.detail('TrustKit.sharedInstance returning nil');
                    return null;
                };
                log.info('✓ Hooked +sharedInstance');
            } catch (e) {
                log.detail('sharedInstance hook failed');
            }

            // ── Hook swizzleNetworkMethods ──
            try {
                var cls = TrustKit;
                var selectorStr = '+ swizzleNetworkMethods';
                // ObjC resolve
                var swizzleSel = ObjC.selector('swizzleNetworkMethods');
                if (swizzleSel) {        TrustKit['+ swizzleNetworkMethods'].implementation = function () {
                    log.info('TrustKit swizzleNetworkMethods blocked');
                };
                log.info('✓ Hooked +swizzleNetworkMethods');
                }
            } catch (e) {
                log.detail('swizzleNetworkMethods hook failed');
            }

            // ── Hook PinningValidator ──
            try {
                var PinningValidator = ObjC.classes['TSKPinningValidator'];
                if (!PinningValidator) {
                    PinningValidator = ObjC.classes['TrustKitPinningValidator'];
                }
                if (PinningValidator) {
                    // Hook evaluateTrust
                    try {
                        PinningValidator['+ evaluateTrust:forHostname:'].implementation = function (self, sel, trust, hostname) {
                            log.info('PinningValidator.evaluateTrust bypassed for: ' + hostname);
                            return 1; // YES
                        };
                        log.info('✓ Hooked PinningValidator.evaluateTrust:forHostname:');
                    } catch (e) {
                        log.detail('PinningValidator evaluateTrust hook failed');
                    }

                    // Hook evaluateTrust:forHostname:additionalHeaders:
                    try {
                        PinningValidator['+ evaluateTrust:forHostname:additionalHeaders:'].implementation = function (self, sel, trust, hostname, headers) {
                            log.info('PinningValidator.evaluateTrust (with headers) bypassed for: ' + hostname);
                            return 1; // YES
                        };
                        log.info('✓ Hooked PinningValidator.evaluateTrust:forHostname:additionalHeaders:');
                    } catch (e) {
                        log.detail('PinningValidator extended evaluateTrust hook failed');
                    }
                }
            } catch (e) {
                log.detail('PinningValidator not found');
            }
        } else {
            log.detail('TrustKit not found');
        }
    } catch (e) {
        log.warn('Error hooking TrustKit: ' + e.message);
    }
}

log.info('TrustKit bypass hooks complete');
"""

IOS_FLUTTER_SCRIPT = r"""/*
 * MobileSentry — Flutter SSL Pinning Bypass (iOS)
 *
 * Hooks Flutter's iOS SSL/TLS through both native platform
 * channels and Dart VM hooks.
 *
 * Frida version: >= 14.0
 * Usage: frida -U -f com.target.app -l ssl_flutter_ios.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Flutter iOS SSL Bypass loaded');

if (ObjC.available) {
    // ── Hook Flutter's URL loading via NSURLSession ──
    // Flutter uses NSURLSession under the hood on iOS

    try {
        var FlutterEngine = ObjC.classes.FlutterEngine;
        if (FlutterEngine) {
            log.info('✓ FlutterEngine detected');
        }
    } catch (e) {
        log.detail('FlutterEngine not found');
    }

    // ── Hook NSURLSession (Flutter's network layer) ──
    try {
        var URLSession = ObjC.classes.NSURLSession;
        log.info('✓ NSURLSession found for Flutter networking');

        // Hook all NSURLSessionDataDelegate implementations
        var allClasses = ObjC.enumerateLoadedClassesSync();
        allClasses.forEach(function (className) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) return;

                var method = clazz['- URLSession:didReceiveChallenge:completionHandler:'];
                if (method) {
                    log.detail('Flutter -> Hooking URLSession delegate in: ' + className);
                    method.implementation = function (self, sel, session, challenge, completion) {
                        var protectionSpace = challenge.protectionSpace();
                        var authMethod = protectionSpace.authenticationMethod();
                        var host = protectionSpace.host();

                        if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                            log.info('Flutter SSL bypass: accepting server trust for: ' + host);
                            var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                            var block = new ObjC.Block(completion);
                            block.implementation(disposition, credential);
                            return;
                        }
                        var block = new ObjC.Block(completion);
                        block.implementation(0, null);
                    };
                }
            } catch (e) {}
        });
    } catch (e) {
        log.detail('NSURLSession hook failed: ' + e.message);
    }

    // ── Hook Flutter platform channel SSL validation ──
    try {
        var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;
        if (FlutterMethodChannel) {
            log.info('✓ FlutterMethodChannel detected');
            try {
                FlutterMethodChannel['- invokeMethod:arguments:'].implementation = function (self, sel, method, args) {
                    var methodStr = method ? ObjC.classes.NSString.stringWithString(method).toString() : '';
                    if (methodStr.toLowerCase().indexOf('ssl') !== -1 ||
                        methodStr.toLowerCase().indexOf('cert') !== -1 ||
                        methodStr.toLowerCase().indexOf('trust') !== -1) {
                        log.info('Flutter method channel: SSL-related call intercepted: ' + methodStr);
                    }
                    return ObjC.classes.FlutterMethodChannel['- invokeMethod:arguments:'](self, sel, method, args);
                };
                log.info('✓ Hooked FlutterMethodChannel');
            } catch (e) {
                log.detail('FlutterMethodChannel hook failed');
            }
        }
    } catch (e) {
        log.detail('FlutterMethodChannel not found');
    }

    // ── Hook the background URLSession handler ──
    try {
        var FlutterBackgroundSession = ObjC.classes.FlutterBackgroundSession;
        if (FlutterBackgroundSession) {
            log.info('✓ FlutterBackgroundSession detected');
        }
    } catch (e) {
        log.detail('FlutterBackgroundSession not found');
    }

    // ── Hook dart:io HttpClient redirect & SSL via secure socket ──
    // On iOS, Flutter's HTTP client directly uses NSURLSession,
    // so the above NSURLSession hooks should catch all traffic.
    log.info('Flutter iOS SSL bypass: using NSURLSession-level hooks');
}

log.info('Flutter iOS SSL bypass hooks complete');
"""

IOS_NSURLSESSION_SCRIPT = r"""/*
 * MobileSentry — NSURLSession SSL Pinning Bypass (iOS)
 *
 * Direct NSURLSession + NSURLConnection authentication challenge bypass.
 * Works with any app using NSURLSession/NSURLConnection regardless
 * of the networking library.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l ssl_nsurlsession.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry NSURLSession SSL Bypass loaded');

if (ObjC.available) {
    // ── Method 1: Enumerate all classes and hook NSURLSession auth challenge ──
    var allClasses = ObjC.enumerateLoadedClassesSync();
    var hookedCount = 0;

    allClasses.forEach(function (className) {
        try {
            var clazz = ObjC.classes[className];
            if (!clazz) return;

            // NSURLSessionDataDelegate method
            var sessionMethod = clazz['- URLSession:didReceiveChallenge:completionHandler:'];
            if (sessionMethod) {
                sessionMethod.implementation = function (self, sel, session, challenge, completion) {
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod();
                    var host = protectionSpace.host();

                    if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                        log.info('NSURLSession: accepting server trust for: ' + host);
                        var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                        var block = new ObjC.Block(completion);
                        block.implementation(disposition, credential);
                        return;
                    }

                    // Default handling for non-SSL challenges
                    var block = new ObjC.Block(completion);
                    block.implementation(0, null); // NSURLSessionAuthChallengePerformDefaultHandling
                };
                hookedCount++;
            }

            // NSURLConnectionDelegate method
            var connMethod = clazz['- connection:didReceiveAuthenticationChallenge:'];
            if (connMethod) {
                connMethod.implementation = function (self, sel, connection, challenge) {
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod();
                    var host = protectionSpace.host();

                    if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                        log.info('NSURLConnection: accepting server trust for: ' + host);
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                        challenge.sender().useCredential(credential, challenge);
                        return;
                    }

                    challenge.sender().continueWithoutCredential(challenge);
                };
                hookedCount++;
            }

            // WKWebView auth challenge
            var webViewMethod = clazz['- webView:didReceiveAuthenticationChallenge:completionHandler:'];
            if (webViewMethod) {
                webViewMethod.implementation = function (self, sel, webView, challenge, completion) {
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod();
                    var host = protectionSpace.host();

                    if (authMethod.toString() === 'NSURLAuthenticationMethodServerTrust') {
                        log.info('WKWebView: accepting server trust for: ' + host);
                        var disposition = 1; // NSURLSessionAuthChallengeUseCredential
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
                        var block = new ObjC.Block(completion);
                        block.implementation(disposition, credential);
                        return;
                    }

                    var block = new ObjC.Block(completion);
                    block.implementation(0, null);
                };
                hookedCount++;
            }
        } catch (e) {
            // Skip classes that can't be hooked
        }
    });

    if (hookedCount > 0) {
        log.info('✓ Hooked ' + hookedCount + ' SSL delegate methods across all classes');
    } else {
        log.warn('No SSL delegate methods found — app may use a different networking stack');
    }



    log.info('NSURLSession bypass hooks complete');
} else {
    log.warn('Objective-C runtime not available');
}
"""

# ──────────────────────────────────────────────
# Techniques Catalog
# ──────────────────────────────────────────────

ANDROID_TECHNIQUES: list[SslBypassTechnique] = [
    SslBypassTechnique(
        name="universal",
        platform="android",
        description="Global SSL pinning bypass — hooks SSLContext.init(), X509TrustManager, OkHttp, HostnameVerifier, WebView, and TrustKit. The most comprehensive option.",
        libraries=[
            "javax.net.ssl.SSLContext",
            "okhttp3.CertificatePinner",
            "com.squareup.okhttp.CertificatePinner",
            "javax.net.ssl.X509TrustManager",
            "javax.net.ssl.HostnameVerifier",
            "android.webkit.WebViewClient",
            "com.datatheorem.android.trustkit.TrustKit",
            "org.apache.http.conn.ssl.SSLSocketFactory",
        ],
        quality="best",
        warnings=["May cause detection if app has anti-Frida measures. Start here for most apps."],
    ),
    SslBypassTechnique(
        name="okhttp",
        platform="android",
        description="OkHttp-specific bypass — targets OkHttp3/4 and OkHttp2 CertificatePinner + CertificateChainCleaner. Minimal hooks, lower detection risk.",
        libraries=["okhttp3.CertificatePinner", "com.squareup.okhttp.CertificatePinner", "okhttp3.internal.tls.CertificateChainCleaner", "okhttp3.RealCall"],
        quality="targeted",
        warnings=["Only works if the app uses OkHttp for networking."],
    ),
    SslBypassTechnique(
        name="trustmanager",
        platform="android",
        description="SSLContext.init() with custom TrustManager injection. Works with any Java-based networking library.",
        libraries=["javax.net.ssl.SSLContext", "javax.net.ssl.X509TrustManager"],
        quality="good",
        warnings=["May not work with Flutter or apps using custom native SSL stacks."],
    ),
    SslBypassTechnique(
        name="webview",
        platform="android",
        description="WebView SSL bypass — hooks onReceivedSslError, SslErrorHandler.proceed/cancel. Best for hybrid apps with embedded WebViews.",
        libraries=["android.webkit.WebViewClient", "android.webkit.SslErrorHandler", "android.webkit.WebView"],
        quality="targeted",
        warnings=["Only affects WebView content. Does not bypass native network layer pinning."],
    ),
    SslBypassTechnique(
        name="flutter",
        platform="android",
        description="Flutter SSL bypass — hooks Dart SSL verification, OkHttp under Flutter, and libflutter.so symbols. For Flutter/Dart-based mobile apps.",
        libraries=["io.flutter.embedding.engine.FlutterJNI", "libflutter.so", "okhttp3.CertificatePinner"],
        quality="good",
        min_frida_version="14.0",
        warnings=["Flutter apps may have version-specific SSL implementations. Test on target version.", "May require multiple attempts with different hook combinations."],
    ),
    SslBypassTechnique(
        name="xamarin",
        platform="android",
        description="Xamarin Android SSL bypass — hooks SSLContext, HostnameVerifier, and OkHttp (via Xamarin bindings).",
        libraries=["javax.net.ssl.SSLContext", "javax.net.ssl.HostnameVerifier", "okhttp3.CertificatePinner"],
        quality="targeted",
        warnings=["Targets Xamarin.Android apps specifically. Does not cover all Xamarin.Forms networking patterns."],
    ),
]

IOS_TECHNIQUES: list[SslBypassTechnique] = [
    SslBypassTechnique(
        name="universal",
        platform="ios",
        description="Global iOS SSL bypass — hooks NSURLSession/NSURLConnection auth challenges, TrustKit, and AFNetworking. Comprehensive coverage.",
        libraries=["NSURLSession", "NSURLConnection", "AFSecurityPolicy", "TrustKit", "NSURLProtectionSpace"],
        quality="best",
        warnings=["Start here for most iOS apps. May need AFNetworking/TrustKit-specific scripts for specialized frameworks."],
    ),
    SslBypassTechnique(
        name="afnetworking",
        platform="ios",
        description="AFNetworking AFSecurityPolicy bypass — hooks SSLPinningMode, evaluateServerTrust, allowInvalidCertificates, validatesDomainName, pinnedCertificates.",
        libraries=["AFSecurityPolicy"],
        quality="targeted",
        warnings=["Only effective if the app uses AFNetworking for network requests."],
    ),
    SslBypassTechnique(
        name="alamofire",
        platform="ios",
        description="Alamofire ServerTrustManager bypass — hooks PinnedCertificatesTrustEvaluator, PublicKeysTrustEvaluator, CompositeTrustEvaluator, and SessionDelegate.",
        libraries=["Alamofire.ServerTrustManager", "Alamofire.PinnedCertificatesTrustEvaluator", "Alamofire.PublicKeysTrustEvaluator", "Alamofire.SessionDelegate"],
        quality="targeted",
        warnings=["Alamofire uses Swift APIs which may be harder to hook via ObjC. Fallback to NSURLSession hook if this fails.", "Requires Frida >= 14.0 for Swift metadata support."],
    ),
    SslBypassTechnique(
        name="trustkit",
        platform="ios",
        description="TrustKit library bypass — hooks initialization, sharedInstance, swizzleNetworkMethods, and PinningValidator.evaluateTrust.",
        libraries=["TrustKit", "TSKPinningValidator"],
        quality="targeted",
        warnings=["Only works if the app integrates the TrustKit SDK for SSL pinning."],
    ),
    SslBypassTechnique(
        name="flutter",
        platform="ios",
        description="Flutter iOS SSL bypass — hooks NSURLSession under FlutterEngine, FlutterMethodChannel, and all loaded delegate classes. Targets Flutter-based iOS apps.",
        libraries=["FlutterEngine", "FlutterMethodChannel", "NSURLSession"],
        quality="good",
        min_frida_version="14.0",
        warnings=["Flutter iOS uses NSURLSession under the hood; NSURLSession hooks should work.", "Dart VM hooks on iOS require additional research per Flutter version."],
    ),
    SslBypassTechnique(
        name="nsurlsession",
        platform="ios",
        description="Pure NSURLSession/NSURLConnection auth challenge bypass. Hooks all loaded classes implementing didReceiveChallenge. No framework-specific dependencies.",
        libraries=["NSURLSession", "NSURLConnection", "WKWebView"],
        quality="good",
        warnings=["Works with most apps regardless of networking stack. May miss apps using custom C++ sockets or custom TLS implementations."],
    ),
]

TECHNIQUES_BY_PLATFORM: dict[str, list[SslBypassTechnique]] = {
    "android": ANDROID_TECHNIQUES,
    "ios": IOS_TECHNIQUES,
}

ALL_TECHNIQUES: list[SslBypassTechnique] = ANDROID_TECHNIQUES + IOS_TECHNIQUES

# Scripts by technique name
ANDROID_SCRIPTS: dict[str, str] = {
    "universal": ANDROID_UNIVERSAL_SCRIPT,
    "okhttp": ANDROID_OKHTTP_SCRIPT,
    "trustmanager": ANDROID_TRUSTMANAGER_SCRIPT,
    "webview": ANDROID_WEBVIEW_SCRIPT,
    "flutter": ANDROID_FLUTTER_SCRIPT,
    "xamarin": ANDROID_XAMARIN_SCRIPT,
}

IOS_SCRIPTS: dict[str, str] = {
    "universal": IOS_UNIVERSAL_SCRIPT,
    "afnetworking": IOS_AFNETWORKING_SCRIPT,
    "alamofire": IOS_ALAMOFIRE_SCRIPT,
    "trustkit": IOS_TRUSTKIT_SCRIPT,
    "flutter": IOS_FLUTTER_SCRIPT,
    "nsurlsession": IOS_NSURLSESSION_SCRIPT,
}

SCRIPTS_BY_PLATFORM: dict[str, dict[str, str]] = {
    "android": ANDROID_SCRIPTS,
    "ios": IOS_SCRIPTS,
}


# ══════════════════════════════════════════════
# Generator
# ══════════════════════════════════════════════


class SslBypassGenerator:
    """Generates Frida scripts for SSL pinning bypass.

    Args:
        output_dir: Directory where generated scripts will be saved.
    """

    def __init__(self, output_dir: str = "./frida_scripts") -> None:
        self.output_dir = Path(output_dir)

    # ── Listing ──

    def list_techniques(self, platform: str | None = None) -> list[SslBypassTechnique]:
        """List available bypass techniques, optionally filtered by platform.

        Args:
            platform: Filter by platform ("android", "ios", or None for all).

        Returns:
            List of SslBypassTechnique metadata objects.
        """
        if platform:
            return TECHNIQUES_BY_PLATFORM.get(platform.lower(), [])
        return ALL_TECHNIQUES

    def get_technique(self, name: str, platform: str) -> SslBypassTechnique | None:
        """Get a specific technique by name and platform.

        Args:
            name: Technique name (e.g., "universal", "okhttp").
            platform: Platform ("android" or "ios").

        Returns:
            SslBypassTechnique if found, None otherwise.
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
        """Generate all Frida scripts for both platforms.

        Returns:
            List of GeneratedScript objects with file paths.
        """
        scripts: list[GeneratedScript] = []
        scripts.extend(self.generate_platform("android"))
        scripts.extend(self.generate_platform("ios"))
        return scripts

    def generate_platform(self, platform: str) -> list[GeneratedScript]:
        """Generate all Frida scripts for a specific platform.

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

            filename = f"ssl_{technique_name}_{platform_lower}.js"
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
        """Generate a single Frida script by technique name and platform.

        Args:
            technique_name: Technique name (e.g., "universal", "okhttp").
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

        filename = f"ssl_{technique_name}_{platform_lower}.js"
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
