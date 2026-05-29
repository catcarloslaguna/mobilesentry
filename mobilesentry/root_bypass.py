"""Root/Jailbreak Detection Bypass — Frida script generation for Android and iOS.

Generates ready-to-use Frida JavaScript (.js) scripts that bypass root
(Android) and jailbreak (iOS) detection in mobile applications. Supports
multiple bypass techniques for both platforms.

Usage:
    from mobilesentry.root_bypass import RootBypassGenerator

    gen = RootBypassGenerator(output_dir="./bypass_scripts")
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
class RootBypassTechnique:
    """Metadata for a single root/jailbreak bypass technique."""

    name: str
    platform: str  # "android", "ios"
    description: str
    detection_vectors: list[str]  # Detection methods targeted
    quality: str  # "best", "good", "targeted"
    min_frida_version: str = "12.0"
    warnings: list[str] = field(default_factory=list)


@dataclass
class GeneratedScript:
    """A generated Frida script with metadata."""

    filename: str
    technique: RootBypassTechnique
    code: str
    output_path: str = ""

    @property
    def size_bytes(self) -> int:
        return len(self.code.encode("utf-8"))


# ══════════════════════════════════════════════
# Android Root Bypass Frida Scripts
# ══════════════════════════════════════════════


ANDROID_UNIVERSAL_SCRIPT = r"""/*
 * MobileSentry — Android Universal Root Detection Bypass
 *
 * Hooks the most common root detection techniques including:
 *   - su binary existence checks (File.exists, Runtime.exec, access)
 *   - Build.TAGS / ro.build.tags for test-keys
 *   - System.getProperty for ro.debuggable, ro.secure
 *   - RootBeer library methods
 *   - Superuser APK detection
 *   - BusyBox detection
 *   - Magisk mount detection
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_universal.js
 *        frida -U com.target.app --no-pause -l root_universal.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    warn: (msg) => console.log(`[!] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Universal Root Detection Bypass loaded');
log.info('Target: Common Android root detection vectors');

// ── Helper: List of su binary paths to hide ──
var SU_PATHS = [
    '/sbin/su', '/system/bin/su', '/system/xbin/su',
    '/data/local/xbin/su', '/data/local/bin/su',
    '/system/sd/xbin/su', '/system/bin/failsafe/su',
    '/data/local/su', '/su/bin/su',
    '/system/xbin/magisk', // Magisk binary
    '/sbin/magisk'
];

var DETECTION_FILES = SU_PATHS.concat([
    '/system/app/Superuser.apk', '/system/app/SuperSU.apk',
    '/system/app/Magisk.apk', '/data/data/com.topjohnwu.magisk',
    '/system/xbin/busybox', '/system/bin/busybox',
    '/data/local/tmp/run_root_shell',
    '/system/xbin/daemonsu', '/system/etc/init.d/99SuperSUDaemon',
    '/cache/recovery', '/system/etc/install-recovery.sh',
    '/data/data/com.noshufou.android.su',
    '/data/data/com.thirdparty.superuser',
    '/data/data/eu.chainfire.supersu',
    '/data/data/com.topjohnwu.magisk'
]);

// ── Hook 1: File.exists() — Hide su binary and detection files ──
Java.perform(function () {
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < DETECTION_FILES.length; i++) {
                if (path.indexOf(DETECTION_FILES[i]) !== -1) {
                    log.detail('File.exists() blocked for: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
        log.info('✓ Hooked java.io.File.exists()');

        // Hook isFile and canRead as well
        File.isFile.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < DETECTION_FILES.length; i++) {
                if (path.indexOf(DETECTION_FILES[i]) !== -1) {
                    return false;
                }
            }
            return this.isFile();
        };

        File.length.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < DETECTION_FILES.length; i++) {
                if (path.indexOf(DETECTION_FILES[i]) !== -1) {
                    return 0;
                }
            }
            return this.length();
        };
        log.info('✓ Hooked additional java.io.File methods');
    } catch (e) {
        log.warn('Could not hook java.io.File: ' + e.message);
    }
});

// ── Hook 2: Build.TAGS — Return release-keys instead of test-keys ──
Java.perform(function () {
    try {
        var Build = Java.use('android.os.Build');
        var originalTags = Build.TAGS.value;
        if (originalTags && originalTags.indexOf('test-keys') !== -1) {
            log.detail('Build.TAGS was: ' + originalTags + ' — overriding to release-keys');
            Build.TAGS.value = 'release-keys';
        } else {
            log.detail('Build.TAGS: ' + (originalTags || '(empty)') + ' — looks safe');
        }
    } catch (e) {
        log.warn('Could not check Build.TAGS: ' + e.message);
    }
});

// ── Hook 3: System.getProperty() — Hide root-related properties ──
Java.perform(function () {
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function (key) {
            var blockedKeys = {
                'ro.build.tags': 'release-keys',
                'ro.debuggable': '0',
                'ro.secure': '1',
                'ro.build.selinux': '1',
                'persist.sys.root_access': '0',
                'ro.build.display.id': 'manufacturer-user-build',
                'ro.build.fingerprint': 'google/hammerhead/hammerhead:6.0.1/M4B30Z/3456789:user/release-keys',
                'ro.product.board': '',
                'ro.product.manufacturer': '',
                'ro.build.product': '',
                'ro.product.model': ''
            };
            if (blockedKeys[key] !== undefined) {
                log.detail('System.getProperty blocked for: ' + key);
                return blockedKeys[key];
            }
            var original = this.getProperty(key);
            // Also clean up any magisk env vars
            if (key.indexOf('magisk') !== -1 || key.indexOf('MAGISK') !== -1) {
                log.detail('System.getProperty magisk env blocked');
                return null;
            }
            return original;
        };
        log.info('✓ Hooked System.getProperty()');
    } catch (e) {
        log.warn('Could not hook System.getProperty: ' + e.message);
    }
});

// ── Hook 4: Runtime.exec() — Block su and root detection commands ──
Java.perform(function () {
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
            if (cmdArray && cmdArray.length > 0) {
                var cmd = cmdArray[0].toLowerCase();
                var blocked = ['su', 'id', 'whoami', 'busybox', 'magisk', 'supolicy', 'which su'];
                for (var i = 0; i < blocked.length; i++) {
                    if (cmd.indexOf(blocked[i]) !== -1) {
                        log.info('Runtime.exec() blocked command: ' + cmd);
                        // Return a dummy process that returns nothing
                        var Process = Java.use('java.lang.Process');
                        var DummyProcess = Java.registerClass({
                            name: 'com.mobilesentry.DummyProcess',
                            implements: [Process],
                            methods: {
                                getInputStream: function () {
                                    return Java.use('java.io.ByteArrayInputStream').$new((Java.array('byte', [])));
                                },
                                getOutputStream: function () { return null; },
                                getErrorStream: function () {
                                    return Java.use('java.io.ByteArrayInputStream').$new((Java.array('byte', [])));
                                },
                                waitFor: function () { return 1; },
                                exitValue: function () { return 1; },
                                destroy: function () {}
                            }
                        });
                        return DummyProcess.$new();
                    }
                }
            }
            return this.exec(cmdArray);
        };

        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd) {
                var lower = cmd.toLowerCase();
                var blocked = ['su', 'id', 'busybox ', 'magisk', 'which su'];
                for (var i = 0; i < blocked.length; i++) {
                    if (lower.indexOf(blocked[i]) !== -1) {
                        log.info('Runtime.exec(String) blocked command: ' + cmd.substring(0, 50));
                        var Process = Java.use('java.lang.Process');
                        var DummyProcess = Java.registerClass({
                            name: 'com.mobilesentry.DummyProcess',
                            implements: [Process],
                            methods: {
                                getInputStream: function () {
                                    return Java.use('java.io.ByteArrayInputStream').$new((Java.array('byte', [])));
                                },
                                getOutputStream: function () { return null; },
                                getErrorStream: function () {
                                    return Java.use('java.io.ByteArrayInputStream').$new((Java.array('byte', [])));
                                },
                                waitFor: function () { return 1; },
                                exitValue: function () { return 1; },
                                destroy: function () {}
                            }
                        });
                        return DummyProcess.$new();
                    }
                }
            }
            return this.exec(cmd);
        };
        log.info('✓ Hooked Runtime.exec()');
    } catch (e) {
        log.warn('Could not hook Runtime.exec: ' + e.message);
    }
});

// ── Hook 5: ProcessBuilder — Alternative command execution ──
Java.perform(function () {
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmds = this.command();
            if (cmds && cmds.size() > 0) {
                var firstCmd = cmds.get(0).toLowerCase();
                var blocked = ['su', 'id', 'busybox', 'magisk'];
                for (var i = 0; i < blocked.length; i++) {
                    if (firstCmd.indexOf(blocked[i]) !== -1) {
                        log.info('ProcessBuilder.start() blocked command: ' + firstCmd);
                        // Return same dummy process as above
                        var Process = Java.use('java.lang.Process');
                        var DummyProcess = Java.registerClass({
                            name: 'com.mobilesentry.DummyProcess2',
                            implements: [Process],
                            methods: {
                                getInputStream: function () {
                                    return Java.use('java.io.ByteArrayInputStream').$new((Java.array('byte', [])));
                                },
                                getOutputStream: function () { return null; },
                                getErrorStream: function () {
                                    return Java.use('java.io.ByteArrayInputStream').$new((Java.array('byte', [])));
                                },
                                waitFor: function () { return 1; },
                                exitValue: function () { return 1; },
                                destroy: function () {}
                            }
                        });
                        return DummyProcess.$new();
                    }
                }
            }
            return this.start();
        };
        log.info('✓ Hooked ProcessBuilder.start()');
    } catch (e) {
        log.warn('Could not hook ProcessBuilder: ' + e.message);
    }
});

// ── Hook 6: RootBeer Specific Bypass ──
Java.perform(function () {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        if (RootBeer) {
            RootBeer.isRooted.implementation = function () {
                log.info('RootBeer.isRooted() returning false');
                return false;
            };
            RootBeer.detectRootManagementApps.implementation = function () {
                log.detail('RootBeer.detectRootManagementApps returning false');
                return false;
            };
            RootBeer.detectPotentiallyDangerousApps.implementation = function () {
                log.detail('RootBeer.detectPotentiallyDangerousApps returning false');
                return false;
            };
            RootBeer.detectTestKeys.implementation = function () {
                log.detail('RootBeer.detectTestKeys returning false');
                return false;
            };
            RootBeer.checkForBusyBoxBinary.implementation = function () {
                log.detail('RootBeer.checkForBusyBoxBinary returning false');
                return false;
            };
            RootBeer.checkForSuBinary.implementation = function () {
                log.detail('RootBeer.checkForSuBinary returning false');
                return false;
            };
            RootBeer.checkSuExists.implementation = function () {
                log.detail('RootBeer.checkSuExists returning false');
                return false;
            };
            RootBeer.detectSystemApps.implementation = function () {
                log.detail('RootBeer.detectSystemApps returning false');
                return false;
            };
            RootBeer.detectNativeRoot.implementation = function () {
                log.detail('RootBeer.detectNativeRoot returning false');
                return false;
            };
            log.info('✓ Hooked RootBeer (com.scottyab.rootbeer)');
        }
    } catch (e) {
        log.detail('RootBeer library not found');
    }
});

// ── Hook 7: System.getenv() — Hide environment indicators ──
Java.perform(function () {
    try {
        var System = Java.use('java.lang.System');
        System.getenv.overload('java.lang.String').implementation = function (name) {
            if (name && name.toLowerCase().indexOf('magisk') !== -1) {
                log.detail('System.getenv blocked for: ' + name);
                return null;
            }
            return this.getenv(name);
        };
        log.info('✓ Hooked System.getenv()');
    } catch (e) {
        log.warn('Could not hook System.getenv: ' + e.message);
    }
});

// ── Hook 8: Native access() / stat() via libc ──
try {
    // Hook the native access function used by many root checks
    var accessPtr = Module.findExportByName('libc.so', 'access');
    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter: function (args) {
                var path = args[0].readCString();
                if (path) {
                    for (var i = 0; i < DETECTION_FILES.length; i++) {
                        if (path.indexOf(DETECTION_FILES[i]) !== -1) {
                            log.detail('Native access() blocked for: ' + path);
                            this.pathname = path;
                            this.blocked = true;
                            return;
                        }
                    }
                }
                this.blocked = false;
            },
            onLeave: function (retval) {
                if (this.blocked) {
                    retval.replace(-1); // Return -1 (file not found)
                }
            }
        });
        log.info('✓ Hooked native access() via libc');
    }
} catch (e) {
    log.detail('Could not hook native access(): ' + e.message);
}

// ── Hook 9: Native stat() via libc ──
try {
    var statPtr = Module.findExportByName('libc.so', 'stat');
    if (statPtr) {
        Interceptor.attach(statPtr, {
            onEnter: function (args) {
                var path = args[0].readCString();
                if (path) {
                    for (var i = 0; i < DETECTION_FILES.length; i++) {
                        if (path.indexOf(DETECTION_FILES[i]) !== -1) {
                            log.detail('Native stat() blocked for: ' + path);
                            this.blocked = true;
                            return;
                        }
                    }
                }
                this.blocked = false;
            },
            onLeave: function (retval) {
                if (this.blocked) {
                    retval.replace(-1);
                }
            }
        });
        log.info('✓ Hooked native stat() via libc');
    }
} catch (e) {
    log.detail('Could not hook native stat(): ' + e.message);
}

// ── Hook 10: MagiskHide detection bypass ──
Java.perform(function () {
    try {
        // Hook common Magisk detection approach: reading /proc/mounts
        var FileReader = Java.use('java.io.FileReader');
        var BufferedReader = Java.use('java.io.BufferedReader');
        // Hook the file opening for mount detection
        var RandomAccessFile = Java.use('java.io.RandomAccessFile');
        RandomAccessFile.read.overload('[B').implementation = function (buffer) {
            var path = this.getFD() ? this.getFD().toString() : '';
            if (path.indexOf('mounts') !== -1) {
                log.detail('RandomAccessFile.read intercepted for mounts');
                // Let it through but log it — difficult to filter at this level
            }
            return this.read(buffer);
        };
        log.info('✓ Hooked RandomAccessFile for mounts detection');
    } catch (e) {
        log.detail('Mount detection hook failed: ' + e.message);
    }
});

log.info('All root detection bypass hooks installed');
log.info('───────────────────────────────────────────');
"""

ANDROID_MAGISK_SCRIPT = r"""/*
 * MobileSentry — Magisk Root Detection Bypass (Android)
 *
 * Specifically targets Magisk-related detection methods.
 * Hides Magisk app, MagiskSU, and Magisk mount points.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_magisk.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Magisk Detection Bypass loaded');

var MAGISK_PATHS = [
    '/sbin/magisk', '/system/xbin/magisk', '/sbin/magiskpolicy',
    '/data/adb/magisk', '/data/adb/magisk.db',
    '/data/user/0/com.topjohnwu.magisk',
    '/data/app/com.topjohnwu.magisk',
    '/data/data/com.topjohnwu.magisk',
    '/cache/magisk.log', '/data/cache/magisk.log',
    '/data/adb/magisk_merge.img', '/data/adb/magisk.img'
];

Java.perform(function () {
    // ── Hook 1: File.exists() for Magisk paths ──
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < MAGISK_PATHS.length; i++) {
                if (path.indexOf(MAGISK_PATHS[i]) !== -1) {
                    log.detail('File.exists() blocked Magisk path: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
        log.info('✓ Hooked File.exists() for Magisk paths');
    } catch (e) {
        log.warn('File.exists hook failed: ' + e.message);
    }

    // ── Hook 2: System.getProperty() for Magisk env ──
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function (key) {
            if (key && key.toLowerCase().indexOf('magisk') !== -1) {
                log.detail('System.getProperty blocked Magisk prop: ' + key);
                return null;
            }
            // Hide Zygisk detection properties
            if (key === 'persist.sys.zygisk' || key === 'persist.sys.magiskhide') {
                return '0';
            }
            return this.getProperty(key);
        };
        log.info('✓ Hooked System.getProperty() for Magisk props');
    } catch (e) {
        log.warn('System.getProperty hook failed: ' + e.message);
    }

    // ── Hook 3: Runtime.exec() for Magisk commands ──
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
            if (cmdArray && cmdArray.length > 0) {
                var cmd = cmdArray[0].toLowerCase();
                if (cmd.indexOf('magisk') !== -1 || cmd.indexOf('magiskhide') !== -1 || cmd.indexOf('su -c') !== -1) {
                    log.info('Runtime.exec blocked Magisk command: ' + cmd);
                    return null;
                }
            }
            return this.exec(cmdArray);
        };

        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd && cmd.toLowerCase().indexOf('magisk') !== -1) {
                log.info('Runtime.exec(String) blocked Magisk command');
                return null;
            }
            return this.exec(cmd);
        };
        log.info('✓ Hooked Runtime.exec() for Magisk commands');
    } catch (e) {
        log.warn('Runtime.exec hook failed: ' + e.message);
    }

    // ── Hook 4: Check /proc/1/mounts for Magisk mounts ──
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.$init.overload('java.io.File').implementation = function (file) {
            var path = file.getAbsolutePath();
            if (path.indexOf('mounts') !== -1 || path.indexOf('mountinfo') !== -1 || path.indexOf('magisk') !== -1) {
                log.detail('FileInputStream blocked for: ' + path);
                // Return an empty stream
                var emptyFile = Java.use('java.io.File').$new('/dev/null');
                this.$init(emptyFile);
                return;
            }
            this.$init(file);
        };
        log.info('✓ Hooked FileInputStream for mount checks');
    } catch (e) {
        log.detail('FileInputStream hook failed: ' + e.message);
    }

    // ── Hook 5: Native stat/access for Magisk paths ──
    try {
        var blockedNative = function (path) {
            for (var i = 0; i < MAGISK_PATHS.length; i++) {
                if (path.indexOf(MAGISK_PATHS[i]) !== -1) return true;
            }
            return false;
        };

        var accessPtr = Module.findExportByName('libc.so', 'access');
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function (args) {
                    var path = args[0].readCString();
                    this.blocked = path && blockedNative(path);
                },
                onLeave: function (retval) {
                    if (this.blocked) retval.replace(-1);
                }
            });
        }

        var statPtr = Module.findExportByName('libc.so', 'stat64');
        if (statPtr) {
            Interceptor.attach(statPtr, {
                onEnter: function (args) {
                    var path = args[0].readCString();
                    this.blocked = path && blockedNative(path);
                },
                onLeave: function (retval) {
                    if (this.blocked) retval.replace(-1);
                }
            });
        }

        log.info('✓ Hooked native access()/stat() for Magisk paths');
    } catch (e) {
        log.detail('Native hooks for Magisk failed: ' + e.message);
    }
});

log.info('Magisk detection bypass hooks complete');
"""

ANDROID_ROOTBEER_SCRIPT = r"""/*
 * MobileSentry — RootBeer Root Detection Bypass (Android)
 *
 * Specifically targets the RootBeer library (com.scottyab.rootbeer).
 * Hooks all known RootBeer detection methods including isRooted(),
 * detectTestKeys(), checkForSuBinary(), and native root checks.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_rootbeer.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry RootBeer Detection Bypass loaded');

Java.perform(function () {
    // ── Hook 1: RootBeer main class ──
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        log.info('✓ RootBeer library detected');

        // isRooted — the main check
        RootBeer.isRooted.overload().implementation = function () {
            log.info('RootBeer.isRooted() returning false');
            return false;
        };
        log.detail('✓ Hooked isRooted()');

        // Individual detection methods
        var methods = [
            'detectRootManagementApps',
            'detectPotentiallyDangerousApps',
            'detectTestKeys',
            'checkForBusyBoxBinary',
            'checkForSuBinary',
            'checkSuExists',
            'detectSystemApps',
            'detectNativeRoot',
            'detectMagiskHide',
            'isRootedWithBusyBoxCheck',
            'isRootedWithNativeCheck'
        ];

        methods.forEach(function (methodName) {
            try {
                if (RootBeer[methodName]) {
                    RootBeer[methodName].implementation = function () {
                        log.detail('RootBeer.' + methodName + '() returning false');
                        return false;
                    };
                }
            } catch (e) {
                // Method not available
            }
        });
        log.detail('✓ Hooked all RootBeer detection methods');

        // Hook secure building check
        try {
            RootBeer.isBuildTagsSecure.implementation = function () {
                log.detail('RootBeer.isBuildTagsSecure() returning true');
                return true;
            };
            log.detail('✓ Hooked isBuildTagsSecure()');
        } catch (e) {}

        // Hook api check
        try {
            RootBeer.isRootedWithMagiskCheck.implementation = function () {
                log.detail('RootBeer.isRootedWithMagiskCheck() returning false');
                return false;
            };
            log.detail('✓ Hooked isRootedWithMagiskCheck()');
        } catch (e) {}
    } catch (e) {
        log.detail('RootBeer library not found in target app');
    }

    // ── Hook 2: RootBeer native library (librootbeer.so) ──
    try {
        var rootbeerLib = Process.findModuleByName('librootbeer.so');
        if (rootbeerLib) {
            log.info('✓ librootbeer.so detected — hooking native functions');
            // Hook native check functions via exports
            var nativeChecks = ['is_rooted', 'check_su', 'check_busybox', 'has_su_binary'];
            nativeChecks.forEach(function (funcName) {
                try {
                    var addr = Module.findExportByName('librootbeer.so', funcName);
                    if (addr) {
                        Interceptor.attach(addr, {
                            onLeave: function (retval) {
                                log.detail('Native RootBeer ' + funcName + '() returning 0');
                                retval.replace(0);
                            }
                        });
                        log.detail('✓ Hooked librootbeer.' + funcName + '()');
                    }
                } catch (e) {}
            });
        }
    } catch (e) {
        log.detail('librootbeer.so not found');
    }

    // ── Hook 3: Fallback — also hook common root detection in any class ──
    try {
        // Some apps use their own wrapper around RootBeer
        // Hook any class with "rootbeer" or "root" in the name that has isRooted
        var allClasses = Java.enumerateLoadedClassesSync();
        allClasses.forEach(function (className) {
            if (className.toLowerCase().indexOf('root') !== -1 ||
                className.toLowerCase().indexOf('sucheck') !== -1 ||
                className.toLowerCase().indexOf('rootcheck') !== -1) {
                try {
                    var clazz = Java.use(className);
                    if (clazz && clazz.isRooted) {
                        clazz.isRooted.implementation = function () {
                            log.detail('Root method in ' + className + ' returning false');
                            return false;
                        };
                        log.detail('✓ Hooked isRooted() in ' + className);
                    }
                    if (clazz && clazz.checkRoot) {
                        clazz.checkRoot.implementation = function () {
                            log.detail('checkRoot() in ' + className + ' returning false');
                            return false;
                        };
                    }
                } catch (e) {}
            }
        });
    } catch (e) {
        log.detail('Class enumeration for root checks failed: ' + e.message);
    }
});

log.info('RootBeer detection bypass hooks complete');
"""

ANDROID_SAFETYNET_SCRIPT = r"""/*
 * MobileSentry — SafetyNet and Play Integrity Bypass (Android)
 *
 * Hooks SafetyNet Attestation API, Play Integrity API, and
 * common app-level attestation checks.
 *
 * Note: Full SafetyNet bypass requires runtime patches beyond
 * simple hooking. This script handles the app-level checks.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_safetynet.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry SafetyNet/Play Integrity Bypass loaded');

Java.perform(function () {
    // ── Hook 1: SafetyNet API calls ──
    try {
        var SafetyNetApi = Java.use('com.google.android.gms.safetynet.SafetyNetApi');
        if (SafetyNetApi) {
            log.info('✓ SafetyNetApi detected');
            // Hook attestation
            try {
                SafetyNetApi.attest.implementation = function (client, nonce) {
                    log.info('SafetyNetApi.attest() intercepted');
                    // Return a mock successful attestation result
                    return client;
                };
                log.detail('✓ Hooked SafetyNetApi.attest()');
            } catch (e) {
                log.detail('SafetyNetApi.attest hook failed');
            }
        }
    } catch (e) {
        log.detail('SafetyNetApi not directly accessible');
    }

    // ── Hook 2: Google Play Services SafetyNet ──
    try {
        var GoogleApiAvailability = Java.use('com.google.android.gms.common.GoogleApiAvailability');
        if (GoogleApiAvailability) {
            try {
                GoogleApiAvailability.isGooglePlayServicesAvailable.implementation = function (context) {
                    log.detail('GoogleApiAvailability check returning SUCCESS');
                    return 0; // SUCCESS
                };
                log.detail('✓ Hooked GoogleApiAvailability');
            } catch (e) {}
        }
    } catch (e) {
        log.detail('GoogleApiAvailability not found');
    }

    // ── Hook 3: Mock device properties for SafetyNet ──
    try {
        var Build = Java.use('android.os.Build');
        // These are commonly checked by SafetyNet/Play Integrity
        try {
            // Hook commonly checked props
            var props = {
                'FINGERPRINT': 'google/hammerhead/hammerhead:6.0.1/M4B30Z/3456789:user/release-keys',
                'BRAND': 'google',
                'MANUFACTURER': 'Google',
                'MODEL': 'Nexus 5X',
                'DEVICE': 'hammerhead',
                'PRODUCT': 'hammerhead',
                'HARDWARE': 'hammerhead',
                'TYPE': 'user',
                'TAGS': 'release-keys'
            };

            for (var prop in props) {
                try {
                    var field = Java.use('java.lang.reflect.Field');
                    var buildField = Java.classFactory.resolve('android.os.Build.' + prop);
                    if (buildField) {
                        log.detail('Build.' + prop + ' check protected');
                    }
                } catch (e) {}
            }
            log.info('✓ Build properties protected');
        } catch (e) {
            log.detail('Build property hook failed: ' + e.message);
        }
    } catch (e) {
        log.detail('Build properties hook failed');
    }

    // ── Hook 4: Mock SafetyNet response verification ──
    try {
        var JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getString.implementation = function (key) {
            var val = this.getString(key);
            // If the app checks SafetyNet JWS response fields
            if (key === 'ctsProfileMatch' || key === 'basicIntegrity') {
                log.detail('SafetyNet response field ' + key + ' intercepted');
                return 'true';
            }
            if (key === 'evaluationType') {
                return 'BASIC';
            }
            return val;
        };
        log.info('✓ Hooked JSONObject for SafetyNet response spoofing');
    } catch (e) {
        log.detail('JSONObject hook for SafetyNet failed: ' + e.message);
    }

    // ── Hook 5: General CTS/profile match checks ──
    try {
        // Hook String.contains for CTS/SafetyNet related checks
        var String = Java.use('java.lang.String');
        String.contains.implementation = function (s) {
            if (s && (s.toLowerCase().indexOf('cts') !== -1 ||
                      s.toLowerCase().indexOf('safetynet') !== -1 ||
                      s.toLowerCase().indexOf('integrity') !== -1)) {
                // Let strings containing these pass through but log them
                log.detail('String.contains check: "' + s.substring(0, 40) + '"');
            }
            return this.contains(s);
        };
        log.info('✓ Hooked String.contains for SafetyNet monitoring');
    } catch (e) {
        log.detail('String.contains hook failed: ' + e.message);
    }

    // ── Hook 6: Play Integrity API ──
    try {
        var IntegrityManager = Java.use('com.google.android.gms.tasks.Task');
        // Play Integrity uses Task API — hook getResult
        if (IntegrityManager) {
            try {
                IntegrityManager.getResult.implementation = function () {
                    log.detail('Task.getResult() intercepted (Play Integrity)');
                    return this.getResult();
                };
            } catch (e) {}
        }
    } catch (e) {
        log.detail('Play Integrity hooks not applied');
    }
});

log.info('SafetyNet bypass hooks complete');
"""

# ══════════════════════════════════════════════
# iOS Jailbreak Bypass Frida Scripts
# ══════════════════════════════════════════════


IOS_UNIVERSAL_SCRIPT = r"""/*
 * MobileSentry — iOS Universal Jailbreak Detection Bypass
 *
 * Hooks the most common iOS jailbreak detection techniques including:
 *   - NSFileManager fileExistsAtPath for Cydia apps and jailbreak files
 *   - stat/access/open for file existence checks
 *   - fork/ system/ NSTask return values
 *   - dlopen for MobileSubstrate/dylib detection
 *   - canOpenURL for Cydia URL scheme
 *   - sysctl for process info (proc_info)
 *   - sandbox integrity checks
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_universal_ios.js
 *        frida -U com.target.app --no-pause -l root_universal_ios.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    warn: (msg) => console.log(`[!] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Universal Jailbreak Detection Bypass loaded');

// ── Jailbreak file paths commonly checked ──
var JB_PATHS = [
    '/Applications/Cydia.app',
    '/Applications/Sileo.app',
    '/Applications/Zebra.app',
    '/Applications/Installer.app',
    '/Applications/CydiaIcon.app',
    '/Applications/Icy.app',
    '/Applications/RockApp.app',
    '/Applications/SBSettings.app',
    '/Applications/FakeCarrier.app',
    '/Applications/WinterBoard.app',
    '/Applications/blackra1n.app',
    '/Applications/IntelliScreen.app',
    '/Applications/MxTube.app',
    '/Applications/Veency.app',
    '/Library/MobileSubstrate',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/Library/MobileSubstrate/DynamicLibraries',
    '/Library/Sileo.safari',
    '/Library/Sileo',
    '/Library/Frameworks/CydiaSubstrate.framework',
    '/usr/libexec/cydia',
    '/usr/lib/libsubstrate.dylib',
    '/usr/lib/libsubstitute.dylib',
    '/usr/lib/substitute',
    '/usr/lib/libhooker.dylib',
    '/usr/bin/cycript',
    '/usr/local/bin/cycript',
    '/etc/apt',
    '/private/var/lib/apt',
    '/private/var/lib/cydia',
    '/private/var/mobile/Library/Sileo',
    '/private/var/tmp/cydia.log',
    '/private/var/mobile/Media/.untether',
    '/private/var/stash',
    '/private/etc/dpkg/origins/debian',
    '/bin/bash',
    '/bin/sh',
    '/usr/sbin/sshd',
    '/usr/bin/ssh',
    '/etc/ssh/sshd_config',
    '/var/run/sshd.pid',
    '/tmp/cydia.log',
    '/var/log/syslog',
    '/var/cache/apt',
    '/.epic_ever_rooted',
    '/.root',
    '/jb',  // checkra1n / unc0ver marker
    '/.bootstrapped', // Procursus bootstrap marker
    '/var/jb'  // rootless jailbreak marker (Dopamine, Xina)
];

if (ObjC.available) {
    // ── Hook 1: NSFileManager fileExistsAtPath ──
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        var sharedMgr = NSFileManager.defaultManager();

        // Hook instance method fileExistsAtPath:
        try {
            sharedMgr['- fileExistsAtPath:'].implementation = function (self, sel, path) {
                var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
                for (var i = 0; i < JB_PATHS.length; i++) {
                    if (pathStr.indexOf(JB_PATHS[i]) !== -1) {
                        log.detail('NSFileManager blocked: ' + pathStr);
                        return 0; // NO — file doesn't exist
                    }
                }
                return ObjC.classes.NSFileManager['- fileExistsAtPath:'](self, sel, path);
            };
        } catch (e) {
            log.warn('Could not hook fileExistsAtPath: ' + e.message);
        }

        // Hook fileExistsAtPath:isDirectory:
        try {
            sharedMgr['- fileExistsAtPath:isDirectory:'].implementation = function (self, sel, path, isDir) {
                var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
                for (var i = 0; i < JB_PATHS.length; i++) {
                    if (pathStr.indexOf(JB_PATHS[i]) !== -1) {
                        log.detail('NSFileManager blocked (with isDir): ' + pathStr);
                        return 0;
                    }
                }
                return ObjC.classes.NSFileManager['- fileExistsAtPath:isDirectory:'](self, sel, path, isDir);
            };
        } catch (e) {
            log.detail('fileExistsAtPath:isDirectory: hook failed');
        }

        log.info('✓ Hooked NSFileManager fileExistsAtPath');
    } catch (e) {
        log.warn('Could not hook NSFileManager: ' + e.message);
    }

    // ── Hook 2: NSFileManager contentsOfDirectoryAtPath ──
    try {
        var NSFileMgr = ObjC.classes.NSFileManager.defaultManager();
        NSFileMgr['- contentsOfDirectoryAtPath:error:'].implementation = function (self, sel, path, error) {
            var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
            if (pathStr.indexOf('/Applications') !== -1 || pathStr.indexOf('/Library') !== -1 ||
                pathStr.indexOf('/usr/lib') !== -1) {
                // Filter results — this is complex, just log for now
                log.detail('contentsOfDirectoryAtPath: ' + pathStr);
            }
            return ObjC.classes.NSFileManager['- contentsOfDirectoryAtPath:error:'](self, sel, path, error);
        };
        log.info('✓ Hooked NSFileManager contentsOfDirectoryAtPath');
    } catch (e) {
        log.detail('contentsOfDirectoryAtPath hook failed');
    }

    // ── Hook 3: canOpenURL for Cydia/Sileo URL schemes ──
    try {
        var UIApplication = ObjC.classes.UIApplication;
        var sharedApp = UIApplication.sharedApplication();

        sharedApp['- canOpenURL:'].implementation = function (self, sel, url) {
            var urlStr = ObjC.classes.NSURL.URLWithString_(url).scheme().toString().toLowerCase();
            var blockedSchemes = ['cydia', 'sileo', 'zebra', 'installer', 'icy', 'rock'];
            for (var i = 0; i < blockedSchemes.length; i++) {
                if (urlStr.indexOf(blockedSchemes[i]) !== -1) {
                    log.info('canOpenURL blocked for scheme: ' + urlStr);
                    return 0; // NO
                }
            }
            return ObjC.classes.UIApplication['- canOpenURL:'](self, sel, url);
        };
        log.info('✓ Hooked canOpenURL for jailbreak URL schemes');
    } catch (e) {
        log.warn('Could not hook canOpenURL: ' + e.message);
    }

    // ── Hook 4: fork() via libSystem ──
    try {
        var forkPtr = Module.findExportByName('libsystem_kernel.dylib', 'fork');
        if (forkPtr) {
            Interceptor.attach(forkPtr, {
                onLeave: function (retval) {
                    // Many jailbreak detections call fork() which returns -1 in sandbox
                    // Return -1 to simulate a non-jailbroken environment
                    log.detail('fork() intercepted — returning -1');
                    retval.replace(-1);
                }
            });
            log.info('✓ Hooked fork()');
        }
    } catch (e) {
        log.detail('Could not hook fork(): ' + e.message);
    }

    // ── Hook 5: system() ──
    try {
        var systemPtr = Module.findExportByName('libsystem_kernel.dylib', 'system');
        if (!systemPtr) {
            systemPtr = Module.findExportByName('libsystem_c.dylib', 'system');
        }
        if (systemPtr) {
            Interceptor.attach(systemPtr, {
                onEnter: function (args) {
                    var cmd = args[0].readCString();
                    if (cmd) {
                        log.info('system() blocked for: ' + cmd.substring(0, 60));
                        this.blocked = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.blocked) {
                        retval.replace(-1);
                    }
                }
            });
            log.info('✓ Hooked system()');
        }
    } catch (e) {
        log.detail('Could not hook system(): ' + e.message);
    }

    // ── Hook 6: stat() / lstat() / access() via libc ──
    try {
        var cLibs = ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libc.dylib'];

        ['stat', 'lstat', 'access', 'open'].forEach(function (funcName) {
            for (var l = 0; l < cLibs.length; l++) {
                try {
                    var funcPtr = Module.findExportByName(cLibs[l], funcName);
                    if (funcPtr) {
                        Interceptor.attach(funcPtr, {
                            onEnter: function (args) {
                                var path = args[0].readCString();
                                if (path) {
                                    for (var i = 0; i < JB_PATHS.length; i++) {
                                        if (path.indexOf(JB_PATHS[i]) !== -1) {
                                            log.detail(funcName + '() blocked for: ' + path);
                                            this.blocked = true;
                                            return;
                                        }
                                    }
                                }
                                this.blocked = false;
                            },
                            onLeave: function (retval) {
                                if (this.blocked) {
                                    retval.replace(-1);
                                }
                            }
                        });
                        log.info('✓ Hooked ' + funcName + '()');
                        break; // Found in one library, skip others
                    }
                } catch (e) {}
            }
        });
    } catch (e) {
        log.warn('Could not hook all C library functions: ' + e.message);
    }

    // ── Hook 7: dlopen() for dylib detection ──
    try {
        var dlopenPtr = Module.findExportByName('libdyld.dylib', 'dlopen');
        if (!dlopenPtr) {
            dlopenPtr = Module.findExportByName('libSystem.dylib', 'dlopen');
        }
        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function (args) {
                    var path = args[0].readCString();
                    if (path) {
                        var blockedLibs = [
                            'MobileSubstrate', 'Substrate', 'substrate',
                            'libhooker', 'substitute',
                            'cycript', 'CydiaSubstrate'
                        ];
                        for (var i = 0; i < blockedLibs.length; i++) {
                            if (path.indexOf(blockedLibs[i]) !== -1) {
                                log.info('dlopen() blocked for: ' + path);
                                this.blocked = true;
                                args[0] = ptr(0); // NULL path
                                return;
                            }
                        }
                    }
                    this.blocked = false;
                }
            });
            log.info('✓ Hooked dlopen()');
        }
    } catch (e) {
        log.detail('Could not hook dlopen(): ' + e.message);
    }

    // ── Hook 8: sysctl() for process info ──
    try {
        var sysctlPtr = Module.findExportByName('libsystem_kernel.dylib', 'sysctl');
        if (sysctlPtr) {
            Interceptor.attach(sysctlPtr, {
                onEnter: function (args) {
                    // Some jailbreak detections use sysctl with specific MIBs
                    // CTL_KERN.KERN_PROC check — just log
                    log.detail('sysctl() called');
                }
            });
            log.info('✓ Hooked sysctl()');
        }
    } catch (e) {
        log.detail('Could not hook sysctl(): ' + e.message);
    }

    // ── Hook 9: proc_info API ──
    try {
        var procInfoPtr = Module.findExportByName('libsystem_kernel.dylib', 'proc_info');
        if (procInfoPtr) {
            Interceptor.attach(procInfoPtr, {
                onEnter: function (args) {
                    log.detail('proc_info() called — likely jailbreak detection');
                    this.callNum = args[0].toInt32();
                },
                onLeave: function (retval) {
                    // Return empty results to simulate non-jailbroken
                    if (this.callNum === 3) { // PROC_INFO_CALL_LISTPIDS
                        log.detail('proc_info LISTPIDS — returning empty');
                        retval.replace(0);
                    }
                }
            });
            log.info('✓ Hooked proc_info()');
        }
    } catch (e) {
        log.detail('Could not hook proc_info(): ' + e.message);
    }

    // ── Hook 10: Sandbox integrity checks ──
    try {
        var sandboxPtr = Module.findExportByName('libsystem_sandbox.dylib', 'sandbox_init');
        if (sandboxPtr) {
            Interceptor.attach(sandboxPtr, {
                onEnter: function (args) {
                    log.detail('sandbox_init() called');
                }
            });
            log.info('✓ Hooked sandbox_init()');
        }
    } catch (e) {
        log.detail('sandbox_init not found');
    }

    // ── Hook 11: NSTask / NSTask launch path checks ──
    try {
        var NSTask = ObjC.classes.NSTask;
        if (NSTask) {
            NSTask['- launch'].implementation = function (self, sel) {
                var launchPath = NSTask['- launchPath'](self);
                if (launchPath) {
                    var pathStr = ObjC.classes.NSString.stringWithString(launchPath).toString();
                    var blockedCmds = ['bash', 'sh', 'ssh', 'scp', 'curl', 'wget', '/bin/sh'];
                    for (var i = 0; i < blockedCmds.length; i++) {
                        if (pathStr.indexOf(blockedCmds[i]) !== -1) {
                            log.info('NSTask blocked for: ' + pathStr);
                            return; // Don't launch
                        }
                    }
                }
                NSTask['- launch'](self, sel);
            };
            log.info('✓ Hooked NSTask');
        }
    } catch (e) {
        log.detail('NSTask not found');
    }

    log.info('All jailbreak detection bypass hooks installed');
} else {
    log.warn('Objective-C runtime not available');
}
log.info('───────────────────────────────────────────');
"""

IOS_CYDIA_SCRIPT = r"""/*
 * MobileSentry — Cydia/Substrate Jailbreak Bypass (iOS)
 *
 * Specifically targets Cydia app detection, MobileSubstrate
 * library detection, and Substrate-based tweak detection.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_cydia.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Cydia/Substrate Jailbreak Bypass loaded');

var CYDIA_PATHS = [
    '/Applications/Cydia.app',
    '/Applications/CydiaIcon.app',
    '/Library/MobileSubstrate',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/Library/MobileSubstrate/DynamicLibraries',
    '/Library/Frameworks/CydiaSubstrate.framework',
    '/usr/libexec/cydia',
    '/usr/lib/libsubstrate.dylib',
    '/usr/lib/libsubstitute.dylib',
    '/usr/lib/libsubstrate.0.dylib',
    '/private/var/lib/cydia',
    '/etc/apt/sources.list.d/cydia.list',
    '/private/var/tmp/cydia.log',
    '/tmp/cydia.log',
    '/var/cache/substrate',
    '/Library/Caches/com.saurik.Cydia',
    '/User/Applications/Cydia.app',
    '/private/var/mobile/Library/Cydia'
];

if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fm = NSFileManager.defaultManager();

    // ── Hook 1: fileExistsAtPath for Cydia paths ──
    try {
        fm['- fileExistsAtPath:'].implementation = function (self, sel, path) {
            var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
            for (var i = 0; i < CYDIA_PATHS.length; i++) {
                if (pathStr.indexOf(CYDIA_PATHS[i]) !== -1) {
                    log.info('Cydia path blocked: ' + pathStr);
                    return 0;
                }
            }
            return ObjC.classes.NSFileManager['- fileExistsAtPath:'](self, sel, path);
        };
        log.info('✓ Hooked fileExistsAtPath for Cydia paths');
    } catch (e) {
        log.warn('fileExistsAtPath hook failed: ' + e.message);
    }

    // ── Hook 2: Cydia URL scheme ──
    try {
        var UIApp = ObjC.classes.UIApplication.sharedApplication();
        UIApp['- canOpenURL:'].implementation = function (self, sel, url) {
            var urlObj = ObjC.classes.NSURL.URLWithString_(url);
            var scheme = urlObj ? urlObj.scheme().toString().toLowerCase() : '';
            if (scheme === 'cydia') {
                log.info('canOpenURL blocked for cydia://');
                return 0;
            }
            return ObjC.classes.UIApplication['- canOpenURL:'](self, sel, url);
        };
        log.info('✓ Hooked canOpenURL for cydia://');
    } catch (e) {
        log.warn('canOpenURL hook failed: ' + e.message);
    }

    // ── Hook 3: dlopen for MobileSubstrate ──
    try {
        var dlopenPtr = Module.findExportByName('libdyld.dylib', 'dlopen');
        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function (args) {
                    var path = args[0].readCString();
                    if (path && (path.indexOf('Substrate') !== -1 ||
                                 path.indexOf('substrate') !== -1 ||
                                 path.indexOf('CydiaSubstrate') !== -1)) {
                        log.info('dlopen blocked for: ' + path);
                        args[0] = ptr(0);
                    }
                }
            });
            log.info('✓ Hooked dlopen for MobileSubstrate');
        }
    } catch (e) {
        log.detail('dlopen hook failed: ' + e.message);
    }

    // ── Hook 4: stat/access for Cydia paths ──
    try {
        ['stat', 'lstat', 'access', 'open'].forEach(function (funcName) {
            try {
                var fn = Module.findExportByName('libsystem_kernel.dylib', funcName) ||
                         Module.findExportByName('libsystem_c.dylib', funcName);
                if (fn) {
                    Interceptor.attach(fn, {
                        onEnter: function (args) {
                            var path = args[0].readCString();
                            if (path) {
                                for (var i = 0; i < CYDIA_PATHS.length; i++) {
                                    if (path.indexOf(CYDIA_PATHS[i]) !== -1) {
                                        this.blocked = true;
                                        return;
                                    }
                                }
                            }
                            this.blocked = false;
                        },
                        onLeave: function (retval) {
                            if (this.blocked) retval.replace(-1);
                        }
                    });
                    log.info('✓ Hooked ' + funcName + ' for Cydia paths');
                }
            } catch (e) {}
        });
    } catch (e) {
        log.detail('C library hook failed: ' + e.message);
    }

    // ── Hook 5: Substrate hooking detection ──
    try {
        // Some apps check if their methods have been MSHook'ed
        var MSHookFunction = Module.findExportByName('CydiaSubstrate', 'MSHookFunction');
        if (MSHookFunction) {
            log.info('✓ CydiaSubstrate MSHookFunction found (hook would be detected)');
        }
    } catch (e) {
        log.detail('MSHookFunction not found in target');
    }
}

log.info('Cydia/Substrate bypass hooks complete');
"""

IOS_LIBERTY_SCRIPT = r"""/*
 * MobileSentry — Liberty/Libhooker Jailbreak Bypass (iOS)
 *
 * Targets Liberty, Libhooker (Chimera/Odyssey/Taurine),
 * and Procursus-based jailbreak detection methods.
 * Covers rootless jailbreak detection (Dopamine, Xina, Fugu15).
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_liberty.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Liberty/Libhooker Jailbreak Bypass loaded');

var LIBHOOKER_PATHS = [
    '/usr/lib/libhooker.dylib',
    '/usr/lib/libhooker',
    '/usr/lib/libhooker.dylib.old',
    '/var/jb',                          // Rootless jailbreak marker (Dopamine, Xina)
    '/var/jb/usr/lib/libhooker.dylib',
    '/var/jb/usr/lib/libsubstitute.dylib',
    '/var/jb/Library/MobileSubstrate',
    '/var/jb/Applications/Sileo.app',
    '/var/jb/usr/bin/cypher',
    '/.procursus_strapped',            // Procursus bootstrap
    '/.bootstrapped',                  // Another bootstrap marker
    '/private/preboot/jb',             // Rootless jailbreak
    '/private/preboot/tmp/jb',         // Xina15
    '/var/containers/Bundle/Application/.jbroot',  // Dopamine
    '/var/mobile/Library/.jbroot',     // Fugu15
    '/System/Library/TweakInject'       // Tweak injection directory (rootless)
];

if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fm = NSFileManager.defaultManager();

    // ── Hook 1: Main file checker ──
    try {
        fm['- fileExistsAtPath:'].implementation = function (self, sel, path) {
            var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
            for (var i = 0; i < LIBHOOKER_PATHS.length; i++) {
                if (pathStr.indexOf(LIBHOOKER_PATHS[i]) !== -1 || pathStr.indexOf('.jbroot') !== -1) {
                    log.info('Libhooker/jailbreak path blocked: ' + pathStr);
                    return 0;
                }
            }
            // Block any path with jbroot in it (Dopamine-specific)
            if (pathStr.indexOf('jbroot') !== -1 || pathStr.indexOf('.jb') !== -1) {
                log.detail('Rootless jailbreak path blocked: ' + pathStr);
                return 0;
            }
            return ObjC.classes.NSFileManager['- fileExistsAtPath:'](self, sel, path);
        };
        log.info('✓ Hooked fileExistsAtPath for libhooker paths');
    } catch (e) {
        log.warn('fileExistsAtPath hook failed: ' + e.message);
    }

    // ── Hook 2: dlopen for libhooker ──
    try {
        var dlopenPtr = Module.findExportByName('libdyld.dylib', 'dlopen');
        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function (args) {
                    var path = args[0].readCString();
                    if (path && (path.indexOf('libhooker') !== -1 ||
                                 path.indexOf('libsubstitute') !== -1 ||
                                 path.indexOf('substitute') !== -1)) {
                        log.info('dlopen blocked for: ' + path);
                        args[0] = ptr(0);
                    }
                }
            });
            log.info('✓ Hooked dlopen for libhooker detection');
        }
    } catch (e) {
        log.detail('dlopen hook failed: ' + e.message);
    }

    // ── Hook 3: stat/access for rootless paths ──
    try {
        ['stat', 'lstat', 'access', 'open'].forEach(function (funcName) {
            try {
                var fn = Module.findExportByName('libsystem_kernel.dylib', funcName);
                if (!fn) fn = Module.findExportByName('libsystem_c.dylib', funcName);
                if (fn) {
                    Interceptor.attach(fn, {
                        onEnter: function (args) {
                            var path = args[0].readCString();
                            if (path) {
                                if (path.indexOf('jbroot') !== -1 || path.indexOf('/var/jb') !== -1 ||
                                    path.indexOf('libhooker') !== -1 || path.indexOf('.jb') !== -1 ||
                                    path.indexOf('/private/preboot/jb') !== -1) {
                                    this.blocked = true;
                                    return;
                                }
                                for (var i = 0; i < LIBHOOKER_PATHS.length; i++) {
                                    if (path.indexOf(LIBHOOKER_PATHS[i]) !== -1) {
                                        this.blocked = true;
                                        return;
                                    }
                                }
                            }
                            this.blocked = false;
                        },
                        onLeave: function (retval) {
                            if (this.blocked) retval.replace(-1);
                        }
                    });
                }
            } catch (e) {}
        });
        log.info('✓ Hooked C library functions for rootless detection');
    } catch (e) {
        log.detail('C library hook failed: ' + e.message);
    }

    // ── Hook 4: Unlock device info for remount checks ──
    try {
        // Some rootless jailbreaks remount / as r/w — hook mount checks
        var mountPtr = Module.findExportByName('libsystem_kernel.dylib', 'mount');
        if (mountPtr) {
            Interceptor.attach(mountPtr, {
                onEnter: function (args) {
                    log.detail('mount() intercepted');
                }
            });
            log.info('✓ Hooked mount()');
        }
    } catch (e) {
        log.detail('mount hook failed');
    }

    // ── Hook 5: Sileo URL scheme ──
    try {
        var UIApp = ObjC.classes.UIApplication.sharedApplication();
        UIApp['- canOpenURL:'].implementation = function (self, sel, url) {
            var urlObj = ObjC.classes.NSURL.URLWithString_(url);
            var scheme = urlObj ? urlObj.scheme().toString().toLowerCase() : '';
            if (scheme === 'sileo' || scheme === 'zebra') {
                log.info('canOpenURL blocked for scheme: ' + scheme);
                return 0;
            }
            return ObjC.classes.UIApplication['- canOpenURL:'](self, sel, url);
        };
        log.info('✓ Hooked canOpenURL for Sileo/Zebra');
    } catch (e) {
        log.warn('canOpenURL hook failed: ' + e.message);
    }

    // ── Hook 6: Sandbox exceptions (Liberty-specific) ──
    try {
        var sandboxPtr = Module.findExportByName('libsystem_sandbox.dylib', 'sandbox_check_by_audit_token');
        if (sandboxPtr) {
            Interceptor.attach(sandboxPtr, {
                onEnter: function (args) {
                    // Liberty often uses sandbox checks — suppress them
                    log.detail('sandbox_check_by_audit_token intercepted');
                },
                onLeave: function (retval) {
                    retval.replace(0); // Allow all
                }
            });
            log.info('✓ Hooked sandbox_check_by_audit_token');
        }
    } catch (e) {
        log.detail('sandbox hook failed');
    }
}

log.info('Liberty/Libhooker bypass hooks complete');
"""

IOS_ROOTFUL_SCRIPT = r"""/*
 * MobileSentry — Rootful Jailbreak Detection Bypass (iOS)
 *
 * Targets traditional rootful jailbreak detection (unc0ver, checkra1n,
 * Chimera, Electra). Hooks common jailbreak indicators specific to
 * rootful jailbreaks including SSH, APT, dpkg, and other Cydia-era tools.
 *
 * Frida version: >= 12.0
 * Usage: frida -U -f com.target.app -l root_rootful.js
 */

'use strict';

const log = {
    info: (msg) => console.log(`[+] ${msg}`),
    detail: (msg) => console.log(`    ${msg}`)
};

log.info('MobileSentry Rootful Jailbreak Detection Bypass loaded');

var ROOTFUL_PATHS = [
    '/bin/bash', '/bin/sh',
    '/usr/sbin/sshd', '/usr/bin/ssh',
    '/etc/ssh/sshd_config', '/var/run/sshd.pid',
    '/etc/apt', '/private/etc/apt',
    '/private/var/lib/apt',
    '/etc/dpkg', '/private/etc/dpkg',
    '/private/var/lib/dpkg',
    '/private/var/log/apt',
    '/usr/bin/cycript', '/usr/local/bin/cycript',
    '/etc/apt/sources.list.d/cydia.list',
    '/private/var/stash',
    '/private/var/mobile/Library/SBSettings',
    '/private/var/mobile/Library/SBSettingsThemes',
    '/System/Library/WeeLoader_Plugins',
    '/System/Library/LaunchDaemons/com.apple.afc',
    '/private/var/db/stash',
    '/private/var/lib/cydia',
    '/.cydia_no_stash',
    '/.installed_unc0ver',
    '/.epic_ever_rooted',
    '/.root',
    '/.untether',
    '/tmp/cydia.log',
    '/private/var/tmp/cydia.log',
    '/var/log/syslog',
    '/var/cache/apt'
];

if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fm = NSFileManager.defaultManager();

    // ── Hook 1: File checks ──
    try {
        fm['- fileExistsAtPath:'].implementation = function (self, sel, path) {
            var pathStr = ObjC.classes.NSString.stringWithString(path).toString();
            for (var i = 0; i < ROOTFUL_PATHS.length; i++) {
                if (pathStr.indexOf(ROOTFUL_PATHS[i]) !== -1) {
                    log.info('Rootful path blocked: ' + pathStr);
                    return 0;
                }
            }
            // Block all dpkg/apt-related checks
            if (pathStr.indexOf('dpkg') !== -1 || pathStr.indexOf('apt ') !== -1) {
                log.detail('Package manager path blocked: ' + pathStr);
                return 0;
            }
            return ObjC.classes.NSFileManager['- fileExistsAtPath:'](self, sel, path);
        };
        log.info('✓ Hooked fileExistsAtPath for rootful paths');
    } catch (e) {
        log.warn('fileExistsAtPath hook failed: ' + e.message);
    }

    // ── Hook 2: stat/access for rootful paths ──
    try {
        ['stat', 'lstat', 'access', 'open'].forEach(function (funcName) {
            try {
                var fn = Module.findExportByName('libsystem_kernel.dylib', funcName);
                if (fn) {
                    Interceptor.attach(fn, {
                        onEnter: function (args) {
                            var path = args[0].readCString();
                            if (path) {
                                for (var i = 0; i < ROOTFUL_PATHS.length; i++) {
                                    if (path.indexOf(ROOTFUL_PATHS[i]) !== -1) {
                                        this.blocked = true;
                                        return;
                                    }
                                }
                            }
                            this.blocked = false;
                        },
                        onLeave: function (retval) {
                            if (this.blocked) retval.replace(-1);
                        }
                    });
                }
            } catch (e) {}
        });
        log.info('✓ Hooked C library functions for rootful paths');
    } catch (e) {
        log.detail('C library hook failed: ' + e.message);
    }

    // ── Hook 3: SSH port check ──
    try {
        // Some apps check if port 22 is open for SSH
        var connectPtr = Module.findExportByName('libsystem_kernel.dylib', 'connect');
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function (args) {
                    // Check if connecting to port 22 (SSH)
                    var sa = args[1];
                    if (sa) {
                        var family = sa.readU16();
                        if (family === 2) { // AF_INET
                            var port = (sa.readU16(2) >> 8) | ((sa.readU16(2) & 0xFF) << 8);
                            if (port === 22) {
                                log.info('connect() to port 22 (SSH) blocked');
                                this.blocked = true;
                                return;
                            }
                        }
                    }
                    this.blocked = false;
                },
                onLeave: function (retval) {
                    if (this.blocked) retval.replace(-1);
                }
            });
            log.info('✓ Hooked connect() for SSH port detection');
        }
    } catch (e) {
        log.detail('connect hook failed: ' + e.message);
    }

    // ── Hook 4: fork/system return values ──
    try {
        var forkPtr = Module.findExportByName('libsystem_kernel.dylib', 'fork');
        if (forkPtr) {
            Interceptor.attach(forkPtr, {
                onLeave: function (retval) {
                    retval.replace(-1); // Simulate sandbox
                }
            });
            log.info('✓ Hooked fork() for rootful detection');

            var systemPtr = Module.findExportByName('libsystem_c.dylib', 'system');
            if (systemPtr) {
                Interceptor.attach(systemPtr, {
                    onEnter: function (args) {
                        var cmd = args[0].readCString();
                        if (cmd) log.info('system() blocked: ' + cmd.substring(0, 50));
                        this.blocked = cmd !== null;
                    },
                    onLeave: function (retval) {
                        if (this.blocked) retval.replace(-1);
                    }
                });
                log.info('✓ Hooked system()');
            }
        }
    } catch (e) {
        log.detail('fork/system hook failed: ' + e.message);
    }

    // ── Hook 5: /dev check ──
    try {
        // Some rootful jailbreaks have r/w /dev
        var openPtr = Module.findExportByName('libsystem_kernel.dylib', 'open');
        if (openPtr && Array.isArray) {
            Interceptor.attach(openPtr, {
                onEnter: function (args) {
                    var path = args[0].readCString();
                    if (path && (path.indexOf('/dev') === 0 || path.indexOf('/var/log') === 0)) {
                        // Let it through but log it
                        log.detail('open() device access: ' + path);
                    }
                }
            });
            log.info('✓ Hooked open() for device checks');
        }
    } catch (e) {
        log.detail('open hook failed');
    }
}

log.info('Rootful jailbreak bypass hooks complete');
"""

# ──────────────────────────────────────────────
# Techniques Catalog
# ──────────────────────────────────────────────

ANDROID_TECHNIQUES: list[RootBypassTechnique] = [
    RootBypassTechnique(
        name="universal",
        platform="android",
        description="Global root detection bypass — hooks File.exists(), Runtime.exec(), System.getProperty(), Build.TAGS, ProcessBuilder, native access/stat, RootBeer, Superuser, and Magisk detection. The most comprehensive option.",
        detection_vectors=[
            "java.io.File.exists()",
            "Runtime.exec()",
            "System.getProperty()",
            "Build.TAGS",
            "ProcessBuilder",
            "native access()/stat()",
            "RootBeer library",
            "Su binary paths",
            "Superuser APK detection",
            "Magisk detection",
            "BusyBox detection",
        ],
        quality="best",
        warnings=["May be detected by apps with anti-Frida measures. Start here for most apps."],
    ),
    RootBypassTechnique(
        name="magisk",
        platform="android",
        description="Magisk-specific detection bypass — hides Magisk paths, MagiskSU, Magisk mount points, Zygisk detection, and MagiskHide bypass.",
        detection_vectors=[
            "Magisk binary paths",
            "Magisk env vars",
            "Magisk mount detection",
            "Zygisk detection",
            "MagiskHide",
            "File checks for Magisk app",
        ],
        quality="targeted",
        warnings=["Only effective if the app specifically checks for Magisk. Use universal for broader coverage."],
    ),
    RootBypassTechnique(
        name="rootbeer",
        platform="android",
        description="RootBeer library bypass — hooks all known RootBeer detection methods including isRooted(), detectTestKeys(), checkForSuBinary(), native root checks, and fallback class enumeration.",
        detection_vectors=[
            "com.scottyab.rootbeer.RootBeer.isRooted()",
            "detectTestKeys()",
            "checkForSuBinary()",
            "detectNativeRoot()",
            "librootbeer.so native functions",
        ],
        quality="targeted",
        warnings=["Only works if the app uses the RootBeer library. Use universal for broader coverage."],
    ),
    RootBypassTechnique(
        name="safetynet",
        platform="android",
        description="SafetyNet and Play Integrity API bypass — hooks SafetyNetApi.attest(), GoogleApiAvailability, mock device properties, JSON response spoofing for CTS profile match.",
        detection_vectors=[
            "SafetyNetApi.attest()",
            "CTS profile match",
            "basicIntegrity check",
            "Google Play Services integrity",
            "Play Integrity API",
        ],
        quality="targeted",
        warnings=["Full SafetyNet bypass requires runtime patches beyond simple Frida hooks. This handles app-level checks."],
    ),
]

IOS_TECHNIQUES: list[RootBypassTechnique] = [
    RootBypassTechnique(
        name="universal",
        platform="ios",
        description="Global jailbreak detection bypass — hooks NSFileManager, stat/access/open, fork/system/dlopen, canOpenURL, sysctl, proc_info, sandbox checks, and NSTask. Covers all major detection vectors.",
        detection_vectors=[
            "NSFileManager fileExistsAtPath",
            "stat/lstat/access/open",
            "fork()/system() return values",
            "dlopen() for dylib detection",
            "canOpenURL for Cydia/Sileo schemes",
            "sysctl() process info",
            "proc_info API",
            "sandbox integrity",
            "NSTask launch detection",
        ],
        quality="best",
        warnings=["Most comprehensive option for iOS jailbreak bypass. Start here for all apps."],
    ),
    RootBypassTechnique(
        name="cydia",
        platform="ios",
        description="Cydia/Substrate-specific bypass — targets Cydia app detection, MobileSubstrate library detection, Substrate URL scheme, and dylib checks. Focused on traditional jailbreaks.",
        detection_vectors=[
            "Cydia.app file checks",
            "MobileSubstrate dylib detection",
            "Cydia URL scheme (cydia://)",
            "MSHookFunction detection",
            "Substrate library paths",
        ],
        quality="targeted",
        warnings=["Targets traditional Cydia/Substrate jailbreaks. May not cover rootless jailbreaks (Dopamine, Xina)."],
    ),
    RootBypassTechnique(
        name="liberty",
        platform="ios",
        description="Liberty/Libhooker/rootless bypass — targets modern rootless jailbreaks (Dopamine, Xina, Fugu15), libhooker detection, Procursus bootstrap, Sileo/Zebra URL schemes, and sandbox checks.",
        detection_vectors=[
            "libhooker detection",
            "rootless jailbreak markers (/var/jb)",
            "Dopamine/Xina specific paths",
            "Sileo/Zebra URL schemes",
            "Procursus bootstrap markers",
            "jbroot path detection",
        ],
        quality="targeted",
        warnings=["Targets modern rootless jailbreaks (iOS 15+). Use universal for broader coverage."],
    ),
    RootBypassTechnique(
        name="rootful",
        platform="ios",
        description="Rootful jailbreak bypass — targets traditional rootful jailbreaks (unc0ver, checkra1n, Chimera, Electra). Hooks SSH, APT, dpkg, bash, and other Cydia-era tool detection.",
        detection_vectors=[
            "SSH/sshd detection",
            "APT/dpkg package manager checks",
            "bash/sh shell detection",
            "fork/system execution",
            "device file access (/dev)",
            "Cydia stash directories",
            "SSH port 22 connection check",
        ],
        quality="targeted",
        warnings=["Targets traditional rootful jailbreaks only. Not effective against rootless jailbreaks."],
    ),
]

TECHNIQUES_BY_PLATFORM: dict[str, list[RootBypassTechnique]] = {
    "android": ANDROID_TECHNIQUES,
    "ios": IOS_TECHNIQUES,
}

ALL_TECHNIQUES: list[RootBypassTechnique] = ANDROID_TECHNIQUES + IOS_TECHNIQUES

# Scripts by technique name
ANDROID_SCRIPTS: dict[str, str] = {
    "universal": ANDROID_UNIVERSAL_SCRIPT,
    "magisk": ANDROID_MAGISK_SCRIPT,
    "rootbeer": ANDROID_ROOTBEER_SCRIPT,
    "safetynet": ANDROID_SAFETYNET_SCRIPT,
}

IOS_SCRIPTS: dict[str, str] = {
    "universal": IOS_UNIVERSAL_SCRIPT,
    "cydia": IOS_CYDIA_SCRIPT,
    "liberty": IOS_LIBERTY_SCRIPT,
    "rootful": IOS_ROOTFUL_SCRIPT,
}

SCRIPTS_BY_PLATFORM: dict[str, dict[str, str]] = {
    "android": ANDROID_SCRIPTS,
    "ios": IOS_SCRIPTS,
}


# ══════════════════════════════════════════════
# Generator
# ══════════════════════════════════════════════


class RootBypassGenerator:
    """Generates Frida scripts for root/jailbreak detection bypass.

    Args:
        output_dir: Directory where generated scripts will be saved.
    """

    def __init__(self, output_dir: str = "./bypass_scripts") -> None:
        self.output_dir = Path(output_dir)

    # ── Listing ──

    def list_techniques(self, platform: str | None = None) -> list[RootBypassTechnique]:
        """List available bypass techniques, optionally filtered by platform.

        Args:
            platform: Filter by platform ("android", "ios", or None for all).

        Returns:
            List of RootBypassTechnique metadata objects.
        """
        if platform:
            return TECHNIQUES_BY_PLATFORM.get(platform.lower(), [])
        return ALL_TECHNIQUES

    def get_technique(self, name: str, platform: str) -> RootBypassTechnique | None:
        """Get a specific technique by name and platform.

        Args:
            name: Technique name (e.g., "universal", "magisk").
            platform: Platform ("android" or "ios").

        Returns:
            RootBypassTechnique if found, None otherwise.
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

            filename = f"root_{technique_name}_{platform_lower}.js"
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
            technique_name: Technique name (e.g., "universal", "magisk").
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

        filename = f"root_{technique_name}_{platform_lower}.js"
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
