"""MobileSentry CLI — Command-line interface for mobile security testing.

Commands:
  apk analyze <file>     Full APK analysis (permissions, components, secrets, security)
  apk info <file>        Quick APK info summary
  apk decompile <file>   Decompile APK to smali source
  apk secrets <file>     Scan decompiled source for hardcoded secrets
  ipa analyze <file>     Full IPA analysis (Info.plist, entitlements, binary, SDKs)
  ipa info <file>        Quick IPA info summary
  ipa decompile <file>   Extract IPA to .app bundle
  ipa secrets <file>     Scan app bundle for hardcoded secrets
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from mobilesentry import __version__
from mobilesentry.apk_analyzer import (
    ComponentInfo,
    PermissionInfo,
    SecretFinding,
    SecurityIssue,
    analyze_apk,
)
from mobilesentry.dynamic_analyzer import (
    DynamicAnalyzer,
    RuntimeMonitorGenerator,
)
from mobilesentry.ipa_analyzer import (
    BinaryInfo,
    EntitlementInfo,
    IosPermission,
    SdkFinding,
    UrlScheme,
    analyze_ipa,
)
from mobilesentry.ipa_analyzer import (
    SecretFinding as IpaSecretFinding,
)
from mobilesentry.ipa_analyzer import (
    SecurityIssue as IpaSecurityIssue,
)
from mobilesentry.ipa_analyzer import (
    format_analysis_summary as format_ipa_summary,
)
from mobilesentry.obfuscation_detect import (
    ObfuscationDetector,
)
from mobilesentry.obfuscation_detect import (
    format_report as format_obfuscation_report,
)
from mobilesentry.obfuscation_detect import (
    list_techniques as list_obfuscation_techniques,
)
from mobilesentry.report_generator import ReportGenerator
from mobilesentry.root_bypass import (
    RootBypassGenerator,
)
from mobilesentry.ssl_pinning import (
    SslBypassGenerator,
)
from mobilesentry.static_analyzer import (
    AnalysisContext,
    OwaspCategory,
    format_owasp_result,
)
from mobilesentry.static_analyzer import (
    analyze as owasp_analyze,
)
from mobilesentry.traffic_intercept import (
    InterceptionSetup,
    TlsAnalyzer,
    TrafficAnalyzer,
    validate_addon,
)

# ──────────────────────────────────────────────
# Console Helpers
# ──────────────────────────────────────────────

console = Console()


def _severity_style(severity: str) -> str:
    """Return Rich style string for a severity level."""
    styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
        "dangerous": "bold red",
        "normal": "green",
        "signature": "dim",
        "unknown": "yellow",
        "custom": "magenta",
    }
    return styles.get(severity, "white")


def _severity_icon(severity: str) -> str:
    icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "ℹ️",
        "dangerous": "⚠️",
        "normal": "✅",
    }
    return icons.get(severity, "▪️")


def _print_header():
    """Print the MobileSentry banner."""
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]MobileSentry[/bold cyan] — Mobile Application Security Testing Framework",
            border_style="cyan",
        )
    )
    console.print()


def _print_apk_info(result):
    """Display APK metadata in a formatted table."""
    info = result.apk_info

    table = Table(title="APK Metadata", box=box.ROUNDED, border_style="cyan")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Package", f"[bold]{info.package_name}[/bold]")
    table.add_row("Version", f"{info.version_name} ({info.version_code})")
    table.add_row("Min SDK", info.min_sdk or "—")
    table.add_row("Target SDK", info.target_sdk or "—")
    table.add_row("Size", f"{info.file_size_kb:.1f} KB")
    table.add_row(
        "Debuggable",
        f"[{_severity_style('high' if info.debuggable else 'green')}]{'⚠️ YES' if info.debuggable else '✅ No'}[/]",
    )
    table.add_row(
        "Allow Backup",
        f"[{_severity_style('medium' if info.allow_backup else 'green')}]{'⚠️ Enabled' if info.allow_backup else '✅ Disabled'}[/]",
    )
    table.add_row(
        "Network Security Config",
        f"[{'green' if info.has_network_security_config else 'yellow'}]{'✅ Present' if info.has_network_security_config else '⚠️ Missing'}[/]",
    )
    table.add_row(
        "Signed",
        f"[{'green' if info.is_signed else 'red'}]{'✅ Yes' if info.is_signed else '❌ No'}[/]",
    )
    if info.signature_name:
        table.add_row("Signature", info.signature_name[:60])

    console.print(table)


def _print_permissions(permissions: list[PermissionInfo]):
    """Display permissions in a severity-grouped table."""
    if not permissions:
        return

    table = Table(title="Declared Permissions", box=box.ROUNDED, border_style="yellow")
    table.add_column("Permission", style="bold")
    table.add_column("Severity", no_wrap=True)

    # Sort: dangerous first, then signature, unknown, custom, normal
    severity_order = {"dangerous": 0, "signature": 1, "unknown": 2, "custom": 3, "normal": 4}
    sorted_perms = sorted(
        permissions,
        key=lambda p: (severity_order.get(p.severity, 99), p.name),
    )

    for perm in sorted_perms:
        style = _severity_style(perm.severity)
        icon = _severity_icon(perm.severity)
        table.add_row(
            perm.name,
            f"[{style}]{icon} {perm.severity.upper()}[/{style}]",
        )

    # Summary counts
    dangerous_count = sum(1 for p in permissions if p.severity == "dangerous")
    normal_count = sum(1 for p in permissions if p.severity == "normal")
    console.print(table)
    console.print(f"   [bold]{len(permissions)}[/] total  ·  [{_severity_style('dangerous')}]{dangerous_count} dangerous[/]  ·  [green]{normal_count} normal[/]")
    console.print()


def _print_components(components: list[ComponentInfo]):
    """Display components in a table with export status."""
    if not components:
        return

    table = Table(title="Components", box=box.ROUNDED, border_style="blue")
    table.add_column("Type", style="bold", no_wrap=True)
    table.add_column("Name")
    table.add_column("Exported", no_wrap=True)
    table.add_column("Intent Filters", no_wrap=True)

    comp_order = {"activity": 0, "service": 1, "receiver": 2, "provider": 3}
    sorted_comps = sorted(
        components,
        key=lambda c: (comp_order.get(c.component_type, 99), c.name),
    )

    for comp in sorted_comps:
        exported_style = "red" if comp.exported else "green"
        exported_str = f"[{exported_style}]{'⚠️ Yes' if comp.exported else '✅ No'}[/{exported_style}]"
        filter_str = "✅ Yes" if comp.has_intent_filters else "—"
        short_name = comp.name.split(".")[-1] if "." in comp.name else comp.name
        table.add_row(
            comp.component_type.capitalize(),
            short_name,
            exported_str,
            filter_str,
        )

    exported_count = sum(1 for c in components if c.exported)
    console.print(table)
    console.print(f"   [bold]{len(components)}[/] total  ·  [{_severity_style('medium')}]{exported_count} exported[/]")
    console.print()


def _print_security_issues(issues: list[SecurityIssue]):
    """Display security issues grouped by severity."""
    if not issues:
        console.print("[green]✅ No security issues found.[/green]")
        console.print()
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.severity, 99))

    for issue in sorted_issues:
        style = _severity_style(issue.severity)
        icon = _severity_icon(issue.severity)
        panel = Panel(
            f"[bold]{issue.description}[/bold]\n\n[italic]Recommendation:[/italic] {issue.recommendation}",
            title=f"[{style}]{icon} [{issue.severity.upper()}] {issue.title}[/{style}]",
            border_style=style,
            box=box.ROUNDED,
        )
        console.print(panel)
        console.print()


def _print_secrets(secrets: list[SecretFinding]):
    """Display secrets findings in a table."""
    if not secrets:
        console.print("[green]✅ No hardcoded secrets detected.[/green]")
        console.print()
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_secrets = sorted(secrets, key=lambda s: severity_order.get(s.severity, 99))

    table = Table(title="Hardcoded Secrets", box=box.ROUNDED, border_style="red")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type", style="bold")
    table.add_column("Value (truncated)")
    table.add_column("File")
    table.add_column("Line")

    for secret in sorted_secrets:
        style = _severity_style(secret.severity)
        icon = _severity_icon(secret.severity)
        table.add_row(
            f"[{style}]{icon} {secret.severity.upper()}[/{style}]",
            secret.secret_type,
            secret.value,
            secret.file,
            str(secret.line),
        )

    console.print(table)
    critical_count = sum(1 for s in secrets if s.severity == "critical")
    high_count = sum(1 for s in secrets if s.severity == "high")
    console.print(f"   [bold]{len(secrets)}[/] total  ·  [bold red]{critical_count} critical[/]  ·  [red]{high_count} high[/]")
    console.print()


def _print_statistics(result):
    """Display analysis statistics summary."""
    stats = [
        (f"[bold]{result.file_count}[/] files", "📁"),
        (f"[bold]{result.dex_count}[/] DEX files", "📦"),
        ("🧠 Native code", "✅" if result.has_native_code else "—"),
        ("🔒 Obfuscated", "✅" if result.has_obfuscation else "—"),
        ("🔨 Decompiled", "✅" if result.decompiled else "❌"),
        (f"[bold]{len(result.permissions)}[/] permissions", "🔑"),
        (f"[bold]{len(result.components)}[/] components", "🧩"),
        (f"[bold]{len(result.secrets)}[/] secrets", "🤫"),
        (f"[bold]{len(result.security_issues)}[/] issues", "🔍"),
        (f"[bold]{result.analysis_time_ms}ms[/]", "⏱️"),
    ]

    table = Table(title="Analysis Summary", box=box.SIMPLE_HEAD, border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    for label, icon in stats:
        table.add_row(f"{icon} {label.split(' ')[-1]}", label)

    console.print(table)
    console.print()


# ──────────────────────────────────────────────
# Command Handlers
# ──────────────────────────────────────────────


def cmd_analyze(args: argparse.Namespace) -> int:
    """Full APK analysis."""
    _print_header()
    console.print(f"[bold]Analyzing:[/bold] {args.apk_file}")
    console.print()

    with console.status("[cyan]Analyzing APK...[/cyan]", spinner="dots"):
        result = analyze_apk(
            apk_path=args.apk_file,
            decompile=not args.no_decompile,
            output_dir=args.output,
        )

    if result.error:
        console.print(f"[red]❌ {result.error}[/red]")
        return 1

    # Print all sections
    _print_apk_info(result)
    _print_permissions(result.permissions)
    _print_components(result.components)
    _print_security_issues(result.security_issues)
    _print_secrets(result.secrets)
    _print_statistics(result)

    # JSON output
    if args.json:
        from mobilesentry.apk_analyzer import format_analysis_summary

        json_path = Path(args.output) / f"{result.apk_info.package_name}_analysis.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(format_analysis_summary(result), indent=2, default=str))
        console.print(f"[green]✅ JSON report saved: {json_path}[/green]")

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Quick APK info display."""
    _print_header()

    with console.status("[cyan]Loading APK...[/cyan]", spinner="dots"):
        result = analyze_apk(
            apk_path=args.apk_file,
            decompile=False,
        )

    if result.error:
        console.print(f"[red]❌ {result.error}[/red]")
        return 1

    _print_apk_info(result)
    _print_permissions(result.permissions)
    console.print(f"📁 [bold]{result.file_count}[/] files  ·  📦 {result.dex_count} DEX files")
    console.print()
    return 0


def cmd_decompile(args: argparse.Namespace) -> int:
    """Decompile APK to smali."""
    _print_header()

    decompile_dir = Path(args.output) / "decompiled" / Path(args.apk_file).stem
    decompile_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Decompiling:[/bold] {args.apk_file}")
    console.print(f"[bold]Output:[/bold] {decompile_dir}")
    console.print()

    with console.status("[cyan]Running apktool...[/cyan]", spinner="dots"):
        import subprocess

        try:
            result_proc = subprocess.run(
                ["apktool", "d", "-f", "-o", str(decompile_dir), args.apk_file],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            console.print("[red]❌ apktool not found. Install it first.[/red]")
            return 1
        except subprocess.TimeoutExpired:
            console.print("[red]❌ Decompilation timed out (120s).[/red]")
            return 1

    if result_proc.returncode == 0:
        console.print(f"[green]✅ Decompiled successfully to: {decompile_dir}[/green]")

        # Show directory tree
        tree = Tree(f"[bold]{decompile_dir.name}[/bold]")
        tree.add("[bold]smali/[/bold] 📜")
        tree.add("[bold]res/[/bold] 🎨")
        tree.add("[bold]AndroidManifest.xml[/bold] 📋")
        tree.add("[bold]original/[/bold] 📦")
        tree.add("[bold]...[/bold]")
        console.print(tree)
    else:
        console.print("[red]❌ Decompilation failed:[/red]")
        console.print(result_proc.stderr[:500])

    return 0 if result_proc.returncode == 0 else 1


def cmd_secrets(args: argparse.Namespace) -> int:
    """Scan decompiled source for hardcoded secrets."""
    _print_header()
    console.print(f"[bold]Scanning:[/bold] {args.apk_file}")
    console.print()

    with console.status("[cyan]Analyzing + decompiling...[/cyan]", spinner="dots"):
        result = analyze_apk(
            apk_path=args.apk_file,
            decompile=True,
            output_dir=args.output,
        )

    if result.error:
        console.print(f"[red]❌ {result.error}[/red]")
        return 1

    if not result.decompiled:
        console.print("[yellow]⚠️  Could not decompile APK. Secrets scan requires apktool.[/yellow]")
        return 1

    _print_secrets(result.secrets)
    _print_statistics(result)

    return 0


# ══════════════════════════════════════════════
# IPA Command Handlers
# ══════════════════════════════════════════════


def _print_ipa_info(result):
    """Display IPA metadata in a formatted table."""
    info = result.ipa_info

    table = Table(title="IPA Metadata", box=box.ROUNDED, border_style="cyan")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Bundle ID", f"[bold]{info.bundle_id}[/bold]")
    table.add_row("Name", info.bundle_name or "—")
    table.add_row("Display Name", info.display_name or "—")
    table.add_row("Version", f"{info.version} (build {info.build})")
    table.add_row("Minimum OS", info.min_os or "—")
    table.add_row("SDK", info.sdk_name or "—")
    table.add_row("Executable", info.executable or "—")
    table.add_row("Size", f"{info.file_size_kb:.1f} KB")

    console.print(table)


def _print_ipa_permissions(permissions: list[IosPermission]):
    """Display iOS permissions in a table."""
    if not permissions:
        return

    table = Table(title="iOS Permissions", box=box.ROUNDED, border_style="yellow")
    table.add_column("Permission", style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Purpose")

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_perms = sorted(permissions, key=lambda p: (severity_order.get(p.severity, 99), p.key))

    for perm in sorted_perms:
        style = _severity_style(perm.severity)
        icon = _severity_icon(perm.severity)
        purpose = (perm.purpose[:60] + "…") if len(perm.purpose) > 60 else (perm.purpose or "—")
        table.add_row(
            perm.key,
            f"[{style}]{icon} {perm.severity.upper()}[/{style}]",
            purpose,
        )

    console.print(table)
    high_count = sum(1 for p in permissions if p.severity == "high")
    console.print(f"   [bold]{len(permissions)}[/] total  ·  [red]{high_count} high-risk[/]")
    console.print()


def _print_ipa_schemes(schemes: list[UrlScheme]):
    """Display URL schemes."""
    if not schemes:
        return

    table = Table(title="Custom URL Schemes", box=box.ROUNDED, border_style="blue")
    table.add_column("URL Scheme", style="bold")
    table.add_column("Role")

    for scheme in schemes:
        table.add_row(scheme.name, scheme.role)

    console.print(table)
    console.print()


def _print_ipa_entitlements(entitlements: list[EntitlementInfo]):
    """Display entitlements with risk indicators."""
    if not entitlements:
        return

    table = Table(title="Entitlements", box=box.ROUNDED, border_style="magenta")
    table.add_column("Entitlement", style="bold")
    table.add_column("Value")
    table.add_column("Risk", no_wrap=True)

    risky_first = sorted(entitlements, key=lambda e: (0 if e.is_risky else 1, e.key))

    for ent in risky_first:
        risk_style = "red" if ent.is_risky else "green"
        risk_label = "⚠️ Risky" if ent.is_risky else "✅ Standard"
        table.add_row(
            ent.key,
            ent.value[:80],
            f"[{risk_style}]{risk_label}[/{risk_style}]",
        )

    console.print(table)
    risky_count = sum(1 for e in entitlements if e.is_risky)
    console.print(f"   [bold]{len(entitlements)}[/] total  ·  [red]{risky_count} risky[/]")
    console.print()


def _print_ipa_binary(binary_info: BinaryInfo):
    """Display binary analysis info."""
    table = Table(title="Binary Analysis", box=box.ROUNDED, border_style="cyan")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    arch_str = ", ".join(binary_info.architectures) if binary_info.architectures else "—"
    table.add_row("Architectures", arch_str)
    table.add_row("64-bit", "✅ Yes" if binary_info.is_64bit else "⚠️ No (32-bit)")
    table.add_row(
        "PIE (Position Independent)",
        f"[{'green' if binary_info.is_pie else 'red'}]{'✅ Yes' if binary_info.is_pie else '❌ No'}[/]",
    )
    table.add_row(
        "Stack Canary",
        f"[{'green' if binary_info.has_stack_canary else 'yellow'}]{'✅ Yes' if binary_info.has_stack_canary else '❓ Not detected'}[/]",
    )
    table.add_row(
        "ARC (Auto Ref Counting)",
        f"[{'green' if binary_info.has_arc else 'yellow'}]{'✅ Yes' if binary_info.has_arc else '❓ Not detected'}[/]",
    )
    table.add_row(
        "FairPlay Encrypted",
        f"[{'green' if binary_info.is_encrypted else 'yellow'}]{'✅ Yes' if binary_info.is_encrypted else '❓ Not detected'}[/]",
    )
    if binary_info.file_type:
        table.add_row("File Type", binary_info.file_type[:80])

    console.print(table)
    console.print()


def _print_ipa_sdks(sdks: list[SdkFinding]):
    """Display detected third-party SDKs."""
    if not sdks:
        console.print("[dim]No third-party SDKs detected.[/dim]")
        console.print()
        return

    table = Table(title="Third-Party SDKs", box=box.ROUNDED, border_style="blue")
    table.add_column("SDK", style="bold")
    table.add_column("Type")
    table.add_column("Risk", no_wrap=True)

    risk_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_sdks = sorted(sdks, key=lambda s: (risk_order.get(s.risk, 99), s.name))

    for sdk in sorted_sdks:
        style = _severity_style(sdk.risk)
        icon = _severity_icon(sdk.risk)
        table.add_row(
            sdk.name,
            sdk.type_,
            f"[{style}]{icon} {sdk.risk.upper()}[/{style}]",
        )

    console.print(table)
    console.print(f"   [bold]{len(sdks)}[/] SDKs detected")
    console.print()


def _print_ipa_security_issues(issues: list[IpaSecurityIssue]):
    """Display security issues grouped by severity."""
    if not issues:
        console.print("[green]✅ No security issues found.[/green]")
        console.print()
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.severity, 99))

    for issue in sorted_issues:
        style = _severity_style(issue.severity)
        icon = _severity_icon(issue.severity)
        panel = Panel(
            f"[bold]{issue.description}[/bold]\n\n[italic]Recommendation:[/italic] {issue.recommendation}",
            title=f"[{style}]{icon} [{issue.severity.upper()}] {issue.title}[/{style}]",
            border_style=style,
            box=box.ROUNDED,
        )
        console.print(panel)
        console.print()


def _print_ipa_secrets(secrets: list[IpaSecretFinding]):
    """Display secrets findings in a table."""
    if not secrets:
        console.print("[green]✅ No hardcoded secrets detected.[/green]")
        console.print()
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_secrets = sorted(secrets, key=lambda s: severity_order.get(s.severity, 99))

    table = Table(title="Hardcoded Secrets", box=box.ROUNDED, border_style="red")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type", style="bold")
    table.add_column("Value (truncated)")
    table.add_column("File")
    table.add_column("Line")

    for secret in sorted_secrets:
        style = _severity_style(secret.severity)
        icon = _severity_icon(secret.severity)
        table.add_row(
            f"[{style}]{icon} {secret.severity.upper()}[/{style}]",
            secret.secret_type,
            secret.value,
            secret.file,
            str(secret.line),
        )

    console.print(table)
    critical_count = sum(1 for s in secrets if s.severity == "critical")
    high_count = sum(1 for s in secrets if s.severity == "high")
    console.print(f"   [bold]{len(secrets)}[/] total  ·  [bold red]{critical_count} critical[/]  ·  [red]{high_count} high[/]")
    console.print()


def _print_ipa_statistics(result):
    """Display IPA analysis statistics."""
    stats = [
        (f"[bold]{result.file_count}[/] files", "📁"),
        (f"[bold]{result.framework_count}[/] frameworks", "📦"),
        (f"[bold]{len(result.permissions)}[/] permissions", "🔑"),
        (f"[bold]{len(result.url_schemes)}[/] URL schemes", "🔗"),
        (f"[bold]{len(result.entitlements)}[/] entitlements", "📋"),
        (f"[bold]{len(result.sdks)}[/] SDKs", "🧩"),
        (f"[bold]{len(result.secrets)}[/] secrets", "🤫"),
        (f"[bold]{len(result.security_issues)}[/] issues", "🔍"),
        (f"[bold]{result.analysis_time_ms}ms[/]", "⏱️"),
    ]

    table = Table(title="Analysis Summary", box=box.SIMPLE_HEAD, border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    for label, icon in stats:
        table.add_row(f"{icon} {label.split(' ')[-1]}", label)

    console.print(table)
    console.print()


def cmd_ipa_analyze(args: argparse.Namespace) -> int:
    """Full IPA analysis."""
    _print_header()
    console.print(f"[bold]Analyzing:[/bold] {args.ipa_file}")
    console.print()

    with console.status("[cyan]Extracting and analyzing IPA...[/cyan]", spinner="dots"):
        result = analyze_ipa(
            ipa_path=args.ipa_file,
            extract=True,
            scan_secrets=not args.no_secrets,
            cleanup_temp=True,
        )

    if result.error:
        console.print(f"[red]❌ {result.error}[/red]")
        return 1

    _print_ipa_info(result)
    _print_ipa_permissions(result.permissions)
    _print_ipa_schemes(result.url_schemes)
    _print_ipa_entitlements(result.entitlements)
    _print_ipa_binary(result.binary_info)
    _print_ipa_sdks(result.sdks)
    _print_ipa_security_issues(result.security_issues)
    _print_ipa_secrets(result.secrets)
    _print_ipa_statistics(result)

    # JSON output
    if args.json:
        json_path = Path(args.output) / f"{result.ipa_info.bundle_id}_analysis.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(format_ipa_summary(result), indent=2, default=str))
        console.print(f"[green]✅ JSON report saved: {json_path}[/green]")

    return 0


def cmd_ipa_info(args: argparse.Namespace) -> int:
    """Quick IPA info display."""
    _print_header()

    with console.status("[cyan]Loading IPA...[/cyan]", spinner="dots"):
        result = analyze_ipa(
            ipa_path=args.ipa_file,
            extract=True,
            scan_secrets=False,
        )

    if result.error:
        console.print(f"[red]❌ {result.error}[/red]")
        return 1

    _print_ipa_info(result)
    _print_ipa_permissions(result.permissions)
    console.print(f"📁 [bold]{result.file_count}[/] files  ·  📦 {result.framework_count} frameworks")
    console.print()
    return 0


def cmd_ipa_decompile(args: argparse.Namespace) -> int:
    """Extract IPA to its .app bundle."""
    _print_header()

    output_dir = Path(args.output) / "extracted" / Path(args.ipa_file).stem
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Extracting:[/bold] {args.ipa_file}")
    console.print(f"[bold]Output:[/bold] {output_dir}")
    console.print()

    with console.status("[cyan]Extracting IPA...[/cyan]", spinner="dots"):
        import zipfile

        try:
            with zipfile.ZipFile(args.ipa_file, "r") as zf:
                zf.extractall(str(output_dir))
        except zipfile.BadZipFile:
            console.print("[red]❌ Corrupt IPA file.[/red]")
            return 1

    console.print(f"[green]✅ Extracted to: {output_dir}[/green]")

    # Show .app bundle
    payload_dir = output_dir / "Payload"
    if payload_dir.is_dir():
        apps = [p.name for p in payload_dir.iterdir() if p.name.endswith(".app")]
        tree = Tree(f"[bold]{output_dir.name}[/bold]")
        tree.add("[bold]Payload/[/bold] 📦")
        for app in apps[:5]:
            tree.add(f"  [bold]{app}[/bold] 🍎")
            app_path = payload_dir / app
            items = sorted([i.name for i in app_path.iterdir()])[:10]
            for item in items:
                tree.add(f"    {item}")
            if len(os.listdir(str(app_path))) > 10:
                tree.add(f"    [dim]... and {len(os.listdir(str(app_path))) - 10} more files[/dim]")
        console.print(tree)

    return 0


def cmd_ipa_secrets(args: argparse.Namespace) -> int:
    """Scan IPA for hardcoded secrets."""
    _print_header()
    console.print(f"[bold]Scanning:[/bold] {args.ipa_file}")
    console.print()

    with console.status("[cyan]Extracting and scanning IPA...[/cyan]", spinner="dots"):
        result = analyze_ipa(
            ipa_path=args.ipa_file,
            extract=True,
            scan_secrets=True,
            cleanup_temp=True,
        )

    if result.error:
        console.print(f"[red]❌ {result.error}[/red]")
        return 1

    _print_ipa_secrets(result.secrets)
    _print_ipa_statistics(result)

    return 0


# ══════════════════════════════════════════════
# OWASP Command Handlers
# ══════════════════════════════════════════════


def _print_owasp_header(result):
    """Display the overall OWASP analysis header with score."""
    risk_style = _severity_style(result.overall_risk)
    risk_icon = _severity_icon(result.overall_risk)

    header = Panel.fit(
        f"[bold]OWASP Mobile Top 10 Security Assessment[/bold]\n"
        f"Platform: [bold]{result.platform.upper()}[/bold]  ·  "
        f"Score: [{risk_style}]{result.overall_score}/100 ({result.overall_risk.upper()})[/{risk_style}]  ·  "
        f"Findings: [bold]{result.total_findings}[/bold]\n"
        f"{risk_icon} [bold]Risk Level: [/bold][{risk_style}]{result.overall_risk.upper()}[/{risk_style}]  ·  "
        f"Time: {result.analysis_time_ms}ms",
        border_style=risk_style if result.overall_risk in ("critical", "high") else "yellow",
    )
    console.print(header)
    console.print()


def _print_owasp_summaries(result):
    """Display OWASP category summary table."""
    table = Table(title="OWASP Mobile Top 10 — Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Category", style="bold", no_wrap=True)
    table.add_column("Title")
    table.add_column("Findings", justify="center")
    table.add_column("Critical", justify="center")
    table.add_column("High", justify="center")
    table.add_column("Medium", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("Risk", no_wrap=True)

    # Sort summaries by score descending
    sorted_summaries = sorted(result.summaries, key=lambda s: s.score, reverse=True)

    for summary in sorted_summaries:
        risk_style = _severity_style(summary.risk_label)
        cat_str = f"[{risk_style}]{summary.category.value}[/{risk_style}]"
        risk_str = f"[{risk_style}]{_severity_icon(summary.risk_label)} {summary.risk_label.upper()}[/{risk_style}]"

        table.add_row(
            cat_str,
            summary.category.category_title[:45],
            str(summary.total_findings),
            f"[bold red]{summary.critical_count}[/]" if summary.critical_count else "—",
            f"[red]{summary.high_count}[/]" if summary.high_count else "—",
            f"[yellow]{summary.medium_count}[/]" if summary.medium_count else "—",
            str(summary.score),
            risk_str,
        )

    console.print(table)
    console.print()


def _print_owasp_findings(result):
    """Display all OWASP findings grouped by category."""
    cat_order = sorted(OwaspCategory, key=lambda c: c.value)

    for cat in cat_order:
        cat_findings = result.get_findings_by_category(cat)
        if not cat_findings:
            continue

        # Category header
        console.print()
        cat_panel = Panel(
            f"[bold]{cat.category_title}[/bold]\n[dim]{cat.category_description}[/dim]",
            title=f"[{_severity_style('info')}]{cat.value}: {cat.category_title}[/{_severity_style('info')}]",
            border_style="cyan",
            box=box.ROUNDED,
        )
        console.print(cat_panel)
        console.print()

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(cat_findings, key=lambda f: severity_order.get(f.severity, 99))

        for finding in sorted_findings:
            style = _severity_style(finding.severity)
            icon = _severity_icon(finding.severity)

            # Evidence list
            evidence_str = ""
            if finding.evidence:
                ev_lines = "\n".join(f"    • {e}" for e in finding.evidence[:5])
                evidence_str = f"\n\n[dim]Evidence:[/dim]\n{ev_lines}"

            cwe_str = f" [{finding.cwe}]" if finding.cwe else ""
            platform_str = rf" \[bold]({finding.platform})[/bold]" if finding.platform else ""
            conf_str = rf" \[confidence: {finding.confidence}][/]"

            panel = Panel(
                f"[bold]{finding.description}[/bold]\n\n[italic]Recommendation:[/italic] {finding.recommendation}{evidence_str}",
                title=f"[{style}]{icon} [{finding.severity.upper()}]{cwe_str}{platform_str}{conf_str} {finding.title}[/{style}]",
                border_style=style,
                box=box.ROUNDED,
            )
            console.print(panel)
            console.print()


def _print_owasp_remediation(result):
    """Display prioritized remediation summary."""
    critical_findings = result.critical_findings
    high_findings = result.high_findings

    if not critical_findings and not high_findings:
        console.print("[green]✅ No critical or high-severity findings. Continue following mobile security best practices.[/green]")
        console.print()
        return

    console.print(Panel.fit("[bold red]Priority Remediation Items[/bold red]", border_style="red"))

    for i, finding in enumerate(critical_findings + high_findings, 1):
        style = _severity_style(finding.severity)
        icon = _severity_icon(finding.severity)
        console.print(f"[bold]{i}. [/bold][{style}]{icon} [{finding.severity.upper()}] {finding.category.value} — {finding.title}[/{style}]")
        console.print(f"   {finding.recommendation[:120]}…" if len(finding.recommendation) > 120 else f"   {finding.recommendation}")
        console.print()


def cmd_owasp_analyze(args: argparse.Namespace) -> int:
    """Run OWASP Mobile Top 10 static analysis."""
    _print_header()
    file_path = args.file

    if not os.path.isfile(file_path):
        console.print(f"[red]❌ File not found: {file_path}[/red]")
        return 1

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print()

    # Detect file type and run appropriate analyzer
    ext = Path(file_path).suffix.lower()

    if ext == ".apk":
        with console.status("[cyan]Analyzing APK + running OWASP checks...[/cyan]", spinner="dots"):
            from mobilesentry.apk_analyzer import analyze_apk as run_apk_analyzer

            apk_result = run_apk_analyzer(
                apk_path=file_path,
                decompile=not args.no_decompile,
                output_dir=args.output,
            )
            if apk_result.error:
                console.print(f"[red]❌ APK analysis failed: {apk_result.error}[/red]")
                return 1
            ctx = AnalysisContext.from_apk(apk_result)
            owasp_result = owasp_analyze(ctx)

    elif ext == ".ipa":
        with console.status("[cyan]Analyzing IPA + running OWASP checks...[/cyan]", spinner="dots"):
            ipa_result = analyze_ipa(
                ipa_path=file_path,
                extract=True,
                scan_secrets=not args.no_secrets,
                cleanup_temp=True,
            )
            if ipa_result.error:
                console.print(f"[red]❌ IPA analysis failed: {ipa_result.error}[/red]")
                return 1
            ctx = AnalysisContext.from_ipa(ipa_result)
            owasp_result = owasp_analyze(ctx)
    else:
        console.print(f"[red]❌ Unsupported file type: {ext}. Expected .apk or .ipa[/red]")
        return 1

    # Display results
    _print_owasp_header(owasp_result)
    _print_owasp_summaries(owasp_result)
    _print_owasp_findings(owasp_result)
    _print_owasp_remediation(owasp_result)

    # JSON output
    if args.json:
        stem = Path(file_path).stem
        json_path = Path(args.output) / f"{stem}_owasp.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(format_owasp_result(owasp_result), indent=2, default=str))
        console.print(f"[green]✅ OWASP JSON report saved: {json_path}[/green]")

    return 0


def cmd_owasp_list(args: argparse.Namespace) -> int:
    """List all OWASP Mobile Top 10 categories and descriptions."""
    _print_header()

    table = Table(title="OWASP Mobile Top 10 (2024)", box=box.ROUNDED, border_style="cyan")
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Title")
    table.add_column("Description")

    for cat in OwaspCategory:
        table.add_row(
            f"[bold]{cat.value}[/bold]",
            cat.category_title,
            cat.category_description[:100] + "…",
        )

    console.print(table)
    console.print()

    console.print(
        Panel.fit(
            "[bold]Usage:[/bold] mobilesentry owasp analyze <apk_or_ipa_file> [options]\n"
            "[bold]Example:[/bold] mobilesentry owasp analyze app.apk\n"
            "[bold]Options:[/bold] --json[=/path/to/output]  --no-decompile  --no-secrets",
            border_style="cyan",
        )
    )
    console.print()
    return 0


# ══════════════════════════════════════════════
# Frida Command Handlers
# ══════════════════════════════════════════════


def _print_frida_techniques(techniques, platform_label):
    """Display Frida bypass techniques for a platform."""
    table = Table(title=f"SSL Pinning Bypass Techniques — {platform_label}", box=box.ROUNDED, border_style="green")
    table.add_column("Name", style="bold", no_wrap=True)
    table.add_column("Quality", no_wrap=True)
    table.add_column("Description")
    table.add_column("Target Libraries")

    quality_order = {"best": 0, "good": 1, "targeted": 2}
    sorted_techs = sorted(techniques, key=lambda t: (quality_order.get(t.quality, 99), t.name))

    for tech in sorted_techs:
        quality_style = {
            "best": "bold green",
            "good": "green",
            "targeted": "yellow",
        }.get(tech.quality, "cyan")
        quality_icon = {"best": "🌟", "good": "✅", "targeted": "🎯"}.get(tech.quality, "▪️")

        libs_str = ", ".join(tech.libraries[:3])
        if len(tech.libraries) > 3:
            libs_str += f" [+{len(tech.libraries) - 3} more]"

        warnings = ""
        if tech.warnings:
            warnings = f"\n[dim]⚠️  {tech.warnings[0]}[/dim]"

        table.add_row(
            f"[bold]{tech.name}[/bold]",
            f"[{quality_style}]{quality_icon} {tech.quality.upper()}[/{quality_style}]",
            f"{tech.description}{warnings}",
            f"[dim]{libs_str}[/dim]",
        )

    console.print(table)
    console.print()


def _print_generated_scripts(written: list[str]):
    """Display generated Frida scripts."""
    if not written:
        console.print("[red]❌ No scripts were generated.[/red]")
        return

    # Group by platform
    android_paths = [p for p in written if "/android/" in p or p.endswith("_android.js")]
    ios_paths = [p for p in written if "/ios/" in p or p.endswith("_ios.js")]

    table = Table(title="Generated Frida Scripts", box=box.ROUNDED, border_style="green")
    table.add_column("Platform", style="bold", no_wrap=True)
    table.add_column("Script", style="bold")
    table.add_column("File Path")

    for paths, platform in [(android_paths, "Android"), (ios_paths, "iOS")]:
        for path in paths:
            filename = Path(path).name
            technique_name = filename.replace("ssl_", "").replace("_android.js", "").replace("_ios.js", "")
            table.add_row(
                f"[bold]{'🤖 Android' if platform == 'Android' else '🍎 iOS'}[/bold]",
                f"[cyan]{technique_name}[/cyan]",
                str(path),
            )

    console.print(table)
    console.print()

    # Show usage instructions
    usage_panel = Panel.fit(
        "[bold]Quick Usage:[/bold]\n"
        "[dim]# Attach to running app[/dim]\n"
        "frida -U com.target.app -l frida_scripts/android/ssl_universal_android.js\n\n"
        "[dim]# Spawn and inject[/dim]\n"
        "frida -U -f com.target.app -l frida_scripts/android/ssl_universal_android.js --no-pause\n\n"
        "[dim]# USB device, iOS[/dim]\n"
        "frida -U -f com.target.app -l frida_scripts/ios/ssl_universal_ios.js",
        border_style="cyan",
        title="🚀 Usage",
    )
    console.print(usage_panel)
    console.print()


def cmd_frida_generate(args: argparse.Namespace) -> int:
    """Generate Frida SSL pinning bypass scripts."""
    _print_header()

    output_dir = args.output
    console.print(f"[bold]Output directory:[/bold] {output_dir}")
    console.print()

    gen = SslBypassGenerator(output_dir=output_dir)

    with console.status("[cyan]Generating Frida scripts...[/cyan]", spinner="dots"):
        # Generate once, write once, validate from the same dataset
        if args.platform == "all":
            scripts = gen.generate_all()
        else:
            scripts = gen.generate_platform(args.platform)

        written = gen.write_scripts(scripts)

        # Validate scripts
        issues = gen.validate_scripts(scripts)

    if not written:
        console.print("[red]❌ No scripts were generated. Check the platform parameter.[/red]")
        return 1

    console.print(f"[green]✅ Generated [bold]{len(written)}[/bold] Frida scripts successfully![/green]")
    if issues:
        for issue in issues:
            console.print(f"[yellow]{issue}[/yellow]")

    _print_generated_scripts(written)

    # Show generated file sizes
    total_size = 0
    for path in written:
        total_size += os.path.getsize(path)
    console.print(f"   📦 Total size: [bold]{total_size / 1024:.1f} KB[/bold] across [bold]{len(written)}[/bold] scripts")
    console.print()

    return 0


def cmd_frida_list(args: argparse.Namespace) -> int:
    """List available SSL pinning bypass techniques."""
    _print_header()

    gen = SslBypassGenerator()

    if args.platform == "all":
        android_techs = gen.list_techniques("android")
        ios_techs = gen.list_techniques("ios")

        console.print("[bold]🤖 Android Techniques[/bold]")
        _print_frida_techniques(android_techs, "Android")

        console.print("[bold]🍎 iOS Techniques[/bold]")
        _print_frida_techniques(ios_techs, "iOS")
    else:
        techs = gen.list_techniques(args.platform)
        platform_label = "Android" if args.platform == "android" else "iOS"
        _print_frida_techniques(techs, platform_label)

    console.print(
        Panel.fit(
            "[bold]Generate scripts:[/bold] mobilesentry frida generate [platform] [options]\n"
            "[bold]Example:[/bold] mobilesentry frida generate android --output ./scripts\n"
            "[bold]Example:[/bold] mobilesentry frida generate all --output ./frida_scripts\n"
            "[bold]Attach to app:[/bold] frida -U -f com.target.app -l <script.js>",
            border_style="cyan",
            title="📋 How to Use",
        )
    )
    console.print()
    return 0


# ══════════════════════════════════════════════
# Root/Jailbreak Bypass Command Handlers
# ══════════════════════════════════════════════


def _print_root_bypass_techniques(techniques, platform_label):
    """Display root/jailbreak bypass techniques for a platform."""
    table = Table(title=f"Root/Jailbreak Detection Bypass Techniques — {platform_label}", box=box.ROUNDED, border_style="magenta")
    table.add_column("Name", style="bold", no_wrap=True)
    table.add_column("Quality", no_wrap=True)
    table.add_column("Description")
    table.add_column("Detection Vectors")

    quality_order = {"best": 0, "good": 1, "targeted": 2}
    sorted_techs = sorted(techniques, key=lambda t: (quality_order.get(t.quality, 99), t.name))

    for tech in sorted_techs:
        quality_style = {
            "best": "bold green",
            "good": "green",
            "targeted": "yellow",
        }.get(tech.quality, "cyan")
        quality_icon = {"best": "🌟", "good": "✅", "targeted": "🎯"}.get(tech.quality, "▪️")

        vecs_str = ", ".join(tech.detection_vectors[:3])
        if len(tech.detection_vectors) > 3:
            vecs_str += f" [+{len(tech.detection_vectors) - 3} more]"

        warnings = ""
        if tech.warnings:
            warnings = f"\n[dim]⚠️  {tech.warnings[0]}[/dim]"

        table.add_row(
            f"[bold]{tech.name}[/bold]",
            f"[{quality_style}]{quality_icon} {tech.quality.upper()}[/{quality_style}]",
            f"{tech.description}{warnings}",
            f"[dim]{vecs_str}[/dim]",
        )

    console.print(table)
    console.print()


def _print_root_bypass_scripts(written: list[str]):
    """Display generated root/jailbreak bypass scripts."""
    if not written:
        console.print("[red]❌ No scripts were generated.[/red]")
        return

    # Group by platform
    android_paths = [p for p in written if "/android/" in p or p.endswith("_android.js")]
    ios_paths = [p for p in written if "/ios/" in p or p.endswith("_ios.js")]

    table = Table(title="Generated Root/Jailbreak Bypass Scripts", box=box.ROUNDED, border_style="magenta")
    table.add_column("Platform", style="bold", no_wrap=True)
    table.add_column("Script", style="bold")
    table.add_column("File Path")

    for paths, platform in [(android_paths, "Android"), (ios_paths, "iOS")]:
        for path in paths:
            filename = Path(path).name
            technique_name = filename.replace("root_", "").replace("_android.js", "").replace("_ios.js", "")
            table.add_row(
                f"[bold]{'🤖 Android' if platform == 'Android' else '🍎 iOS'}[/bold]",
                f"[cyan]{technique_name}[/cyan]",
                str(path),
            )

    console.print(table)
    console.print()

    # Show usage instructions
    usage_panel = Panel.fit(
        "[bold]Quick Usage:[/bold]\n"
        "[dim]# Attach to running Android app[/dim]\n"
        "frida -U com.target.app -l bypass_scripts/android/root_universal_android.js\n\n"
        "[dim]# Spawn and inject (iOS)[/dim]\n"
        "frida -U -f com.target.app -l bypass_scripts/ios/root_universal_ios.js",
        border_style="cyan",
        title="🚀 Usage",
    )
    console.print(usage_panel)
    console.print()


def cmd_root_bypass_generate(args: argparse.Namespace) -> int:
    """Generate root/jailbreak detection bypass Frida scripts."""
    _print_header()

    output_dir = args.output
    console.print(f"[bold]Output directory:[/bold] {output_dir}")
    console.print()

    gen = RootBypassGenerator(output_dir=output_dir)

    with console.status("[cyan]Generating root/jailbreak bypass scripts...[/cyan]", spinner="dots"):
        if args.platform == "all":
            scripts = gen.generate_all()
        else:
            scripts = gen.generate_platform(args.platform)

        written = gen.write_scripts(scripts)
        issues = gen.validate_scripts(scripts)

    if not written:
        console.print("[red]❌ No scripts were generated. Check the platform parameter.[/red]")
        return 1

    console.print(f"[green]✅ Generated [bold]{len(written)}[/bold] Frida scripts successfully![/green]")
    if issues:
        for issue in issues:
            console.print(f"[yellow]{issue}[/yellow]")

    _print_root_bypass_scripts(written)

    total_size = 0
    for path in written:
        total_size += os.path.getsize(path)
    console.print(f"   📦 Total size: [bold]{total_size / 1024:.1f} KB[/bold] across [bold]{len(written)}[/bold] scripts")
    console.print()

    return 0


def cmd_root_bypass_list(args: argparse.Namespace) -> int:
    """List available root/jailbreak bypass techniques."""
    _print_header()

    gen = RootBypassGenerator()

    if args.platform == "all":
        android_techs = gen.list_techniques("android")
        ios_techs = gen.list_techniques("ios")

        console.print("[bold]🤖 Android Techniques (Root Bypass)[/bold]")
        _print_root_bypass_techniques(android_techs, "Android")

        console.print("[bold]🍎 iOS Techniques (Jailbreak Bypass)[/bold]")
        _print_root_bypass_techniques(ios_techs, "iOS")
    else:
        techs = gen.list_techniques(args.platform)
        platform_label = "Android" if args.platform == "android" else "iOS"
        _print_root_bypass_techniques(techs, platform_label)

    console.print(
        Panel.fit(
            "[bold]Generate scripts:[/bold] mobilesentry frida root-bypass generate [platform] [options]\n"
            "[bold]Example:[/bold] mobilesentry frida root-bypass generate android --output ./bypass_scripts\n"
            "[bold]Example:[/bold] mobilesentry frida root-bypass generate all\n"
            "[bold]Attach to app:[/bold] frida -U -f com.target.app -l <script.js>",
            border_style="cyan",
            title="📋 How to Use",
        )
    )
    console.print()
    return 0


# ══════════════════════════════════════════════
# Traffic Command Handlers
# ══════════════════════════════════════════════


def _print_addon_info(addons_list):
    """Display generated addon scripts info."""
    table = Table(title="Generated MITMproxy Addon Scripts", box=box.ROUNDED, border_style="blue")
    table.add_column("Name", style="bold", no_wrap=True)
    table.add_column("Description")
    table.add_column("File", no_wrap=True)
    table.add_column("Size", justify="right")

    for addon in addons_list:
        table.add_row(
            f"[bold cyan]{addon.name}[/]",
            addon.description,
            str(addon.output_path),
            f"{addon.size_bytes / 1024:.1f} KB",
        )

    console.print(table)
    console.print()

    usage_panel = Panel.fit(
        "[bold]Quick Start:[/bold]\n\n"
        "[dim]# Start mitmproxy with the full addon[/dim]\n"
        "mitmproxy -s mitmproxy_config/mobilesentry_addon.py\n\n"
        "[dim]# Or headless capture[/dim]\n"
        "mitmdump -s mitmproxy_config/mobilesentry_addon.py\n\n"
        "[dim]# On device, set proxy to <HOST_IP>:8080[/dim]\n"
        "[dim]# Install CA cert: open http://mitm.it on device[/dim]",
        border_style="cyan",
        title="🚀 Usage",
    )
    console.print(usage_panel)
    console.print()


def _print_traffic_analysis(result):
    """Display traffic analysis results."""
    # Summary header
    https_pct = ((result.total_requests - len(result.http_urls)) / max(result.total_requests, 1)) * 100
    header_style = "green" if https_pct == 100 else "yellow" if https_pct >= 80 else "red"
    header = Panel.fit(
        f"[bold]Traffic Security Analysis[/bold]\n"
        f"Requests: [bold]{result.total_requests}[/bold]  ·  "
        f"Domains: [bold]{len(result.total_domains)}[/bold]  ·  "
        f"HTTPS: [{header_style}]{https_pct:.1f}%[/{header_style}]  ·  "
        f"Findings: [bold]{result.total_findings}[/bold]  ·  "
        f"Time: {result.analysis_time_ms:.0f}ms",
        border_style=header_style,
    )
    console.print(header)
    console.print()

    # Protocol summary
    proto_table = Table(title="Protocol Summary", box=box.SIMPLE_HEAD, border_style="cyan")
    proto_table.add_column("Metric", style="bold")
    proto_table.add_column("Value")
    proto_table.add_row("Total Requests", str(result.total_requests))
    proto_table.add_row("Unique Domains", str(len(result.total_domains)))
    proto_table.add_row("HTTPS Requests", f"[green]{result.total_requests - len(result.http_urls)}[/]")
    proto_table.add_row("HTTP Requests", f"[red]{len(result.http_urls)}[/]" if result.http_urls else "[green]0[/]")
    console.print(proto_table)
    console.print()

    # Findings by severity
    if result.findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))

        for finding in sorted_findings:
            style = _severity_style(finding.severity)
            icon = _severity_icon(finding.severity)
            url_str = f"\n[dim]URL: {finding.url[:100]}[/dim]" if finding.url else ""
            evidence_str = ""
            if finding.evidence:
                ev_lines = "\n".join(f"    • {e}" for e in finding.evidence[:3])
                evidence_str = f"\n[dim]{ev_lines}[/dim]"
            panel = Panel(
                f"[bold]{finding.title}[/bold]\n{finding.description}{url_str}{evidence_str}",
                title=f"[{style}]{icon} [{finding.severity.upper()}] {finding.category.upper()}[/{style}]",
                border_style=style,
                box=box.ROUNDED,
            )
            console.print(panel)
            console.print()

    # Cookie stats
    if result.cookie_stats["total"] > 0:
        cookie_table = Table(title="Cookie Security", box=box.SIMPLE_HEAD, border_style="yellow")
        cookie_table.add_column("Metric", style="bold")
        cookie_table.add_column("Count")
        cookie_table.add_row("Total Cookies", str(result.cookie_stats["total"]))
        cookie_table.add_row("[red]Missing Secure[/]", str(result.cookie_stats["missing_secure"]))
        cookie_table.add_row("[red]Missing HttpOnly[/]", str(result.cookie_stats["missing_httponly"]))
        cookie_table.add_row("[yellow]Missing SameSite[/]", str(result.cookie_stats["missing_samesite"]))
        console.print(cookie_table)
        console.print()

    # Domain list
    if result.total_domains:
        domain_str = "\n".join(f"  • {d}" for d in sorted(result.total_domains)[:15])
        if len(result.total_domains) > 15:
            domain_str += f"\n  [dim]... and {len(result.total_domains) - 15} more[/dim]"
        domain_panel = Panel(domain_str, title="🌐 Unique Domains", border_style="cyan")
        console.print(domain_panel)
        console.print()


def _print_tls_analysis(result):
    """Display TLS analysis results."""
    header = Panel.fit(
        f"[bold]TLS Certificate Analysis[/bold]\n"
        f"Certificates: [bold]{result.total_certs}[/bold]  ·  "
        f"Findings: [bold]{result.total_findings}[/bold]  ·  "
        f"TLS Versions: {', '.join(result.tls_versions.keys()) if result.tls_versions else 'N/A'}",
        border_style="cyan",
    )
    console.print(header)
    console.print()

    # TLS versions table
    if result.tls_versions:
        tls_table = Table(title="TLS Versions", box=box.SIMPLE_HEAD, border_style="cyan")
        tls_table.add_column("Version", style="bold")
        tls_table.add_column("Count", justify="right")
        for version, count in sorted(result.tls_versions.items()):
            style = "red" if any(w in version for w in ["SSLv3", "TLSv1.0", "TLSv1.1"]) else "green"
            tls_table.add_row(f"[{style}]{version}[/{style}]", str(count))
        console.print(tls_table)
        console.print()

    # Certificates
    if result.certificates:
        cert_table = Table(title="Certificates", box=box.ROUNDED, border_style="cyan")
        cert_table.add_column("Host", style="bold")
        cert_table.add_column("Subject")
        cert_table.add_column("Expiry")
        cert_table.add_column("Issuer")
        cert_table.add_column("Status", no_wrap=True)

        for cert in result.certificates:
            expiry_str = f"{cert.days_until_expiry}d" if cert.days_until_expiry > 0 else "[red]EXPIRED[/]"
            subj = str(next(iter(cert.subject.values())))[:40] if cert.subject else "—"
            issuer_str = str(next(iter(cert.issuer.values())))[:40] if cert.issuer else "—"
            status_str = "[red]✗ Expired[/]" if cert.is_expired else "[green]✓ Valid[/]"
            if cert.is_self_signed:
                status_str += " [yellow]Self-Signed[/]"
            if cert.is_wildcard:
                status_str += " [blue]Wildcard[/]"
            cert_table.add_row(
                cert.hostname,
                subj,
                expiry_str,
                issuer_str,
                status_str,
            )
        console.print(cert_table)
        console.print()

    # Findings
    if result.findings:
        for finding in result.findings:
            style = _severity_style(finding.severity)
            icon = _severity_icon(finding.severity)
            panel = Panel(
                f"[bold]{finding.title}[/bold]\n{finding.description}",
                title=f"[{style}]{icon} [{finding.severity.upper()}][/{style}]",
                border_style=style,
                box=box.ROUNDED,
            )
            console.print(panel)
            console.print()

    # Summary
    summary_items = []
    if result.weak_ciphers:
        summary_items.append(f"[red]⚠️ {len(result.weak_ciphers)} weak ciphers[/]")
    if result.expired_certs:
        summary_items.append(f"[red]❌ {len(result.expired_certs)} expired certs[/]")
    if result.self_signed_certs:
        summary_items.append(f"[yellow]⚠️ {len(result.self_signed_certs)} self-signed certs[/]")
    if not summary_items:
        summary_items.append("[green]✅ No TLS issues found[/]")
    console.print("  ·  ".join(summary_items))
    console.print()


def cmd_traffic_setup(args: argparse.Namespace) -> int:
    """Generate mitmproxy addon scripts for traffic interception."""
    _print_header()

    output_dir = args.output
    console.print(f"[bold]Output directory:[/bold] {output_dir}")
    console.print()

    setup = InterceptionSetup(output_dir=output_dir)

    with console.status("[cyan]Generating mitmproxy addon scripts...[/cyan]", spinner="dots"):
        if args.addon_type == "all":
            addons_list = setup.generate_all()
            written = setup.write_addons(addons_list)
        else:
            addon = setup.generate_addon(args.addon_type)
            if addon is None:
                console.print(f"[red]❌ Unknown addon type: {args.addon_type}. Choose from: full, minimal, auth[/red]")
                return 1
            written = setup.write_addons([addon])
            addons_list = [addon]

        # Write setup guide if requested
        if args.guide:
            guide_path = setup.write_setup_guide()
            console.print(f"[green]✅ Device setup guide written: {guide_path}[/green]")

    if not written:
        console.print("[red]❌ No addons were generated.[/red]")
        return 1

    console.print(f"[green]✅ Generated [bold]{len(written)}[/bold] mitmproxy addon scripts![/green]")
    console.print()

    # Validate each addon
    for addon in addons_list:
        issues = validate_addon(addon)
        if issues:
            for issue in issues:
                console.print(f"[yellow]{issue}[/yellow]")

    _print_addon_info(addons_list)

    total_size = sum(a.size_bytes for a in addons_list)
    console.print(f"   📦 Total size: [bold]{total_size / 1024:.1f} KB[/bold] across [bold]{len(addons_list)}[/bold] scripts")
    console.print()

    return 0


def cmd_traffic_analyze(args: argparse.Namespace) -> int:
    """Analyze a HAR file for security issues in captured traffic."""
    _print_header()

    har_path = args.har_file
    if not os.path.isfile(har_path):
        console.print(f"[red]❌ File not found: {har_path}[/red]")
        return 1

    console.print(f"[bold]Analyzing:[/bold] {har_path}")
    console.print()

    analyzer = TrafficAnalyzer()

    with console.status("[cyan]Analyzing traffic capture...[/cyan]", spinner="dots"):
        # First show quick summary
        summary = analyzer.analyze_har_summary(har_path)
        result = analyzer.analyze_har(har_path)

    # Display summary
    summary_table = Table(title="HAR File Summary", box=box.SIMPLE_HEAD, border_style="cyan")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value")
    summary_table.add_row("Total Requests", str(summary["total_requests"]))
    summary_table.add_row("HTTPS", f"[green]{summary['https_requests']}[/] ({summary['https_percentage']}%)")
    summary_table.add_row("HTTP", f"[red]{summary['http_requests']}[/]" if summary["http_requests"] > 0 else "[green]0[/]")
    summary_table.add_row("Unique Hosts", str(summary["unique_hosts"]))
    console.print(summary_table)
    console.print()

    # Top hosts
    if summary.get("hosts"):
        host_table = Table(title="Top Hosts", box=box.SIMPLE_HEAD, border_style="dim")
        host_table.add_column("Host", style="bold")
        host_table.add_column("Requests", justify="right")
        for host, count in list(summary["hosts"].items())[:10]:
            host_table.add_row(host, str(count))
        console.print(host_table)
        console.print()

    # Full analysis
    console.print(Panel.fit("[bold]Security Analysis[/bold]", border_style="yellow"))
    console.print()
    _print_traffic_analysis(result)

    return 0


def cmd_traffic_certs(args: argparse.Namespace) -> int:
    """Analyze TLS certificates from a HAR file."""
    _print_header()

    har_path = args.har_file
    if not os.path.isfile(har_path):
        console.print(f"[red]❌ File not found: {har_path}[/red]")
        return 1

    console.print(f"[bold]Analyzing TLS:[/bold] {har_path}")
    console.print()

    analyzer = TlsAnalyzer()

    with console.status("[cyan]Analyzing TLS certificates...[/cyan]", spinner="dots"):
        result = analyzer.analyze_har(har_path)

    _print_tls_analysis(result)

    if result.total_certs == 0:
        console.print(
            Panel.fit(
                "[yellow]No TLS metadata found in the HAR file.\n\n"
                "The MobileSentry mitmproxy addon must be used to capture TLS information.\n"
                "Generate it with: [bold]mobilesentry traffic setup full[/bold]\n\n"
                "Then restart mitmproxy with the generated addon and re-capture traffic.",
                border_style="yellow",
                title="⚠️  No TLS Data",
            )
        )
        console.print()

    return 0


# ══════════════════════════════════════════════
# Dynamic Analysis Command Handlers
# ══════════════════════════════════════════════


def _print_monitor_techniques(techniques, platform_label):
    """Display runtime monitoring techniques for a platform."""
    table = Table(title=f"Runtime Monitoring Techniques — {platform_label}", box=box.ROUNDED, border_style="blue")
    table.add_column("Name", style="bold", no_wrap=True)
    table.add_column("Quality", no_wrap=True)
    table.add_column("Description")
    table.add_column("Monitor Targets")

    quality_order = {"best": 0, "good": 1, "targeted": 2}
    sorted_techs = sorted(techniques, key=lambda t: (quality_order.get(t.quality, 99), t.name))

    for tech in sorted_techs:
        quality_style = {
            "best": "bold green",
            "good": "green",
            "targeted": "yellow",
        }.get(tech.quality, "cyan")
        quality_icon = {"best": "🌟", "good": "✅", "targeted": "🎯"}.get(tech.quality, "▪️")

        targets_str = ", ".join(tech.monitor_targets[:4])
        if len(tech.monitor_targets) > 4:
            targets_str += f" [+{len(tech.monitor_targets) - 4} more]"

        warnings = ""
        if tech.warnings:
            warnings = f"\n[dim]⚠️  {tech.warnings[0]}[/dim]"

        table.add_row(
            f"[bold]{tech.name}[/bold]",
            f"[{quality_style}]{quality_icon} {tech.quality.upper()}[/{quality_style}]",
            f"{tech.description}{warnings}",
            f"[dim]{targets_str}[/dim]",
        )

    console.print(table)
    console.print()


def _print_monitor_scripts(written: list[str]):
    """Display generated runtime monitor scripts."""
    if not written:
        console.print("[red]❌ No scripts were generated.[/red]")
        return

    # Group by platform
    android_paths = [p for p in written if "/android/" in p]
    ios_paths = [p for p in written if "/ios/" in p]

    table = Table(title="Generated Runtime Monitor Scripts", box=box.ROUNDED, border_style="blue")
    table.add_column("Platform", style="bold", no_wrap=True)
    table.add_column("Script", style="bold")
    table.add_column("File Path")

    for paths, platform in [(android_paths, "Android"), (ios_paths, "iOS")]:
        for path in paths:
            filename = Path(path).name
            technique_name = filename.replace("monitor_", "").replace("_android.js", "").replace("_ios.js", "")
            table.add_row(
                f"[bold]{'🤖 Android' if platform == 'Android' else '🍎 iOS'}[/bold]",
                f"[cyan]{technique_name}[/cyan]",
                str(path),
            )

    console.print(table)
    console.print()

    usage_panel = Panel.fit(
        "[bold]Quick Usage:[/bold]\n"
        "[dim]# Attach to running Android app[/dim]\n"
        "frida -U com.target.app -l monitor_scripts/android/monitor_universal_android.js\n\n"
        "[dim]# Spawn and inject with trace output[/dim]\n"
        "frida -U -f com.target.app -l monitor_scripts/android/monitor_universal_android.js --no-pause 2>&1 | tee trace.json\n\n"
        "[dim]# Analyze captured trace[/dim]\n"
        "mobilesentry frida dynamic trace trace.json",
        border_style="cyan",
        title="🚀 Usage",
    )
    console.print(usage_panel)
    console.print()


def _print_dynamic_report(report):
    """Display dynamic analysis report."""
    if report.total_events == 0:
        console.print("[yellow]⚠️  No events found in trace file. The monitor scripts may not have captured any data.[/yellow]")
        console.print()
        return

    # Summary header
    header_style = "green" if report.total_findings == 0 else "yellow" if report.total_findings < 5 else "red"
    header = Panel.fit(
        f"[bold]Dynamic Analysis Report[/bold]\n"
        f"Events: [bold]{report.total_events}[/bold]  ·  "
        f"Duration: [bold]{report.duration_seconds:.1f}s[/bold]  ·  "
        f"Etypes: [bold]{len(report.events_by_type)}[/bold]  ·  "
        f"APIs: [bold]{len(report.sensitive_apis)}[/bold]  ·  "
        f"Findings: [bold]{report.total_findings}[/bold]\n"
        f"Critical: [bold red]{len(report.critical_findings)}[/bold red]  ·  "
        f"High: [red]{len(report.high_findings)}[/red]",
        border_style=header_style,
    )
    console.print(header)
    console.print()

    # Event type breakdown
    if report.events_by_type:
        event_table = Table(title="Events by Type", box=box.SIMPLE_HEAD, border_style="cyan")
        event_table.add_column("Event Type", style="bold")
        event_table.add_column("Count", justify="right")
        for etype, count in sorted(report.events_by_type.items(), key=lambda x: x[1], reverse=True):
            event_table.add_row(etype, str(count))
        console.print(event_table)
        console.print()

    # Top methods called
    if report.methods_called:
        top_methods = sorted(report.methods_called.items(), key=lambda x: x[1], reverse=True)[:10]
        method_table = Table(title="Top Methods Called", box=box.SIMPLE_HEAD, border_style="dim")
        method_table.add_column("Method", style="bold")
        method_table.add_column("Count", justify="right")
        for method, count in top_methods:
            method_table.add_row(method[:80], str(count))
        console.print(method_table)
        console.print()

    # Behavioral findings
    if report.findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 99))

        for finding in sorted_findings:
            style = _severity_style(finding.severity)
            icon = _severity_icon(finding.severity)
            evidence_str = ""
            if finding.evidence:
                ev_lines = "\n".join(f"    • {e}" for e in finding.evidence[:5])
                evidence_str = f"\n\n[dim]Evidence:[/dim]\n{ev_lines}"
            panel = Panel(
                f"[bold]{finding.title}[/bold]\n{finding.description}{evidence_str}",
                title=f"[{style}]{icon} [{finding.severity.upper()}] {finding.category.upper()}[/{style}]",
                border_style=style,
                box=box.ROUNDED,
            )
            console.print(panel)
            console.print()

    # Sensitive APIs summary
    if report.sensitive_apis:
        sa_table = Table(title="Sensitive API Usage", box=box.SIMPLE_HEAD, border_style="yellow")
        sa_table.add_column("API", style="bold")
        sa_table.add_column("Description")
        sa_table.add_column("Count", justify="right")
        sa_table.add_column("Platform")
        for api in report.sensitive_apis[:15]:
            sa_table.add_row(
                api["api"][:60],
                api.get("description", "")[:40],
                str(api.get("count", 1)),
                api.get("platform", ""),
            )
        console.print(sa_table)
        console.print()

    # Call graph
    if report.call_graph:
        graph_size = sum(len(v) for v in report.call_graph.values())
        console.print(f"📊 Call graph: [bold]{len(report.call_graph)}[/] nodes, [bold]{graph_size}[/] edges")
        console.print()


def cmd_dynamic_generate(args: argparse.Namespace) -> int:
    """Generate runtime monitoring Frida scripts."""
    _print_header()

    output_dir = args.output
    console.print(f"[bold]Output directory:[/bold] {output_dir}")
    console.print()

    gen = RuntimeMonitorGenerator(output_dir=output_dir)

    with console.status("[cyan]Generating runtime monitor scripts...[/cyan]", spinner="dots"):
        if args.platform == "all":
            scripts = gen.generate_all()
        else:
            scripts = gen.generate_platform(args.platform)

        written = gen.write_scripts(scripts)
        issues = gen.validate_scripts(scripts)

    if not written:
        console.print("[red]❌ No scripts were generated. Check the platform parameter.[/red]")
        return 1

    console.print(f"[green]✅ Generated [bold]{len(written)}[/bold] monitor scripts successfully![/green]")
    if issues:
        for issue in issues:
            console.print(f"[yellow]{issue}[/yellow]")

    _print_monitor_scripts(written)

    total_size = 0
    for path in written:
        total_size += os.path.getsize(path)
    console.print(f"   📦 Total size: [bold]{total_size / 1024:.1f} KB[/bold] across [bold]{len(written)}[/bold] scripts")
    console.print()

    return 0


def cmd_dynamic_list(args: argparse.Namespace) -> int:
    """List available runtime monitoring techniques."""
    _print_header()

    gen = RuntimeMonitorGenerator()

    if args.platform == "all":
        android_techs = gen.list_techniques("android")
        ios_techs = gen.list_techniques("ios")

        console.print("[bold]🤖 Android Techniques (Runtime Monitor)[/bold]")
        _print_monitor_techniques(android_techs, "Android")

        console.print("[bold]🍎 iOS Techniques (Runtime Monitor)[/bold]")
        _print_monitor_techniques(ios_techs, "iOS")
    else:
        techs = gen.list_techniques(args.platform)
        platform_label = "Android" if args.platform == "android" else "iOS"
        _print_monitor_techniques(techs, platform_label)

    console.print(
        Panel.fit(
            "[bold]Generate scripts:[/bold] mobilesentry frida dynamic generate [platform] [options]\n"
            "[bold]Analyze trace:[/bold] mobilesentry frida dynamic trace <trace.json>\n"
            "[bold]Example:[/bold] mobilesentry frida dynamic generate android\n"
            "[bold]Example:[/bold] mobilesentry frida dynamic generate all --output ./monitor_scripts\n"
            "[bold]Example:[/bold] mobilesentry frida dynamic trace trace.json",
            border_style="cyan",
            title="📋 How to Use",
        )
    )
    console.print()
    return 0


def cmd_dynamic_trace(args: argparse.Namespace) -> int:
    """Analyze a trace file from runtime monitoring."""
    _print_header()

    trace_path = args.trace_file
    if not os.path.isfile(trace_path):
        console.print(f"[red]❌ File not found: {trace_path}[/red]")
        return 1

    console.print(f"[bold]Analyzing trace:[/bold] {trace_path}")
    console.print()

    analyzer = DynamicAnalyzer()

    with console.status("[cyan]Analyzing trace data...[/cyan]", spinner="dots"):
        report = analyzer.analyze_trace(trace_path)

    _print_dynamic_report(report)

    return 0


# ══════════════════════════════════════════════
# Obfuscation Detection Command Handlers
# ══════════════════════════════════════════════


def _print_obfuscation_header(report):
    """Display obfuscation analysis header with score."""
    risk_style = _severity_style(report.risk_level)
    risk_icon = _severity_icon(report.risk_level)

    header = Panel.fit(
        f"[bold]Code Obfuscation Analysis[/bold]\n"
        f"Platform: [bold]{report.platform.upper()}[/bold]  ·  "
        f"Findings: [bold]{report.total_findings}[/bold]  ·  "
        f"Obfuscation Score: [bold]{report.obfuscation_score}/100[/bold]  ·  "
        f"Time: {report.analysis_time_ms}ms\n"
        f"{risk_icon} Risk: [{risk_style}]{report.risk_level.upper()}[/{risk_style}]  ·  "
        f"{'🛡️ Protected' if report.protected else '⚠️ Not Protected'}",
        border_style=risk_style if report.risk_level in ("critical", "high") else "yellow",
    )
    console.print(header)
    console.print()


def _print_obfuscation_findings(findings):
    """Display obfuscation detection findings."""
    if not findings:
        console.print("[yellow]⚠️ No obfuscation techniques detected.[/yellow]")
        console.print()
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.severity, 99), -f.score))

    for finding in sorted_findings:
        style = _severity_style(finding.severity)
        icon = _severity_icon(finding.severity)

        evidence_str = ""
        if finding.evidence:
            ev_lines = "\n".join(f"    • {e}" for e in finding.evidence[:6])
            evidence_str = f"\n\n[dim]Evidence:[/dim]\n{ev_lines}"

        details_str = ""
        if finding.details:
            detail_items = []
            for key, val in finding.details.items():
                if isinstance(val, (int, float, bool, str)):
                    detail_items.append(f"    • {key.replace('_', ' ').title()}: {val}")
            if detail_items:
                details_str = "\n[dim]Details:[/dim]\n" + "\n".join(detail_items[:6])

        panel = Panel(
            f"[bold]{finding.description}[/bold]\n"
            f"Confidence: [bold]{finding.confidence.upper()}[/bold]{evidence_str}{details_str}",
            title=f"[{style}]{icon} [{finding.severity.upper()}] {finding.technique}[/{style}]",
            border_style=style,
            box=box.ROUNDED,
        )
        console.print(panel)
        console.print()


def _print_obfuscation_techniques(platform=None):
    """Display available obfuscation detection techniques."""
    if platform in ("android", "all", None):
        android_techs = list_obfuscation_techniques("android")
        table = Table(title="Android Obfuscation Detection Techniques", box=box.ROUNDED, border_style="magenta")
        table.add_column("Technique", style="bold", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Description")
        for tech in android_techs:
            style = _severity_style(tech.severity)
            table.add_row(
                f"[bold]{tech.name}[/bold]",
                f"[{style}]{_severity_icon(tech.severity)} {tech.severity.upper()}[/{style}]",
                tech.description[:80],
            )
        console.print(table)
        console.print()

    if platform in ("ios", "all", None):
        ios_techs = list_obfuscation_techniques("ios")
        table = Table(title="iOS Obfuscation Detection Techniques", box=box.ROUNDED, border_style="cyan")
        table.add_column("Technique", style="bold", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Description")
        for tech in ios_techs:
            style = _severity_style(tech.severity)
            table.add_row(
                f"[bold]{tech.name}[/bold]",
                f"[{style}]{_severity_icon(tech.severity)} {tech.severity.upper()}[/{style}]",
                tech.description[:80],
            )
        console.print(table)
        console.print()


def cmd_obfuscation_analyze(args: argparse.Namespace) -> int:
    """Run obfuscation detection on an APK or IPA."""
    _print_header()
    file_path = args.file

    if not os.path.isfile(file_path):
        console.print(f"[red]❌ File not found: {file_path}[/red]")
        return 1

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print()

    ext = Path(file_path).suffix.lower()
    detector = ObfuscationDetector()

    if ext == ".apk":
        # Decompile first, then analyze
        decompile_dir = Path(args.output) / "decompiled" / Path(file_path).stem

        with console.status("[cyan]Decompiling APK for obfuscation analysis...[/cyan]", spinner="dots"):
            import subprocess

            try:
                result_proc = subprocess.run(
                    ["apktool", "d", "-f", "-o", str(decompile_dir), file_path],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except FileNotFoundError:
                console.print("[red]❌ apktool not found. Install it first.[/red]")
                return 1
            except subprocess.TimeoutExpired:
                console.print("[red]❌ Decompilation timed out (120s).[/red]")
                return 1

        if result_proc.returncode != 0:
            console.print("[red]❌ Decompilation failed. Check the file and try again.[/red]")
            return 1

        with console.status("[cyan]Running obfuscation detection...[/cyan]", spinner="dots"):
            report = detector.analyze_apk(decompile_dir=str(decompile_dir))

    elif ext == ".ipa":
        # Extract first, then analyze
        extract_dir = Path(args.output) / "extracted" / Path(file_path).stem

        with console.status("[cyan]Extracting IPA for obfuscation analysis...[/cyan]", spinner="dots"):
            import zipfile

            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    zf.extractall(str(extract_dir))
            except zipfile.BadZipFile:
                console.print("[red]❌ Corrupt IPA file.[/red]")
                return 1

        with console.status("[cyan]Running obfuscation detection...[/cyan]", spinner="dots"):
            report = detector.analyze_ipa(ipa_extract_dir=str(extract_dir))
    else:
        console.print(f"[red]❌ Unsupported file type: {ext}. Expected .apk or .ipa[/red]")
        return 1

    # Display results
    _print_obfuscation_header(report)
    _print_obfuscation_findings(report.findings)

    # Obfuscation summary table
    if report.findings:
        summary_table = Table(title="Obfuscation Detection Summary", box=box.ROUNDED, border_style="cyan")
        summary_table.add_column("Severity", no_wrap=True)
        summary_table.add_column("Technique", style="bold")
        summary_table.add_column("Confidence", no_wrap=True)
        summary_table.add_column("Platform", no_wrap=True)
        for finding in sorted(report.findings, key=lambda f: f.score, reverse=True):
            style = _severity_style(finding.severity)
            summary_table.add_row(
                f"[{style}]{_severity_icon(finding.severity)} {finding.severity.upper()}[/{style}]",
                finding.technique,
                f"[bold]{finding.confidence.upper()}[/bold]",
                finding.platform.capitalize(),
            )
        console.print(summary_table)
        console.print()

    # Overall protection assessment
    if report.protected:
        console.print(
            Panel.fit(
                f"[green]🛡️ App is obfuscated (score: {report.obfuscation_score}/100)[/green]\n\n"
                f"The app employs {len(report.findings)} obfuscation techniques.\n"
                f"Review the findings above to understand what protections are in place.\n"
                f"Higher obfuscation scores indicate stronger binary protection.",
                border_style="green",
                title="✅ Obfuscation Status",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[yellow]⚠️ App is NOT obfuscated (score: {report.obfuscation_score}/100)[/yellow]\n\n"
                f"No significant obfuscation detected. The app's bytecode and resources\n"
                f"can be trivially reverse engineered. Consider enabling ProGuard/R8\n"
                f"(Android) or symbol obfuscation (iOS) as a baseline.",
                border_style="yellow",
                title="⚠️ Obfuscation Status",
            )
        )
        console.print()

    # JSON output
    if args.json:
        stem = Path(file_path).stem
        json_path = Path(args.output) / f"{stem}_obfuscation.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(format_obfuscation_report(report), indent=2, default=str)
        )
        console.print(f"[green]✅ JSON report saved: {json_path}[/green]")

    return 0


def cmd_obfuscation_list(args: argparse.Namespace) -> int:
    """List available obfuscation detection techniques."""
    _print_header()

    console.print("[bold]🤖 Android Obfuscation Detection Techniques[/bold]")
    _print_obfuscation_techniques("android")

    console.print("[bold]🍎 iOS Obfuscation Detection Techniques[/bold]")
    _print_obfuscation_techniques("ios")

    console.print(
        Panel.fit(
            "[bold]Usage:[/bold] mobilesentry obfuscation analyze <apk_or_ipa_file> [options]\n"
            "[bold]Example:[/bold] mobilesentry obfuscation analyze app.apk\n"
            "[bold]Example:[/bold] mobilesentry obfuscation analyze app.ipa --json\n"
            "[bold]Options:[/bold] --json  --output[=/path/to/output]",
            border_style="cyan",
            title="📋 How to Use",
        )
    )
    console.print()
    return 0


# ══════════════════════════════════════════════
# Report Command Handlers
# ══════════════════════════════════════════════


def cmd_report_generate(args: argparse.Namespace) -> int:
    """Generate a unified report from multiple analysis JSON files."""
    _print_header()

    gen = ReportGenerator()
    loaded_any = False

    if args.apk and gen.load_json("apk", args.apk):
        loaded_any = True
        console.print(f"[green]✅ Loaded APK analysis: {args.apk}[/green]")
    if args.ipa and gen.load_json("ipa", args.ipa):
        loaded_any = True
        console.print(f"[green]✅ Loaded IPA analysis: {args.ipa}[/green]")
    if args.owasp and gen.load_json("owasp", args.owasp):
        loaded_any = True
        console.print(f"[green]✅ Loaded OWASP analysis: {args.owasp}[/green]")
    if args.obfuscation and gen.load_json("obfuscation", args.obfuscation):
        loaded_any = True
        console.print(f"[green]✅ Loaded obfuscation analysis: {args.obfuscation}[/green]")
    if args.dynamic and gen.load_json("dynamic", args.dynamic):
        loaded_any = True
        console.print(f"[green]✅ Loaded dynamic analysis: {args.dynamic}[/green]")
    if args.traffic and gen.load_json("traffic", args.traffic):
        loaded_any = True
        console.print(f"[green]✅ Loaded traffic analysis: {args.traffic}[/green]")
    if args.tls and gen.load_json("tls", args.tls):
        loaded_any = True
        console.print(f"[green]✅ Loaded TLS analysis: {args.tls}[/green]")

    if not loaded_any:
        console.print("[red]❌ No data sources loaded. Provide at least one JSON report file.[/red]")
        console.print("[yellow]  Example: mobilesentry report generate --apk ./output/com.example_analysis.json[/yellow]")
        return 1

    output_path = args.output
    fmt = args.format

    console.print()
    with console.status(f"[cyan]Generating {fmt.upper()} report...[/cyan]", spinner="dots"):
        if fmt == "html":
            if output_path is None:
                output_path = f"./mobilesentry_report_{int(time.time())}.html"
            result_path = gen.write_html(output_path)
        elif fmt == "json":
            if output_path is None:
                output_path = f"./mobilesentry_report_{int(time.time())}.json"
            result_path = gen.write_json(output_path)
        elif fmt == "md":
            if output_path is None:
                output_path = f"./mobilesentry_report_{int(time.time())}.md"
            result_path = gen.write_markdown(output_path)
        else:
            console.print(f"[red]❌ Unknown format: {fmt}. Use html, json, or md.[/red]")
            return 1

    report = gen.report
    console.print(f"[green]✅ {fmt.upper()} report saved: {result_path}[/green]")
    console.print()

    # Summary
    console.print(
        Panel.fit(
            f"[bold]Report Summary[/bold]\n"
            f"Sources: [bold]{len(report.sources)}[/bold]  ·  "
            f"Findings: [bold]{report.severity_counts.total}[/bold]  ·  "
            f"Critical: [bold red]{report.severity_counts.critical}[/bold red]  ·  "
            f"High: [red]{report.severity_counts.high}[/red]  ·  "
            f"Medium: [yellow]{report.severity_counts.medium}[/yellow]  ·  "
            f"Score: [bold]{report.overall_score}/100[/bold]  ·  "
            f"Risk: [{_severity_style(report.overall_risk)}]{report.overall_risk.upper()}[/{_severity_style(report.overall_risk)}]",
            border_style="cyan",
            title="📊 Report Generated",
        )
    )
    console.print()

    return 0


# ══════════════════════════════════════════════
# Parser & Entry Point
# ══════════════════════════════════════════════


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mobilesentry",
        description="Mobile Application Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mobilesentry apk analyze app.apk                 Full analysis
  mobilesentry apk analyze app.apk --json          Full analysis + JSON export
  mobilesentry apk info app.apk                    Quick info summary
  mobilesentry apk decompile app.apk               Decompile to smali
  mobilesentry apk secrets app.apk                 Scan for hardcoded secrets
  mobilesentry ipa analyze app.ipa                 Full IPA analysis
  mobilesentry owasp analyze app.apk               OWASP Mobile Top 10 assessment
  mobilesentry owasp analyze app.ipa               OWASP Mobile Top 10 assessment
  mobilesentry owasp list                          List OWASP categories
  mobilesentry frida generate all                  Generate all SSL bypass scripts
  mobilesentry frida generate android              Generate Android SSL bypass scripts
  mobilesentry frida generate ios                  Generate iOS SSL bypass scripts
  mobilesentry frida list                          List available SSL bypass techniques
  mobilesentry frida root-bypass generate all       Generate all root/jailbreak bypass scripts
  mobilesentry frida root-bypass generate android   Generate Android root bypass scripts
  mobilesentry frida root-bypass generate ios       Generate iOS jailbreak bypass scripts
  mobilesentry frida root-bypass list               List available root/jailbreak bypass techniques
  mobilesentry frida dynamic generate               Generate all runtime monitor scripts
  mobilesentry frida dynamic generate android       Generate Android runtime monitor scripts
  mobilesentry frida dynamic generate ios           Generate iOS runtime monitor scripts
  mobilesentry frida dynamic list                   List available runtime monitoring techniques
  mobilesentry frida dynamic trace trace.json       Analyze trace file from runtime monitoring
  mobilesentry traffic setup                        Generate all mitmproxy addon scripts
  mobilesentry traffic setup full --guide           Generate full addon + device setup guide
  mobilesentry traffic setup auth                   Generate auth-focused addon
  mobilesentry traffic analyze capture.har          Analyze HAR file for security issues
  mobilesentry traffic certs capture.har            Analyze TLS certificates from HAR file
  mobilesentry obfuscation list                    List obfuscation detection techniques
  mobilesentry obfuscation analyze app.apk         Detect obfuscation in APK
  mobilesentry obfuscation analyze app.ipa         Detect obfuscation in IPA
  mobilesentry report --apk result.json             Generate HTML report from APK analysis
  mobilesentry report --apk a.json --ipa i.json     Generate report from multiple sources
  mobilesentry report --apk a.json --format json    Generate JSON report
  mobilesentry report --apk a.json -f md            Generate Markdown report
        """,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── apk command ──
    apk_parser = subparsers.add_parser("apk", help="APK analysis commands")
    apk_sub = apk_parser.add_subparsers(dest="apk_action", required=True)

    # apk analyze
    analyze_parser = apk_sub.add_parser("analyze", help="Full APK analysis")
    analyze_parser.add_argument("apk_file", help="Path to the APK file")
    analyze_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    analyze_parser.add_argument("--json", action="store_true", help="Export results as JSON")
    analyze_parser.add_argument("--no-decompile", action="store_true", help="Skip decompilation")
    analyze_parser.set_defaults(func=cmd_analyze)

    # apk info
    info_parser = apk_sub.add_parser("info", help="Quick APK info summary")
    info_parser.add_argument("apk_file", help="Path to the APK file")
    info_parser.set_defaults(func=cmd_info)

    # apk decompile
    decompile_parser = apk_sub.add_parser("decompile", help="Decompile APK to smali")
    decompile_parser.add_argument("apk_file", help="Path to the APK file")
    decompile_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    decompile_parser.set_defaults(func=cmd_decompile)

    # apk secrets
    secrets_parser = apk_sub.add_parser("secrets", help="Scan decompiled source for hardcoded secrets")
    secrets_parser.add_argument("apk_file", help="Path to the APK file")
    secrets_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    secrets_parser.set_defaults(func=cmd_secrets)

    # ── owasp command ──
    owasp_parser = subparsers.add_parser("owasp", help="OWASP Mobile Top 10 static analysis")
    owasp_sub = owasp_parser.add_subparsers(dest="owasp_action", required=True)

    # owasp analyze
    owasp_analyze_parser = owasp_sub.add_parser("analyze", help="Run OWASP Mobile Top 10 assessment on an APK or IPA")
    owasp_analyze_parser.add_argument("file", help="Path to the APK or IPA file")
    owasp_analyze_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    owasp_analyze_parser.add_argument("--json", action="store_true", help="Export results as JSON")
    owasp_analyze_parser.add_argument("--no-decompile", action="store_true", help="Skip APK decompilation")
    owasp_analyze_parser.add_argument("--no-secrets", action="store_true", help="Skip secrets scanning")
    owasp_analyze_parser.set_defaults(func=cmd_owasp_analyze)

    # owasp list
    owasp_list_parser = owasp_sub.add_parser("list", help="List OWASP Mobile Top 10 categories")
    owasp_list_parser.set_defaults(func=cmd_owasp_list)

    # ── traffic command ──
    traffic_parser = subparsers.add_parser("traffic", help="Traffic interception, HAR analysis, and TLS certificate analysis")
    traffic_sub = traffic_parser.add_subparsers(dest="traffic_action", required=True)

    # traffic setup
    traffic_setup_parser = traffic_sub.add_parser("setup", help="Generate mitmproxy addon scripts for traffic interception")
    traffic_setup_parser.add_argument(
        "addon_type",
        nargs="?",
        default="all",
        choices=["full", "minimal", "auth", "all"],
        help="Addon type: 'full' (sec analysis), 'minimal' (capture only), 'auth' (auth-focused), or 'all'",
    )
    traffic_setup_parser.add_argument("--output", "-o", default="./mitmproxy_config", help="Output directory")
    traffic_setup_parser.add_argument("--guide", action="store_true", help="Also write device setup guide")
    traffic_setup_parser.set_defaults(func=cmd_traffic_setup)

    # traffic analyze
    traffic_analyze_parser = traffic_sub.add_parser("analyze", help="Analyze a HAR file for security issues")
    traffic_analyze_parser.add_argument("har_file", help="Path to the HAR file to analyze")
    traffic_analyze_parser.set_defaults(func=cmd_traffic_analyze)

    # traffic certs
    traffic_certs_parser = traffic_sub.add_parser("certs", help="Analyze TLS certificates from HAR file")
    traffic_certs_parser.add_argument("har_file", help="Path to the HAR file containing TLS metadata")
    traffic_certs_parser.set_defaults(func=cmd_traffic_certs)

    # ── frida command ──
    frida_parser = subparsers.add_parser("frida", help="Frida script generation for SSL pinning bypass and root/jailbreak detection bypass")
    frida_sub = frida_parser.add_subparsers(dest="frida_action", required=True)

    # frida generate
    frida_gen_parser = frida_sub.add_parser("generate", help="Generate Frida SSL pinning bypass scripts")
    frida_gen_parser.add_argument(
        "platform",
        nargs="?",
        default="all",
        choices=["android", "ios", "all"],
        help="Target platform (android, ios, or all)",
    )
    frida_gen_parser.add_argument("--output", "-o", default="./frida_scripts", help="Output directory for generated scripts")
    frida_gen_parser.set_defaults(func=cmd_frida_generate)

    # frida list
    frida_list_parser = frida_sub.add_parser("list", help="List available SSL bypass techniques")
    frida_list_parser.add_argument(
        "platform",
        nargs="?",
        default="all",
        choices=["android", "ios", "all"],
        help="Filter by platform (android, ios, or all)",
    )
    frida_list_parser.set_defaults(func=cmd_frida_list)

    # ── frida dynamic subcommand (Phase 7) ──
    dynamic_parser = frida_sub.add_parser("dynamic", help="Generate runtime monitoring Frida scripts and analyze trace output")
    dynamic_sub = dynamic_parser.add_subparsers(dest="dynamic_action", required=True)

    # dynamic generate
    dynamic_gen_parser = dynamic_sub.add_parser("generate", help="Generate runtime monitoring Frida scripts")
    dynamic_gen_parser.add_argument(
        "platform",
        nargs="?",
        default="all",
        choices=["android", "ios", "all"],
        help="Target platform (android, ios, or all)",
    )
    dynamic_gen_parser.add_argument("--output", "-o", default="./monitor_scripts", help="Output directory for generated scripts")
    dynamic_gen_parser.set_defaults(func=cmd_dynamic_generate)

    # dynamic list
    dynamic_list_parser = dynamic_sub.add_parser("list", help="List available runtime monitoring techniques")
    dynamic_list_parser.add_argument(
        "platform",
        nargs="?",
        default="all",
        choices=["android", "ios", "all"],
        help="Filter by platform (android, ios, or all)",
    )
    dynamic_list_parser.set_defaults(func=cmd_dynamic_list)

    # dynamic trace
    dynamic_trace_parser = dynamic_sub.add_parser("trace", help="Analyze a trace file from runtime monitoring")
    dynamic_trace_parser.add_argument("trace_file", help="Path to the trace file (JSON-lines format from frida send())")
    dynamic_trace_parser.set_defaults(func=cmd_dynamic_trace)

    # ── frida root-bypass subcommand ──
    root_bypass_parser = frida_sub.add_parser("root-bypass", help="Generate root/jailbreak detection bypass Frida scripts")
    root_bypass_sub = root_bypass_parser.add_subparsers(dest="root_bypass_action", required=True)

    # root-bypass generate
    root_gen_parser = root_bypass_sub.add_parser("generate", help="Generate root/jailbreak bypass Frida scripts")
    root_gen_parser.add_argument(
        "platform",
        nargs="?",
        default="all",
        choices=["android", "ios", "all"],
        help="Target platform (android, ios, or all)",
    )
    root_gen_parser.add_argument("--output", "-o", default="./bypass_scripts", help="Output directory for generated scripts")
    root_gen_parser.set_defaults(func=cmd_root_bypass_generate)

    # root-bypass list
    root_list_parser = root_bypass_sub.add_parser("list", help="List available root/jailbreak bypass techniques")
    root_list_parser.add_argument(
        "platform",
        nargs="?",
        default="all",
        choices=["android", "ios", "all"],
        help="Filter by platform (android, ios, or all)",
    )
    root_list_parser.set_defaults(func=cmd_root_bypass_list)

    # ── obfuscation command ──
    obfuscation_parser = subparsers.add_parser("obfuscation", help="Code obfuscation detection (ProGuard, OLLVM, string encryption, packers, etc.)")
    obfuscation_sub = obfuscation_parser.add_subparsers(dest="obfuscation_action", required=True)

    # obfuscation analyze
    obfuscation_analyze_parser = obfuscation_sub.add_parser("analyze", help="Analyze APK or IPA for code obfuscation techniques")
    obfuscation_analyze_parser.add_argument("file", help="Path to the APK or IPA file")
    obfuscation_analyze_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory for decompiled/extracted files")
    obfuscation_analyze_parser.add_argument("--json", action="store_true", help="Export results as JSON")
    obfuscation_analyze_parser.set_defaults(func=cmd_obfuscation_analyze)

    # obfuscation list
    obfuscation_list_parser = obfuscation_sub.add_parser("list", help="List available obfuscation detection techniques")
    obfuscation_list_parser.set_defaults(func=cmd_obfuscation_list)

    # ── report command ──
    report_parser = subparsers.add_parser("report", help="Generate unified security reports from analysis JSON files")
    report_parser.add_argument("--apk", help="Path to APK analysis JSON file")
    report_parser.add_argument("--ipa", help="Path to IPA analysis JSON file")
    report_parser.add_argument("--owasp", help="Path to OWASP analysis JSON file")
    report_parser.add_argument("--obfuscation", help="Path to obfuscation detection JSON file")
    report_parser.add_argument("--dynamic", help="Path to dynamic analysis JSON file")
    report_parser.add_argument("--traffic", help="Path to traffic analysis JSON file")
    report_parser.add_argument("--tls", help="Path to TLS analysis JSON file")
    report_parser.add_argument("--format", "-f", default="html", choices=["html", "json", "md"], help="Output format: html, json, or md (default: html)")
    report_parser.add_argument("--output", "-o", help="Output file path (auto-generated if not provided)")
    report_parser.set_defaults(func=cmd_report_generate)

    # ── ipa command ──
    ipa_parser = subparsers.add_parser("ipa", help="IPA analysis commands (iOS)")
    ipa_sub = ipa_parser.add_subparsers(dest="ipa_action", required=True)

    # ipa analyze
    ipa_analyze_parser = ipa_sub.add_parser("analyze", help="Full IPA analysis")
    ipa_analyze_parser.add_argument("ipa_file", help="Path to the IPA file")
    ipa_analyze_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    ipa_analyze_parser.add_argument("--json", action="store_true", help="Export results as JSON")
    ipa_analyze_parser.add_argument("--no-secrets", action="store_true", help="Skip secrets scanning")
    ipa_analyze_parser.set_defaults(func=cmd_ipa_analyze)

    # ipa info
    ipa_info_parser = ipa_sub.add_parser("info", help="Quick IPA info summary")
    ipa_info_parser.add_argument("ipa_file", help="Path to the IPA file")
    ipa_info_parser.set_defaults(func=cmd_ipa_info)

    # ipa decompile (extract)
    ipa_decompile_parser = ipa_sub.add_parser("decompile", help="Extract IPA to .app bundle")
    ipa_decompile_parser.add_argument("ipa_file", help="Path to the IPA file")
    ipa_decompile_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    ipa_decompile_parser.set_defaults(func=cmd_ipa_decompile)

    # ipa secrets
    ipa_secrets_parser = ipa_sub.add_parser("secrets", help="Scan app bundle for hardcoded secrets")
    ipa_secrets_parser.add_argument("ipa_file", help="Path to the IPA file")
    ipa_secrets_parser.add_argument("--output", "-o", default="./mobilesentry_output", help="Output directory")
    ipa_secrets_parser.set_defaults(func=cmd_ipa_secrets)

    return parser


def main() -> None:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        sys.exit(args.func(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e!s}[/red]")
        if "--debug" in sys.argv:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
