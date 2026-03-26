"""CLI: privacy-label — scan any website, get a privacy nutrition label."""
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from .scanner import scan, ScanResult


GRADE_COLORS = {
    "A+": "bold green", "A": "green", "B+": "cyan", "B": "cyan",
    "C+": "yellow", "C": "yellow", "D+": "red", "D": "red", "F": "bold red",
}

CATEGORY_ICONS = {
    "advertising": "[red]AD[/red]",
    "analytics": "[yellow]AN[/yellow]",
    "marketing": "[yellow]MK[/yellow]",
    "social": "[cyan]SO[/cyan]",
    "fingerprinting": "[bold red]FP[/bold red]",
    "error_tracking": "[dim]ER[/dim]",
    "monitoring": "[dim]MO[/dim]",
    "infrastructure": "[dim]IF[/dim]",
    "consent": "[green]CO[/green]",
    "support": "[dim]SP[/dim]",
    "functionality": "[dim]FN[/dim]",
    "security": "[dim]SE[/dim]",
}


def render_result(console: Console, result: ScanResult, compact: bool = False):
    """Render a single scan result."""
    grade_style = GRADE_COLORS.get(result.grade, "white")

    # Header
    console.print(f"\n[bold]{result.domain}[/bold] — Privacy Nutrition Label")
    console.print("=" * 60)

    # Score
    score_bar = "█" * (result.score // 5) + "░" * (20 - result.score // 5)
    console.print(f"\n  Privacy Score: [{grade_style}]{result.score}/100 ({result.grade})[/{grade_style}]")
    console.print(f"  [{grade_style}]{score_bar}[/{grade_style}]")

    if result.errors:
        for e in result.errors:
            console.print(f"  [red]Error: {e}[/red]")

    # Trackers
    if result.trackers:
        tracker_table = Table(title="Trackers Found", border_style="dim", show_lines=False)
        tracker_table.add_column("Type", width=6)
        tracker_table.add_column("Name")
        tracker_table.add_column("Category")
        tracker_table.add_column("Via")

        # Sort: worst first
        sorted_trackers = sorted(result.trackers, key=lambda t: -t.severity)
        for t in sorted_trackers:
            if t.severity == 0 and compact:
                continue
            icon = CATEGORY_ICONS.get(t.category, "[dim]--[/dim]")
            cat_color = "red" if t.severity >= 3 else "yellow" if t.severity >= 2 else "dim"
            tracker_table.add_row(icon, t.name, f"[{cat_color}]{t.category}[/{cat_color}]", t.source)
        console.print(tracker_table)
    else:
        console.print("\n  [green]No trackers detected![/green]")

    # Data collection
    if result.data_signals:
        data_table = Table(title="Data Collection Signals", border_style="dim")
        data_table.add_column("Data Type")
        data_table.add_column("Category")
        for s in result.data_signals:
            cat_color = "red" if s.category == "fingerprinting" else "yellow" if s.category == "api_access" else "dim"
            data_table.add_row(s.name, f"[{cat_color}]{s.category}[/{cat_color}]")
        console.print(data_table)

    # Cookies
    if result.cookies_set:
        cookie_names = ", ".join(f"[yellow]{c.name}[/yellow]" for c in result.cookies_set)
        console.print(f"\n  Tracking Cookies: {cookie_names}")

    # Third parties
    tp_count = len(result.third_party_requests)
    tp_color = "red" if tp_count > 15 else "yellow" if tp_count > 5 else "green"
    console.print(f"\n  Third-Party Domains: [{tp_color}]{tp_count}[/{tp_color}]")

    # Security & privacy features
    features = []
    features.append(f"  HTTPS: {'[green]Yes[/green]' if result.https else '[red]No[/red]'}")
    features.append(f"  Privacy Policy: {'[green]Found[/green]' if result.has_privacy_policy else '[red]Not found[/red]'}")
    features.append(f"  Cookie Banner: {'[green]Yes[/green]' if result.has_cookie_banner else '[yellow]No[/yellow]'}")
    features.append(f"  DNT Respected: {'[green]Yes[/green]' if result.has_dnf_header else '[red]No[/red]'}")

    sec_count = sum(1 for v in result.security_headers.values() if v)
    sec_total = len(result.security_headers)
    sec_color = "green" if sec_count >= 4 else "yellow" if sec_count >= 2 else "red"
    features.append(f"  Security Headers: [{sec_color}]{sec_count}/{sec_total}[/{sec_color}]")

    console.print("\n" + "\n".join(features))

    # Known intel notice
    ki_count = len([t for t in result.trackers if t.source == "known_intel"])
    if ki_count:
        console.print(f"\n  [dim]Note: {ki_count} trackers from known site intelligence (JS-loaded, not visible in static HTML).[/dim]")

    # Summary
    ad_count = len([t for t in result.trackers if t.category == "advertising"])
    fp_count = len([t for t in result.trackers if t.category == "fingerprinting"])
    console.print()

    if result.score >= 70:
        console.print(Panel(
            f"[green]This site respects your privacy reasonably well.[/green]\n"
            f"{len(result.trackers)} trackers, {tp_count} third parties, {ad_count} ad networks.",
            title="[green]Verdict[/green]", border_style="green",
        ))
    elif result.score >= 40:
        console.print(Panel(
            f"[yellow]This site collects significant data about you.[/yellow]\n"
            f"{len(result.trackers)} trackers, {tp_count} third parties, {ad_count} ad networks."
            + (f"\n[red]{fp_count} fingerprinting scripts detected.[/red]" if fp_count else ""),
            title="[yellow]Verdict[/yellow]", border_style="yellow",
        ))
    else:
        console.print(Panel(
            f"[red]This site aggressively tracks you.[/red]\n"
            f"{len(result.trackers)} trackers, {tp_count} third parties, {ad_count} ad networks."
            + (f"\n[bold red]{fp_count} fingerprinting scripts detected.[/bold red]" if fp_count else "")
            + "\n\nConsider using a privacy browser or blocker.",
            title="[red]Verdict[/red]", border_style="red",
        ))


def render_compare(console: Console, results: list[ScanResult]):
    """Side-by-side comparison of multiple sites."""
    table = Table(title="Privacy Comparison", border_style="dim")
    table.add_column("Metric", style="bold")
    for r in results:
        table.add_column(r.domain, justify="center")

    # Grade
    table.add_row("Grade", *[f"[{GRADE_COLORS.get(r.grade, 'white')}]{r.grade}[/{GRADE_COLORS.get(r.grade, 'white')}]" for r in results])
    table.add_row("Score", *[f"{r.score}/100" for r in results])
    table.add_row("Trackers", *[f"{'[red]' if len(r.trackers) > 10 else '[yellow]' if len(r.trackers) > 3 else '[green]'}{len(r.trackers)}[/]" for r in results])
    table.add_row("Ad Networks", *[str(len([t for t in r.trackers if t.category == "advertising"])) for r in results])
    table.add_row("Fingerprinting", *[f"{'[red]' if any(t.category == 'fingerprinting' for t in r.trackers) else '[green]'}{'Yes' if any(t.category == 'fingerprinting' for t in r.trackers) else 'No'}[/]" for r in results])
    table.add_row("3rd Party Domains", *[str(len(r.third_party_requests)) for r in results])
    table.add_row("Tracking Cookies", *[str(len(r.cookies_set)) for r in results])
    table.add_row("HTTPS", *["[green]Yes[/green]" if r.https else "[red]No[/red]" for r in results])
    table.add_row("Privacy Policy", *["[green]Yes[/green]" if r.has_privacy_policy else "[red]No[/red]" for r in results])
    table.add_row("Cookie Banner", *["[green]Yes[/green]" if r.has_cookie_banner else "[yellow]No[/yellow]" for r in results])
    table.add_row("DNT Respected", *["[green]Yes[/green]" if r.has_dnf_header else "[red]No[/red]" for r in results])

    sec_scores = []
    for r in results:
        sc = sum(1 for v in r.security_headers.values() if v)
        sec_scores.append(f"{sc}/{len(r.security_headers)}")
    table.add_row("Security Headers", *sec_scores)

    console.print(table)

    # Winner
    best = max(results, key=lambda r: r.score)
    worst = min(results, key=lambda r: r.score)
    console.print(f"\n  [green]Most private:[/green] [bold]{best.domain}[/bold] ({best.grade}, {best.score}/100)")
    console.print(f"  [red]Least private:[/red] [bold]{worst.domain}[/bold] ({worst.grade}, {worst.score}/100)")


def main():
    console = Console()
    args = sys.argv[1:]
    json_mode = "--json" in args

    if not json_mode:
        console.print("\n[bold cyan]privacy-label[/bold cyan] — privacy nutrition label for any website\n")

    if not args or args[0] in ("-h", "--help", "help"):
        console.print("[bold]Usage:[/bold]")
        console.print("  privacy-label [bold]reddit.com[/bold]                     Scan one site")
        console.print("  privacy-label [bold]reddit.com twitter.com github.com[/bold]  Compare multiple")
        console.print("  privacy-label [bold]--compare reddit.com github.com[/bold]    Explicit compare mode")
        console.print("  privacy-label [bold]--json reddit.com[/bold]                  JSON output for scripts")
        console.print()
        console.print("[dim]Scans for trackers, data collection, fingerprinting, cookies,")
        console.print("third-party requests, security headers, and privacy features.")
        console.print("Outputs a privacy score (0-100) and grade (A+ to F).[/dim]")
        return

    compare_mode = "--compare" in args
    urls = [a for a in args if not a.startswith("-")]

    if not urls:
        console.print("[red]No URLs provided.[/red]")
        sys.exit(1)

    results = []
    for url in urls:
        if not json_mode:
            console.print(f"[dim]Scanning {url}...[/dim]")
        result = scan(url)
        results.append(result)

    if json_mode:
        import json
        output = []
        for r in results:
            output.append({
                "url": r.url,
                "domain": r.domain,
                "score": r.score,
                "grade": r.grade,
                "trackers": [{"name": t.name, "category": t.category, "severity": t.severity, "source": t.source} for t in r.trackers],
                "data_signals": [{"name": s.name, "category": s.category} for s in r.data_signals],
                "cookies": len(r.cookies_set),
                "third_party_domains": len(r.third_party_requests),
                "https": r.https,
                "privacy_policy": r.has_privacy_policy,
                "cookie_banner": r.has_cookie_banner,
                "dnt_respected": r.has_dnf_header,
                "security_headers": r.security_headers,
            })
        print(json.dumps(output[0] if len(output) == 1 else output, indent=2))
        return

    if len(results) == 1 and not compare_mode:
        render_result(console, results[0])
    elif len(results) > 1 or compare_mode:
        render_compare(console, results)
        console.print()
        for r in results:
            render_result(console, r, compact=True)

    console.print()


if __name__ == "__main__":
    main()
