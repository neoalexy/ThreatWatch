import argparse
import time
from config import get_date_range, DAYS_BACK
from fetcher import fetch_cves, fetch_epss
from parserr import parse_cve
from analyzer import analyze
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

BANNER = """
╔╦╗╦ ╦╦═╗╔═╗╔═╗╔╦╗╦ ╦╔═╗╔╦╗╔═╗╦ ╦
 ║ ╠═╣╠╦╝║╣ ╠═╣ ║ ║║║╠═╣ ║ ║  ╠═╣
 ╩ ╩ ╩╩╚═╚═╝╩ ╩ ╩ ╚╩╝╩ ╩ ╩ ╚═╝╩ ╩
  CVE Threat Intelligence Monitor
"""


def main():
    args = _parse_args()
    days = args.days or DAYS_BACK

    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    #console.print(f"Period: last {days} days\n")

    start_current, end_current = get_date_range(days)
    start_previous, end_previous = get_date_range(days * 2)

    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task1 = progress.add_task("Fetching current period...", total=None)
        raw_current = fetch_cves(start_current, end_current)
        progress.update(task1, completed=100, total=100)

        task2 = progress.add_task("Fetching previous period...", total=None)
        raw_previous = fetch_cves(start_previous, end_previous)
        current_ids = set(r["cve"]["id"] for r in raw_current)
        raw_previous = [r for r in raw_previous if r["cve"]["id"] not in current_ids]
        progress.update(task2, completed=100, total=100)

        task3 = progress.add_task("Fetching EPSS scores...", total=None)
        all_ids = [r["cve"]["id"] for r in raw_current]
        epss_scores = fetch_epss(all_ids)
        progress.update(task3, completed=100, total=100)

        task4 = progress.add_task("Analyzing...", total=None)
        cves_current = [parse_cve(r, epss_scores) for r in raw_current]
        cves_previous = [parse_cve(r, {}) for r in raw_previous]
        progress.update(task4, completed=100, total=100)

    if args.vendor:
        cves_current = [c for c in cves_current if c["vendor"] == args.vendor.lower()]

    results = analyze(cves_current, cves_previous)
    _print_results(results, start_current, end_current)


def _parse_args():
    parser = argparse.ArgumentParser(description="ThreatWatch - CVE threat monitor")
    parser.add_argument("--vendor", type=str, help="Filter by vendor name")
    parser.add_argument("--days", type=int, help="Days to look back (default: 30)")
    return parser.parse_args()


def _print_results(results, start, end):
    console.print(f"[bold]Period :[/bold] {start[:10]} → {end[:10]}")
    console.print(f"[bold]Total  :[/bold] {results['total']} CVEs (CVSS ≥ 7.0)\n")

    _print_severity_breakdown(results["severity_count"])
    _print_top_vendors(results["top_vendors"], results["trends"], results["product_breakdown"])
    _print_coefficients(results["coefficients"])
    _print_watched_alerts(results["watched_alerts"])
    _print_emerging(results["emerging"])
    _print_exploitable(results["exploitable"])
    _print_top10(results["top10"])


def _print_severity_breakdown(severity_count):
    console.print("[bold]── SEVERITY BREAKDOWN ──────────────────────[/bold]")
    for severity in ["CRITICAL", "HIGH"]:
        count = severity_count.get(severity, 0)
        if count == 0:
            continue
        color = {"CRITICAL": "red", "HIGH": "yellow"}.get(severity, "white")
        console.print(f"  [{color}]{severity:<10}[/{color}] {count:>5}")
    console.print()


def _print_top_vendors(top_vendors, trends, product_breakdown):
    console.print("[bold]── TOP 5 VENDORS ───────────────────────────[/bold]")
    for i, (vendor, count) in enumerate(top_vendors, 1):
        trend = trends.get(vendor, {}).get("trend", "")
        console.print(f"  {i}.  {vendor:<18} {count:>4} CVEs   {trend}")

        products = product_breakdown.get(vendor, [])
        if products:
            filtered = [(p, c) for p, c in products[:5]
                        if p != "unknown" and p != vendor]
            if filtered:
                product_str = "  ".join([f"{p}({c})" for p, c in filtered[:3]])
                console.print(f"      [dim] → {product_str}[/dim]")
    console.print()


def _print_coefficients(coefficients):
    console.print("[bold]── VENDOR EXPLOITABILITY COEFFICIENT ───────[/bold]")
    console.print("[dim]  real-world risk = CVE volume × avg EPSS[/dim]\n")
    for item in coefficients[:6]:
        coeff = item["coefficient"]
        if coeff > 40:
            label = "[red]HIGH ACTIVE RISK[/red]"
        elif coeff > 15:
            label = "[yellow]MODERATE RISK[/yellow]"
        else:
            label = "[dim]low exploitation[/dim]"
        console.print(
            f"  {item['vendor']:<18} "
            f"{item['cve_count']:>3} CVEs  "
            f"avg EPSS {item['avg_epss']:>5.1f}%  "
            f"coeff {coeff:>6.1f}  {label}"
        )
    console.print()


def _print_watched_alerts(watched_alerts):
    if not watched_alerts:
        return
    console.print("[bold]── WATCHED VENDOR ALERTS ───────────────────[/bold]")
    for vendor, data in watched_alerts.items():
        epss_str = f"{data['max_epss']*100:.1f}%" if data['max_epss'] else "n/a"
        console.print(
            f"  {vendor:<14}  "
            f"{data['count']:>3} CVEs  "
            f"max CVSS {data['max_score']}  "
            f"max EPSS {epss_str}"
        )
    console.print()


def _print_emerging(emerging):
    if not emerging:
        return
    console.print("[bold]── PRE-EMERGING THREATS ────────────────────[/bold]")
    console.print("[dim]  high EPSS, non-mainstream vendors — weaponization likely soon[/dim]\n")
    for cve in emerging:
        epss_str = f"{cve['epss']*100:.1f}%"
        tag = cve.get("saas_tag")
        if tag:
            tag_str = f"  [dim][{tag}][/dim]"
        else:
            desc = cve.get("description", "")[:60]
            tag_str = f"  [dim]{desc}...[/dim]" if desc else ""
        console.print(
            f"  {cve['id']:<22} "
            f"{cve['vendor']:<14} "
            f"CVSS {cve['score']}  "
            f"EPSS {epss_str}"
            f"{tag_str}"
        )
    console.print()


def _print_exploitable(exploitable):
    if not exploitable:
        return
    console.print("[bold]── EASILY EXPLOITABLE (AV:N/AC:L/PR:N) ────[/bold]")
    for cve in exploitable[:5]:
        epss_str = f"{cve['epss']*100:.1f}%" if cve.get("epss") else "n/a"
        flag = "  [red]HIGH PROB[/red]" if cve.get("epss") and cve["epss"] > 0.5 else ""
        console.print(
            f"  {cve['id']:<22} "
            f"{cve['vendor']:<14} "
            f"CVSS {cve['score']}  "
            f"EPSS {epss_str}{flag}"
        )
    console.print()


def _print_top10(top10):
    console.print("[bold]── TOP 10 HIGHEST SCORING ──────────────────[/bold]")
    console.print(f"  {'CVE ID':<22} {'Vendor':<16} {'CVSS':<6} {'EPSS':<8} {'Severity':<10} Attack")
    console.print(f"  {'─'*22} {'─'*16} {'─'*6} {'─'*8} {'─'*10} {'─'*12}")
    for cve in top10:
        epss_str = f"{cve['epss']*100:.1f}%" if cve.get("epss") else "n/a"
        severity = cve.get("severity") or ""
        color = "red" if severity == "CRITICAL" else "yellow"
        console.print(
            f"  {cve['id']:<22} "
            f"{cve['vendor']:<16} "
            f"{cve['score']:<6} "
            f"{epss_str:<8} "
            f"[{color}]{severity:<10}[/{color}] "
            f"{cve['cwe_group']}"
        )
    console.print()


if __name__ == "__main__":
    main()