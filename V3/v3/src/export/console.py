"""Export console avec Rich pour un affichage ameliore."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime


console = Console()


def print_scan_result(scan_result) -> None:
    """Affiche le rapport de scan dans la console."""
    summary = scan_result.summary()

    # Header
    console.print()
    console.print(Panel.fit(
        f"[bold white]PHISHING DETECTION AGENT v3.0[/]\n"
        f"[dim]Scan termine le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]",
        border_style="blue",
    ))

    # Stats
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_row("Emails analyses", f"[bold]{summary['total_emails']}[/]")
    stats_table.add_row("Users scannes", f"{summary['users_scanned']}")
    stats_table.add_row("[red]Phishing (HIGH)[/]", f"[bold red]{summary['phishing_high']}[/]")
    stats_table.add_row("[yellow]Suspects (MEDIUM)[/]", f"[bold yellow]{summary['suspects_medium']}[/]")
    stats_table.add_row("[green]Legitimes (LOW)[/]", f"[bold green]{summary['legitimes_low']}[/]")
    stats_table.add_row("Taux de detection", f"{summary['detection_rate']}")
    console.print(stats_table)
    console.print()

    # Tableau des emails flagges
    flagged = [r for r in scan_result.results if r["niveau"] in ("HIGH", "MEDIUM")]
    if not flagged:
        console.print("[green]Aucun email suspect detecte.[/]")
        return

    table = Table(title=f"Emails flagges ({len(flagged)})", show_lines=True)
    table.add_column("Niveau", style="bold", width=8)
    table.add_column("Score", justify="center", width=7)
    table.add_column("Expediteur", width=30)
    table.add_column("Sujet", width=40)
    table.add_column("Anomalies", width=50)

    for r in flagged:
        level_style = "red" if r["niveau"] == "HIGH" else "yellow"
        anomalies_text = "\n".join(
            f"[{a['severite']}] {a['description'][:55]}"
            for a in r.get("anomalies", [])
        )
        table.add_row(
            f"[{level_style}]{r['niveau']}[/]",
            f"{r['score']}/100",
            r["expediteur"][:30],
            r["sujet"][:40],
            anomalies_text,
        )

    console.print(table)
    console.print()


def print_quick_result(email_data: dict, evaluation: dict, anomalies: list) -> None:
    """Affiche le resultat d'un scan rapide pour un email."""
    if evaluation["niveau"] == "HIGH":
        tag = "[bold red][!!!] PHISHING[/]"
    elif evaluation["niveau"] == "MEDIUM":
        tag = "[bold yellow][ ! ] SUSPECT[/]"
    else:
        tag = "[bold green][ OK] LEGITIME[/]"

    console.print(f"  {tag} | Score: {evaluation['score']}/100")
    console.print(f"  Date  : {email_data['date']}")
    console.print(f"  De    : {email_data['expediteur']}")
    console.print(f"  Sujet : {email_data['sujet'][:55]}")
    console.print(f"  SPF: {email_data['spf']} | DKIM: {email_data['dkim']} | DMARC: {email_data['dmarc']}")
    for a in anomalies:
        console.print(f"    -> [{a['severite']}] {a['description'][:60]}")
    console.print("-" * 70)
