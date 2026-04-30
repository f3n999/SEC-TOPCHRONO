"""
Affichage du rapport d'analyse — V5
Utilise rich pour un rendu coloré dans le terminal.
"""
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

COLORS = {
    "HIGH":   "red",
    "MEDIUM": "yellow",
    "LOW":    "green",
    "haute":  "red",
    "moyenne":"yellow",
    "faible": "cyan",
    "bonus":  "green",
}

ICONS = {
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def print_report(email_data: dict, anomalies: list[dict], result: dict):
    if _RICH:
        _rich_report(email_data, anomalies, result)
    else:
        _plain_report(email_data, anomalies, result)


# ─── Rapport Rich ──────────────────────────────────────────────────────────────

def _rich_report(email_data, anomalies, result):
    console = Console()
    niveau = result["niveau"]
    score = result["score"]
    icon = ICONS.get(niveau, "❓")

    console.print()

    # En-tête verdict
    color = COLORS.get(niveau, "white")
    verdict_text = Text()
    verdict_text.append(f" {icon} VERDICT : {niveau} ", style=f"bold white on {color}")
    verdict_text.append(f"  Score : {score}/100", style=f"bold {color}")
    console.print(Panel(verdict_text, title="[bold]Analyse V5 — Détecteur de Phishing[/bold]", border_style=color))

    # Infos email
    info_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    info_table.add_column("Champ", style="bold dim", width=14)
    info_table.add_column("Valeur")
    info_table.add_row("Expéditeur", email_data.get("expediteur", "—"))
    info_table.add_row("Sujet", email_data.get("sujet", "—")[:80])
    info_table.add_row("Date", email_data.get("date", "—")[:30])
    info_table.add_row("SPF", email_data.get("spf", "?"))
    info_table.add_row("DKIM", email_data.get("dkim", "?"))
    info_table.add_row("DMARC", email_data.get("dmarc", "?"))
    urls_count = len(email_data.get("urls", []))
    pj_count = len(email_data.get("pieces_jointes", []))
    info_table.add_row("URLs détectées", str(urls_count))
    info_table.add_row("Pièces jointes", str(pj_count))
    console.print(Panel(info_table, title="[bold]Informations email[/bold]", border_style="dim"))

    # Anomalies
    visible = [a for a in anomalies if a.get("rule") != "whitelist_bonus"]
    bonuses = [a for a in anomalies if a.get("rule") == "whitelist_bonus"]

    if visible:
        anom_table = Table(box=box.SIMPLE_HEAD, show_lines=False)
        anom_table.add_column("Sévérité", width=10)
        anom_table.add_column("Règle", width=22)
        anom_table.add_column("Description")
        anom_table.add_column("Score", justify="right", width=7)

        for a in sorted(visible, key=lambda x: -x.get("score", 0)):
            sev = a.get("severite", "?")
            col = COLORS.get(sev, "white")
            anom_table.add_row(
                Text(sev.upper(), style=f"bold {col}"),
                a.get("rule", "?"),
                a.get("description", "")[:70],
                f"+{a.get('score', 0)}",
            )

        console.print(Panel(anom_table, title=f"[bold]Anomalies détectées ({len(visible)})[/bold]", border_style=color))
    else:
        console.print(Panel("[green]Aucune anomalie détectée.[/green]", border_style="green"))

    if bonuses:
        console.print(f"[dim green]  ✓ Bonus expéditeur de confiance appliqué : {bonuses[0]['score']} pts[/dim green]")

    # Action recommandée
    console.print()
    action_color = COLORS.get(niveau, "white")
    console.print(f"[bold {action_color}]→ Action : {result['action']}[/bold {action_color}]")
    console.print()


# ─── Rapport Plain Text (fallback) ────────────────────────────────────────────

def _plain_report(email_data, anomalies, result):
    sep = "=" * 60
    niveau = result["niveau"]
    icon = ICONS.get(niveau, "?")

    print(f"\n{sep}")
    print(f"  {icon}  VERDICT : {niveau}  |  Score : {result['score']}/100")
    print(sep)
    print(f"  Expéditeur : {email_data.get('expediteur', '—')}")
    print(f"  Sujet      : {email_data.get('sujet', '—')[:70]}")
    print(f"  SPF/DKIM/DMARC : {email_data.get('spf','?')} / {email_data.get('dkim','?')} / {email_data.get('dmarc','?')}")
    print(sep)

    visible = [a for a in anomalies if a.get("rule") != "whitelist_bonus"]
    if visible:
        print(f"  Anomalies ({len(visible)}) :")
        for a in sorted(visible, key=lambda x: -x.get("score", 0)):
            print(f"    [{a.get('severite','?').upper():7}] +{a.get('score',0):3}  {a.get('description','')[:65]}")
    else:
        print("  Aucune anomalie détectée.")

    print(sep)
    print(f"  → {result['action']}")
    print(sep + "\n")
