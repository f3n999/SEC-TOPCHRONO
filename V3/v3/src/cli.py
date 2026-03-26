"""
CLI moderne avec Typer v3.0
Interface en ligne de commande pour l'agent de detection de phishing.
"""
import asyncio
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from loguru import logger

from config.settings import get_settings
from src.core.logger import setup_logging
from src.core.graph_client import GraphClient, message_to_dict
from src.detection.engine import DetectionEngine
from src.scoring.risk_scorer import score_email
from src.core.scanner import Scanner
from src.export.console import print_scan_result, print_quick_result
from src.export.api_export import export_all
from src.db.database import init_db

app = typer.Typer(
    name="phishing-agent",
    help="Agent de detection de phishing via Microsoft Graph API",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    user: str = typer.Option(None, "--user", "-u", help="UPN d'un utilisateur specifique"),
    top: int = typer.Option(25, "--top", "-n", help="Nombre d'emails par boite"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Scan rapide (10 emails, affichage inline)"),
    no_export: bool = typer.Option(False, "--no-export", help="Desactiver l'export fichiers"),
    no_server: bool = typer.Option(False, "--no-server", help="Ne pas envoyer au serveur"),
):
    """Lance un scan de phishing sur les boites mail."""
    asyncio.run(_scan(user, top, quick, no_export, no_server))


async def _scan(user: str | None, top: int, quick: bool, no_export: bool, no_server: bool):
    settings = get_settings()
    setup_logging(settings.log_level, settings.data_dir)

    console.print(Panel.fit(
        "[bold blue]PHISHING DETECTION AGENT v3.0[/]\n"
        "[dim]Microsoft Graph API + Moteur Heuristique[/]",
        border_style="blue",
    ))

    graph = GraphClient(settings.azure)
    engine = DetectionEngine(settings.scan.rules_file)

    if quick:
        await _quick_scan(graph, engine, user, top)
    else:
        await _full_scan(graph, engine, user, top, no_export, no_server, settings)


async def _quick_scan(graph: GraphClient, engine: DetectionEngine, user: str | None, top: int):
    """Scan rapide avec affichage inline."""
    if not user:
        users = await graph.list_users()
        if not users:
            console.print("[red]Aucun utilisateur.[/]")
            return

        console.print("\n[bold]Utilisateurs disponibles :[/]")
        for i, u in enumerate(users):
            console.print(f"  {i+1}. {u.display_name or '?'} ({u.user_principal_name or '?'})")

        choix = IntPrompt.ask("\nNumero") - 1
        if choix < 0 or choix >= len(users):
            console.print("[red]Choix invalide.[/]")
            return
        user = users[choix].user_principal_name or users[choix].id

    top = min(top, 10)
    console.print(f"\n[cyan]Scan rapide de {user} ({top} emails)...[/]\n")

    messages = await graph.list_user_messages(user, top=top)
    if not messages:
        console.print("[yellow]Aucun email.[/]")
        return

    console.print("=" * 70)
    for msg in messages:
        data = message_to_dict(msg)
        anomalies = engine.analyser(data)
        evaluation = score_email(anomalies)
        print_quick_result(data, evaluation, anomalies)


async def _full_scan(
    graph: GraphClient,
    engine: DetectionEngine,
    user: str | None,
    top: int,
    no_export: bool,
    no_server: bool,
    settings,
):
    """Scan complet avec export."""
    scanner = Scanner(graph, engine)

    user_ids = None
    if user:
        user_ids = [(user, user)]
    else:
        users = await graph.list_users()
        if not users:
            console.print("[red]Aucun utilisateur.[/]")
            return

        console.print("\n[bold]Utilisateurs disponibles :[/]")
        for i, u in enumerate(users):
            console.print(f"  {i+1}. {u.display_name or '?'} ({u.user_principal_name or '?'})")
        console.print(f"  0. Scanner TOUS")

        choix = IntPrompt.ask("\nNumero (0=tous)")
        if choix == 0:
            user_ids = [
                (u.user_principal_name or u.id, u.display_name or u.user_principal_name or u.id)
                for u in users
            ]
        elif 1 <= choix <= len(users):
            u = users[choix - 1]
            user_ids = [(u.user_principal_name or u.id, u.display_name or "")]
        else:
            console.print("[red]Choix invalide.[/]")
            return

    scan_result = await scanner.scan_all(user_ids=user_ids, top=top)

    if not scan_result.results:
        console.print("[yellow]Aucun email analyse.[/]")
        return

    if no_export:
        print_scan_result(scan_result)
    else:
        export_all(
            scan_result,
            server_url="" if no_server else settings.server.remote_server,
            output_dir=settings.data_dir,
        )


@app.command()
def token():
    """Verifie le token d'acces Azure."""
    asyncio.run(_token())


async def _token():
    settings = get_settings()
    setup_logging(settings.log_level, settings.data_dir)
    graph = GraphClient(settings.azure)
    tok = await graph.get_token()
    console.print(f"\n[green][OK][/] Token obtenu ({len(tok)} caracteres)")
    console.print(f"     Debut: {tok[:50]}...\n")


@app.command()
def users():
    """Liste les utilisateurs du tenant Azure."""
    asyncio.run(_users())


async def _users():
    settings = get_settings()
    setup_logging(settings.log_level, settings.data_dir)
    graph = GraphClient(settings.azure)
    user_list = await graph.list_users()
    if not user_list:
        console.print("[yellow]Aucun utilisateur.[/]")
        return
    console.print(f"\n[bold]{len(user_list)} utilisateur(s) :[/]\n")
    for i, u in enumerate(user_list):
        console.print(f"  {i+1}. {u.display_name or 'N/A'}")
        console.print(f"     UPN : {u.user_principal_name or 'N/A'}")
        console.print(f"     Mail: {u.mail or 'N/A'}")
        console.print(f"     ID  : {u.id}\n")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h"),
    port: int = typer.Option(8080, "--port", "-p"),
):
    """Demarre l'API REST FastAPI."""
    import uvicorn
    console.print(f"[cyan]Demarrage API sur {host}:{port}...[/]")
    uvicorn.run("src.api.server:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
