"""
Client Microsoft Graph API v3.0
- Mode app-only (client credentials)
- Support scan differentiel (filtre par date)
- Pagination automatique
- Logging structure
"""
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.users.item.messages.messages_request_builder import MessagesRequestBuilder
from loguru import logger

from config.settings import AzureSettings


class GraphClient:
    """Client Microsoft Graph API avec authentification app-only."""

    def __init__(self, settings: AzureSettings):
        self.credential = ClientSecretCredential(
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
            client_secret=settings.client_secret,
        )
        self.client = GraphServiceClient(
            self.credential,
            scopes=["https://graph.microsoft.com/.default"],
        )
        logger.info("Graph client initialise (tenant: {})", settings.tenant_id[:8] + "...")

    async def get_token(self) -> str:
        """Recupere le token d'acces app-only."""
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        logger.debug("Token obtenu ({} caracteres)", len(token.token))
        return token.token

    async def list_users(self, top: int = 25) -> list:
        """Liste les utilisateurs du tenant."""
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            count=True,
            orderby=["displayName"],
            top=top,
            select=["displayName", "id", "mail", "userPrincipalName"],
        )
        request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
            query_parameters=query_params,
        )
        request_config.headers.add("ConsistencyLevel", "eventual")

        result = await self.client.users.get(request_configuration=request_config)
        users = result.value if result else []
        logger.info("{} utilisateur(s) recupere(s)", len(users))
        return users

    async def list_user_messages(
        self,
        user_id: str,
        top: int = 25,
        since: str | None = None,
    ) -> list:
        """
        Recupere les messages d'un utilisateur.

        Args:
            user_id: UPN ou ID de l'utilisateur
            top: Nombre max de messages
            since: Date ISO pour scan differentiel (ex: "2024-01-15T00:00:00Z")
        """
        select_fields = [
            "subject", "from", "receivedDateTime",
            "internetMessageHeaders", "body", "hasAttachments",
        ]

        query_params = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
            top=top,
            select=select_fields,
            expand=["attachments"],
            orderby=["receivedDateTime desc"],
        )

        # Scan differentiel : uniquement les nouveaux emails
        if since:
            query_params.filter = f"receivedDateTime ge {since}"
            logger.debug("Scan differentiel depuis {}", since)

        request_config = MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration(
            query_parameters=query_params,
        )

        try:
            result = await self.client.users.by_user_id(user_id).messages.get(
                request_configuration=request_config,
            )
            messages = result.value if result else []
            logger.info("  {} message(s) pour {}", len(messages), user_id)
            return messages
        except Exception as e:
            error_str = str(e)
            if "404" in error_str or "MailboxNotFound" in error_str:
                logger.warning("Boite introuvable pour {} (pas de licence Exchange?)", user_id)
            elif "401" in error_str or "403" in error_str:
                logger.error("Acces refuse pour {} - verifier les permissions", user_id)
            else:
                logger.error("Erreur Graph pour {} : {}", user_id, e)
            raise


def parse_auth_headers(internet_message_headers) -> dict:
    """
    Extrait SPF, DKIM, DMARC et Reply-To depuis les headers.
    Retourne un dict avec les cles : spf, dkim, dmarc, reply_to.
    """
    result = {"spf": "?", "dkim": "?", "dmarc": "?", "reply_to": ""}

    if not internet_message_headers:
        return result

    for header in internet_message_headers:
        name = (header.name or "").lower()
        value = header.value or ""

        if name == "authentication-results":
            val = value.lower()
            for proto, key in [("spf", "spf"), ("dkim", "dkim"), ("dmarc", "dmarc")]:
                if f"{proto}=pass" in val:
                    result[key] = "PASS"
                elif f"{proto}=fail" in val:
                    result[key] = "FAIL"
                elif f"{proto}=softfail" in val:
                    result[key] = "SOFTFAIL"
                elif f"{proto}=none" in val:
                    result[key] = "NONE"

        elif name == "reply-to":
            result["reply_to"] = value

        elif name == "x-originating-ip":
            result["originating_ip"] = value.strip("[]")

    return result


def message_to_dict(message) -> dict:
    """Convertit un message Graph en dict exploitable par le moteur de detection."""
    sender = ""
    if message.from_ and message.from_.email_address:
        sender = message.from_.email_address.address or ""

    subject = message.subject or ""
    date = str(message.received_date_time)[:19] if message.received_date_time else "?"
    message_id = message.id or ""

    auth = parse_auth_headers(message.internet_message_headers)

    corps = ""
    corps_html = ""
    if message.body and message.body.content:
        content_type = str(getattr(message.body.content_type, "value", "text")).lower()
        if content_type == "html":
            corps_html = message.body.content
            corps = message.body.content
        else:
            corps = message.body.content

    pieces_jointes = []
    if message.attachments:
        for att in message.attachments:
            pieces_jointes.append({
                "name": att.name or "",
                "size": getattr(att, "size", 0),
                "content_type": getattr(att, "content_type", ""),
            })

    return {
        "message_id": message_id,
        "expediteur": sender,
        "sujet": subject,
        "date": date,
        "reply_to": auth["reply_to"],
        "originating_ip": auth.get("originating_ip", ""),
        "corps": corps,
        "corps_html": corps_html,
        "urls": [],
        "pieces_jointes": pieces_jointes,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
    }
