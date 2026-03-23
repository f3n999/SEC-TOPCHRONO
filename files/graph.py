"""
Client Microsoft Graph API - Mode app-only (client credentials).
"""
from configparser import SectionProxy
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.users.item.messages.messages_request_builder import MessagesRequestBuilder


class Graph:

    def __init__(self, config: SectionProxy):
        self.settings = config
        client_id = self.settings['clientId']
        client_secret = self.settings['clientSecret']
        tenant_id = self.settings['tenantId']

        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        self.client = GraphServiceClient(
            self.credential,
            scopes=['https://graph.microsoft.com/.default']
        )

    async def get_app_only_token(self) -> str:
        token = self.credential.get_token('https://graph.microsoft.com/.default')
        return token.token

    async def list_users(self):
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            count=True,
            orderby=['displayName'],
            top=25,
            select=['displayName', 'id', 'mail', 'userPrincipalName']
        )
        request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
            query_parameters=query_params
        )
        request_config.headers.add('ConsistencyLevel', 'eventual')
        return await self.client.users.get(request_configuration=request_config)

    async def list_user_messages(self, user_id: str, top: int = 10):
        query_params = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
            top=top,
            select=['subject', 'from', 'receivedDateTime', 'internetMessageHeaders', 'body', 'hasAttachments'],
            expand=['attachments'],
            orderby=['receivedDateTime desc']
        )
        request_config = MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration(
            query_parameters=query_params
        )
        return await self.client.users.by_user_id(user_id).messages.get(
            request_configuration=request_config
        )
