from datetime import datetime

from mcp.server.fastmcp import FastMCP

from mcp_email_server.config import (
    AccountAttributes,
    EmailSettings,
    ProviderSettings,
    get_settings,
)
from mcp_email_server.emails.dispatcher import dispatch_handler
from mcp_email_server.emails.models import EmailPageResponse

mcp = FastMCP("email")


@mcp.resource("email://{account_name}")
async def get_account(account_name: str) -> EmailSettings | ProviderSettings | None:
    settings = get_settings()
    return settings.get_account(account_name, masked=True)


@mcp.tool()
async def list_available_accounts() -> list[AccountAttributes]:
    settings = get_settings()
    return [account.masked() for account in settings.get_accounts()]


@mcp.tool()
async def add_email_account(email: EmailSettings) -> None:
    settings = get_settings()
    settings.add_email(email)
    settings.store()


@mcp.tool()
async def page_email(
    account_name: str,
    page: int = 1,
    page_size: int = 10,
    before: datetime | None = None,
    after: datetime | None = None,
    include: str | None = None,
) -> EmailPageResponse:
    handler = dispatch_handler(account_name)

    return await handler.get_emails(page=page, page_size=page_size, before=before, after=after, include=include)


@mcp.tool()
async def send_email(account_name: str, recipient: str, subject: str, body: str) -> None:
    handler = dispatch_handler(account_name)
    await handler.send_email(recipient, subject, body)
    return
