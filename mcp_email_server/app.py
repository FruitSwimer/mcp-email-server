from datetime import datetime
from typing import List, Tuple

from mcp.server.fastmcp import FastMCP

from mcp_email_server.config import (
    AccountAttributes,
    EmailSettings,
    ProviderSettings,
    get_settings,
)
from mcp_email_server.emails.dispatcher import dispatch_handler
from mcp_email_server.emails.models import AttachmentData, EmailPageResponse

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


@mcp.tool(description="Paginate emails, page start at 1, before and since as UTC datetime.")
async def page_email(
    account_name: str,
    page: int = 1,
    page_size: int = 10,
    before: datetime | None = None,
    since: datetime | None = None,
    subject: str | None = None,
    body: str | None = None,
    text: str | None = None,
    from_address: str | None = None,
    to_address: str | None = None,
) -> EmailPageResponse:
    handler = dispatch_handler(account_name)

    return await handler.get_emails(
        page=page,
        page_size=page_size,
        before=before,
        since=since,
        subject=subject,
        body=body,
        text=text,
        from_address=from_address,
        to_address=to_address,
    )


@mcp.tool()
async def send_email(account_name: str, recipient: str, subject: str, body: str) -> None:
    handler = dispatch_handler(account_name)
    await handler.send_email(recipient, subject, body)
    return


@mcp.tool(description="Mark emails as read or unread.")
async def mark_email_as_read(account_name: str, message_ids: list[str], read: bool = True) -> None:
    """Mark emails as read or unread.
    
    Args:
        account_name: Name of the email account
        message_ids: List of message IDs to modify
        read: True to mark as read, False to mark as unread
    """
    handler = dispatch_handler(account_name)
    await handler.mark_as_read(message_ids, read)
    return


@mcp.tool(description="Move emails to another folder.")
async def move_email(account_name: str, message_ids: list[str], destination_folder: str) -> None:
    """Move emails to another folder.
    
    Args:
        account_name: Name of the email account
        message_ids: List of message IDs to move
        destination_folder: Destination folder name
    """
    handler = dispatch_handler(account_name)
    await handler.move_email(message_ids, destination_folder)
    return


@mcp.tool(description="Delete emails (move to trash or permanently delete).")
async def delete_email(account_name: str, message_ids: list[str], permanent: bool = False) -> None:
    """Delete emails (move to trash or permanently delete).
    
    Args:
        account_name: Name of the email account
        message_ids: List of message IDs to delete
        permanent: If True, permanently delete; if False, move to trash
    """
    handler = dispatch_handler(account_name)
    await handler.delete_email(message_ids, permanent)
    return


@mcp.tool(description="Get list of available folders/mailboxes.")
async def list_folders(account_name: str) -> list[str]:
    """Get list of available folders/mailboxes.
    
    Args:
        account_name: Name of the email account
        
    Returns:
        List of folder names
    """
    handler = dispatch_handler(account_name)
    return await handler.get_folders()


@mcp.tool(description="Get list of attachments for an email.")
async def get_attachments(account_name: str, message_id: str) -> List[AttachmentData]:
    """Get list of attachments for an email.
    
    Args:
        account_name: Name of the email account
        message_id: ID of the email message
        
    Returns:
        List of attachment metadata
    """
    handler = dispatch_handler(account_name)
    return await handler.get_attachments(message_id)


@mcp.tool(description="Download a specific attachment from an email.")
async def download_attachment(account_name: str, message_id: str, attachment_id: str) -> bytes:
    """Download a specific attachment from an email.
    
    Args:
        account_name: Name of the email account
        message_id: ID of the email message
        attachment_id: ID of the attachment to download
        
    Returns:
        The attachment content as bytes
    """
    handler = dispatch_handler(account_name)
    return await handler.download_attachment(message_id, attachment_id)


@mcp.tool(description="Send email with attachments.")
async def send_email_with_attachments(
    account_name: str, 
    recipient: str, 
    subject: str, 
    body: str, 
    attachments: List[Tuple[str, bytes]]
) -> None:
    """Send email with attachments.
    
    Args:
        account_name: Name of the email account
        recipient: Email recipient
        subject: Email subject
        body: Email body
        attachments: List of tuples containing (filename, file_content)
    """
    handler = dispatch_handler(account_name)
    await handler.send_email_with_attachments(recipient, subject, body, attachments)
    return
