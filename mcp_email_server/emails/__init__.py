import abc
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Tuple

if TYPE_CHECKING:
    from mcp_email_server.emails.models import AttachmentData, EmailPageResponse


class EmailHandler(abc.ABC):
    @abc.abstractmethod
    async def get_emails(
        self,
        page: int = 1,
        page_size: int = 10,
        before: datetime | None = None,
        after: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
    ) -> "EmailPageResponse":
        """
        Get emails
        """

    @abc.abstractmethod
    async def send_email(self, recipient: str, subject: str, body: str) -> None:
        """
        Send email
        """

    @abc.abstractmethod
    async def mark_as_read(self, message_ids: List[str], read: bool = True) -> None:
        """
        Mark emails as read or unread
        """

    @abc.abstractmethod
    async def move_email(self, message_ids: List[str], destination_folder: str) -> None:
        """
        Move emails to another folder
        """

    @abc.abstractmethod
    async def delete_email(self, message_ids: List[str], permanent: bool = False) -> None:
        """
        Delete emails (move to trash or permanently delete)
        """

    @abc.abstractmethod
    async def get_folders(self) -> List[str]:
        """
        Get list of available folders/mailboxes
        """

    @abc.abstractmethod
    async def get_attachments(self, message_id: str) -> List["AttachmentData"]:
        """
        Get list of attachments for an email
        """

    @abc.abstractmethod
    async def download_attachment(self, message_id: str, attachment_id: str) -> bytes:
        """
        Download a specific attachment from an email
        """

    @abc.abstractmethod
    async def send_email_with_attachments(
        self, recipient: str, subject: str, body: str, attachments: List[Tuple[str, bytes]]
    ) -> None:
        """
        Send email with attachments

        Args:
            recipient: Email recipient
            subject: Email subject
            body: Email body
            attachments: List of tuples containing (filename, file_content)
        """
