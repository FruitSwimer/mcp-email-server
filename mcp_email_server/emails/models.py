from datetime import datetime
from typing import Any, List, Dict, Optional

from pydantic import BaseModel


class AttachmentData(BaseModel):
    attachment_id: str
    filename: str
    size: int
    content_type: str
    message_id: str


class EmailData(BaseModel):
    subject: str
    sender: str
    body: str
    date: datetime
    attachments: List[str]  # List of attachment filenames
    message_id: Optional[str] = None  # IMAP message ID

    @classmethod
    def from_email(cls, email: Dict[str, Any]):
        return cls(
            subject=email["subject"],
            sender=email["from"],
            body=email["body"],
            date=email["date"],
            attachments=email["attachments"],
            message_id=email.get("message_id"),
        )


class EmailPageResponse(BaseModel):
    page: int
    page_size: int
    before: datetime | None
    since: datetime | None
    subject: str | None
    body: str | None
    text: str | None
    emails: List[EmailData]
    total: int
