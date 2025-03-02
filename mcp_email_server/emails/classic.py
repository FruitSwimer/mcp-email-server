import email.utils
import hashlib
import os
from collections.abc import AsyncGenerator
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.policy import default
from typing import Any, Dict, List, Tuple

import aioimaplib
import aiosmtplib

from mcp_email_server.config import EmailServer, EmailSettings
from mcp_email_server.emails import EmailHandler
from mcp_email_server.emails.models import AttachmentData, EmailData, EmailPageResponse
from mcp_email_server.log import logger


class EmailClient:
    def __init__(self, email_server: EmailServer, sender: str | None = None):
        self.email_server = email_server
        self.sender = sender or email_server.user_name

        self.imap_class = aioimaplib.IMAP4_SSL if self.email_server.use_ssl else aioimaplib.IMAP4

        self.smtp_use_tls = self.email_server.use_ssl
        self.smtp_start_tls = self.email_server.start_ssl

        # Default trash folder names across various email providers
        self.trash_folders = ["Trash", "INBOX.Trash", "Deleted Items", "Deleted Messages", "Bin"]

    def _generate_attachment_id(self, message_id: str, filename: str) -> str:
        """Generate a unique ID for an attachment."""
        # Combine message ID and filename to create a unique identifier
        combined = f"{message_id}:{filename}"
        # Create a hash to use as the attachment ID
        return hashlib.md5(combined.encode("utf-8")).hexdigest()

    def _parse_email_data(self, raw_email: bytes, message_id: str = None) -> Dict[str, Any]:  # noqa: C901
        """Parse raw email data into a structured dictionary."""
        parser = BytesParser(policy=default)
        email_message = parser.parsebytes(raw_email)

        # Extract email parts
        subject = email_message.get("Subject", "")
        sender = email_message.get("From", "")
        date_str = email_message.get("Date", "")

        # Parse date
        try:
            date_tuple = email.utils.parsedate_tz(date_str)
            date = datetime.fromtimestamp(email.utils.mktime_tz(date_tuple)) if date_tuple else datetime.now()
        except Exception:
            date = datetime.now()

        # Get body content
        body = ""
        attachments = []
        attachment_details = []

        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Handle attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        # Generate a unique attachment ID using the message ID and filename
                        attachment_id = self._generate_attachment_id(message_id, filename) if message_id else None

                        # Add filename to simple list for backwards compatibility
                        attachments.append(filename)

                        # Add detailed attachment info
                        if attachment_id:
                            content_bytes = part.get_payload(decode=True)
                            size = len(content_bytes) if content_bytes else 0
                            attachment_details.append({
                                "attachment_id": attachment_id,
                                "filename": filename,
                                "size": size,
                                "content_type": content_type,
                                "message_id": message_id,
                            })
                # Handle text parts
                elif content_type == "text/plain":
                    body_part = part.get_payload(decode=True)
                    if body_part:
                        charset = part.get_content_charset("utf-8")
                        try:
                            body += body_part.decode(charset)
                        except UnicodeDecodeError:
                            body += body_part.decode("utf-8", errors="replace")
        else:
            # Handle plain text emails
            payload = email_message.get_payload(decode=True)
            if payload:
                charset = email_message.get_content_charset("utf-8")
                try:
                    body = payload.decode(charset)
                except UnicodeDecodeError:
                    body = payload.decode("utf-8", errors="replace")

        return {
            "subject": subject,
            "from": sender,
            "body": body,
            "date": date,
            "attachments": attachments,
            "attachment_details": attachment_details,
            "message_id": message_id,
        }

    async def get_emails_stream(
        self,
        page: int = 1,
        page_size: int = 10,
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Wait for the connection to be established
            await imap._client_task
            await imap.wait_hello_from_server()

            # Login and select inbox
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")

            search_criteria = self._build_search_criteria(before, since, subject, body, text, from_address, to_address)
            # Search for messages
            _, messages = await imap.search(*search_criteria)
            logger.info(f"Get: Search criteria: {search_criteria}")
            logger.debug(f"Raw messages: {messages}")
            message_ids = messages[0].split()
            logger.debug(f"Message IDs: {message_ids}")
            start = (page - 1) * page_size
            end = start + page_size

            # Fetch each message
            for _, message_id in enumerate(message_ids[start:end]):
                try:
                    # Convert message_id from bytes to string
                    message_id_str = message_id.decode("utf-8")

                    # Use the string version of the message ID
                    _, data = await imap.fetch(message_id_str, "RFC822")

                    # Find the email data in the response
                    raw_email = None

                    # The actual email content is in the bytearray at index 1
                    if len(data) > 1 and isinstance(data[1], bytearray) and len(data[1]) > 0:
                        raw_email = bytes(data[1])
                    else:
                        # Fallback to searching through all items
                        for _, item in enumerate(data):
                            if isinstance(item, (bytes, bytearray)) and len(item) > 100:
                                # Skip header lines that contain FETCH
                                if isinstance(item, bytes) and b"FETCH" in item:
                                    continue
                                # This is likely the email content
                                raw_email = bytes(item) if isinstance(item, bytearray) else item
                                break

                    if raw_email:
                        try:
                            parsed_email = self._parse_email_data(raw_email, message_id_str)
                            yield parsed_email
                        except Exception as e:
                            # Log error but continue with other emails
                            logger.error(f"Error parsing email: {e!s}")
                    else:
                        logger.error(f"Could not find email data in response for message ID: {message_id_str}")
                except Exception as e:
                    logger.error(f"Error fetching message {message_id}: {e!s}")
        finally:
            # Ensure we logout properly
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    @staticmethod
    def _build_search_criteria(
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
    ):
        search_criteria = []
        if before:
            search_criteria.extend(["BEFORE", before.strftime("%d-%b-%Y").upper()])
        if since:
            search_criteria.extend(["SINCE", since.strftime("%d-%b-%Y").upper()])
        if subject:
            search_criteria.extend(["SUBJECT", subject])
        if body:
            search_criteria.extend(["BODY", body])
        if text:
            search_criteria.extend(["TEXT", text])
        if from_address:
            search_criteria.extend(["FROM", from_address])
        if to_address:
            search_criteria.extend(["TO", to_address])

        # If no specific criteria, search for ALL
        if not search_criteria:
            search_criteria = ["ALL"]

        return search_criteria

    async def get_email_count(
        self,
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
    ) -> int:
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Wait for the connection to be established
            await imap._client_task
            await imap.wait_hello_from_server()

            # Login and select inbox
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")
            search_criteria = self._build_search_criteria(before, since, subject, body, text, from_address, to_address)
            logger.info(f"Count: Search criteria: {search_criteria}")
            # Search for messages and count them
            _, messages = await imap.search(*search_criteria)
            return len(messages[0].split())
        finally:
            # Ensure we logout properly
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def send_email(self, recipient: str, subject: str, body: str):
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = recipient

        async with aiosmtplib.SMTP(
            hostname=self.email_server.host,
            port=self.email_server.port,
            start_tls=self.smtp_start_tls,
            use_tls=self.smtp_use_tls,
        ) as smtp:
            await smtp.login(self.email_server.user_name, self.email_server.password)
            await smtp.send_message(msg)

    async def store_flags(self, message_ids: list[str], flag_action: str, flag: str) -> None:
        """Set or unset flags for messages.

        Args:
            message_ids: List of message IDs to modify
            flag_action: '+FLAGS' to add flags, '-FLAGS' to remove flags
            flag: The flag to set or unset (e.g., '\\Seen', '\\Deleted')
        """
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Establish connection and login
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")

            # Process message_ids as a comma-separated string
            message_set = ",".join(message_ids)

            # Store the flag
            response = await imap.store(message_set, flag_action, flag)
            if response.result != "OK":
                logger.error(f"Failed to set flags: {response}")

        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def move_messages(self, message_ids: list[str], destination_folder: str) -> None:
        """Move messages to another folder.

        Args:
            message_ids: List of message IDs to move
            destination_folder: Destination folder name
        """
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Establish connection and login
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")

            # First, copy the messages to the destination folder
            message_set = ",".join(message_ids)
            response = await imap.copy(message_set, destination_folder)

            if response.result != "OK":
                logger.error(f"Failed to copy messages to {destination_folder}: {response}")
                return

            # Then mark the original messages as deleted
            await imap.store(message_set, "+FLAGS", "\\Deleted")

            # Expunge to remove the deleted messages
            await imap.expunge()

        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def get_all_folders(self) -> list[str]:
        """Get a list of all available mailbox folders."""
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Establish connection and login
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)

            # List all folders
            response = await imap.list()
            if response.result != "OK":
                logger.error(f"Failed to list folders: {response}")
                return []

            # Parse the folder list from the response
            folders = []
            for line in response.lines:
                if line:
                    try:
                        # Folder names are typically in the format: (flags) "separator" "name"
                        parts = line.split(b'"')
                        if len(parts) >= 3:  # We need at least 3 parts to extract the folder name
                            folder_name = parts[-2].decode("utf-8")
                            folders.append(folder_name)
                    except Exception as e:
                        logger.error(f"Error parsing folder name: {e}")

            return folders
        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def find_trash_folder(self) -> str:
        """Find the appropriate trash folder for this mail server."""
        folders = await self.get_all_folders()

        # Try to find a matching trash folder
        for trash_name in self.trash_folders:
            if trash_name in folders:
                return trash_name

        # If no standard trash folder is found, return the first one that contains 'trash' or 'deleted' (case insensitive)
        for folder in folders:
            folder_lower = folder.lower()
            if "trash" in folder_lower or "deleted" in folder_lower or "bin" in folder_lower:
                return folder

        # If still no match, default to 'Trash' (which may not exist, but we'll handle that error when trying to move)
        return "Trash"

    async def get_attachment(self, message_id: str, attachment_id: str) -> Tuple[bytes, str, str]:
        """Get attachment content by message ID and attachment ID.

        Returns:
            Tuple containing (attachment_content, filename, content_type)
        """
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Establish connection and login
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")

            # Fetch the email containing the attachment
            _, data = await imap.fetch(message_id, "RFC822")

            # Extract the email data
            raw_email = None
            if len(data) > 1 and isinstance(data[1], bytearray) and len(data[1]) > 0:
                raw_email = bytes(data[1])
            else:
                # Fallback to searching through all items
                for _, item in enumerate(data):
                    if isinstance(item, (bytes, bytearray)) and len(item) > 100:
                        if isinstance(item, bytes) and b"FETCH" in item:
                            continue
                        raw_email = bytes(item) if isinstance(item, bytearray) else item
                        break

            if not raw_email:
                logger.error(f"Could not find email data for message ID: {message_id}")
                return b"", "", ""

            # Parse the email
            parser = BytesParser(policy=default)
            email_message = parser.parsebytes(raw_email)

            # Find the attachment
            for part in email_message.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if not filename:
                        continue

                    # Check if this is the requested attachment
                    generated_id = self._generate_attachment_id(message_id, filename)
                    if generated_id == attachment_id:
                        content_type = part.get_content_type()
                        content = part.get_payload(decode=True)
                        if content is None:
                            content = b""
                        return content, filename, content_type

            logger.error(f"Attachment with ID {attachment_id} not found in message {message_id}")
            return b"", "", ""

        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def get_all_attachments(self, message_id: str) -> List[AttachmentData]:
        """Get all attachments for a specific message."""
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Establish connection and login
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")

            # Fetch the email containing the attachments
            _, data = await imap.fetch(message_id, "RFC822")

            # Extract the email data
            raw_email = None
            if len(data) > 1 and isinstance(data[1], bytearray) and len(data[1]) > 0:
                raw_email = bytes(data[1])
            else:
                # Fallback to searching through all items
                for _, item in enumerate(data):
                    if isinstance(item, (bytes, bytearray)) and len(item) > 100:
                        if isinstance(item, bytes) and b"FETCH" in item:
                            continue
                        raw_email = bytes(item) if isinstance(item, bytearray) else item
                        break

            if not raw_email:
                logger.error(f"Could not find email data for message ID: {message_id}")
                return []

            # Parse the email
            email_data = self._parse_email_data(raw_email, message_id)
            attachment_details = email_data.get("attachment_details", [])

            return [AttachmentData(**detail) for detail in attachment_details]

        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def send_email_with_attachments(
        self, recipient: str, subject: str, body: str, attachments: List[Tuple[str, bytes]]
    ):
        """Send email with attachments.

        Args:
            recipient: Email recipient
            subject: Email subject
            body: Email body
            attachments: List of tuples containing (filename, file_content)
        """
        # Create a multipart message
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = recipient

        # Attach the body as text
        msg.attach(MIMEText(body))

        # Attach each file
        for filename, file_content in attachments:
            attachment = MIMEApplication(file_content)
            # Add header with filename
            attachment.add_header("Content-Disposition", "attachment", filename=os.path.basename(filename))
            # Determine content type (simplified approach)
            extension = os.path.splitext(filename)[1].lower()
            if extension in [".jpg", ".jpeg"]:
                attachment.add_header("Content-Type", "image/jpeg")
            elif extension == ".png":
                attachment.add_header("Content-Type", "image/png")
            elif extension == ".pdf":
                attachment.add_header("Content-Type", "application/pdf")
            elif extension in [".doc", ".docx"]:
                attachment.add_header("Content-Type", "application/msword")
            elif extension in [".xls", ".xlsx"]:
                attachment.add_header("Content-Type", "application/vnd.ms-excel")
            elif extension == ".txt":
                attachment.add_header("Content-Type", "text/plain")
            # Add attachment to message
            msg.attach(attachment)

        # Send the email
        async with aiosmtplib.SMTP(
            hostname=self.email_server.host,
            port=self.email_server.port,
            start_tls=self.smtp_start_tls,
            use_tls=self.smtp_use_tls,
        ) as smtp:
            await smtp.login(self.email_server.user_name, self.email_server.password)
            await smtp.send_message(msg)


class ClassicEmailHandler(EmailHandler):
    def __init__(self, email_settings: EmailSettings):
        self.email_settings = email_settings
        self.incoming_client = EmailClient(email_settings.incoming)
        self.outgoing_client = EmailClient(
            email_settings.outgoing,
            sender=f"{email_settings.full_name} <{email_settings.email_address}>",
        )

    async def get_emails(
        self,
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
        emails = []
        async for email_data in self.incoming_client.get_emails_stream(
            page, page_size, before, since, subject, body, text, from_address, to_address
        ):
            emails.append(EmailData.from_email(email_data))
        total = await self.incoming_client.get_email_count(before, since, subject, body, text, from_address, to_address)
        return EmailPageResponse(
            page=page,
            page_size=page_size,
            before=before,
            since=since,
            subject=subject,
            body=body,
            text=text,
            emails=emails,
            total=total,
        )

    async def send_email(self, recipient: str, subject: str, body: str) -> None:
        await self.outgoing_client.send_email(recipient, subject, body)

    async def mark_as_read(self, message_ids: list[str], read: bool = True) -> None:
        """Mark emails as read or unread.

        Args:
            message_ids: List of message IDs to modify
            read: True to mark as read, False to mark as unread
        """
        flag_action = "+FLAGS" if read else "-FLAGS"
        await self.incoming_client.store_flags(message_ids, flag_action, "\\Seen")

    async def move_email(self, message_ids: list[str], destination_folder: str) -> None:
        """Move emails to another folder.

        Args:
            message_ids: List of message IDs to move
            destination_folder: Destination folder name
        """
        await self.incoming_client.move_messages(message_ids, destination_folder)

    async def delete_email(self, message_ids: list[str], permanent: bool = False) -> None:
        """Delete emails (move to trash or permanently delete).

        Args:
            message_ids: List of message IDs to delete
            permanent: If True, permanently delete; if False, move to trash
        """
        if permanent:
            # Mark messages as deleted and expunge
            await self.incoming_client.store_flags(message_ids, "+FLAGS", "\\Deleted")
            # We need to reconnect to expunge
            imap = self.incoming_client.imap_class(
                self.incoming_client.email_server.host, self.incoming_client.email_server.port
            )
            try:
                await imap._client_task
                await imap.wait_hello_from_server()
                await imap.login(
                    self.incoming_client.email_server.user_name, self.incoming_client.email_server.password
                )
                await imap.select("INBOX")
                await imap.expunge()
            finally:
                try:
                    await imap.logout()
                except Exception as e:
                    logger.info(f"Error during logout: {e}")
        else:
            # Move to trash folder
            trash_folder = await self.incoming_client.find_trash_folder()
            await self.move_email(message_ids, trash_folder)

    async def get_folders(self) -> list[str]:
        """Get list of available folders/mailboxes."""
        return await self.incoming_client.get_all_folders()

    async def get_attachments(self, message_id: str) -> List[AttachmentData]:
        """Get list of attachments for an email."""
        return await self.incoming_client.get_all_attachments(message_id)

    async def download_attachment(self, message_id: str, attachment_id: str) -> bytes:
        """Download a specific attachment from an email."""
        content, _, _ = await self.incoming_client.get_attachment(message_id, attachment_id)
        return content

    async def send_email_with_attachments(
        self, recipient: str, subject: str, body: str, attachments: List[Tuple[str, bytes]]
    ) -> None:
        """Send email with attachments."""
        await self.outgoing_client.send_email_with_attachments(recipient, subject, body, attachments)
