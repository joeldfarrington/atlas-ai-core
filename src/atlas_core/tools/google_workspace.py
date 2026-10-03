from __future__ import annotations

import base64
from datetime import datetime
from email.message import EmailMessage
from typing import Any

from atlas_core.connectors.google import (
    CALENDAR_API_BASE,
    GMAIL_API_BASE,
    GoogleWorkspaceConnector,
)
from atlas_core.errors import ToolError
from atlas_core.tools.base import Tool


def _bounded_integer(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    number = default if value is None else int(value)
    if number < minimum or number > maximum:
        raise ToolError(f"Value must be between {minimum} and {maximum}")
    return number


class GmailTool(Tool):
    """Bounded Gmail access without any send or permanent-delete action."""

    name = "gmail"

    def __init__(self, connector: GoogleWorkspaceConnector) -> None:
        self.connector = connector

    @staticmethod
    def _header_map(payload: dict[str, Any]) -> dict[str, str]:
        headers = payload.get("headers") or []
        result: dict[str, str] = {}
        for item in headers:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").lower()
            if name in {"from", "to", "cc", "bcc", "subject", "date", "message-id"}:
                result[name] = str(item.get("value") or "")
        return result

    @staticmethod
    def _decode_data(value: str) -> str:
        if not value:
            return ""
        padded = value + "=" * (-len(value) % 4)
        try:
            return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except (ValueError, UnicodeError):
            return ""

    @classmethod
    def _plain_text_parts(cls, payload: dict[str, Any]) -> list[str]:
        parts: list[str] = []
        mime_type = str(payload.get("mimeType") or "")
        body = payload.get("body") or {}
        if mime_type == "text/plain" and isinstance(body, dict) and not body.get("attachmentId"):
            text = cls._decode_data(str(body.get("data") or ""))
            if text:
                parts.append(text)
        for child in payload.get("parts") or []:
            if isinstance(child, dict):
                parts.extend(cls._plain_text_parts(child))
        return parts

    @classmethod
    def _message_view(
        cls,
        message: dict[str, Any],
        *,
        include_body: bool,
        max_body_chars: int = 20_000,
    ) -> dict[str, Any]:
        payload = message.get("payload") or {}
        headers = cls._header_map(payload if isinstance(payload, dict) else {})
        view: dict[str, Any] = {
            "id": message.get("id"),
            "thread_id": message.get("threadId"),
            "label_ids": message.get("labelIds") or [],
            "snippet": str(message.get("snippet") or "")[:500],
            "from": headers.get("from", ""),
            "to": headers.get("to", ""),
            "cc": headers.get("cc", ""),
            "subject": headers.get("subject", ""),
            "date": headers.get("date", ""),
        }
        if include_body:
            parts = cls._plain_text_parts(payload if isinstance(payload, dict) else {})
            body = "\n\n".join(parts)
            view["body"] = body[:max_body_chars]
            view["body_truncated"] = len(body) > max_body_chars
            view["attachments_fetched"] = False
        return view

    def _get_message(
        self,
        message_id: str,
        *,
        include_body: bool,
        max_body_chars: int = 20_000,
    ) -> dict[str, Any]:
        format_name = "full" if include_body else "metadata"
        params: dict[str, Any] = {"format": format_name}
        if not include_body:
            params["metadataHeaders"] = ["From", "To", "Cc", "Subject", "Date"]
        message = self.connector.api_json(
            "GET",
            f"{GMAIL_API_BASE}/users/me/messages/{message_id}",
            params=params,
        )
        return self._message_view(
            message,
            include_body=include_body,
            max_body_chars=max_body_chars,
        )

    @staticmethod
    def _draft_raw(arguments: dict[str, Any]) -> str:
        message = EmailMessage()
        for source, header in (("to", "To"), ("cc", "Cc"), ("bcc", "Bcc")):
            value = str(arguments.get(source) or "").strip()
            if value:
                message[header] = value
        message["Subject"] = str(arguments.get("subject") or "")
        message.set_content(str(arguments.get("body") or ""))
        return base64.urlsafe_b64encode(message.as_bytes()).rstrip(b"=").decode("ascii")

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action == "profile":
            return self.connector.verify_connection()

        if action == "self_test_draft":
            if arguments:
                raise ToolError("self_test_draft does not accept arguments")
            raw = self._draft_raw(
                {
                    "to": self.connector.config.expected_account,
                    "subject": "Atlas connector test — disposable unsent draft",
                    "body": (
                        "This disposable unsent draft was created by Atlas to verify "
                        "the Gmail connector. It is never sent and is deleted "
                        "immediately after verification."
                    ),
                }
            )
            created = self.connector.api_json(
                "POST",
                f"{GMAIL_API_BASE}/users/me/drafts",
                json_body={"message": {"raw": raw}},
            )
            draft_id = str(created.get("id") or "").strip()
            message_id = str((created.get("message") or {}).get("id") or "").strip()
            if not draft_id or not message_id:
                raise ToolError("Google did not return the disposable test draft identifiers")

            verification_error: Exception | None = None
            verified = False
            try:
                stored = self.connector.api_json(
                    "GET",
                    f"{GMAIL_API_BASE}/users/me/drafts/{draft_id}",
                    params={"format": "metadata"},
                )
                stored_message = stored.get("message") or {}
                verified = (
                    str(stored.get("id") or "") == draft_id
                    and str(stored_message.get("id") or "") == message_id
                    and "DRAFT" in (stored_message.get("labelIds") or [])
                )
                if not verified:
                    raise ToolError("The disposable Gmail draft could not be verified")
            except Exception as exc:  # Cleanup must still run after a failed read.
                verification_error = exc

            try:
                self.connector.api_json(
                    "DELETE",
                    f"{GMAIL_API_BASE}/users/me/drafts/{draft_id}",
                )
            except Exception as exc:
                if verification_error is not None:
                    raise ToolError(
                        "Disposable draft verification and cleanup both failed"
                    ) from exc
                raise ToolError("Disposable draft cleanup failed") from exc

            if verification_error is not None:
                raise verification_error
            return {
                "created": True,
                "verified": verified,
                "deleted": True,
                "sent": False,
                "recipient_is_configured_owner": True,
            }

        if action == "search":
            maximum = _bounded_integer(
                arguments.get("max_results"), default=20, minimum=1, maximum=25
            )
            listing = self.connector.api_json(
                "GET",
                f"{GMAIL_API_BASE}/users/me/messages",
                params={
                    "q": str(arguments.get("query") or ""),
                    "maxResults": maximum,
                    "includeSpamTrash": bool(arguments.get("include_spam_trash", False)),
                },
            )
            messages = [
                self._get_message(str(item["id"]), include_body=False)
                for item in listing.get("messages") or []
                if isinstance(item, dict) and item.get("id")
            ]
            return {
                "messages": messages,
                "count": len(messages),
                "result_size_estimate": listing.get("resultSizeEstimate", len(messages)),
                "bounded": True,
            }

        if action == "read":
            message_id = str(arguments.get("message_id") or "").strip()
            if not message_id:
                raise ToolError("message_id is required")
            maximum = _bounded_integer(
                arguments.get("max_body_chars"),
                default=20_000,
                minimum=1_000,
                maximum=50_000,
            )
            return self._get_message(
                message_id,
                include_body=True,
                max_body_chars=maximum,
            )

        if action == "read_thread":
            thread_id = str(arguments.get("thread_id") or "").strip()
            if not thread_id:
                raise ToolError("thread_id is required")
            maximum = _bounded_integer(
                arguments.get("max_body_chars_per_message"),
                default=12_000,
                minimum=1_000,
                maximum=30_000,
            )
            thread = self.connector.api_json(
                "GET",
                f"{GMAIL_API_BASE}/users/me/threads/{thread_id}",
                params={"format": "full"},
            )
            messages = [
                self._message_view(
                    item,
                    include_body=True,
                    max_body_chars=maximum,
                )
                for item in thread.get("messages") or []
                if isinstance(item, dict)
            ]
            return {"id": thread.get("id"), "messages": messages, "count": len(messages)}

        if action == "modify_labels":
            message_id = str(arguments.get("message_id") or "").strip()
            add_ids = [str(item) for item in arguments.get("add_label_ids") or []]
            remove_ids = [str(item) for item in arguments.get("remove_label_ids") or []]
            if not message_id or not (add_ids or remove_ids):
                raise ToolError("message_id and at least one label change are required")
            result = self.connector.api_json(
                "POST",
                f"{GMAIL_API_BASE}/users/me/messages/{message_id}/modify",
                json_body={"addLabelIds": add_ids, "removeLabelIds": remove_ids},
            )
            return {
                "modified": True,
                "id": result.get("id", message_id),
                "thread_id": result.get("threadId"),
                "label_ids": result.get("labelIds") or [],
            }

        if action in {"trash", "untrash"}:
            message_id = str(arguments.get("message_id") or "").strip()
            if not message_id:
                raise ToolError("message_id is required")
            result = self.connector.api_json(
                "POST",
                f"{GMAIL_API_BASE}/users/me/messages/{message_id}/{action}",
            )
            return {
                "id": result.get("id", message_id),
                "thread_id": result.get("threadId"),
                "trashed": action == "trash",
                "restored": action == "untrash",
                "recoverable": action == "trash",
            }

        if action in {"create_draft", "update_draft"}:
            try:
                raw = self._draft_raw(arguments)
            except (TypeError, ValueError) as exc:
                raise ToolError("Draft headers or content are invalid") from exc
            body = {"message": {"raw": raw}}
            if action == "create_draft":
                method = "POST"
                url = f"{GMAIL_API_BASE}/users/me/drafts"
            else:
                draft_id = str(arguments.get("draft_id") or "").strip()
                if not draft_id:
                    raise ToolError("draft_id is required")
                method = "PUT"
                url = f"{GMAIL_API_BASE}/users/me/drafts/{draft_id}"
                body["id"] = draft_id
            result = self.connector.api_json(method, url, json_body=body)
            return {
                "created": action == "create_draft",
                "updated": action == "update_draft",
                "draft_id": result.get("id"),
                "message_id": (result.get("message") or {}).get("id"),
                "sent": False,
            }

        if action == "delete_draft":
            draft_id = str(arguments.get("draft_id") or "").strip()
            if not draft_id:
                raise ToolError("draft_id is required")
            self.connector.api_json(
                "DELETE",
                f"{GMAIL_API_BASE}/users/me/drafts/{draft_id}",
            )
            return {"deleted": True, "draft_id": draft_id, "sent": False}

        raise ToolError(f"Unknown Gmail action: {action}")

    def audit_arguments(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {"action": action}
        for key in ("message_id", "thread_id", "draft_id", "max_results"):
            if arguments.get(key) is not None:
                summary[key] = arguments[key]
        if action == "modify_labels":
            summary["labels_added"] = len(arguments.get("add_label_ids") or [])
            summary["labels_removed"] = len(arguments.get("remove_label_ids") or [])
        if action in {"create_draft", "update_draft"}:
            summary["recipient_fields_present"] = sum(
                bool(arguments.get(key)) for key in ("to", "cc", "bcc")
            )
            summary["body_characters"] = len(str(arguments.get("body") or ""))
        return summary

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {"action": action}
        for key in (
            "id",
            "thread_id",
            "draft_id",
            "message_id",
            "count",
            "modified",
            "trashed",
            "restored",
            "created",
            "updated",
            "deleted",
            "sent",
            "connected",
            "account",
        ):
            if key in result:
                summary[key] = result[key]
        return summary

    def audit_error(self, action: str, error: Exception) -> str:
        del action
        return error.__class__.__name__

    def describe(self) -> dict[str, Any]:
        text_field = {"type": "string", "maxLength": 200_000}
        id_field = {"type": "string", "minLength": 1, "maxLength": 500}
        draft_properties = {
            "to": {"type": "string", "maxLength": 4_000},
            "cc": {"type": "string", "maxLength": 4_000},
            "bcc": {"type": "string", "maxLength": 4_000},
            "subject": {"type": "string", "maxLength": 998},
            "body": text_field,
        }
        return {
            "name": self.name,
            "description": "Gmail access for the configured owner account. Sending and permanent deletion are unavailable.",
            "actions": {
                "profile": {
                    "description": "Verify the connected Gmail account without reading messages.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
                "self_test_draft": {
                    "description": "Create, verify, and immediately delete one hard-coded unsent draft addressed only to the configured owner. Accepts no arguments and never sends mail.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
                "search": {
                    "description": "Search a bounded set of Gmail message metadata. Does not fetch attachments.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "maxLength": 4_000},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 25, "default": 20},
                            "include_spam_trash": {"type": "boolean", "default": False},
                        },
                        "additionalProperties": False,
                    },
                },
                "read": {
                    "description": "Read one Gmail message body. Attachments are not fetched.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "message_id": id_field,
                            "max_body_chars": {"type": "integer", "minimum": 1_000, "maximum": 50_000, "default": 20_000},
                        },
                        "required": ["message_id"],
                        "additionalProperties": False,
                    },
                },
                "read_thread": {
                    "description": "Read one Gmail thread. Attachments are not fetched.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "thread_id": id_field,
                            "max_body_chars_per_message": {"type": "integer", "minimum": 1_000, "maximum": 30_000, "default": 12_000},
                        },
                        "required": ["thread_id"],
                        "additionalProperties": False,
                    },
                },
                "modify_labels": {
                    "description": "Add or remove Gmail labels, including archive/read/star changes.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "message_id": id_field,
                            "add_label_ids": {"type": "array", "items": id_field, "maxItems": 50},
                            "remove_label_ids": {"type": "array", "items": id_field, "maxItems": 50},
                        },
                        "required": ["message_id"],
                        "additionalProperties": False,
                    },
                },
                "trash": {
                    "description": "Move one Gmail message to Trash so it remains recoverable.",
                    "parameters": {"type": "object", "properties": {"message_id": id_field}, "required": ["message_id"], "additionalProperties": False},
                },
                "untrash": {
                    "description": "Restore one Gmail message from Trash.",
                    "parameters": {"type": "object", "properties": {"message_id": id_field}, "required": ["message_id"], "additionalProperties": False},
                },
                "create_draft": {
                    "description": "Create an unsent Gmail draft. This action cannot send it.",
                    "parameters": {"type": "object", "properties": draft_properties, "additionalProperties": False},
                },
                "update_draft": {
                    "description": "Replace an unsent Gmail draft. This action cannot send it.",
                    "parameters": {"type": "object", "properties": {"draft_id": id_field, **draft_properties}, "required": ["draft_id"], "additionalProperties": False},
                },
                "delete_draft": {
                    "description": "Delete one unsent Gmail draft.",
                    "parameters": {"type": "object", "properties": {"draft_id": id_field}, "required": ["draft_id"], "additionalProperties": False},
                },
            },
        }


class GoogleCalendarTool(Tool):
    """Primary-calendar event access without invitation or attendee operations."""

    name = "calendar"

    def __init__(self, connector: GoogleWorkspaceConnector) -> None:
        self.connector = connector

    @staticmethod
    def _date_time(value: Any, label: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ToolError(f"{label} is required")
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ToolError(f"{label} must be an RFC 3339 date-time") from exc
        if parsed.tzinfo is None:
            raise ToolError(f"{label} must include a time-zone offset")
        return text

    @staticmethod
    def _event_view(event: dict[str, Any]) -> dict[str, Any]:
        attendees = [
            {
                "email": item.get("email"),
                "response_status": item.get("responseStatus"),
                "self": bool(item.get("self")),
            }
            for item in event.get("attendees") or []
            if isinstance(item, dict)
        ]
        return {
            "id": event.get("id"),
            "status": event.get("status"),
            "summary": event.get("summary"),
            "description": event.get("description"),
            "location": event.get("location"),
            "start": event.get("start"),
            "end": event.get("end"),
            "organizer": (event.get("organizer") or {}).get("email"),
            "attendees": attendees,
            "html_link": event.get("htmlLink"),
            "updated": event.get("updated"),
        }

    def _event_url(self, event_id: str | None = None) -> str:
        base = f"{CALENDAR_API_BASE}/calendars/{self.connector.config.calendar_id}/events"
        return f"{base}/{event_id}" if event_id else base

    def _get_event(self, event_id: str) -> dict[str, Any]:
        return self.connector.api_json("GET", self._event_url(event_id))

    @staticmethod
    def _reject_attendee_event(event: dict[str, Any]) -> None:
        if event.get("attendees"):
            raise ToolError(
                "Atlas will not modify or delete an event with attendees in the initial calendar gate"
            )

    def _event_body(self, arguments: dict[str, Any], *, existing: dict[str, Any] | None = None) -> dict[str, Any]:
        body = dict(existing or {})
        for key in ("summary", "description", "location"):
            if key in arguments:
                body[key] = str(arguments.get(key) or "")
        if "start" in arguments:
            body["start"] = {
                "dateTime": self._date_time(arguments.get("start"), "start"),
                "timeZone": self.connector.config.time_zone,
            }
        if "end" in arguments:
            body["end"] = {
                "dateTime": self._date_time(arguments.get("end"), "end"),
                "timeZone": self.connector.config.time_zone,
            }
        start = (body.get("start") or {}).get("dateTime")
        end = (body.get("end") or {}).get("dateTime")
        if not start or not end:
            raise ToolError("start and end are required")
        start_value = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        end_value = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        if start_value >= end_value:
            raise ToolError("Event end must be after start")
        allowed = {"summary", "description", "location", "start", "end"}
        return {key: value for key, value in body.items() if key in allowed}

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action == "list_events":
            time_min = self._date_time(arguments.get("time_min"), "time_min")
            time_max = self._date_time(arguments.get("time_max"), "time_max")
            min_value = datetime.fromisoformat(time_min.replace("Z", "+00:00"))
            max_value = datetime.fromisoformat(time_max.replace("Z", "+00:00"))
            if min_value >= max_value:
                raise ToolError("time_max must be after time_min")
            if (max_value - min_value).days > 31:
                raise ToolError("Calendar reads are limited to a 31-day window")
            maximum = _bounded_integer(
                arguments.get("max_results"), default=25, minimum=1, maximum=50
            )
            result = self.connector.api_json(
                "GET",
                self._event_url(),
                params={
                    "timeMin": time_min,
                    "timeMax": time_max,
                    "maxResults": maximum,
                    "singleEvents": True,
                    "orderBy": "startTime",
                    "showDeleted": False,
                    "timeZone": self.connector.config.time_zone,
                },
            )
            events = [
                self._event_view(item)
                for item in result.get("items") or []
                if isinstance(item, dict)
            ]
            return {
                "calendar": "primary",
                "time_zone": self.connector.config.time_zone,
                "events": events,
                "count": len(events),
                "bounded": True,
            }

        if action == "get_event":
            event_id = str(arguments.get("event_id") or "").strip()
            if not event_id:
                raise ToolError("event_id is required")
            return self._event_view(self._get_event(event_id))

        if action == "create_event":
            body = self._event_body(arguments)
            result = self.connector.api_json(
                "POST",
                self._event_url(),
                params={"sendUpdates": "none"},
                json_body=body,
            )
            return {"created": True, "calendar": "primary", "event": self._event_view(result)}

        if action == "update_event":
            event_id = str(arguments.get("event_id") or "").strip()
            if not event_id:
                raise ToolError("event_id is required")
            current = self._get_event(event_id)
            self._reject_attendee_event(current)
            body = self._event_body(arguments, existing=current)
            result = self.connector.api_json(
                "PATCH",
                self._event_url(event_id),
                params={"sendUpdates": "none"},
                json_body=body,
            )
            return {"updated": True, "calendar": "primary", "event": self._event_view(result)}

        if action == "delete_event":
            event_id = str(arguments.get("event_id") or "").strip()
            if not event_id:
                raise ToolError("event_id is required")
            current = self._get_event(event_id)
            self._reject_attendee_event(current)
            self.connector.api_json(
                "DELETE",
                self._event_url(event_id),
                params={"sendUpdates": "none"},
            )
            return {"deleted": True, "calendar": "primary", "event_id": event_id}

        raise ToolError(f"Unknown Calendar action: {action}")

    def audit_arguments(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {"action": action, "calendar": "primary"}
        if arguments.get("event_id") is not None:
            summary["event_id"] = arguments["event_id"]
        if arguments.get("max_results") is not None:
            summary["max_results"] = arguments["max_results"]
        if action in {"create_event", "update_event"}:
            summary["fields"] = sorted(
                key
                for key in ("summary", "description", "location", "start", "end")
                if key in arguments
            )
        return summary

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        event = result.get("event") if isinstance(result.get("event"), dict) else result
        return {
            "action": action,
            "calendar": "primary",
            "event_id": result.get("event_id") or event.get("id"),
            "count": result.get("count"),
            "created": result.get("created"),
            "updated": result.get("updated"),
            "deleted": result.get("deleted"),
        }

    def audit_error(self, action: str, error: Exception) -> str:
        del action
        return error.__class__.__name__

    def describe(self) -> dict[str, Any]:
        id_field = {"type": "string", "minLength": 1, "maxLength": 1_024}
        date_field = {"type": "string", "format": "date-time", "maxLength": 64}
        event_fields = {
            "summary": {"type": "string", "maxLength": 2_000},
            "description": {"type": "string", "maxLength": 20_000},
            "location": {"type": "string", "maxLength": 2_000},
            "start": date_field,
            "end": date_field,
        }
        return {
            "name": self.name,
            "description": "Google primary-calendar access. Invitation responses and attendee-event mutations are unavailable.",
            "actions": {
                "list_events": {
                    "description": "List events from an explicit, bounded window on the primary calendar.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "time_min": date_field,
                            "time_max": date_field,
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 25},
                        },
                        "required": ["time_min", "time_max"],
                        "additionalProperties": False,
                    },
                },
                "get_event": {
                    "description": "Read one event from the primary calendar.",
                    "parameters": {"type": "object", "properties": {"event_id": id_field}, "required": ["event_id"], "additionalProperties": False},
                },
                "create_event": {
                    "description": "Create a no-attendee event on the primary calendar. Requires exact approval.",
                    "parameters": {"type": "object", "properties": event_fields, "required": ["summary", "start", "end"], "additionalProperties": False},
                },
                "update_event": {
                    "description": "Update a no-attendee event on the primary calendar. Requires exact approval and refuses attendee events.",
                    "parameters": {"type": "object", "properties": {"event_id": id_field, **event_fields}, "required": ["event_id"], "additionalProperties": False},
                },
                "delete_event": {
                    "description": "Delete a no-attendee event from the primary calendar. Requires exact approval and refuses attendee events.",
                    "parameters": {"type": "object", "properties": {"event_id": id_field}, "required": ["event_id"], "additionalProperties": False},
                },
            },
        }
