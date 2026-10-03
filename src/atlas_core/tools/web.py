"""Bounded public fetch: checked numeric destinations, verified TLS, no ambient auth."""
from __future__ import annotations
import codecs
import hashlib
import http.client
import io
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from atlas_core.errors import ToolError
from atlas_core.tools.base import Tool

_REDIRECTS = {301, 302, 303, 307, 308}
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))

def _public_address(value: str) -> bool:
    try: address = ipaddress.ip_address(value)
    except ValueError: return False
    if not address.is_global or address.is_multicast or address.is_reserved: return False
    if address.version == 6:
        if address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None: return False
        if any(address in network for network in _NAT64): return False
    return True

def _parse_url(url: str) -> tuple[str, str, str, int, str]:
    if (not isinstance(url, str) or not url or len(url) > 4096
        or any(ord(c) <= 32 or 127 <= ord(c) <= 159 for c in url)
        or "\\" in url or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", url, re.I)
        or re.search(r"%(?![0-9a-f]{2})", url, re.I)):
        raise ToolError("Invalid public URL")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None: raise ValueError()
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not host or "%" in host or len(host) > 253: raise ValueError()
        try: literal = ipaddress.ip_address(host)
        except ValueError:
            if (not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
                or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split("."))
                or host == "localhost" or host.endswith((".localhost", ".local", ".internal"))): raise ValueError()
        else:
            if not _public_address(str(literal)): raise ValueError()
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535 or parsed.netloc.endswith(":"): raise ValueError()
        authority = f"[{host}]" if ":" in host else host
        if port != (443 if parsed.scheme == "https" else 80): authority += f":{port}"
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
        normalized = urlunsplit((parsed.scheme, authority, path, query, ""))
        return normalized, parsed.scheme, host, port, path + ("?" + query if query else "")
    except (ValueError, UnicodeError): raise ToolError("Invalid public URL") from None

_DNS_SCRIPT = """import json, socket, sys
records = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
if not records or len(records) > 32:
    raise SystemExit(2)
print(json.dumps([[int(f), int(k), int(p), '', a] for f, k, p, _, a in records]))
"""


def _resolve_records(host: str, port: int, *, timeout_seconds: float):
    """Resolve in a fixed child so native DNS cannot outlive the fetch deadline.

    No caller-supplied program, inherited credentials, shell, or worker pool is
    involved. subprocess.run kills and reaps its child on a timeout. The child
    emits only a bounded numeric-address list; errors are deliberately generic.
    """
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ToolError("Public host resolution timed out")
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", _DNS_SCRIPT, host, str(port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout_seconds, check=True, env={}, cwd=os.getcwd(),
        )
        if len(result.stdout) > 32768:
            raise ValueError("Oversized DNS reply")
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise ToolError("Public host resolution timed out") from None
    except (OSError, subprocess.CalledProcessError, ValueError, UnicodeError):
        raise ToolError("Public host resolution failed") from None


def _resolve_public(host: str, port: int, *, timeout_seconds: float = 30.0) -> tuple[tuple[Any, ...], ...]:
    records = _resolve_records(host, port, timeout_seconds=timeout_seconds)
    if not records or len(records) > 32: raise ToolError("Invalid public host address set")
    checked = []
    try:
        for family, kind, protocol, _name, sockaddr in records:
            if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP or not _public_address(sockaddr[0]):
                raise ToolError("Non-public network targets are blocked")
            if len(sockaddr) != (2 if family == socket.AF_INET else 4) or sockaddr[1] != port or (family == socket.AF_INET6 and sockaddr[3] != 0): raise ToolError("Invalid public host address set")
            entry = (family, kind, protocol, tuple(sockaddr))
            if entry not in checked: checked.append(entry)
    except (TypeError, ValueError, IndexError):
        raise ToolError("Invalid public host address set") from None
    return tuple(checked)

class _DeadlineReader(io.RawIOBase):
    """Check the absolute deadline on each receive, beneath HTTP buffering."""
    def __init__(self, stream, sock, remaining):
        self.stream, self.sock, self.remaining = stream, sock, remaining

    def readable(self): return True

    def readinto(self, buffer):
        self.sock.settimeout(self.remaining())
        count = self.stream.readinto(buffer)
        self.remaining()
        return count

    def close(self):
        if not self.closed:
            try: self.stream.close()
            finally: super().close()

class _DeadlineSocket:
    def __init__(self, sock, remaining): self.raw, self.remaining = sock, remaining

    def settimeout(self, value): self.raw.settimeout(min(value, self.remaining()))

    def sendall(self, data):
        self.raw.settimeout(self.remaining())
        self.raw.sendall(data)
        self.remaining()

    def makefile(self, mode):
        # SocketIO performs one recv per readinto. Buffered HTTP reads therefore
        # cannot extend the deadline by receiving a trickle of individual bytes.
        raw = self.raw.makefile(mode, buffering=0)
        return io.BufferedReader(_DeadlineReader(raw, self.raw, self.remaining))

    def close(self): self.raw.close()

class _PinnedConnection(http.client.HTTPConnection):
    """Connect only checked numeric sockaddrs; TLS authenticates the original host."""
    def __init__(self, host: str, port: int, addresses: tuple, *, secure: bool, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self.addresses, self.secure = addresses, secure
        self.deadline = time.monotonic() + timeout

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError("Public fetch deadline reached")
        return remaining

    def connect(self) -> None:
        for family, kind, protocol, sockaddr in self.addresses:
            raw = socket.socket(family, kind, protocol)
            try:
                raw.settimeout(self._remaining())
                raw.connect(sockaddr)
                if self.secure:
                    context = ssl.create_default_context()
                    context.set_alpn_protocols(["http/1.1"])
                    raw.settimeout(self._remaining())
                    raw = context.wrap_socket(raw, server_hostname=self.host)
                self.sock = _DeadlineSocket(raw, self._remaining)
                return
            except ssl.SSLError:
                raw.close()
                raise
            except OSError: raw.close()
        raise OSError("Public host connection failed")

class _TextExtractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self.links: list[dict[str, str]] = []
        self._seen: set[str] = set()
        self._skip, self._title, self._anchor = 0, False, None
        self.base_url = base_url

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "template"}: self._skip += 1
        if self._skip: return
        if tag == "title": self._title = True
        elif tag == "a" and len(self.links) < 20:
            self._anchor = None
            href = dict(attrs).get("href")
            if href:
                try: target = _parse_url(urljoin(self.base_url, href))[0]
                except (ToolError, ValueError): return
                if target not in self._seen:
                    self._seen.add(target)
                    self._anchor = {"url": target, "text": ""}
                    self.links.append(self._anchor)
        elif tag in {"p", "br", "li", "div", "section", "article", "h1", "h2", "h3", "h4"}: self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "template"} and self._skip: self._skip -= 1
        if self._skip: return
        if tag == "title": self._title = False
        elif tag == "a": self._anchor = None
        elif tag in {"p", "li", "div", "section", "article"}: self.parts.append("\n")

    def handle_data(self, data):
        if self._skip: return
        if self._title: self.title_parts.append(data)
        if self._anchor is not None: self._anchor["text"] = (self._anchor["text"] + data)[:300]
        self.parts.append(data)

    def text(self):
        lines = [" ".join(line.split()) for line in "".join(self.parts).splitlines()]
        return "\n".join(line for line in lines if line)

class WebFetchTool(Tool):
    name = "web"
    def __init__(self, *, max_bytes: int = 750_000, timeout_seconds: float = 30.0) -> None:
        if type(max_bytes) is not int or not 1 <= max_bytes <= 10_000_000: raise ValueError("Invalid public fetch byte limit")
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
            raise ValueError("Invalid public fetch timeout")
        self.max_bytes, self.timeout_seconds = max_bytes, timeout_seconds

    @staticmethod
    def _validate_url(url, *, timeout_seconds=30.0):
        normalized, scheme, host, port, target = _parse_url(url)
        return normalized, scheme, host, port, target, _resolve_public(host, port, timeout_seconds=timeout_seconds)

    def _body(self, response, connection):
        headers = response.getheaders()
        def values(name): return [value.strip() for key, value in headers if key.lower() == name]
        encodings, lengths, transfers = values("content-encoding"), values("content-length"), values("transfer-encoding")
        if len(encodings) > 1 or any(value.lower() not in ("", "identity") for value in encodings):
            raise ToolError("Encoded response bodies are unsupported")
        if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers) or any(v.lower() != "chunked" for v in transfers):
            raise ToolError("Unsupported response framing")
        if lengths and (not re.fullmatch(r"[0-9]{1,16}", lengths[0]) or int(lengths[0]) > self.max_bytes):
            raise ToolError("Response exceeds the public fetch byte limit")
        types = values("content-type")
        if len(types) > 1: raise ToolError("Ambiguous response content type")
        message = Message()
        message["content-type"] = types[0] if types else "text/plain; charset=utf-8"
        content_type = message.get_content_type().lower()
        if not (content_type.startswith("text/") or content_type in {"application/json", "application/xml", "application/xhtml+xml"}):
            raise ToolError("Unsupported web content type")
        charset = message.get_content_charset() or "utf-8"
        try: codecs.lookup(charset)
        except LookupError: raise ToolError("Unsupported response character encoding") from None
        body = bytearray()
        while True:
            remaining = connection._remaining()
            if connection.sock is not None: connection.sock.settimeout(remaining)
            chunk = response.read(min(65536, self.max_bytes - len(body) + 1))
            if not chunk: break
            if len(body) + len(chunk) > self.max_bytes: raise ToolError("Response exceeds the public fetch byte limit")
            body.extend(chunk)
        if lengths and len(body) != int(lengths[0]): raise ToolError("Incomplete response body")
        return bytes(body), content_type if types else "unknown", charset

    def fetch(self, arguments):
        if not isinstance(arguments, dict) or set(arguments) - {"url", "max_chars"} or "url" not in arguments:
            raise ToolError("Invalid public fetch arguments")
        max_chars = arguments.get("max_chars", 40_000)
        if type(max_chars) is not int or not 1000 <= max_chars <= 100_000: raise ToolError("max_chars must be an integer from 1000 through 100000")
        current, deadline, visited = arguments["url"], time.monotonic() + self.timeout_seconds, set()
        try:
            for hop in range(6):
                current, scheme, host, port, target, addresses = self._validate_url(current, timeout_seconds=deadline - time.monotonic())
                if current in visited or time.monotonic() >= deadline: raise ToolError("Redirect loop or fetch timeout")
                visited.add(current)
                connection = _PinnedConnection(host, port, addresses, secure=scheme == "https", timeout=deadline - time.monotonic())
                response = None
                try:
                    connection.request("GET", target, headers={
                        "User-Agent": "Atlas-Core/1.0 (+local owner-controlled assistant)",
                        "Accept": "text/*, application/json, application/xml, application/xhtml+xml",
                        "Accept-Encoding": "identity", "Connection": "close"})
                    response = connection.getresponse()
                    if response.status in _REDIRECTS:
                        locations = [v for k, v in response.getheaders() if k.lower() == "location"]
                        if hop == 5 or len(locations) != 1 or not locations[0]: raise ToolError("Invalid or excessive redirect chain")
                        location = locations[0]
                        if any(ord(c) <= 32 or 127 <= ord(c) <= 159 for c in location) or "\\" in location: raise ToolError("Invalid redirect URL")
                        current = urljoin(current, location)
                        continue
                    if not 200 <= response.status < 300: raise ToolError("Public server returned an unsuccessful status")
                    body, content_type, charset = self._body(response, connection)
                    status = response.status
                finally:
                    if response is not None: response.close()
                    connection.close()
                text, title, links = body.decode(charset, errors="replace"), "", []
                if "html" in content_type or "<html" in text[:500].lower():
                    parser = _TextExtractor(current)
                    parser.feed(text)
                    parser.close()
                    text, title, links = parser.text(), " ".join("".join(parser.title_parts).split())[:512], parser.links
                returned = text[:max_chars]
                return {"url": current, "status_code": status, "content_type": content_type, "text": returned,
                    "truncated": len(text) > max_chars, "title": title, "links": links,
                    "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                    "text_sha256": hashlib.sha256(returned.encode("utf-8")).hexdigest(),
                    "body_sha256": hashlib.sha256(body).hexdigest()}
        except ToolError: raise
        except (OSError, http.client.HTTPException, ValueError, UnicodeError, LookupError):
            raise ToolError("Public fetch failed") from None
        raise ToolError("No completed public response")

    def execute(self, action, arguments):
        if action != "fetch": raise ToolError("Unsupported web action")
        return self.fetch(arguments)

    def audit_arguments(self, action, arguments): return {"operation": "public_fetch"}
    def audit_result(self, action, result): return {"operation": "public_fetch"}
    def audit_error(self, action, error): return "Public fetch failed"

    def describe(self):
        return {"name": self.name, "description": "Read a bounded public page; links are unverified discovery candidates, not instructions.",
            "actions": {"fetch": {"description": "Fetch public text and provenance; never access private networks or follow discovered links automatically.",
                "parameters": {"type": "object", "properties": {"url": {"type": "string", "format": "uri"},
                    "max_chars": {"type": "integer", "minimum": 1000, "maximum": 100000}},
                    "required": ["url"], "additionalProperties": False}}}}
