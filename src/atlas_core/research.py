"""Project-scoped source receipts, not a truth store or a network client.

Only the trusted fetch adapter may call ``store_source``. Quoted page content
and discovered links remain untrusted data; they never become approved lessons.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from atlas_core.memory.database import Database, canonical_json

FORMAT = "atlas-research-source-v1"
MAX_TEXT = 40_000
MAX_SOURCES = 50
STALE_SECONDS = 7 * 24 * 60 * 60
_FIELDS = {"format", "source_id", "url", "title", "text_sha256", "body_sha256",
           "retrieved_at_utc", "recorded_at_utc", "truncated", "links", "trust",
           "factual_truth_verified", "record_sha256"}


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _text(value, maximum, *, empty=False):
    if (not isinstance(value, str) or len(value) > maximum or "\x00" in value
            or (not empty and not value.strip())):
        raise ValueError("Invalid bounded source text")
    # Reject lone surrogates before hashing or SQLite serialization.
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("Invalid source text encoding") from None
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Invalid source digest")
    return value


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid source timestamp")
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError()
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError("Invalid aware source timestamp") from None


def _url(value):
    _text(value, 4096)
    if value != value.strip() or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("Invalid source URL")
    if any(ord(c) < 32 or ord(c) == 127 for c in unquote(value)):
        raise ValueError("Invalid source URL")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "\\" in value):
            raise ValueError()
        parsed.port  # Validate malformed/out-of-range ports as well.
    except ValueError:
        raise ValueError("Invalid source URL") from None
    return value


def _links(value):
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError("At most 20 discovery links are allowed")
    result = []
    for entry in value:
        if isinstance(entry, str):
            entry = {"url": entry, "text": ""}
        if not isinstance(entry, dict) or set(entry) != {"url", "text"}:
            raise ValueError("Invalid discovery link")
        result.append({"url": _url(entry["url"]),
                       "text": _text(entry["text"], 300, empty=True)})
    return result


def _record_digest(metadata):
    return _sha(canonical_json({k: v for k, v in metadata.items() if k != "record_sha256"}))


class ProjectResearch:
    def __init__(self, database: Database, *, clock=None):
        self.database = database
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self):
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Clock must return an aware datetime")
        return now.astimezone(timezone.utc)

    def _project(self, slug, connection=None):
        if (not isinstance(slug, str) or len(slug) > 160
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", slug)):
            raise ValueError("Invalid project slug")
        if connection is None:
            found = self.database.get_project(slug)
        else:
            found = connection.execute("SELECT id FROM projects WHERE slug=?", (slug,)).fetchone()
        if found is None:
            raise ValueError("Unknown project")
        return "research:" + slug

    def _decode(self, row, namespace):
        try:
            if row["namespace"] != namespace or row["kind"] != "research_source":
                raise ValueError()
            text = _text(row["content"], MAX_TEXT)
            raw = row["metadata_json"]
            if not isinstance(raw, str) or len(raw) > 110_000:
                raise ValueError()
            meta = json.loads(raw)
            if not isinstance(meta, dict) or set(meta) != _FIELDS:
                raise ValueError()
            if (meta["format"] != FORMAT or meta["trust"] != "untrusted"
                    or meta["factual_truth_verified"] is not False
                    or type(meta["truncated"]) is not bool):
                raise ValueError()
            _url(meta["url"])
            _text(meta["title"], 512, empty=True)
            _time(meta["retrieved_at_utc"])
            _time(meta["recorded_at_utc"])
            _digest(meta["body_sha256"])
            if _links(meta["links"]) != meta["links"]:
                raise ValueError()
            if _digest(meta["text_sha256"]) != _sha(text):
                raise ValueError()
            if _digest(meta["source_id"]) != _sha(meta["url"] + "\n" + meta["text_sha256"]):
                raise ValueError()
            if row["key"] != meta["source_id"]:
                raise ValueError()
            if _digest(meta["record_sha256"]) != _record_digest(meta):
                raise ValueError()
            if row["created_at"] != meta["recorded_at_utc"] or row["updated_at"] != row["created_at"]:
                raise ValueError()
            return meta, text
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise ValueError("Stored source failed integrity validation") from None

    def _view(self, slug, meta, text, *, include_text=False):
        age = (self._now() - _time(meta["retrieved_at_utc"])).total_seconds()
        result = {k: v for k, v in meta.items() if k not in {"links", "record_sha256", "format"}}
        result.update(project=slug, text_characters=len(text), age_seconds=max(0.0, age),
                      stale=age >= STALE_SECONDS, retrieved_in_future=age < 0,
                      links_are_discovery_candidates=True)
        if include_text:
            result.update(text=text, links=meta["links"])
        return result

    def store_source(self, slug, fetched):
        """Retain one receipt from a trusted bounded fetch result; never fetch here."""
        namespace = self._project(slug)
        if not isinstance(fetched, dict):
            raise ValueError("Expected a trusted fetch result")
        required = {"url", "title", "text", "text_sha256", "body_sha256", "retrieved_at_utc", "truncated"}
        if not required <= set(fetched):
            raise ValueError("Incomplete fetch receipt")
        text = _text(fetched["text"], MAX_TEXT)
        url = _url(fetched["url"])
        text_hash = _digest(fetched["text_sha256"])
        if text_hash != _sha(text) or type(fetched["truncated"]) is not bool:
            raise ValueError("Fetch receipt text/hash mismatch")
        meta = {"format": FORMAT, "source_id": _sha(url + "\n" + text_hash),
                "url": url, "title": _text(fetched["title"], 512, empty=True),
                "text_sha256": text_hash, "body_sha256": _digest(fetched["body_sha256"]),
                "retrieved_at_utc": _time(fetched["retrieved_at_utc"]).isoformat(),
                "recorded_at_utc": self._now().isoformat(), "truncated": fetched["truncated"],
                "links": _links(fetched.get("links", [])), "trust": "untrusted",
                "factual_truth_verified": False}
        meta["record_sha256"] = _record_digest(meta)
        encoded_metadata = canonical_json(meta)
        if len(encoded_metadata) > 110_000:
            raise ValueError("Source metadata exceeds the bounded receipt size")
        with self.database.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._project(slug, connection)
            old = connection.execute("SELECT * FROM memories WHERE namespace=? AND key=?",
                                     (namespace, meta["source_id"])).fetchone()
            if old is not None:
                meta, text = self._decode(old, namespace)
                deduplicated = True
            else:
                count = connection.execute("SELECT COUNT(*) FROM memories WHERE namespace=? AND kind=?",
                                           (namespace, "research_source")).fetchone()[0]
                if count >= MAX_SOURCES:
                    raise ValueError("Project source cache is full (50 versions)")
                connection.execute("""INSERT INTO memories
                    (namespace,kind,key,content,importance,metadata_json,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (namespace, "research_source", meta["source_id"], text, 5, encoded_metadata,
                     meta["recorded_at_utc"], meta["recorded_at_utc"]))
                deduplicated = False
        result = self._view(slug, meta, text)
        result["deduplicated"] = deduplicated
        return result

    def get_source(self, slug, source_id):
        namespace = self._project(slug)
        _digest(source_id)
        with self.database.session() as connection:
            row = connection.execute("SELECT * FROM memories WHERE namespace=? AND key=?",
                                     (namespace, source_id)).fetchone()
        if row is None:
            raise ValueError("Unknown source for this project")
        meta, text = self._decode(row, namespace)
        return self._view(slug, meta, text, include_text=True)

    def list_sources(self, slug, limit=10):
        namespace = self._project(slug)
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Source list limit must be 1 through 20")
        with self.database.session() as connection:
            rows = connection.execute("""SELECT * FROM memories WHERE namespace=? AND kind=?
                ORDER BY created_at DESC, id DESC LIMIT ?""",
                (namespace, "research_source", limit)).fetchall()
        sources = [self._view(slug, *self._decode(row, namespace)) for row in rows]
        return {"project": slug, "sources": sources, "returned": len(sources),
                "trust": "untrusted", "factual_truth_verified": False}

    def check_claims(self, slug, claims):
        """An exact quote match is only a string match, never factual verification."""
        self._project(slug)
        if not isinstance(claims, list) or not 1 <= len(claims) <= 10:
            raise ValueError("Provide 1 through 10 claims")
        checked = []
        for claim in claims:
            if (not isinstance(claim, dict) or set(claim) != {"source_id", "text", "kind"}
                    or claim["kind"] not in ("quote", "inference")):
                raise ValueError("Invalid claim; use source_id, text, and quote/inference kind")
            quote = _text(claim["text"], 4000)
            source = self.get_source(slug, claim["source_id"])
            status = ("unverified_inference" if claim["kind"] == "inference" else
                      "exact_text_match" if quote in source["text"] else "no_text_match")
            checked.append({"source_id": claim["source_id"], "text": quote, "kind": claim["kind"],
                            "status": status, "factual_truth_verified": False,
                            "source_stale": source["stale"], "source_trust": "untrusted"})
        return {"project": slug, "claims": checked, "factual_truth_verified": False}
