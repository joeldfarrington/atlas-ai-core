from __future__ import annotations

import hashlib
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from atlas_core.errors import ConfigurationError

_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*\.md$")


class IdentityStore:
    def __init__(self, identity_dir: str | Path) -> None:
        self.identity_dir = Path(identity_dir).expanduser().resolve()
        self.identity_dir.mkdir(parents=True, exist_ok=True)
        self.versions_dir = self.identity_dir / ".versions"
        self.versions_dir.mkdir(exist_ok=True)

    def _path(self, name: str) -> Path:
        if not _NAME.fullmatch(name) or name.lower() == "readme.md":
            raise ConfigurationError("Identity document name must be a safe .md filename")
        path = (self.identity_dir / name).resolve()
        if path.parent != self.identity_dir:
            raise ConfigurationError("Identity document path escapes the identity directory")
        return path

    def documents(self) -> list[dict[str, str]]:
        documents: list[dict[str, str]] = []
        for path in sorted(self.identity_dir.glob("*.md")):
            if path.name.lower() == "readme.md":
                continue
            documents.append(
                {
                    "name": path.name,
                    "content": path.read_text(encoding="utf-8").strip(),
                }
            )
        return documents

    def get(self, name: str) -> dict[str, str]:
        path = self._path(name)
        if not path.exists():
            raise KeyError(f"Identity document not found: {name}")
        return {"name": name, "content": path.read_text(encoding="utf-8")}

    def update(self, name: str, content: str) -> dict[str, str]:
        path = self._path(name)
        if path.exists():
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            backup = self.versions_dir / f"{name}.{timestamp}.bak"
            shutil.copy2(path, backup)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
        return self.get(name)

    def render(self) -> str:
        documents = self.documents()
        if not documents:
            return "# Atlas Identity\n\nNo identity documents are currently configured."
        return "\n\n---\n\n".join(document["content"] for document in documents)

    def fingerprint(self) -> str:
        payload = self.render().encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]
