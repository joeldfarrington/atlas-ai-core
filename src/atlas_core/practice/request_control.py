"""Request-local restrictions and cancellation; this can only remove authority."""
from contextlib import contextmanager
import re
import threading

from atlas_core.development_control import DevelopmentStopped
from atlas_core.errors import ToolError


def explicit_restrictions(message):
    """Recognize common explicit prohibitions, not arbitrary semantic intent."""
    denied=set()
    for match in re.finditer(r"\b(?:do not|don't|don’t|never)\s+([^.!?;\n]+)", message, re.I):
        clause=re.split(r'\bbut\b',match.group(1),maxsplit=1,flags=re.I)[0]
        if re.search(r'\b(?:change|modify|edit|write|save|delete)\b.{0,40}\b(?:files?|anything)\b',clause,re.I):
            denied.update({'practice.write','notebook.save'})
        if re.search(r'\b(?:change|modify|edit|write|delete)\b.{0,30}\b(?:code|source)\b',clause,re.I):
            denied.add('practice.write')
        if re.search(r'\b(?:change|modify|edit|write|save|record|delete)\b.{0,30}\b(?:notes?|notebook|lessons?|ideas?)\b',clause,re.I):
            denied.add('notebook.save')
        if re.search(r'\b(?:run|rerun|execute)\b.{0,30}\b(?:tests?|checks?)\b',clause,re.I):
            denied.add('practice.check')
    if re.search(r'\bread[- ]only\b',message,re.I):
        denied.update({'practice.write','notebook.save'})
    return sorted(denied)


class RequestControl:
    def __init__(self, denied=()):
        self.denied=frozenset(denied)
        self._cancelled=threading.Event()
        self._lock=threading.RLock()

    def check(self, action=None):
        with self._lock:
            if self._cancelled.is_set():raise DevelopmentStopped('This request was interrupted; no further actions are permitted')
            if action in self.denied:raise ToolError('The owner explicitly prohibited this action in the current request')

    def cancel(self):
        # Never block the event loop on a possibly stalled filesystem operation.
        # An already-started publication may finish; the request reports its
        # interrupted outcome and keeps the action's audit evidence.
        self._cancelled.set()

    @contextmanager
    def publication(self):
        # Recheck immediately before publication; previously started writes
        # remain recorded rather than being silently represented as undone.
        with self._lock:
            self.check()
            yield
