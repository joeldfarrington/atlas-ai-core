"""Trusted-host bounded invocation of a separately qualified vocabulary helper.

Selection never comes from a model, a URL or a saved guidance message. A valid
result counts text; it grants no execution authority or provider qualification.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import time

from atlas_core.coding_prompt_renderer import render_qwen35_text, render_qwen25_text
from atlas_core.coding_counter_lifetime import NativeCounterLifetime


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _verified(path, expected, limit):
    _need(type(path) is str and Path(path).is_absolute() and '..' not in Path(path).parts
          and str(Path(path).resolve()) == path, 'counter_regular_absolute_path_required')
    _need(type(expected) is str and re.fullmatch('[a-f0-9]{64}', expected), 'counter_pin_required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'counter_resource_shape')
        digest = hashlib.sha256()
        left = before.st_size
        while left:
            raw = os.read(fd, min(left, 1024 * 1024))
            _need(bool(raw), 'counter_resource_truncated')
            digest.update(raw)
            left -= len(raw)
        after = os.fstat(fd)
        _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
              == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
              and digest.hexdigest() == expected, 'counter_resource_changed')
    finally:
        os.close(fd)


@dataclass(frozen=True)
class NativeCounterSelection:
    binary: str
    binary_sha256: str
    library: str
    library_sha256: str
    metadata: str
    metadata_sha256: str
    profile: str
    profile_sha256: str
    thinking: bool
    timeout_seconds: int = 8
    renderer: str = 'qwen35'
    library_version: str = '0.4.0-dev'

    def __post_init__(self):
        _need(type(self.library_version) is str and self.library_version in ('0.4.0-dev','0.4.1-dev'),
              'qualified_library_version_required')
        _need(type(self.thinking) is bool, 'explicit_thinking_mode_required')
        _need(type(self.renderer) is str and self.renderer in ('qwen35','qwen25')
              and (self.renderer!='qwen25' or self.thinking is False), 'qualified_renderer_required')
        _need(type(self.timeout_seconds) is int and 1 <= self.timeout_seconds <= 8, 'counter_deadline_required')
        self.verify()

    def verify(self):
        for name, limit in (('binary', 2*1024*1024), ('library', 128*1024*1024),
                            ('metadata', 32*1024*1024), ('profile', 65536)):
            _verified(getattr(self, name), getattr(self, name + '_sha256'), limit)


def encode_request(text):
    _need(type(text) is str, 'counter_text_required')
    raw = text.encode('utf-8')
    _need(0 < len(raw) <= 200000, 'counter_input_bound')
    return struct.pack('<II', 1, len(raw)) + raw


def decode_count(raw, *, expected_vocabulary=248320, expected_version='0.4.0-dev'):
    _need(type(expected_version) is str and expected_version in ('0.4.0-dev','0.4.1-dev'),
          'qualified_library_version_required')
    _need(type(expected_vocabulary) is int and expected_vocabulary in (248320,152064),
          'qualified_vocabulary_required')
    _need(type(raw) is bytes and 0 < len(raw) <= 2*1024*1024, 'counter_output_bound')
    def pairs(items):
        value = {}
        for key, item in items:
            _need(key not in value, 'counter_duplicate_field')
            value[key] = item
        return value
    data = json.loads(raw, object_pairs_hook=pairs)
    _need(type(data) is dict and set(data) == {'version','vocabulary_size','cases'}
          and data['version'] == expected_version and type(data['vocabulary_size']) is int
          and data['vocabulary_size'] == expected_vocabulary and type(data['cases']) is list
          and len(data['cases']) == 1, 'counter_result_identity')
    row = data['cases'][0]
    _need(type(row) is dict and set(row) == {'count','roundtrip','ids'}
          and type(row['count']) is int and 0 < row['count'] <= 200000
          and row['roundtrip'] is True and type(row['ids']) is list
          and len(row['ids']) == row['count']
          and all(type(value) is int and 0 <= value < expected_vocabulary for value in row['ids']),
          'counter_result_invalid')
    return row['count']


def _stop(child):
    if not child.cleanup_group():
        raise RuntimeError('counter_cleanup_unconfirmed')


class NativePromptCounter:
    def __init__(self, selection, *, cancelled):
        _need(type(selection) is NativeCounterSelection and callable(cancelled), 'trusted_counter_selection_required')
        self.selection, self.cancelled = selection, cancelled

    def __call__(self, messages):
        _need(not self.cancelled(), 'counter_stopped')
        selection = self.selection
        selection.verify()
        text = (render_qwen25_text(messages) if selection.renderer=='qwen25'
                else render_qwen35_text(messages, thinking=selection.thinking))
        payload = encode_request(text)
        _need(not self.cancelled(), 'counter_stopped')
        argv = ['/usr/bin/sandbox-exec', '-f', selection.profile, selection.binary, selection.library, selection.metadata]
        child = NativeCounterLifetime(argv, cwd=str(Path(selection.binary).parent),
            env={'PATH':'/usr/bin:/bin','LANG':'en_US.UTF-8'}, seconds=selection.timeout_seconds)
        deadline = time.monotonic() + selection.timeout_seconds
        sent = False
        try:
            while True:
                _need(not self.cancelled(), 'counter_stopped')
                _need(time.monotonic() < deadline, 'counter_timeout')
                try:
                    out, _ = child.communicate(None if sent else payload, timeout=.05)
                    break
                except subprocess.TimeoutExpired:
                    sent = True
            _need(child.returncode == 0, 'counter_process_failed')
            _need(not self.cancelled(), 'counter_stopped')
            selection.verify()
            return decode_count(out, expected_vocabulary=152064 if selection.renderer=='qwen25' else 248320,
                                expected_version=selection.library_version)
        finally:
            _stop(child)
