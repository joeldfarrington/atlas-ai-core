"""Explicit trusted-host foundation selection, never an operation grant.

No discovery, environment/HTTP input, file writes, control admission, model calls
or amendment API. This development loader does not authenticate a hostile host
or a different process running as the same OS user.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .constitution_policy import ConstitutionGate, VERSION

# The owner-adopted document for this development version. An amendment needs
# a separately reviewed version and implementation, never just rewritten files
# or a caller's new digest paired with the old label.
SUPPORTED_DOCUMENT_SHA256 = '952acec908ba712d7b6dae598dd879c903277d10dff9763c1801ffe7b542caff'


class FoundationRefused(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise FoundationRefused(reason)


@dataclass(frozen=True)
class FoundationSelection:
    """Constructed explicitly by a trusted host, not parsed from task data."""
    version: str
    document_sha256: str
    adoption_sha256: str


def _selection(value):
    _need(type(value) is FoundationSelection, 'trusted_foundation_selection_required')
    _need(type(value.version) is str and value.version == VERSION, 'foundation_version')
    for digest in (value.document_sha256, value.adoption_sha256):
        _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'foundation_hash')
    _need(value.document_sha256 == SUPPORTED_DOCUMENT_SHA256, 'unreviewed_foundation_version')


def _fixed_root(services):
    root = Path(services.config.app.identity_dir) / 'coding-foundation'
    _need(root.is_absolute() and '..' not in root.parts, 'foundation_path')
    # Keep policy outside every registered source tree and ordinary data/tool
    # workspace. Do not rely on a model obeying a blocked-path string.
    prohibited = [services.config.app.workspace_dir, services.config.app.data_dir]
    prohibited += [project.root for project in services.development.projects.values()]
    for value in prohibited:
        other = Path(value)
        _need(other.is_absolute() and '..' not in other.parts, 'foundation_scope')
        _need(not any(p.is_symlink() for p in (other, *other.parents)), 'foundation_scope_symlink')
        _need(not root.is_relative_to(other) and not other.is_relative_to(root),
              'foundation_overlaps_work')
    return root


def _open_directory(path):
    """Traverse every component without following symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    handle = os.open('/', flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=handle)
            os.close(handle)
            handle = child
        info = os.fstat(handle)
        _need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
              'private_foundation_directory_required')
        return handle, (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
    except BaseException:
        os.close(handle)
        raise


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(directory, name, maximum):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(handle)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
              and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
              and 0 < before.st_size <= maximum, 'private_foundation_file_required')
        with os.fdopen(handle, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        _need(len(raw) == before.st_size and _metadata(before) == _metadata(os.fstat(handle))
              and _metadata(before) == _metadata(os.stat(name, dir_fd=directory, follow_symlinks=False)),
              'foundation_read_changed')
        return raw, _metadata(before)
    finally:
        os.close(handle)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'duplicate_adoption_field')
        result[key] = value
    return result


def _read_selected(root, selection):
    _selection(selection)
    directory, identity = _open_directory(root)
    try:
        document, document_identity = _read_file(directory, 'constitution.md', 131072)
        adoption, adoption_identity = _read_file(directory, 'adoption.json', 8192)
    finally:
        os.close(directory)
    _need(hashlib.sha256(document).hexdigest() == selection.document_sha256
          and hashlib.sha256(adoption).hexdigest() == selection.adoption_sha256,
          'foundation_selection_changed')
    record = json.loads(adoption.decode('utf-8'), object_pairs_hook=_unique_pairs)
    _need(type(record) is dict and record.get('version') == selection.version
          and record.get('document_sha256') == selection.document_sha256, 'foundation_record_mismatch')
    # Preserve the existing schema/context/authorization checks, using the same
    # packaged class that registered preparation requires.
    gate = ConstitutionGate(root / 'constitution.md', record)
    again, current = _open_directory(root)
    os.close(again)
    _need(current == identity, 'foundation_directory_changed')
    return gate, (identity, document_identity, adoption_identity), adoption


class OwnerFoundation:
    """One host-lifetime selection with durable-file freshness and refusal latch."""
    def __init__(self, services, selection):
        from atlas_core.services import AtlasServices
        _need(type(services) is AtlasServices, 'existing_services_required')
        _selection(selection)
        self.services = services
        self.selection = selection
        self.root = _fixed_root(services)
        self.gate, self._identity, self._adoption_bytes = _read_selected(self.root, selection)
        self._selected = selection
        self._root = self.root
        self._failed = False
        self._pid = os.getpid()

    def check_current(self):
        try:
            _need(not self._failed and os.getpid() == self._pid, 'foundation_stopped')
            _need(self.selection is self._selected and self.root == self._root
                  and _fixed_root(self.services) == self._root, 'foundation_owner_changed')
            gate, identity, adoption = _read_selected(self.root, self.selection)
            _need(identity == self._identity and adoption == self._adoption_bytes
                  and type(self.gate) is ConstitutionGate and self.gate.document == gate.document
                  and self.gate.adoption == gate.adoption, 'foundation_binding_changed')
        except Exception:
            self._failed = True
            raise FoundationRefused('foundation_stopped') from None

    def summary(self):
        self.check_current()
        return {'version': self.selection.version, 'document_sha256': self.selection.document_sha256,
                'adoption_sha256': self.selection.adoption_sha256,
                'origin': 'explicit_trusted_host_selection', 'context': 'isolated_development',
                'permission_to_execute': False, 'model_dispatched': False}


def select_for_services(services, selection):
    """Explicit owner-host entry; synchronous, once per services lifetime."""
    from atlas_core.services import AtlasServices
    _need(type(services) is AtlasServices, 'existing_services_required')
    _need(services.coding_constitution is None and services.coding_foundation is None
          and services.coding_preparation is None, 'foundation_already_selected_or_prepared')
    if services.coding_owner is not None:
        from atlas_core.coding_owner import CodingOwner
        _need(type(services.coding_owner) is CodingOwner
              and services.coding_owner.control is services.development.control
              and services.coding_owner.status()['status'] == 'disabled', 'coding_owner_active')
    try:
        binding = OwnerFoundation(services, selection)
        summary = binding.summary()
    except Exception:
        raise FoundationRefused('foundation_selection_refused') from None
    services.coding_foundation = binding
    services.coding_constitution = binding.gate
    return summary
