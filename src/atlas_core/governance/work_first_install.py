"""First installation of Work code, separate from all task authority.

Reuse the verified source transaction and receipt format. This path never
creates foundation adoption, policies, tasks, cognition or action ledgers.
Existing owner setup makes mutation refuse rather than resetting its history.
The trusted host invokes it while the original development control is stopped.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat

from .action_boundary import identifier, private_identity, sha
from .cognitive_state import digest, need
from .live_constitution import LiveConstitution, DOCUMENT_SHA256, ADOPTION_SHA256
from .work_release import ReleaseSelection, WorkRelease, _file, _rows, _sha, _receipt
from .owner_foundation import _unique_pairs
import json


@dataclass(frozen=True)
class FirstWorkCodeSelection:
    manifest_sha256: str
    project: str


def _owner_directory(path):
    # Existing source and identity parents may be readable. Only their owner
    # may write; the new receipt directory and file remain strictly private.
    need(not any(p.is_symlink() for p in (path,*path.parents)), 'first_install_symlink')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and not info.st_mode & 0o022, 'first_install_owner_directory')
    return info.st_dev,info.st_ino


def _context(services, project):
    from atlas_core.services import AtlasServices
    from atlas_core.development_control import DevelopmentControl
    need(type(services) is AtlasServices and identifier(project)
         and project in services.development.projects, 'first_install_project')
    need(type(services.development.control) is DevelopmentControl
         and type(services.constitution) is LiveConstitution
         and services.development.constitution is services.constitution,
         'first_install_existing_controls')
    services.constitution.check_current()
    target = Path(services.config.project_root)
    identity = Path(services.config.app.identity_dir)
    root = identity/'coding-installation'
    for path in (target, identity):
        need(path.is_absolute() and '..' not in path.parts, 'first_install_path')
        _owner_directory(path)
    prohibited = [services.config.app.workspace_dir, services.config.app.data_dir]
    prohibited += [p.root for p in services.development.projects.values()]
    for item in prohibited:
        other = Path(item)
        need(other.is_absolute() and '..' not in other.parts
             and not any(x.is_symlink() for x in (other,*other.parents)),
             'first_install_scope')
        need(not root.is_relative_to(other) and not other.is_relative_to(root),
             'first_install_scope')
    # Check the actual target's existing adopted files as well as host integrity.
    # Release manifests cannot include these resources.
    resources = target/'src/atlas_core/resources/constitution'
    need(_sha(resources/'constitution.md') == DOCUMENT_SHA256
         and _sha(resources/'adoption.json') == ADOPTION_SHA256,
         'first_install_adopted_constitution_changed')
    return target, identity, root


def _initial(services, project, stopped_epoch):
    need(type(stopped_epoch) is int and stopped_epoch >= 0, 'first_install_epoch')
    return {'kind':'code_only_first_install', 'project':project,
            'identity_root':str(services.config.app.identity_dir),
            'stopped_epoch':stopped_epoch, 'constitution_sha256':DOCUMENT_SHA256,
            'adoption_sha256':ADOPTION_SHA256, 'execution_authority':False}


def _read_bound(services, selection):
    need(type(selection) is FirstWorkCodeSelection and sha(selection.manifest_sha256),
         'first_install_typed_selection')
    target,identity,root = _context(services, selection.project)
    record = _receipt(root)
    need(record['manifest_sha256'] == selection.manifest_sha256
         and record['target_root'] == str(target), 'first_install_receipt_binding')
    initial = record['initial_state']
    need(type(initial) is dict and initial == _initial(
        services, selection.project, initial.get('stopped_epoch')), 'first_install_initial_state')
    return target,root,record


class FirstWorkInstall(WorkRelease):
    """Host-only code transaction; no initialization of Work permission state."""
    def __init__(self, services, selection, *, project):
        need(type(selection) is ReleaseSelection and isinstance(selection.package_root, Path)
             and sha(selection.manifest_sha256), 'trusted_first_install_selection')
        self.services = services
        self.project = project
        self.target,self.identity,self.root = _context(services, project)
        self.target_id = _owner_directory(self.target)
        self._identity_id = _owner_directory(self.identity)
        self._control = services.development.control
        self._constitution = services.constitution
        self._project_root = services.development.projects[project].root
        self._pid = os.getpid()
        self.selection = selection
        self.package = selection.package_root
        private_identity(self.package, True)
        need(not self.package.is_relative_to(self.target)
             and not self.target.is_relative_to(self.package), 'release_package_compartment')
        self.manifest = json.loads(_file(self.package/'manifest.json',65536),
                                   object_pairs_hook=_unique_pairs)
        need(digest(self.manifest) == selection.manifest_sha256, 'release_manifest_changed')
        self.rows = _rows(self.manifest)
        self._id = self.manifest['release_id']
        self._check_package()

    def _current(self):
        target,identity,root = _context(self.services, self.project)
        need(os.getpid() == self._pid and self.services.development.control is self._control
             and self.services.constitution is self._constitution
             and self.services.development.projects[self.project].root == self._project_root
             and (target,identity,root) == (self.target,self.identity,self.root)
             and _owner_directory(self.identity) == self._identity_id,
             'first_install_host_changed')
        for name in ('coding-foundation','coding-work'):
            need(not os.path.lexists(self.identity/name), 'first_install_owner_state_exists')
        if os.path.lexists(self.root):
            private_identity(self.root, True)

    def _target_identity(self):
        return _owner_directory(self.target)

    def _check_package(self):
        self._current()
        super()._check_package()

    @contextmanager
    def _guard(self, stopped_epoch):
        self._current()
        # Reuse the original durable writer lock. Never call Stop/Resume/admit.
        with self._control._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute(
                'SELECT epoch,stopped,cleanup,active_write FROM controls WHERE project=?',
                (self.project,)).fetchone()
            with self._control._mutex:
                active = any(type(v) is not int or v != 0
                             for v in self._control._active.values())
            # These sources are shared by all projects. A stopped chosen
            # project is insufficient when another has work or cleanup due.
            durable = db.execute('SELECT COUNT(*) FROM activities').fetchone()[0]
            unsettled = db.execute('SELECT COUNT(*) FROM controls WHERE cleanup != 0 OR active_write != 0').fetchone()[0]
            need(type(stopped_epoch) is int and row == (stopped_epoch,1,0,0)
                 and not active and durable == 0 and unsettled == 0,
                 'first_install_requires_stopped_idle')
            self._current()
            yield
            self._current()

    def _read(self):
        _,_,record = _read_bound(self.services,
            FirstWorkCodeSelection(self.selection.manifest_sha256,self.project))
        need(record['manifest'] == self.manifest, 'first_install_manifest_binding')
        return record

    def _status_locked(self):
        self._check_package()
        record = self._read()
        stage = record['events'][-1]['stage']
        self._sources(('after',) if stage == 'installed' else
                      ('before',) if stage == 'rolled_back' else ('before','after'))
        return {'release_id':self._id, 'stage':stage,
                'installation_verified':stage == 'installed', 'code_only':True,
                'work_available':False, 'execution_authority':False,
                'task_replayed':False, 'service_restarted':False}

    def install(self, *, stopped_epoch):
        with self._guard(stopped_epoch):
            self._check_package()
            self._sources(('before',))
            record = self._prepare(_initial(self.services,self.project,stopped_epoch))
            self._stage('prepared')
            self._replace('after')
            self._sources(('after',))
            self._event(record,'source_installed')
            self._stage('source_installed')
            self._check_package()
            self._sources(('after',))
            self._event(self._read(),'installed')
            return self._status_locked()

    def rollback(self, *, stopped_epoch):
        with self._guard(stopped_epoch):
            self._check_package()
            record = self._read()
            need(record['events'][-1]['stage'] != 'rolled_back', 'release_already_rolled_back')
            self._sources(('before','after'))
            if record['events'][-1]['stage'] != 'rollback_started':
                self._event(record,'rollback_started')
            self._stage('rollback_started')
            self._replace('before')
            self._sources(('before',))
            self._stage('rollback_source_restored')
            self._event(self._read(),'rolled_back')
            return self._status_locked()

    def recover(self, *, stopped_epoch):
        """Verify a committed source stage; never repeat source writes or jobs."""
        with self._guard(stopped_epoch):
            self._check_package()
            record = self._read()
            self._sources(('before','after'))
            if record['events'][-1]['stage'] == 'source_installed':
                self._sources(('after',))
                self._event(record,'installed')
            elif record['events'][-1]['stage'] == 'rollback_started':
                self._sources(('before',))
                self._event(record,'rolled_back')
            return self._status_locked()

    def status(self, *, stopped_epoch):
        with self._guard(stopped_epoch):
            return self._status_locked()


class FirstWorkCodeStartup:
    """Read-only startup receipt; a code installation is never a Work grant."""
    def __init__(self, services, selection):
        need(type(selection) is FirstWorkCodeSelection and sha(selection.manifest_sha256),
             'first_install_typed_selection')
        _context(services,selection.project)
        need(services.coding_work_startup is None, 'work_startup_already_selected')
        self.services,self.selection = services,selection
        self._services,self._selection = services,selection
        self._pid = os.getpid()
        self._failed = False

    def status(self):
        from .work_startup import unavailable
        try:
            need(not self._failed and os.getpid() == self._pid
                 and self.services is self._services and self.selection is self._selection,
                 'first_install_startup_changed')
            target,_,record = _read_bound(self.services,self.selection)
            need(record['events'][-1]['stage'] == 'installed', 'first_install_not_ready')
            for row in _rows(record['manifest']):
                need(_sha(target/row['path']) == row['after_sha256'], 'release_source_changed')
            result = unavailable('installed_code_only')
            result.update(installation_verified=True,task_authority_verified=False)
            return result
        except Exception:
            self._failed = True
            return unavailable()
