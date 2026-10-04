"""Repeat public export checks using synthetic state; never publish artifacts."""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib
import importlib.abc
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from email.parser import BytesParser
import zipfile


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(name: str) -> bool:
    return bool(name) and not name.startswith('/') and '\\' not in name and all(
        part not in ('', '.', '..') for part in name.split('/')
    )


def tracked(root: Path) -> set[str]:
    output = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'])
    return set(output.decode().rstrip('\0').split('\0')) - {'RELEASE_MANIFEST.sha256'}


def manifest(root: Path, write: bool = False) -> dict[str, str]:
    path = root / 'RELEASE_MANIFEST.sha256'
    if write:
        names = sorted(tracked(root))
        for name in names:
            require(safe_path(name) and (root / name).is_file()
                    and not (root / name).is_symlink(), 'unsafe manifest path: ' + name)
        path.write_text(''.join(digest((root / name).read_bytes()) + '  ' + name + '\n'
                                for name in names), encoding='utf-8')
    entries = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        checksum, name = line.split('  ', 1)
        require(len(checksum) == 64 and all(c in '0123456789abcdef' for c in checksum)
                and safe_path(name) and name not in entries
                and name != path.name, 'invalid manifest entry')
        target = root / name
        require(target.is_file() and not target.is_symlink()
                and root in target.resolve().parents, 'unsafe manifest member: ' + name)
        require(digest(target.read_bytes()) == checksum, 'manifest mismatch: ' + name)
        entries[name] = checksum
    if (root / '.git').exists():
        require(set(entries) == tracked(root), 'manifest differs from tracked public inventory')
    print(json.dumps({'manifest_entries': len(entries), 'manifest_sha256': digest(path.read_bytes())}))
    return entries


def packages(root: Path) -> None:
    entries = manifest(root)
    expected = {name: (root / name).read_bytes() for name in entries}
    expected['RELEASE_MANIFEST.sha256'] = (root / 'RELEASE_MANIFEST.sha256').read_bytes()
    version = tomllib.loads((root / 'pyproject.toml').read_text())['project']['version']
    sdists, wheels = list((root / 'dist').glob('*.tar.gz')), list((root / 'dist').glob('*.whl'))
    require(len(sdists) == len(wheels) == 1, 'dist must contain exactly one sdist and wheel')
    prefix = 'atlas_core-' + version + '/'
    with tarfile.open(sdists[0], 'r:gz') as archive:
        members = archive.getmembers()
        require(all(m.isdir() or m.isfile() for m in members), 'sdist contains a link/special member')
        require(all((m.name.startswith(prefix) or (m.isdir() and m.name.rstrip('/') == prefix.rstrip('/')))
                    and safe_path(m.name.rstrip('/')) for m in members),
                'unsafe sdist member')
        payload = {m.name[len(prefix):]: archive.extractfile(m).read()
                   for m in members if m.isfile()}
        require(len(payload) == sum(m.isfile() for m in members), 'duplicate sdist member')
    generated = {'PKG-INFO', 'setup.cfg'} | {
        'src/atlas_core.egg-info/' + name for name in
        ['PKG-INFO', 'SOURCES.txt', 'dependency_links.txt', 'entry_points.txt', 'requires.txt', 'top_level.txt']
    }
    require(set(payload) - set(expected) <= generated, 'unexpected sdist payload')
    require(all(payload.get(name) == data for name, data in expected.items()), 'sdist source differs')
    source_code = {name.removeprefix('src/'): data for name, data in expected.items()
                   if name.startswith('src/atlas_core/')}
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and all(safe_path(n.rstrip('/')) for n in names),
                'unsafe/duplicate wheel member')
        wheel = {name: archive.read(name) for name in names if not name.endswith('/')}
    dist_info = 'atlas_core-' + version + '.dist-info/'
    require(all(name.startswith(('atlas_core/', dist_info)) for name in wheel), 'unexpected wheel payload')
    require({n: d for n, d in wheel.items() if n.startswith('atlas_core/')} == source_code,
            'wheel code/resources differ from source')
    legal = ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'DEPENDENCIES.json']
    for name in legal:
        require(wheel.get(dist_info + 'licenses/' + name) == expected[name], 'wheel legal file differs: ' + name)
    for raw in (payload['PKG-INFO'], wheel[dist_info + 'METADATA']):
        metadata = BytesParser().parsebytes(raw)
        require(metadata['Version'] == version and metadata['License-Expression'] == 'Apache-2.0'
                and metadata['Author'] == 'Joel Farrington'
                and set(metadata.get_all('License-File', [])) == set(legal), 'package metadata differs')
    import csv
    records = list(csv.reader(wheel[dist_info + 'RECORD'].decode().splitlines()))
    require({row[0] for row in records} == set(wheel) and len(records) == len(wheel), 'wheel RECORD inventory differs')
    for name, checksum, size in records:
        if name == dist_info + 'RECORD':
            require(not checksum and not size, 'invalid RECORD self entry')
        else:
            encoded = base64.urlsafe_b64encode(hashlib.sha256(wheel[name]).digest()).decode().rstrip('=')
            require(checksum == 'sha256=' + encoded and size == str(len(wheel[name])), 'wheel RECORD mismatch: ' + name)
    print(json.dumps({'package_contents': 'passed', 'version': version,
                      'packages': [{'file': p.name, 'sha256': digest(p.read_bytes())} for p in (sdists[0], wheels[0])]}))


def runtime(root: Path, import_root: Path, kind: str) -> None:
    # The audit hook is a test guard, not a sandbox for hostile code/native libraries.
    with tempfile.TemporaryDirectory(prefix='atlas-public-check-') as temporary:
        scratch = Path(temporary).resolve()
        (scratch / 'home').mkdir(mode=0o700)
        (scratch / 'tmp').mkdir(mode=0o700)
        os.environ.clear()
        os.environ.update({'HOME': str(scratch / 'home'), 'TMPDIR': str(scratch / 'tmp'),
                           'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                           'PYTHONDONTWRITEBYTECODE': '1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
                           'ATLAS_PRIVATE_ROOT': str(scratch / 'state')})
        tempfile.tempdir = str(scratch / 'tmp')
        os.chdir(root)
        sys.path.insert(0, str(import_root))
        denials = []

        def within(path: Path, parent: Path) -> bool:
            return path == parent or parent in path.parents

        def refused(category: str) -> None:
            denials.append(category)
            raise RuntimeError('public_check_refused_' + category)

        def audit(event, args):
            if event in {'socket.connect', 'socket.bind', 'socket.getaddrinfo', 'subprocess.Popen',
                         'os.system', 'os.posix_spawn', 'os.exec'}:
                refused('network_or_process')
            if event == 'ctypes.dlopen' and args and isinstance(args[0], str) and any(
                    x in args[0].lower() for x in ('security.framework', 'localauthentication', 'keychain')):
                refused('credential_framework')
            if event == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
                target = Path(os.fsdecode(args[0])).absolute()
                mode, flags = args[1], args[2] if len(args) > 2 and isinstance(args[2], int) else 0
                writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or bool(
                    flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
                if writing and target != Path('/dev/null') and not within(target, scratch):
                    refused('outside_fixture_write')
                allowed = (root, import_root, scratch, Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve())
                if target.parts[:2] == ('/', 'Users') and not any(within(target, p) for p in allowed):
                    refused('unrelated_personal_read')

        sys.addaudithook(audit)

        class SelectedOnly(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == 'atlas_core' or fullname.startswith('atlas_core.'):
                    relative = import_root / Path(*fullname.split('.'))
                    require(relative.with_suffix('.py').is_file() or (relative / '__init__.py').is_file(),
                            'module not in selected export: ' + fullname)
                return None

        sys.meta_path.insert(0, SelectedOnly())
        import keyring

        def no_vault(*args, **kwargs):
            refused('credential_store')

        for name in ('get_password', 'get_credential', 'set_password', 'delete_password'):
            if hasattr(keyring, name):
                setattr(keyring, name, no_vault)
        files = sorted((import_root / 'atlas_core').rglob('*.py'))
        errors, attempts = [], 0
        for path in files:
            compile(ast.parse(path.read_bytes()), str(path.relative_to(import_root)), 'exec')
            if path.name == '__main__.py':
                continue
            names = list(path.relative_to(import_root).with_suffix('').parts)
            if names[-1] == '__init__':
                names.pop()
            attempts += 1
            try:
                importlib.import_module('.'.join(names))
            except Exception as error:
                errors.append({'module': '.'.join(names), 'exception': type(error).__name__})
        import pytest

        class Counts:
            def __init__(self):
                self.counts = dict(passed=0, failed=0, skipped=0)

            def pytest_runtest_logreport(self, report):
                if report.when == 'call' or (report.when == 'setup' and report.skipped):
                    self.counts[report.outcome] += 1

        counts = Counts()
        targets = ['tests'] if kind == 'source' else [
            'tests/test_memory.py', 'tests/test_runtime.py', 'tests/test_migration_and_backup.py',
            'tests/test_v1_runtime.py', 'tests/test_security_and_adapters.py']
        status = pytest.main([*targets, '-q', '--basetemp', str(scratch / 'pytest'), '-p', 'no:cacheprovider'],
                             plugins=[counts])
        if errors:
            print(json.dumps({'import_errors': errors}))
        require(status == 0 and not errors, 'tests/imports failed')
        from atlas_core.services import build_services
        from atlas_core.private_owner import PrivateOwnerError, load_owner_file
        try:
            load_owner_file(root / 'examples/owner-settings.example.json', repository_root=root)
        except PrivateOwnerError as error:
            require(str(error) == 'private_path_inside_repository_refused', 'unexpected owner template error')
        else:
            raise ValueError('in-repository owner template accepted')
        services = build_services(root / 'config/atlas.yaml')
        require(services.config.app.data_dir == scratch / 'state/data'
                and services.constitution.status()['owner_adopted'] is False, 'private state boundary failed')
        from typer.testing import CliRunner
        from atlas_core.cli import app
        result = CliRunner().invoke(app, ['chat', 'Hello', '--config', str(root / 'config/atlas.yaml'),
                                        '--provider', 'mock', '--no-tools', '--no-approvals'])
        require(result.exit_code == 0 and bool(result.stdout.strip()), 'mock CLI failed')
        selected = all(not getattr(module, '__file__', None) or within(Path(module.__file__).resolve(), import_root)
                       for name, module in sys.modules.items() if name == 'atlas_core' or name.startswith('atlas_core.'))
        require(selected and not denials, 'module boundary/guard failed')
        print(json.dumps({'kind': kind, 'python': sys.version.split()[0], 'compiled': len(files),
                          'imports': attempts, 'import_errors': errors, 'tests': counts.counts,
                          'guard_denials': denials, 'mock_cli': 'passed', 'private_state_boundary': 'passed'}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('check', choices=['manifest', 'runtime', 'packages'])
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--write', action='store_true', help='refresh the manifest from reviewed tracked paths')
    parser.add_argument('--kind', choices=['source', 'wheel'], default='source')
    parser.add_argument('--import-root', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.check == 'manifest':
        manifest(root, args.write)
    elif args.check == 'packages':
        require(not args.write, '--write only applies to manifest')
        packages(root)
    else:
        require(not args.write, '--write only applies to manifest')
        require(args.kind != 'wheel' or args.import_root is not None, 'wheel requires an installed import root')
        runtime(root, (args.import_root or root / 'src').resolve(), args.kind)


if __name__ == '__main__':
    main()
