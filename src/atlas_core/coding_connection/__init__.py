"""Trusted opt-in loader for the packaged owner-mediated coding connection.

Importing this package alone starts nothing. Public tool data cannot select code,
paths, policy, a control owner or a Session. Existing source identities are pinned.
"""
import hashlib
import importlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import stat
import sys
import threading
from types import MappingProxyType, ModuleType

ROOT = Path(__file__).resolve().parent
PINS = {'code/guidance_mailbox.py': '48ec1e2aba69c9e2781e68bfd8ba220342c0e6910efe596be319897c76e0eca6',
 'code/guidance_tools.py': 'bb9ffd06ed6984c0286402ae8a78a62b96240a2115d2c7fc67dc97ae11aacb75',
 'code/job_request_gateway.py': '3fed9d669eee58238fcd1b86d02f9634282e23019d0852718befe97ab8d9611f',
 'code/owner_guidance_ipc.py': '177cb02278acc9b296e5c589e32721e0129a057af9df63794ea8d6eba5ac102c',
 'code/public_request_projection.py': '5c43efe8ee44857882af266afeed70ea264c4c49fa2b12f7f1fbe513e5842686',
 'code/task_guidance_binding.py': 'fa38b1cad79837e71cc560b3c61892be0540822636b0bcdcaf8a166698b711ae',
 'code/task_host_attachment.py': '97b40bb9cf447d24cbd9597ad04367696508f0c3629e1e0819c83a8d9d824ce5',
 'code/worker_bootstrap.py': '1cec0b60cd903bab63fd1a9f55fb03b21139df91b6653efbe9736e31139f63d3',
 'code/worker_mcp_candidate.py': '5a16cc9ceb26e009d2113cd67c4ac8fab15b2b4c5b75c91f2288dec06b5c60bd',
 'session-code/boundary_controls.py': 'c3e62dac30006a14a2d29c5436bc74d31a536b20165e40464f4b72bf189ec1ad',
 'session-code/coding_manager.py': '0d42d6c5d743a094642020e173eec19534f790ad500fef04b3d4b1fd0d9cecc2',
 'session-code/coding_session.py': 'e0a6ece9e7ec156f485a92caca6d5f3e1aea36b954244bdeac352a65d38fe741',
 'session-code/fresh_task_registry.py': '92826798b367c60cc329191210cef421ae5fc838dbb216ddb592359a2949431a',
 'session-code/handoff_adapter.py': 'd78031dac6c294c1913bc10cfc1df1dc71e23bb320d02b2c382dff71f1754c83',
 'session-code/repair_registry.py': '16dec83d6f09a96394c32b0753422a14a26fd7af3fe3c6f52f5a946c2b7b4b2c',
 'session-code/session_adapter.py': '1fbf2c40b3f901c81cac4ad74cee6889d8bc28b6bf1d43417e1da08730a678f0',
 'session-code/session_checker.py': 'd36accb5b81505eaa10c65175155940ca906f42f2122e576fee07c3145548e36',
 'session-code/trusted_fresh/private/checker.py': '90b6b1fb036414f71b70e2acd17a74c6f09703cb9e51f088badd15abdcf0bfac',
 'session-code/trusted_fresh/public/identity-document-boundary/PROVENANCE.json': 'b75f43ad897beb27e8c526fdd9975d3752261c36d4b09bc32900d26748a77320',
 'session-code/trusted_fresh/public/identity-document-boundary/candidate.py': 'd91aec6d6ad84833a2ab9dce93288cc2f870c5af6fbb6aa71d36aebd1e9308ed',
 'session-code/trusted_repairs/private/checker.py': '3575f89c7dc1a92f50bcf992de6f3a217cb28253ce026063a39a0f5203b9348b',
 'session-code/trusted_repairs/public/artifact-path/candidate.py': '574c2984434bcbe051bcc42e0e387ad6067a0bbb79a6e9fa8d3538225f44a1cf',
 'session-code/trusted_repairs/public/json-overflow/candidate.py': 'c906345a3fd29c63c4c61cda9b224c2b5836e8b57c11e2c584828298b58d7a79',
 'session-code/trusted_repairs/public/stop-marker/candidate.py': '092d1833d4261af3e014fde1bab4f6c93e6a442fb704e178dc20e8742a1dbfeb',
 'session-code/workflow_interruptions.py': 'f40eaa5b0521550a9477c1ef5372bcdd63932f784458a6898eab9c44502e90a7',
 'session-code/workflow_outcomes.py': '0098cee442b8739f9f6fc504eba087b4b119cfcd1517dfbcbe558fb35720bd0f'}

PINS.update({'session-code/deadline_registry.py': 'e0e5c287f04be72e65f46f9a674db4cfc8bf91dcd76c46860165c3ed54659962', 'session-code/deadline_scope.py': '3a665e7be7c45badffd612d7b0f549c87ee5a6f1e45cc2e3a7e8d0bf9710ca24', 'session-code/trusted_deadline/private/checker.py': '2f67eb8e987a97fac3bd9d7bbd08e1080b9d4db0d5084df0d1fa7ff49a630a5a', 'session-code/trusted_deadline/public/review-deadline-budget/PROBLEM.md': '0438ebb22133cd4f1cd7046ab5b2fa09ca7373685f516e3a9d5c66fc2c5f374c', 'session-code/trusted_deadline/public/review-deadline-budget/PROVENANCE.json': '5bfd010e26c129c0ebb4827dce12ed6dc64c82520e7abe0650d0c27884c56920', 'session-code/trusted_deadline/public/review-deadline-budget/candidate.py': 'b461ab26680dcbff96a07f9dfc92676a6a6e6a654a63d9261c2849cf2c97645e', 'session-code/fresh_task_registry.py': '7e8a0ac2498db19cf55333ce74e5c51c649c4fd4718747181b2c51ae1287ac27', 'session-code/coding_session.py': '5d97beb4c9fd831a6935d34301a4466a0911b0d2a173821beb4a4cff9cd1ec69', 'session-code/session_checker.py': '159de8b67cf5c4aa538741cdcc5076c7b6387c57c9cc2d2ad2b724ffffbfae85'})
CONTROL_SHA256 = 'd7546cd64c795676b7cdef3df502abbc9712cf8f32b067391f2d106499606fe2'
_LOCK = threading.RLock()
_LOADED = {}
_CANONICAL = None
_ORDER = ('guidance_mailbox', 'public_request_projection', 'task_guidance_binding',
          'task_host_attachment', 'guidance_tools', 'owner_guidance_ipc',
          'job_request_gateway', 'worker_mcp_candidate', 'worker_bootstrap')
_EXPORTS = {'TaskGuidanceBinding': 'task_guidance_binding', 'OwnedTaskHost': 'task_host_attachment',
            'OwnerGuidanceServer': 'owner_guidance_ipc', 'RemoteGuidance': 'owner_guidance_ipc',
            'IPCRefused': 'owner_guidance_ipc', 'DeliveryUnconfirmed': 'owner_guidance_ipc',
            'WorkerSurface': 'worker_mcp_candidate'}


class PackagingRefused(ValueError):
    pass


def _need(condition, code):
    if not condition:
        raise PackagingRefused(code)


def _read(path):
    _need(not any(p.is_symlink() for p in (path, *path.parents)), 'package_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
              and before.st_nlink == 1 and not before.st_mode & 0o022
              and before.st_size <= 2097152, 'package_file_identity')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(2097153)
        after = os.fstat(fd)
        _need(len(raw) == before.st_size == after.st_size
              and before.st_mtime_ns == after.st_mtime_ns, 'package_changed')
        return raw
    finally:
        os.close(fd)


def _module(module, path):
    _need(type(module) is ModuleType and getattr(module, '__file__', None) == str(path)
          and getattr(getattr(module, '__spec__', None), 'origin', None) == str(path)
          and type(getattr(module, '__loader__', None)) is importlib.machinery.SourceFileLoader,
          'module_identity_changed')


def _verify():
    # Remote worker loading creates no Session or development authority. The
    # unchanged Session loader enforces the stronger no-site requirement when
    # the actual owner initializes/uses a Session.
    _need(sys.flags.isolated and sys.dont_write_bytecode,
          'use_isolated_no_bytecode_python')
    for relative, expected in PINS.items():
        _need(hashlib.sha256(_read(ROOT / relative)).hexdigest() == expected, 'package_changed')
    _need(hashlib.sha256(_read(ROOT.parent / 'development_control.py')).hexdigest() == CONTROL_SHA256,
          'canonical_control_changed')
    for name, module in _LOADED.items():
        _need(sys.modules.get(name) is module, 'ambient_module_refused')
        relative = 'session-code/coding_session.py' if name == 'coding_session' else 'code/' + name + '.py'
        _module(module, ROOT / relative)
    session = _LOADED.get('coding_session')
    if session is not None:
        for name in session.LOAD_ORDER:
            if name in sys.modules:
                loaded = session._LOADED.get(name)
                _need(loaded is not None and loaded == (sys.modules[name], PINS['session-code/' + name + '.py']),
                      'ambient_session_module_refused')
                _module(sys.modules[name], ROOT / 'session-code' / (name + '.py'))


def _load(name, relative):
    if name in sys.modules:
        _need(name in _LOADED and sys.modules[name] is _LOADED[name], 'ambient_module_refused')
        return _LOADED[name]
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    _LOADED[name] = module
    _module(module, path)
    return module


def _canonical_control():
    global _CANONICAL
    module = importlib.import_module('atlas_core.development_control')
    _module(module, ROOT.parent / 'development_control.py')
    _need(_CANONICAL is None or _CANONICAL is module, 'canonical_control_replaced')
    _CANONICAL = module
    return module


def load_session():
    """Return the exact bundled Session module; never initialize a run."""
    with _LOCK:
        _verify()
        session = _load('coding_session', 'session-code/coding_session.py')
        _verify()
        return session


def load_components():
    """Load immutable packaged identities only; no state/control is created."""
    with _LOCK:
        _verify()
        session = load_session()
        _canonical_control()
        for name in _ORDER:
            _load(name, 'code/' + name + '.py')
        _verify()
        result = {name: getattr(_LOADED[module], name) for name, module in _EXPORTS.items()}
        result.update(coding_session=session, Session=session.Session,
                      worker_bootstrap=_LOADED['worker_bootstrap'])
        return MappingProxyType(result)


def create_binding(root, session, control, *, epoch, approval_ref, source_path):
    components = load_components()
    _need(type(control) is _canonical_control().DevelopmentControl, 'canonical_owner_control_required')
    return components['TaskGuidanceBinding'](root, session, control, epoch=epoch,
        approval_ref=approval_ref, source_path=source_path)


def __getattr__(name):
    if name in _EXPORTS or name == 'Session':
        return load_components()[name]
    raise AttributeError(name)
