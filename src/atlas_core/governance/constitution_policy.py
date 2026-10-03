"""Executable development rules for an explicitly adopted constitution digest.

Trusted host inputs only. Neither model text, goal origin nor success history
can create authority. This module does not issue grants or execute operations.
"""
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import stat

from .task_contract import validate,fingerprint,_utc

VERSION='atlas-constitution-v0.1-draft2'
OPERATIONS={'local_model','check_candidate'}

def need(ok,reason):
    if not ok:raise ValueError(reason)

def read_bound(path):
    path=Path(path).absolute()
    need(not any(p.is_symlink() for p in (path,*path.parents)),'foundation_symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
             and info.st_size<=131072,'foundation_identity')
        with os.fdopen(fd,'rb',closefd=False) as f:data=f.read(131073)
        need(len(data)<=131072,'foundation_size')
        return hashlib.sha256(data).hexdigest()
    finally:os.close(fd)

class ConstitutionGate:
    def __init__(self,document,adoption):
        need(type(adoption) is dict and set(adoption)=={'version','document_sha256','context',
             'authorization_reference'},'adoption_schema')
        need(adoption['version']==VERSION and adoption['context']=='isolated_development',
             'adoption_context')
        need(type(adoption['authorization_reference']) is str and adoption['authorization_reference'].strip(),
             'owner_adoption_required')
        self.document=Path(document);self.adoption=adoption.copy()
        self.check_foundation()

    def check_foundation(self):
        need(read_bound(self.document)==self.adoption['document_sha256'],'foundation_changed_stop')

    def assess(self,packet,*,operation,authority,observations):
        self.check_foundation();item=validate(packet)
        need(item['foundation_sha256']==self.adoption['document_sha256'],'different_foundation')
        need(operation in OPERATIONS,'operation_outside_constitution_slice')
        need(type(authority) is dict and set(authority)=={'task_fingerprint','project','control_epoch',
             'operations','expires_utc','revoked','authorization_reference'},'owner_scope_required')
        need(type(authority['revoked']) is bool and not authority['revoked'],'authority_revoked')
        need(type(authority['authorization_reference']) is str and authority['authorization_reference'].strip(),
             'owner_authorization_required')
        need(authority['task_fingerprint']==fingerprint(item),'authority_task_mismatch')
        need(type(authority['operations']) is list and authority['operations']==sorted(OPERATIONS),
             'authority_operations')
        need(type(observations) is dict and set(observations)=={'now_utc','source_sha256',
             'project','control_epoch','stopped','resources_ok'},'current_observation_required')
        need(type(authority['project']) is str and authority['project']==observations['project'],
             'authority_project_mismatch')
        need(type(authority['control_epoch']) is int and authority['control_epoch']>=0
             and type(observations['control_epoch']) is int
             and authority['control_epoch']==observations['control_epoch'],'authority_epoch_mismatch')
        need(observations['stopped'] is False and observations['resources_ok'] is True,'stopped_or_unavailable')
        now=_utc(observations['now_utc'])
        need(now<_utc(item['deadline_utc']) and now<_utc(authority['expires_utc']),'authority_expired')
        need(observations['source_sha256']==item['source_sha256'],'source_changed')
        return {'allowed':True,'operation':operation,'task_fingerprint':fingerprint(item),
                'foundation_sha256':item['foundation_sha256'],'creates_authority':False}

    @staticmethod
    def outcome(*,public_passed,independent_passed,cleanup_verified):
        need(all(type(x) is bool for x in (public_passed,independent_passed,cleanup_verified)),
             'unknown_evidence')
        if not cleanup_verified:return 'unknown'
        return 'accepted' if public_passed and independent_passed else 'failed'
