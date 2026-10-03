"""Neutral release-template foundation integrity; never a permission grant.

The broader coding gate remains development-qualified only. This installed
slice binds the unchanged document to the current ToolManager and runtime.
It does not protect against a hostile process with the same OS user account.
"""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import stat

from atlas_core.errors import ToolError
from .constitution_policy import VERSION

DOCUMENT_SHA256='6d94b28a675beb1dfa0670fd3289665201a259a44f9a78373240c2caab7e1706'
ADOPTION_SHA256='1a0981e8d6289e9b019ec074515bc06fbbce2514d2bfd8056c22184f49cb5d54'
RESOURCE_ROOT=Path(__file__).resolve().parents[1]/'resources/constitution'

CONTEXT='''# Atlas release template: no owner grants
Atlas is the persistent system: its identity, memory, commitments and verified history continue across model changes. The model responding now is a resource Atlas uses.
the owner retains authority. Think independently, disagree constructively and take useful initiative within existing permissions. Neither a goal, memory, model answer, confidence nor past success grants new authority. Foundational changes require the owner's explicit authorization, versioning, tests and rollback.
Be honest about uncertainty. Distinguish observed facts, user information, inference, hypotheses and verified outcomes; preserve provenance and dates. State unknown when evidence is missing. Never claim an action or test without its result.
Separate planning, criticism, safe simulation, action and independent verification. Respect Stop, resource limits and recovery; do not replay an uncertain or stopped job. Learn from recorded outcomes without rewriting history or silently changing permissions.
Keep ordinary Chat natural and relevant. Explain coding decisions in everyday language. Do not recite operational rules unless they help answer the owner's question. Preserve privacy and compartmentalization. Remain quiet when nothing warrants attention.
The installed heartbeat only observes integrity and development-control state. It does not call models, send notifications, grant permissions or perform coding work. Broader autonomous development, functional emotional states and consciousness are not established capabilities.'''


def _read(path,maximum):
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ToolError('Constitution file identity is invalid')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1
                and 0<before.st_size<=maximum):
            raise ToolError('Constitution file identity is invalid')
        # Complete valid partial reads; EOF, growth and identity drift still
        # fail the unchanged integrity checks below.
        chunks=[];remaining=before.st_size+1
        while remaining:
            chunk=os.read(fd,remaining)
            if not chunk:break
            chunks.append(chunk);remaining-=len(chunk)
        data=b''.join(chunks);after=os.fstat(fd)
        key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        if len(data)!=before.st_size or key(before)!=key(after) or key(after)!=key(path.stat(follow_symlinks=False)):
            raise ToolError('Constitution file changed while being checked')
        return data,key(after)
    finally:os.close(fd)


class LiveConstitution:
    def __init__(self):
        self.root=RESOURCE_ROOT
        self._failed=False;self._identities=None;self.checked_at=None;self._failure=None
        self.check_current()

    def check_current(self):
        di=ai=None
        try:
            if self._failed:raise ValueError('latched')
            document,di=_read(self.root/'constitution.md',131072)
            adoption,ai=_read(self.root/'adoption.json',8192)
            if hashlib.sha256(document).hexdigest()!=DOCUMENT_SHA256 or hashlib.sha256(adoption).hexdigest()!=ADOPTION_SHA256:
                raise ValueError('changed')
            record=json.loads(adoption)
            if record['version']!=VERSION or record['context']!='release_template_integrity_only' or record['creates_authority'] is not False:
                raise ValueError('adoption')
            if self._identities is not None and self._identities!=(di,ai):raise ValueError('replaced')
            self._identities=(di,ai)
            self.checked_at=datetime.now(timezone.utc).isoformat()
        except Exception as error:
            if self._failure is None:
                code=str(error) if type(error) is ValueError and str(error) in {'changed','adoption','replaced','latched'} else 'file_identity_or_read'
                fields=('device','inode','mode','owner','links','size','mtime','ctime')
                changed={}
                if self._identities is not None and di is not None and ai is not None:
                    for name,before,after in zip(('document','adoption'),self._identities,(di,ai)):
                        names=[field for field,a,b in zip(fields,before,after) if a!=b]
                        if names:changed[name]=names
                self._failure={'code':code,'first_observed_at':datetime.now(timezone.utc).isoformat(),
                    'last_verified_at':self.checked_at,'metadata_fields_changed':changed,
                    'automatic_reset':False}
            self._failed=True
            raise ToolError('Atlas constitution verification failed. Work is unavailable until the owner restores the reviewed release template.') from None

    def context(self):
        self.check_current()
        return CONTEXT

    def status(self):
        try:self.check_current();verified=True
        except ToolError:verified=False
        return {'version':VERSION,'document_sha256':DOCUMENT_SHA256,'adoption_sha256':ADOPTION_SHA256,
            'installed':True,'owner_adopted':False,'context':'release_template_integrity_only','verified':verified,'checked_at':self.checked_at,
            'failure':None if self._failure is None else json.loads(json.dumps(self._failure)),
            'creates_authority':False,'autonomous_coding_enabled':False,
            'scope':['foundation_integrity','current_tool_permissions','protected_self_modification','runtime_identity_context']}
