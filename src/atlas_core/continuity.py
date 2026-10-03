"""Development-only continuity over Atlas's existing records; no executor.

This service records a supervised fixed-check workflow. It does not grant
production authority, invoke models/tools, schedule work, or promote source.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone

from atlas_core.memory.database import Database, canonical_json, utc_now

FORMAT = 'atlas-project-handoff'
PLAN = 'atlas-continuity-pilot-v1'

def _label(value, maximum=160):
    if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*',value) or len(value)>maximum:
        raise ValueError('Invalid project or record label')
    return value

def _text(value, maximum=3200):
    if not isinstance(value,str) or not value.strip() or len(value)>maximum or '\x00' in value or any('\ud800' <= c <= '\udfff' for c in value):
        raise ValueError('Invalid bounded text')
    return value

def _digest(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('Invalid source/evidence digest')
    return value

def _time(value):
    try:
        stamp=datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            raise ValueError()
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise ValueError('Invalid aware timestamp') from None

def _now(value=None):return value if value is not None else datetime.now(timezone.utc)

def _evidence(value, check_name=None):
    if not isinstance(value,dict) or set(value)!={'origin','passed','artifact_sha256','check'}:return False
    try:_digest(value['artifact_sha256']);_label(value['check'])
    except ValueError:return False
    return (value['origin']=='offline_fixture' and value['passed'] is True
        and (check_name is None or value['check']==check_name))

class ProjectContinuity:
    def __init__(self,database:Database):self.database=database

    def _project(self,slug):
        row=self.database.get_project(_label(slug))
        if row is None:raise ValueError('Unknown project')
        return row

    def project(self,slug,*,name,objective,source_revision):
        _label(slug);_text(name,200);_text(objective);_digest(source_revision)
        old=self.database.get_project(slug)
        metadata=dict(old['metadata']) if old else {}
        metadata.update(source_revision=source_revision,continuity_version=1,automatic_live_change=False)
        return self.database.upsert_project(slug=slug,name=name,status='development',summary=objective,
            next_action='Run one supervised check',metadata=metadata)

    def _task(self,slug,task_id):
        self._project(slug)
        row=self.database.get_supervisor_task(task_id)
        if not row or row['project_slug']!=slug or row['plan'].get('format')!=PLAN:raise ValueError('Task does not belong to this pilot project')
        return row

    def plan(self,slug,*,check_name,expires_at):
        project=self._project(slug);expiry=_time(expires_at);now=_now()
        if not 0<(expiry-now).total_seconds()<=1800:raise ValueError('Pilot allowance must be within 30 minutes')
        _label(check_name)
        return self.database.create_supervisor_task(kind='development.run_check',project_slug=slug,
            check_name=check_name,plan={'format':PLAN,'source_revision':_digest(project['metadata']['source_revision']),
                'expires_at':expiry.isoformat(),'max_attempts':1,'stop_requested':False,
                'prior_experiences':self.experiences(slug,limit=5,check_name=check_name,current_revision_only=True),
                'evidence_origin':'offline_fixture','automatic_live_change':False})

    def experiences(self,slug,*,limit=10,check_name=None,current_revision_only=False):
        """Reuse bounded observations from recorded outcomes, without a review queue.

        These observations are derived from the existing task ledger, not model
        prose. A recorded passing check is evidence of that check alone. It is
        not independently authenticated proof, general truth, or permission.
        """
        project=self._project(slug)
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('Experience limit must be 1 through 20')
        if check_name is not None:_label(check_name)
        revision=project['metadata'].get('source_revision')
        if not isinstance(revision,str) or not re.fullmatch('[0-9a-f]{64}',revision):revision=None
        if current_revision_only and revision is None:raise ValueError('Current source revision is unavailable')
        sql="""SELECT * FROM supervisor_tasks WHERE project_slug=?
            AND json_extract(plan_json, '$.format')=?
            AND status IN ('succeeded','failed','stopped','cancelled','interrupted')"""
        args=[slug,PLAN]
        if check_name is not None:
            sql+=' AND check_name=?';args.append(check_name)
        if current_revision_only:
            sql+=" AND json_extract(plan_json, '$.source_revision')=?";args.append(revision)
        sql+=' ORDER BY updated_at DESC, id DESC LIMIT ?';args.append(limit)
        with self.database.session() as con:rows=con.execute(sql,args).fetchall()
        observations=[]
        for raw in rows:
            row=self.database._row(raw)
            plan=row['plan'];result=row['result'];evidence=result.get('evidence',{})
            source_revision=_digest(plan['source_revision']);check=_label(row['check_name'])
            clean=result.get('cleanup_required') is False
            passed=(row['status']=='succeeded' and clean and _evidence(evidence,check))
            observations.append({'task_id':row['id'],'check':check,
                'outcome':'passed_check' if passed else 'unresolved_outcome',
                'observation':'This check passed for the recorded source revision.' if passed else
                    'This run has no verified clean pass; investigate before relying on it.',
                'source_revision':source_revision,'matches_current_revision':source_revision==revision,
                'completed_at':row['completed_at'],'evidence_origin':'offline_fixture' if passed else 'unverified',
                'artifact_sha256':evidence['artifact_sha256'] if passed else None,
                'automatic_observation':True,'execution_authority':False})
        return observations

    def claim(self,slug,task_id,*,now=None):
        self._task(slug,task_id)
        def validate(row):
            plan=row['plan']
            if row['project_slug']!=slug or plan.get('format')!=PLAN or plan.get('max_attempts')!=1:raise ValueError('Invalid pilot plan')
            if plan.get('stop_requested') is not False:raise ValueError('Task stopped or revoked')
            if _now(now)>=_time(plan['expires_at']):raise ValueError('Pilot allowance expired')
            if plan['source_revision']!=self._project(slug)['metadata'].get('source_revision'):raise ValueError('Project source changed')
        return self.database.claim_supervisor_task(task_id,max_attempts=1,runner_pid=os.getpid(),plan_validator=validate)

    def stop(self,slug,task_id):
        self._task(slug,task_id)
        with self.database.session() as con:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT * FROM supervisor_tasks WHERE id=?',(task_id,)).fetchone()
            plan=json.loads(row['plan_json']);plan['stop_requested']=True
            status='cancelled' if row['status']=='planned' else row['status']
            con.execute('UPDATE supervisor_tasks SET plan_json=?,status=?,updated_at=? WHERE id=?',
                (canonical_json(plan),status,utc_now(),task_id))
        return self.view(slug,task_id)

    def finish(self,slug,task_id,*,evidence,cleanup_required,now=None):
        self._task(slug,task_id)
        if type(cleanup_required) is not bool:raise ValueError('Cleanup must be explicitly reported')
        # No raw result or unrelated fields are retained by this handoff layer.
        with self.database.session() as con:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT * FROM supervisor_tasks WHERE id=?',(task_id,)).fetchone()
            if row['status']!='running':raise ValueError('Task is not running')
            good=_evidence(evidence, row['check_name'])
            plan=json.loads(row['plan_json'])
            stopped=plan.get('stop_requested') or _now(now)>=_time(plan['expires_at'])
            status='stopped' if stopped else ('succeeded' if good and not cleanup_required else 'failed')
            result={'evidence':dict(evidence) if good else {},'cleanup_required':cleanup_required,
                'review_state':'awaiting_owner_review' if status=='succeeded' else 'reconciliation_required',
                'automatic_live_change':False}
            stamp=utc_now()
            con.execute('UPDATE supervisor_tasks SET status=?,result_json=?,runner_pid=NULL,updated_at=?,completed_at=? WHERE id=?',
                (status,canonical_json(result),stamp,stamp,task_id))
        return self.view(slug,task_id)

    def recover(self,slug,task_id,*,runner_stopped=False):
        self._task(slug,task_id)
        if runner_stopped is not True:raise ValueError('Confirm the fixture runner stopped before reconciliation')
        self.database.recover_supervisor_task(task_id)
        return self.view(slug,task_id)

    def view(self,slug,task_id,*,now=None):
        project=self._project(slug);row=self._task(slug,task_id)
        age=max(0,(_now(now)-_time(row['updated_at'])).total_seconds())
        state=row['status'];result=row['result'];evidence=result.get('evidence',{})
        stale=state=='running' and age>60
        expired=_now(now)>=_time(row['plan']['expires_at'])
        if state=='planned' and expired:state='expired'
        if state=='running' and (row['plan'].get('stop_requested') or expired):state='cancelling'
        cleanup=result.get('cleanup_required',state in ('running','cancelling','interrupted'))
        if cleanup and row['status'] not in ('planned','cancelled'):state='cleanup_required' if result else state
        if row['status']=='succeeded' and not _evidence(evidence, row['check_name']):state='unknown'
        actions={
            'planned':'Run one supervised check within the active allowance',
            'running':'Wait for the current check; do not start another',
            'cancelling':'Stop the fixture runner and verify cleanup; do not replay',
            'expired':'Review the expired plan; create a new plan only if approved',
            'succeeded':'Review the completed result; no automatic replay or promotion',
            'cancelled':'Review the cancelled plan; no automatic replay',
            'stopped':'Review the stopped result; no automatic replay',
            'failed':'Review failure evidence before planning any further work',
        }
        next_action=actions.get(state,'Reconcile interrupted or stale work; do not replay')
        if stale:next_action='Reconcile interrupted or stale work; do not replay'
        return {'task_id':task_id,'project':slug,'state':state,'stale':stale,'last_activity':row['updated_at'],
            'age_seconds':age,'attempts':row['attempt_count'],'cleanup_required':cleanup,
            'evidence_origin':evidence.get('origin','unverified'),'evidence':evidence,
            'next_action':next_action,
            'review_state':result.get('review_state','not_reviewed'),'automatic_live_change':False}

    def approve_lesson(self,slug,task_id,*,key,content,owner_approved=False):
        row=self._task(slug,task_id);view=self.view(slug,task_id)
        if owner_approved is not True or view['state']!='succeeded' or view['cleanup_required']:raise ValueError('A verified completed task and explicit owner approval are required')
        _label(key);_text(content)
        return self.database.upsert_memory(namespace='project:'+slug,kind='lesson',key=key,content=content,
            metadata={'continuity_version':1,'source_revision':row['plan']['source_revision'],'task_id':task_id,
                'evidence':view['evidence'],'review_state':'owner_approved','automatic_live_change':False})

    def lessons(self,slug):
        return self._lessons(slug)

    def _lessons(self,slug,*,approved_only=False):
        self._project(slug)
        # Filter before the bound: unrelated or imported records must not hide
        # approved lessons. The 101st eligible row makes an oversized export fail.
        sql="""SELECT * FROM memories WHERE namespace=? AND kind='lesson'
            AND json_extract(metadata_json, '$.continuity_version')=1"""
        if approved_only:
            sql+=" AND json_extract(metadata_json, '$.review_state') IN ('owner_approved','owner_corrected')"
        sql+=' ORDER BY importance DESC, updated_at DESC, id DESC LIMIT 101'
        with self.database.session() as con:
            rows=con.execute(sql,('project:'+slug,)).fetchall()
        return [self.database._row(row) for row in rows]

    def _lesson(self,slug,memory_id,owner_approved):
        self._project(slug);row=self.database.get_memory(memory_id)
        if owner_approved is not True or not row or row['namespace']!='project:'+slug or row['kind']!='lesson':raise ValueError('Owner-approved project lesson required')
        return row

    def correct_lesson(self,slug,memory_id,*,content,owner_approved=False):
        row=self._lesson(slug,memory_id,owner_approved);_text(content)
        metadata=dict(row['metadata']);metadata['review_state']='owner_corrected';metadata['corrected_at']=utc_now()
        return self.database.update_memory(memory_id,namespace=row['namespace'],kind='lesson',key=row['key'],content=content,metadata=metadata)

    def forget_lesson(self,slug,memory_id,*,owner_approved=False):
        self._lesson(slug,memory_id,owner_approved)
        return self.database.delete_memory(memory_id)

    def export_project(self,slug):
        p=self._project(slug);lessons=self._lessons(slug,approved_only=True)
        if len(lessons)>100:raise ValueError('Project handoff exceeds 100 lessons; narrow it before export')
        records=[]
        for m in lessons:
            meta=m['metadata']
            if meta.get('review_state') not in ('owner_approved','owner_corrected'):continue
            records.append({'key':m['key'],'content':m['content'],'source_revision':meta['source_revision'],
                'evidence':meta['evidence'],'review_state':meta['review_state']})
        return {'format':FORMAT,'version':1,'project':{'slug':slug,'name':p['name'],'summary':p['summary'],
            'next_action':p['next_action'],'source_revision':p['metadata']['source_revision']},'lessons':records}

    def import_project(self,payload):
        """Import only selected knowledge, atomically; never tasks or authority."""
        if not isinstance(payload,dict) or set(payload)!={'format','version','project','lessons'} or payload['format']!=FORMAT or type(payload['version']) is not int or payload['version']!=1:raise ValueError('Unsupported handoff schema')
        if len(canonical_json(payload).encode())>512000:raise ValueError('Handoff too large')
        p=payload['project'];items=payload['lessons']
        if not isinstance(p,dict) or set(p)!={'slug','name','summary','next_action','source_revision'} or not isinstance(items,list) or len(items)>100:raise ValueError('Invalid project handoff')
        slug=_label(p['slug']);_text(p['name'],200);_text(p['summary']);_text(p['next_action']);_digest(p['source_revision'])
        seen=set()
        for item in items:
            if not isinstance(item,dict) or set(item)!={'key','content','source_revision','evidence','review_state'}:raise ValueError('Invalid lesson fields')
            _label(item['key']);_text(item['content']);_digest(item['source_revision'])
            if item['key'] in seen or not _evidence(item['evidence']) or item['review_state'] not in ('owner_approved','owner_corrected'):raise ValueError('Invalid lesson provenance')
            seen.add(item['key'])
        incoming_hash=hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        with self.database.session() as con:
            con.execute('BEGIN IMMEDIATE')
            old=con.execute('SELECT metadata_json FROM projects WHERE slug=?',(slug,)).fetchone()
            if old:
                if json.loads(old['metadata_json']).get('handoff_sha256')!=incoming_hash:raise ValueError('Project import conflicts with existing records')
                return {'imported':False,'duplicate':True,'execution_authority':False}
            # One transaction spans project and memories. Existing Atlas tables,
            # FTS triggers and defaults remain the single persistence mechanism.
            stamp=utc_now()
            con.execute('INSERT INTO projects(id,slug,name,status,summary,next_action,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',
                (str(uuid.uuid4()),slug,p['name'],'reference',p['summary'],p['next_action'],canonical_json({'continuity_version':1,'source_revision':p['source_revision'],'handoff_sha256':incoming_hash,'automatic_live_change':False}),stamp,stamp))
            for item in items:
                meta={'continuity_version':1,'source_revision':item['source_revision'],'evidence':item['evidence'],
                    'review_state':'imported_unverified','claimed_review_state':item['review_state'],'automatic_live_change':False}
                con.execute('INSERT INTO memories(namespace,kind,key,content,importance,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                    ('project:'+slug,'lesson',item['key'],item['content'],5,canonical_json(meta),stamp,stamp))
        return {'imported':True,'duplicate':False,'execution_authority':False}
