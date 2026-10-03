"""Durable owner objective requests; persistence never grants execution authority.

Reuse the Atlas database transaction boundary. Claiming is trusted-host custody,
not permission: the independent constitution/task/native execution gates remain
mandatory. Unknown claims never expire into permission to replay work.
"""
from dataclasses import dataclass, asdict
import json
import uuid
from atlas_core.memory.database import Database, canonical_json, utc_now
from atlas_core.conversation_followup import TERMINAL
from atlas_core.governance.cognitive_state import digest
from atlas_core.governance.action_boundary import sha


class ObjectiveRequestError(ValueError):
    pass


def require(ok, reason):
    if not ok: raise ObjectiveRequestError(reason)


def identifier(value):
    require(type(value) is str and len(value)==36, 'invalid_request_id')
    try: parsed=uuid.UUID(value)
    except ValueError: raise ObjectiveRequestError('invalid_request_id') from None
    require(str(parsed)==value, 'invalid_request_id')


@dataclass(frozen=True)
class ObjectiveRequest:
    request_id: str
    conversation_id: str
    run_id: str
    project: str
    objective: str

    def validate(self):
        for value in (self.request_id,self.conversation_id,self.run_id):identifier(value)
        require(type(self.project) is str and 1<=len(self.project)<=80
                and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_-' for c in self.project), 'invalid_project')
        require(type(self.objective) is str and self.objective.strip()==self.objective
                and 1<=len(self.objective)<=1000 and len(self.objective.encode())<=12000
                and '\x00' not in self.objective, 'invalid_objective')
        return asdict(self)


class ObjectiveRequests:
    """Public submit/read/cancel plus explicit trusted-host claim; no dispatcher."""
    def __init__(self,database):
        require(type(database) is Database,'database_required')
        self.database=database

    def _scope(self,c,p,*,idle=False):
        chat=c.execute('SELECT * FROM conversations WHERE id=?',(p['conversation_id'],)).fetchone()
        run=c.execute('SELECT * FROM runs WHERE id=?',(p['run_id'],)).fetchone()
        require(chat is not None and run is not None and run['conversation_id']==chat['id']
                and chat['project_slug']==run['project_slug']==p['project']
                and chat['agent_slug']==run['agent_slug']=='atlas','request_scope_mismatch')
        if idle:
            require(not chat['archived'] and run['status'] in TERMINAL and run['pending_approval_id'] is None
                    and not self.database._unresolved_chat_work(c,chat['id']),'conversation_requires_reconciliation')

    def _row(self,c,request_id):
        identifier(request_id)
        row=c.execute('SELECT * FROM objective_requests WHERE request_id=?',(request_id,)).fetchone()
        require(row is not None,'request_not_found')
        row=dict(row);p=json.loads(row['payload_json'])
        require(type(p) is dict and ObjectiveRequest(**p).validate()==p
                and p['request_id']==request_id and digest(p)==row['request_sha256'],'request_integrity_failure')
        events=c.execute('SELECT * FROM objective_request_events WHERE request_id=? ORDER BY revision',(request_id,)).fetchall()
        state=None;previous='';revision=-1;selection=None
        transitions={None:('pending',),'pending':('claimed','cancelled'),'claimed':('cancel_requested','resolved'),'cancel_requested':('resolved',),'cancelled':(),'resolved':()}
        for e in events:
            value=dict(request_id=request_id,request_sha256=row['request_sha256'],revision=e['revision'],state=e['state'],selection_sha256=e['selection_sha256'],previous_sha256=previous)
            require(e['revision']==revision+1 and e['state'] in transitions[state]
                    and e['previous_sha256']==previous and e['event_sha256']==digest(value),'request_history_integrity_failure')
            if e['state'] in ('claimed','cancel_requested','resolved'):require(sha(e['selection_sha256']),'invalid_selection_pin')
            else:require(e['selection_sha256'] is None,'unexpected_selection')
            if state in ('claimed','cancel_requested'):require(e['selection_sha256']==selection,'request_claim_changed')
            state=e['state'];previous=e['event_sha256'];revision=e['revision'];selection=e['selection_sha256']
        require(state==row['state'] and revision==row['revision'] and selection==row['selection_sha256'],'request_state_integrity_failure')
        result=c.execute('SELECT * FROM objective_request_results WHERE request_id=?',(request_id,)).fetchone()
        require((result is not None)==(state=='resolved'),'request_result_integrity_failure')
        if result is not None:
            value=json.loads(result['result_json'])
            require(digest(value)==result['result_sha256'] and value['selection_sha256']==selection
                    and value['request_sha256']==row['request_sha256'],'request_result_integrity_failure')
            self._validate_result(c,p,value)
            row['result']=value
        return row,p

    def _event(self,c,row,state,selection=None):
        revision=row['revision']+1
        prior=c.execute('SELECT event_sha256 FROM objective_request_events WHERE request_id=? ORDER BY revision DESC LIMIT 1',(row['request_id'],)).fetchone()
        value=dict(request_id=row['request_id'],request_sha256=row['request_sha256'],revision=revision,state=state,selection_sha256=selection,previous_sha256=prior['event_sha256'] if prior else '')
        c.execute('INSERT INTO objective_request_events VALUES(?,?,?,?,?,?,?)',(row['request_id'],revision,state,selection,digest(value),value['previous_sha256'],utc_now()))
        c.execute('UPDATE objective_requests SET state=?,revision=?,selection_sha256=? WHERE request_id=?',(state,revision,selection,row['request_id']))

    def _view(self,row,p):
        return {**p,'request_sha256':row['request_sha256'],'state':row['state'],'revision':row['revision'],
                'selection_sha256':row['selection_sha256'],'execution_authority':False,'starts_work':False,
                'executor_connected':False,'status_message':{
                    'pending':'Saved; awaiting an authorized executor.',
                    'claimed':'Handed to the trusted executor; the outcome still needs verification.',
                    'cancel_requested':'Cancellation requested; execution and cleanup must be reconciled.',
                    'cancelled':'Cancelled before executor handoff.',
                    'resolved':('The attempt stopped safely; its coding outcome remains unconfirmed.'
                        if (row.get('result') or {}).get('kind')=='unconfirmed_settled'
                        else 'The trusted executor returned a verified final outcome.')}[row['state']],
                'requires_reconciliation':row['state'] in ('claimed','cancel_requested'),
                'result':row.get('result')}

    def submit(self,request):
        require(type(request) is ObjectiveRequest,'exact_request_required');p=request.validate();fp=digest(p)
        with self.database.session() as c:
            c.execute('BEGIN IMMEDIATE')
            old=c.execute('SELECT 1 FROM objective_requests WHERE request_id=?',(request.request_id,)).fetchone()
            if old:
                row,saved=self._row(c,request.request_id)
                require(saved==p and row['request_sha256']==fp,'request_id_conflict')
                self._scope(c,p)
                return self._view(row,p)
            self._scope(c,p,idle=True)
            active=c.execute("SELECT payload_json FROM objective_requests WHERE state IN ('pending','claimed','cancel_requested')").fetchall()
            require(len(active)<64,'request_capacity_reached')
            require(all(json.loads(x['payload_json'])['conversation_id']!=p['conversation_id'] for x in active),'conversation_objective_already_open')
            c.execute('INSERT INTO objective_requests VALUES(?,?,?,?,?,?,?)',(request.request_id,canonical_json(p),fp,'pending',-1,None,utc_now()))
            self._event(c,dict(request_id=request.request_id,request_sha256=fp,revision=-1),'pending')
            row,p=self._row(c,request.request_id)
            return self._view(row,p)

    def get(self,request_id):
        with self.database.session() as c:
            c.execute('BEGIN');row,p=self._row(c,request_id);self._scope(c,p)
            return self._view(row,p)

    def cancel(self,request_id,*,expected_sha256):
        with self.database.session() as c:
            c.execute('BEGIN IMMEDIATE');row,p=self._row(c,request_id);self._scope(c,p)
            require(sha(expected_sha256) and row['request_sha256']==expected_sha256,'request_pin_mismatch')
            if row['state']=='pending':self._event(c,row,'cancelled')
            elif row['state']=='claimed':self._event(c,row,'cancel_requested',row['selection_sha256'])
            row,p=self._row(c,request_id);return self._view(row,p)

    def claim(self,request_id,*,expected_sha256,selection_sha256):
        """Trusted executor only. Does not resume a prior claim or issue authority."""
        require(sha(selection_sha256),'invalid_selection_pin')
        with self.database.session() as c:
            c.execute('BEGIN IMMEDIATE');row,p=self._row(c,request_id);self._scope(c,p,idle=True)
            require(sha(expected_sha256) and row['request_sha256']==expected_sha256,'request_pin_mismatch')
            require(row['state']=='pending','request_already_consumed')
            self._event(c,row,'claimed',selection_sha256)
            row,p=self._row(c,request_id);return self._view(row,p)


    def _validate_result(self,c,p,value):
        if type(value) is dict and value.get('kind')=='unconfirmed_settled':
            from atlas_core.objective_uncertainty import validate_unknown
            return validate_unknown(c,p,value)
        if type(value) is dict and value.get('kind') in ('cancelled_before_coding','cancelled_settled'):
            from atlas_core.objective_cancellation import validate_cancelled
            return validate_cancelled(c,p,value)
        require(type(value) is dict and set(value)=={'request_sha256','selection_sha256','goal_state','proof','publication','execution_authority'}
                and value['execution_authority'] is False and value['goal_state'] in ('COMPLETE','FAILED','BLOCKED','NOT_CREATED'),
                'invalid_request_result')
        proof=value['proof'];publication=value['publication']
        require(type(proof) is dict and proof.get('independent') is True
                and proof.get('accepted') is (value['goal_state']=='COMPLETE')
                and proof.get('execution_authority') is False,'independent_result_required')
        require(type(publication) is dict and publication.get('goal_state')==value['goal_state']
                and publication.get('starts_work') is False and publication.get('execution_authority') is False,
                'verified_publication_required')
        ids=publication.get('message_ids')
        require(type(ids) is list and 1<=len(ids)<=12 and all(type(x) is str for x in ids)
                and len(set(ids))==len(ids),'publication_messages_required')
        for message_id in ids:
            message=c.execute('SELECT * FROM messages WHERE id=?',(message_id,)).fetchone()
            require(message is not None and message['conversation_id']==p['conversation_id']
                    and message['role']=='assistant','publication_target_mismatch')
            metadata=json.loads(message['metadata_json'])
            require(metadata.get('origin')=='trusted_local_followup' and metadata.get('kind')=='result'
                    and metadata.get('source_run_id')==p['run_id'] and metadata.get('project_slug')==p['project']
                    and metadata.get('execution_authority') is False,'publication_provenance_mismatch')

    def _close_published(self,request_id,*,expected_sha256,selection_sha256,proof,publication):
        """Trusted independent owner-window adapter only, after restoration.

        Not a verifier or public API: the calling adapter must independently
        verify the window, service restoration, coding receipts and publication.
        These checks preserve that selected outcome; they never manufacture it.
        """
        value=dict(request_sha256=expected_sha256,selection_sha256=selection_sha256,
                   goal_state=publication.get('goal_state'),proof=proof,publication=publication,execution_authority=False)
        with self.database.session() as c:
            c.execute('BEGIN IMMEDIATE');row,p=self._row(c,request_id);self._scope(c,p)
            require(row['request_sha256']==expected_sha256 and row['selection_sha256']==selection_sha256
                    and sha(selection_sha256),'request_resolution_binding')
            self._validate_result(c,p,value)
            if row['state']=='resolved':
                require(row['result']==value,'request_result_conflict');return self._view(row,p)
            require(row['state'] in ('claimed','cancel_requested'),'request_not_claimed')
            c.execute('INSERT INTO objective_request_results VALUES(?,?,?)',(request_id,canonical_json(value),digest(value)))
            self._event(c,row,'resolved',selection_sha256)
            row,p=self._row(c,request_id);return self._view(row,p)

    def _close_cancelled(self,request_id,*,expected_sha256,selection_sha256,proof,publication):
        """Trusted adapter only after independent pre-coding stop/restoration."""
        from atlas_core.objective_cancellation import cancellation_result
        value=cancellation_result(request_sha256=expected_sha256,selection_sha256=selection_sha256,
                                  proof=proof,publication=publication)
        with self.database.session() as c:
            c.execute('BEGIN IMMEDIATE');row,p=self._row(c,request_id);self._scope(c,p)
            require(row['request_sha256']==expected_sha256 and row['selection_sha256']==selection_sha256
                    and sha(selection_sha256),'request_resolution_binding')
            self._validate_result(c,p,value)
            if row['state']=='resolved':
                require(row['result']==value,'request_result_conflict');return self._view(row,p)
            require(row['state']=='cancel_requested','request_cancellation_required')
            c.execute('INSERT INTO objective_request_results VALUES(?,?,?)',(request_id,canonical_json(value),digest(value)))
            self._event(c,row,'resolved',selection_sha256)
            row,p=self._row(c,request_id);return self._view(row,p)

    def _close_settled_unknown(self,request_id,*,expected_sha256,selection_sha256,proof,publication,settlement):
        """Independent owner only, after actual cleanup and restored-state checks.

        Execution is closed; the coding goal remains OUTCOME_UNKNOWN. Repeated
        identical delivery is idempotent and never grants replay permission.
        """
        value=dict(kind='unconfirmed_settled',request_sha256=expected_sha256,
            selection_sha256=selection_sha256,goal_state='OUTCOME_UNKNOWN',proof=proof,
            publication=publication,settlement=settlement,execution_authority=False)
        with self.database.session() as c:
            c.execute('BEGIN IMMEDIATE');row,p=self._row(c,request_id);self._scope(c,p)
            require(row['request_sha256']==expected_sha256 and row['selection_sha256']==selection_sha256
                and sha(selection_sha256),'request_resolution_binding')
            self._validate_result(c,p,value)
            if row['state']=='resolved':
                require(row['result']==value,'request_result_conflict');return self._view(row,p)
            require(row['state']=='claimed','unknown_request_not_claimed')
            c.execute('INSERT INTO objective_request_results VALUES(?,?,?)',(request_id,canonical_json(value),digest(value)))
            self._event(c,row,'resolved',selection_sha256)
            row,p=self._row(c,request_id);return self._view(row,p)
