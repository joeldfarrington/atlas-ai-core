"""Bounded deterministic attention and reflection; no executor or notifier.

Observations are trusted host snapshots. Text retrieved from a document is not a
snapshot or permission. This extends the existing CognitiveJournal and keeps the
installed native observer unchanged until lifecycle integration qualifies.
"""
from .cognitive_state import CognitiveJournal, digest, need, timestamp


class AttentionPipeline:
    def __init__(self, journal, *, custody_check=None):
        need(type(journal) is CognitiveJournal, 'existing_journal_required')
        need(custody_check is None or callable(custody_check), 'trusted_custody_check')
        self.journal = journal
        self._custody_check = custody_check

    def _current(self):
        if self._custody_check is not None:
            self._custody_check()

    def _append(self, *, kind, subject, now, value, evidence, basis='observed', suffix=''):
        key = kind+':'+digest({'subject':subject,'value':value,'evidence':evidence,'suffix':suffix})[:32]
        events=self.journal.events()
        if any(e['id']==key for e in events):
            return key
        self.journal.append({'id':key,'kind':kind,'basis':basis,'subject':subject,
            'occurred_at':now,'recorded_at':now,'verified_at':now if basis in ('observed','tested') else None,
            'expires_at':None,'evidence':['sha256:'+evidence], 'supersedes':None,'value':value})
        return key

    def tick(self, snapshot, now):
        self._current()
        need(timestamp(now) and type(snapshot) is dict and set(snapshot)=={
            'observed_at','constitution_verified','control_state_known','cleanup_required',
            'resources_ok','open_commitments'}, 'snapshot_schema')
        need(type(snapshot['observed_at']) is int and 0<=now-snapshot['observed_at']<=120, 'stale_snapshot')
        need(all(type(snapshot[k]) is bool for k in ('constitution_verified','control_state_known',
             'cleanup_required','resources_ok')), 'snapshot_types')
        need(type(snapshot['open_commitments']) is int and 0<=snapshot['open_commitments']<=100, 'commitment_count')
        base={'execution_authority':False,'model_calls':0,'notifications_sent':0}
        if not snapshot['constitution_verified']:
            reason='foundation_integrity';priority=100
        elif not snapshot['control_state_known'] or snapshot['cleanup_required']:
            reason='recovery_required';priority=95
        elif not snapshot['resources_ok']:
            return dict(base,state='quiet',reason='resources_reserved')
        elif snapshot['open_commitments']:
            reason='open_commitment';priority=50
        else:
            return dict(base,state='quiet',reason='nothing_actionable')
        state={k:v for k,v in snapshot.items() if k!='observed_at'}
        evidence=digest(state);subject='attention:'+reason
        observation=self._append(kind='observation',subject=subject,now=now,
            value={'reason':reason,'snapshot':state},evidence=evidence)
        events=self.journal.events();replaced={e['supersedes'] for e in events}
        goals=[e for e in events if e['kind']=='goal' and e['id'] not in replaced and e['value']['status']=='open']
        existing=[e for e in goals if e['subject']==subject]
        if existing:
            return dict(base,state='waiting',reason=reason,proposal=existing[0]['id'])
        if len(goals)>=3:
            return dict(base,state='quiet',reason='attention_capacity')
        proposal=self._append(kind='goal',subject=subject,now=now,basis='inference',
            value={'origin':'atlas_generated','status':'open','priority':priority,'not_before':now,'expires_at':None},
            evidence=evidence,suffix=observation)
        self._append(kind='plan',subject=subject,now=now,basis='hypothesis',evidence=evidence,
            value={'step':'inspect_fixed_current_state','requires_registered_capability':True,
                   'automatic_repair':False,'expected_outcome':'Verified explanation or explicit unknown'})
        self._append(kind='critique',subject=subject,now=now,basis='inference',evidence=evidence,
            value={'failure_modes':['stale_state','missing_permission','uncertain_previous_action'],
                   'independent_verification_required':True})
        return dict(base,state='proposal',reason=reason,proposal=proposal)

    def safe_test(self, attention_id, boundary, proposal, candidate, now):
        """Host-selected safe test; generated goals still need a current grant.

        The candidate is not applied to a source tree. Investigation, independent
        sandbox testing and reflection are recorded as distinct evidence steps.
        """
        from .action_boundary import ActionBoundary, Proposal
        self._current()
        need(type(boundary) is ActionBoundary and type(proposal) is Proposal and timestamp(now), 'independent_boundary_required')
        events=self.journal.events();replaced={e['supersedes'] for e in events}
        selected=[e for e in events if e['kind']=='goal' and e['id']==attention_id
                  and e['id'] not in replaced and e['value']['status']=='open']
        need(len(selected)==1, 'current_attention_proposal_required')
        goal=selected[0]
        need(proposal.origin == goal['value']['origin'], 'goal_origin_mismatch')
        need({'plan','critique'} <= {e['kind'] for e in events if e['subject']==goal['subject']}, 'plan_and_challenge_required')
        # Re-read actual state through the broker's independent observer.
        boundary._gate(proposal)
        reference=digest({'request':proposal.__dict__,'policy':boundary.policy_sha256})
        self._append(kind='observation',subject='action:'+proposal.request_id,now=now,
            evidence=reference,value={'stage':'investigation','source_sha256':proposal.source_sha256,
                                      'task_id':proposal.task_id,'fresh_authority_checked':True})
        self._append(kind='prediction',subject='action:'+proposal.request_id,now=now,basis='hypothesis',
            evidence=reference,value={'expected':'verified_candidate','source_applied':False})
        self._append(kind='action',subject='action:'+proposal.request_id,now=now,
            evidence=reference,value={'kind':'independent_sandbox_test','scope':'candidate_only'})
        result=boundary.test_candidate(proposal,candidate)
        # The independent test may span multiple clock ticks. Its completion
        # and reflection are later events, not events at the planning timestamp.
        # Preserve supplied logical fixture time when the checker clock lags it.
        completed_at=max(now,int(boundary.clock()))
        self.reflect(boundary,completed_at)
        value=dict(goal['value']);value['status']='completed'
        # Completing this inspection does not claim completion of the coding task.
        revision=dict(goal,id='goal:'+digest({'prior':goal['id'],'result':result})[:32],
            occurred_at=completed_at,recorded_at=completed_at,verified_at=completed_at,basis='tested',value=value,
            evidence=['sha256:'+digest(result)],supersedes=goal['id'])
        self.journal.append(revision)
        return result

    def health_tick(self, observation, now):
        self._current()
        events=self.journal.events();replaced={e['supersedes'] for e in events}
        commitments=sum(e['kind']=='goal' and e['id'] not in replaced and
            e['value']['status']=='open' and e['value']['origin']!='atlas_generated' for e in events)
        return self.tick({'observed_at':now,'constitution_verified':observation['constitution_verified'],
            'control_state_known':observation['control_state_known'],
            'cleanup_required':observation['cleanup_required'],
            'resources_ok':observation.get('active_operations',0)==0,
            'open_commitments':commitments},now)

    def reflect(self, boundary, now):
        from .action_boundary import ActionBoundary
        self._current()
        need(type(boundary) is ActionBoundary and timestamp(now), 'independent_boundary_required')
        status=boundary.status()
        written=0
        for action in status['actions']:
            if action['state'] in ('reserved','uncertain'):
                continue
            subject='action:'+action['id']
            prior=[e for e in self.journal.events() if e['kind']=='reflection' and e['subject']==subject]
            if prior:
                continue
            receipt=digest({'action':action,'ledger_head':status['history_sha256']})
            self._append(kind='verification',subject=subject,now=now,basis='tested',evidence=receipt,
                value={'result':action['state'],'basis':'independent_checker','source_applied':False,
                       'response_complete':True,'cleanup_verified':True})
            self._append(kind='reflection',subject=subject,now=now,basis='inference',evidence=receipt,
                value={'lesson':'Retain bounded evidence; do not generalize beyond the tested candidate.'
                    if action['state']=='verified' else 'Candidate failed independent checking; preserve failure.',
                    'domain':action['domain'],'permission_increase':False,'model_weights_trained':False})
            written+=1
        return {'new_reflections':written,'execution_authority':False,'model_calls':0,
                'unresolved_work':status['requires_recovery']}
