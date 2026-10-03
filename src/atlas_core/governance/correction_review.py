"""Host review before closing an active attempt; no dispatch or grant issuance.

The existing host must call this after independent checks and before closing.
It never reopens a closed job, extends a deadline or resets a request allowance.
"""
from .task_contract import validate, fingerprint


def review_attempt(packet, *, task_fingerprint, state, closed, stopped,
                   now_utc, requests_used, correction_used, changed_hypothesis):
    item = validate(packet)
    if task_fingerprint != fingerprint(item): raise ValueError('wrong_task')
    if state not in ('accepted','failed','incomplete','unknown'): raise ValueError('unknown_outcome')
    if any(type(value) is not bool for value in (closed,stopped,correction_used)):
        raise ValueError('invalid_control_state')
    if type(requests_used) is not int or requests_used < 0 or requests_used > item['max_requests']:
        raise ValueError('invalid_request_count')
    from datetime import datetime
    def moment(value):
        if type(value) is not str: raise ValueError('invalid_time')
        result = datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ')
        if result.strftime('%Y-%m-%dT%H:%M:%SZ') != value: raise ValueError('invalid_time')
        return result
    expired = moment(now_utc) >= moment(item['deadline_utc'])
    if type(changed_hypothesis) is not str or len(changed_hypothesis.encode()) > 1200:
        raise ValueError('invalid_hypothesis')
    result = {'execution_authority':False,'automatic_retry':False,'task_id':item['task_id']}
    if closed or stopped or expired:
        return dict(result,next_step='retain_closed_outcome',reason='Do not reopen or renew this task.')
    if state == 'accepted': return dict(result,next_step='record_and_close',reason='Independent checks accepted the candidate.')
    if state in ('unknown','incomplete'):
        return dict(result,next_step='reconcile',reason='Verify the existing attempt without duplicate work.')
    if requests_used == 0:
        return dict(result,next_step='inspect_baseline',reason='No worker generation is recorded.')
    if correction_used or requests_used >= item['max_requests'] or not changed_hypothesis.strip():
        return dict(result,next_step='record_and_close',reason='No justified correction remains.')
    return dict(result,next_step='propose_one_correction',reason=changed_hypothesis.strip())
