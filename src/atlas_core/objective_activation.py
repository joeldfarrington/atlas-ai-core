"""Optional trusted-host notification after durable objective submission.

This adapter never issues authority, claims a request, starts a model or judges
success. The owner supplies a qualified synchronous activation port in Python;
there is no request/config field for choosing code, commands, paths or grants.
The external port owns durable deduplication and bounded process custody.
"""
from dataclasses import dataclass,asdict
import inspect
from atlas_core.memory.database import Database
from atlas_core.objective_requests import ObjectiveRequests,require

STATES=frozenset(('not_matched','not_pending','notified','already_notified','window_consumed','requires_reconciliation'))

@dataclass(frozen=True)
class ActivationNotice:
    state: str
    execution_authority: bool = False
    coding_success: bool = False

    def view(self):
        require(type(self.state) is str and self.state in STATES
                and self.execution_authority is False and self.coding_success is False,'invalid_activation_notice')
        return asdict(self)


class ObjectiveActivation:
    def __init__(self,database,*,notify):
        require(type(database) is Database,'activation_database_required')
        require(callable(notify) and not inspect.iscoroutinefunction(notify)
                and not inspect.iscoroutinefunction(getattr(notify,'__call__',None)), 'synchronous_activation_port_required')
        self.database=database;self._notify=notify

    def notify(self,request_id,*,expected_sha256):
        row=ObjectiveRequests(self.database).get(request_id)
        require(row['request_sha256']==expected_sha256,'activation_request_changed')
        if row['state']!='pending':return ActivationNotice('not_pending').view()
        result=self._notify(row)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):result.close()
            raise ValueError('synchronous_activation_notice_required')
        require(type(result) is ActivationNotice,'exact_activation_notice_required')
        return result.view()
