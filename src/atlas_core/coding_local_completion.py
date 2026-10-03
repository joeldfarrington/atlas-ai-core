"""One Aider completion through the host-selected shared native transport.

Existing AiderProcessWorker still owns request assembly/token admission, the
editable-file sandbox, output bounds and independent coding acceptance. This
port only adapts that worker's synchronous callback to the same reserved local
provider used by a cooperating Core router. Binding is explicit, never a grant.
"""
import asyncio
import threading

from atlas_core.governance.cognitive_state import need
from atlas_core.models.admission import LocalModelAdmission,ModelAdmissionRefused
from atlas_core.models.base import ChatMessage
from atlas_core.models.openai_compatible import OpenAICompatibleProvider


class LocalCodingCompletion:
    def __init__(self, provider, *, output_tokens=1536):
        need(type(provider) is OpenAICompatibleProvider and
             type(provider._model_admission) is LocalModelAdmission and
             provider._model_admission_lane=='registered','shared_local_transport_required')
        self.provider=self._provider=provider;self.admission=provider._model_admission
        need(type(output_tokens) is int and 0<output_tokens<=self.admission.profile.max_tokens,
             'bounded_completion_output_required')
        self.output_tokens=self._output_tokens=output_tokens
        self._used=False;self._lock=threading.Lock();self.last_usage=None

    def validate(self):
        need(self.provider is self._provider and self.provider._model_admission is self.admission
             and self.provider._model_admission_lane=='registered'
             and type(self.output_tokens) is int and self.output_tokens==self._output_tokens,
             'completion_binding_changed')
        self.admission.checkpoint()

    def validate_budget(self,budget):
        from atlas_core.coding_request_budget import AiderRequestBudget
        self.validate()
        need(type(budget) is AiderRequestBudget and budget.output_tokens==self.output_tokens,
             'completion_must_match_admitted_output_reserve')

    def __call__(self,messages,cancel):
        need(type(cancel) is threading.Event,'worker_cancellation_required')
        with self._lock:
            need(not self._used and not cancel.is_set(),'completion_attempt_consumed_or_stopped')
            self._used=True
        self.validate()
        need(type(messages) is list and 0<len(messages)<=100 and
             all(type(m) is dict and set(m)=={'role','content'} and m['role'] in
                 {'system','user','assistant'} and type(m['content']) is str for m in messages),
             'assembled_text_messages_required')
        need(sum(len(m['content'].encode()) for m in messages)<=150000,'bounded_completion_context_required')
        typed=[ChatMessage(role=m['role'],content=m['content']) for m in messages]
        async def run():
            task=asyncio.create_task(self.provider.generate(typed,max_tokens=self.output_tokens))
            try:
                while not task.done():
                    if cancel.is_set():
                        task.cancel()
                        raise ModelAdmissionRefused('Worker stopped; request outcome needs recovery.')
                    await asyncio.wait({task},timeout=.05)
                response=task.result()
                need(not cancel.is_set() and not response.tool_calls and
                     type(response.content) is str and len(response.content.encode())<=65536,
                     'bounded_text_completion_required')
                self.last_usage=dict(response.usage)
                return response.content
            finally:
                if not task.done():
                    task.cancel();await asyncio.wait({task},timeout=.5)
        return asyncio.run(run())
