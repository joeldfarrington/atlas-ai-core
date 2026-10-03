"""Low-resource observer in the existing Core lifecycle. No model or actions."""
import asyncio
from datetime import datetime,timezone
import time


class AtlasHeartbeat:
    INTERVAL_SECONDS=60
    def __init__(self,foundation,development,*,attention=None):
        if attention is not None:
            from .attention_pipeline import AttentionPipeline
            if type(attention) is not AttentionPipeline:
                raise ValueError('Trusted attention pipeline required')
        self.foundation,self.development=foundation,development
        self._task=None;self._ticks=0;self._last=None
        self.attention=attention;self._attention_status=None

    def observe(self):
        started=time.monotonic()
        foundation=self.foundation.status()
        controls=[]
        for slug,project in self.development.projects.items():
            if not project.self_development:continue
            try:
                state=self.development.control.status(slug)
                controls.append({k:state.get(k) for k in ('stopped','cleanup_required','active_operations')})
            except Exception:
                controls.append({'state':'unknown'})
        unknown=any(x.get('state')=='unknown' for x in controls)
        self._ticks+=1
        self._last={'observed_at':datetime.now(timezone.utc).isoformat(),
            'constitution_verified':foundation['verified'],'development_projects':len(controls),
            'stopped_projects':sum(x.get('stopped') is True for x in controls),
            'cleanup_required':any(x.get('cleanup_required') is True for x in controls),
            'active_operations':sum(x.get('active_operations') or 0 for x in controls),
            'control_state_known':not unknown,'seconds':round(time.monotonic()-started,6)}
        if self.attention is not None:
            try:self._attention_status=self.attention.health_tick(self._last,int(time.time()))
            except Exception:self._attention_status={'state':'unavailable','execution_authority':False}
        self._last['seconds']=round(time.monotonic()-started,6)
        return dict(self._last)

    async def _run(self):
        while True:
            self.observe()
            await asyncio.sleep(self.INTERVAL_SECONDS)

    async def start(self):
        if self._task is not None:raise RuntimeError('Atlas heartbeat already started')
        self._task=asyncio.create_task(self._run(),name='atlas-observe-only-heartbeat')
        await asyncio.sleep(0)

    async def close(self):
        task=self._task
        if task is None:return
        task.cancel()
        try:await task
        except asyncio.CancelledError:pass
        finally:self._task=None

    def status(self):
        return {'running':self._task is not None and not self._task.done(),
            'mode':'observe_only' if self.attention is None else 'observe_and_propose','interval_seconds':self.INTERVAL_SECONDS,'ticks':self._ticks,
            'last_observation':None if self._last is None else dict(self._last),
            'model_calls':0,'jobs_dispatched':0,'notifications_sent':0,'creates_authority':False,
            'attention':None if self.attention is None else self._attention_status,
            'persists_while':'Atlas Core is running; no separate service or schedule'}
