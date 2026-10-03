from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Literal

import httpx

from atlas_core.errors import ProviderError
from atlas_core.models.base import (
    ChatMessage,
    ModelProvider,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)


def reasoning_review_sampling():
    """Fixed supported subset of Qwen3.5 precise-coding sampling guidance.

    Selected by the trusted host for the bound review route only. This does
    not change model identity, token/time limits, retries or tool authority.
    """
    return {'temperature': 0.6, 'top_p': 0.95, 'presence_penalty': 0.0}


class OpenAICompatibleProvider(ModelProvider):
    """Adapter for Ollama and other OpenAI-compatible chat-completions servers."""

    def __init__(
        self,
        *,
        name: str,
        model: str,
        local: bool,
        enabled: bool,
        base_url: str,
        api_key_env: str | None,
        timeout_seconds: float,
        reasoning_effort: Literal["none"] | None = None,
        default_max_tokens: int | None = None,
    ) -> None:
        if reasoning_effort is not None and reasoning_effort != "none":
            raise ValueError("reasoning_effort must be none or unset")
        if default_max_tokens is not None and (
            type(default_max_tokens) is not int or not 1 <= default_max_tokens <= 32_768
        ):
            raise ValueError("default_max_tokens must be an integer from 1 to 32768")
        if not local and (reasoning_effort is not None or default_max_tokens is not None):
            raise ValueError("explicit response options require a local provider")
        super().__init__(
            name=name,
            model=model,
            local=local,
            enabled=enabled,
            api_key_env=api_key_env,
        )
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.reasoning_effort = reasoning_effort
        self.default_max_tokens = default_max_tokens
        self._model_admission = None
        self._review_reasoning_counter_identity = None
        self._review_reasoning_counter = None
        self._model_admission_lane = 'supplemental'
        self._plan_review_binding = None
        self._plan_review_counter = None

    def bind_model_admission(self, admission, *, lane='supplemental') -> None:
        """Trusted host selection only; no config/model/tool can issue a grant."""
        from atlas_core.models.admission import LocalModelAdmission
        if (type(admission) is not LocalModelAdmission or self._model_admission is not None
                or lane not in {'supplemental','registered'} or not self.local or not self.enabled
                or self.base_url != admission.profile.base_url or self.model != admission.profile.model
                or self.reasoning_effort != 'none' or self.default_max_tokens != admission.profile.max_tokens
                or self.api_key_env not in (None,'ATLAS_LOCAL_API_KEY')):
            raise ValueError('Model admission must match the exact qualified local provider')
        admission.checkpoint()
        self._model_admission=admission;self._model_admission_lane=lane
        self._model_admission_binding=self._transport_identity()

    def bind_reasoning_review(self, admission, *, review_counter) -> None:
        """Explicit trusted-host route for one bounded local code review.

        Existing provider/config admission remains nonreasoning. This route uses
        the same ledger and lock, and cannot carry tools or a builder request.
        The independently registered parent must return this exact counter ID.
        """
        from atlas_core.coding_counter_peer import PeerReviewCounter
        if (type(review_counter) is not PeerReviewCounter
                or type(review_counter.identity) is not str
                or re.fullmatch('[0-9a-f]{64}', review_counter.identity) is None
                or self.model != 'atlas-qwen3.5:9b-8k' or self.api_key_env is not None
                or self.base_url != 'http://127.0.0.1:11434/v1'
                or type(self.timeout_seconds) not in (int, float)
                or not 0 < self.timeout_seconds <= 105):
            raise ValueError('Exact bounded local reasoning review selection required')
        # Tokenizer resources remain exclusively with the registered parent.
        # The child accepts only a count receipt with this exact identity.
        identity = review_counter.identity
        self.bind_model_admission(admission, lane='supplemental')
        self.reasoning_effort = 'low'
        self._review_reasoning_counter = review_counter
        self._review_reasoning_counter_identity = identity
        self._model_admission_binding = self._transport_identity()

    def bind_reasoning_plan_review(self, admission, *, planning_counter, context, protocol="v8_grounded", repository_sources=None):
        """Trusted-host opt-in for one exact source-grounded plan critique.

        Reuses shared admission and the existing bounded reasoning sampling. The
        complete request, schema, model and parent counter identity are bound;
        this is neither a generic reasoning provider nor an execution capability.
        """
        from atlas_core.coding_counter_peer import PeerPlanningCounter
        from atlas_core.models.admission import LocalModelAdmission
        from atlas_core.governance import coding_plan_grounded_review as critic
        from atlas_core.governance.cognitive_state import digest
        if (type(admission) is not LocalModelAdmission
                or type(planning_counter) is not PeerPlanningCounter
                or re.fullmatch('[0-9a-f]{64}', planning_counter.identity) is None
                or self.model != 'atlas-qwen3.5:9b-8k' or self.api_key_env is not None
                or self.base_url != 'http://127.0.0.1:11434/v1'
                or type(self.timeout_seconds) not in (int, float)
                or not 0 < self.timeout_seconds <= 105
                or planning_counter.scope != admission._scope
                or admission.profile.max_tokens != 4096):
            raise ValueError('Exact bounded reasoning plan review required')
        if protocol == 'v9_references':
            from atlas_core.governance import coding_plan_reference_review as critic
        elif protocol == 'v10_reference_schema':
            from atlas_core.governance import coding_plan_reference_strict_review as critic
        elif protocol == 'v11_single_pass':
            from atlas_core.governance import coding_plan_single_pass_review as critic
        elif protocol == 'v12_direct':
            from atlas_core.governance import coding_plan_direct_review as critic
        elif protocol != 'v8_grounded':
            raise ValueError('Unknown bounded reasoning plan protocol')
        request = critic.request(context,repository_sources)
        selected_reasoning = 'none' if protocol == 'v12_direct' else 'low'
        binding = (digest(request['messages']), digest(request['response_format']),
                   planning_counter.identity, planning_counter.scope, selected_reasoning)
        self.bind_model_admission(admission, lane='supplemental')
        self._plan_review_counter = planning_counter
        self._plan_review_binding = binding
        self.reasoning_effort = selected_reasoning
        self._model_admission_binding = self._transport_identity()

    def _bounded_reasoning_plan_review(self, messages, tools, temperature, max_tokens, response_format):
        from atlas_core.governance.cognitive_state import digest
        counter = self._plan_review_counter
        binding = self._plan_review_binding
        return (binding is not None and self.reasoning_effort == binding[4]
            and self._model_admission_lane == 'supplemental'
            and self.model == 'atlas-qwen3.5:9b-8k' and self.api_key_env is None
            and self._review_reasoning_counter_identity is None
            and counter is not None and counter.identity == binding[2]
            and counter.scope == binding[3] == self._model_admission._scope
            and type(messages) is list and len(messages) == 2
            and all(type(m) is ChatMessage for m in messages)
            and [m.role for m in messages] == ['system', 'user']
            and tools is None and type(temperature) is float and temperature == 0.6
            and type(max_tokens) is int and max_tokens == 3072
            and digest([dict(role=m.role, content=m.content) for m in messages]) == binding[0]
            and all(not m.tool_calls and m.tool_call_id is None and m.name is None for m in messages)
            and all(m.for_openai_chat() == dict(role=m.role,content=m.content) for m in messages)
            and digest(response_format) == binding[1])

    def _bounded_reasoning_review(self, messages, tools, temperature, max_tokens, response_format):
        from atlas_core.coding_reviewer import review_response_format
        return (self._review_reasoning_counter_identity is not None
            and self.reasoning_effort == 'low' and self._model_admission_lane == 'supplemental'
            and self.model == 'atlas-qwen3.5:9b-8k' and self.api_key_env is None
            and type(messages) is list and len(messages) == 2
            and all(type(m) is ChatMessage for m in messages)
            and [m.role for m in messages] == ['system', 'user']
            and tools is None and type(temperature) is float and temperature == 0.6
            and type(max_tokens) is int and 0 < max_tokens <= 4096
            and response_format == review_response_format())

    def _transport_identity(self):
        return (self.name,self.model,self.base_url,self.local,self.enabled,self.api_key_env,
                self.timeout_seconds,self.reasoning_effort,self.default_max_tokens,
                self._model_admission_lane,self._review_reasoning_counter_identity,
                id(self._review_reasoning_counter),getattr(self._review_reasoning_counter,'identity',None),
                self._plan_review_binding,id(self._plan_review_counter),
                getattr(self._plan_review_counter,'identity',None),getattr(self._plan_review_counter,'scope',None))

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key_env:
            api_key = os.getenv(self.api_key_env)
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        return headers

    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[ToolDefinition] | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> ModelResponse:
        if response_format is not None:
            # Trusted caller option, copied before dispatch. It cannot replace
            # transport, messages, tools, model, admission or token limits.
            if type(response_format) is not dict or response_format.get('type') != 'json_schema':
                raise ValueError('A bounded JSON schema response format is required')
            encoded_format = json.dumps(response_format, allow_nan=False)
            if len(encoded_format.encode()) > 8192:
                raise ValueError('Response format exceeds its size bound')
            response_format = json.loads(encoded_format)
        if self._model_admission is not None:
            from atlas_core.models.admission import ModelAdmissionRefused
            gate=self._model_admission
            if (self._transport_identity()!=self._model_admission_binding
                    or (model or self.model)!=gate.profile.model or self.base_url!=gate.profile.base_url
                    or not self.enabled or not self.local
                    or not (self.reasoning_effort=='none' and self._review_reasoning_counter_identity is None and self._plan_review_binding is None
                            or self._bounded_reasoning_review(messages,tools,temperature,max_tokens,response_format)
                            or self._bounded_reasoning_plan_review(messages,tools,temperature,max_tokens,response_format))
                    or self.default_max_tokens!=gate.profile.max_tokens):
                raise ModelAdmissionRefused('Selected local provider changed; no fallback or request')
            return await gate.run(lambda:self._generate(messages,tools=tools,model=model,
                temperature=temperature,max_tokens=max_tokens,response_format=response_format),lane=self._model_admission_lane)
        return await self._generate(messages,tools=tools,model=model,temperature=temperature,max_tokens=max_tokens,response_format=response_format)

    async def _generate(
        self, messages: list[ChatMessage], *, tools: list[ToolDefinition] | None = None,
        model: str | None = None, temperature: float = 0.2, max_tokens: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> ModelResponse:
        selected_model = model or self.model
        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": [message.for_openai_chat() for message in messages],
            "temperature": temperature,
            "stream": False,
        }
        effective_max_tokens = max_tokens
        if self.default_max_tokens is not None:
            if max_tokens is not None and (type(max_tokens) is not int or max_tokens < 1):
                raise ValueError("max_tokens must be a positive integer")
            effective_max_tokens = min(max_tokens, self.default_max_tokens) if max_tokens is not None else self.default_max_tokens
        if effective_max_tokens is not None:
            payload["max_tokens"] = effective_max_tokens
        if self.reasoning_effort is not None:
            payload["reasoning_effort"] = self.reasoning_effort
        if response_format is not None:
            payload['response_format'] = response_format
        if self._review_reasoning_counter_identity is not None or self._plan_review_binding is not None:
            payload.update(reasoning_review_sampling())
        if tools:
            payload["tools"] = [tool.for_openai_chat() for tool in tools]
            payload["tool_choice"] = "auto"

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

                # Some Ollama thinking models can finish a post-tool response with
                # only a private `reasoning` field and no user-visible content.
                # Local post-tool calls may also exhaust their output allowance
                # before emitting an answer or tool call. Retry only that narrow
                # length case, once, with the same model, tools, and token budget.
                # Never turn private reasoning into user-visible content.
                try:
                    retry_choice = data["choices"][0]
                    retry_message = retry_choice["message"]
                    needs_visible_answer = (
                        (retry_choice.get("finish_reason") == "stop"
                         or (retry_choice.get("finish_reason") == "length"
                             and self.local and bool(tools) and bool(messages)
                             and messages[-1].role == "tool"))
                        and not retry_message.get("content")
                        and not retry_message.get("tool_calls")
                        and bool(
                            retry_message.get("reasoning")
                            or retry_message.get("reasoning_content")
                        )
                    )
                except (KeyError, IndexError, TypeError, AttributeError):
                    needs_visible_answer = False

                if needs_visible_answer and self.reasoning_effort is None:
                    retry_payload = dict(payload)
                    retry_payload["reasoning_effort"] = "none"
                    try:
                        retry_response = await client.post(
                            f"{self.base_url}/chat/completions",
                            headers=self._headers(),
                            json=retry_payload,
                        )
                        retry_response.raise_for_status()
                        retry_data = retry_response.json()
                        visible_message = retry_data["choices"][0]["message"]
                        if visible_message.get("content") or visible_message.get("tool_calls"):
                            data = retry_data
                    except (
                        httpx.HTTPError,
                        ValueError,
                        KeyError,
                        IndexError,
                        TypeError,
                        AttributeError,
                    ):
                        # Not every OpenAI-compatible server accepts
                        # `reasoning_effort`; retain the original response when it
                        # does not support this Ollama compatibility retry.
                        pass
        except httpx.ConnectError as exc:
            raise ProviderError(
                f"Cannot connect to provider '{self.name}' at {self.base_url}. "
                "For Ollama, make sure Ollama is running and the configured model is installed."
            ) from exc
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:2_000]
            raise ProviderError(
                f"Provider '{self.name}' returned HTTP {exc.response.status_code}: {body}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError(f"Provider '{self.name}' request failed: {exc}") from exc

        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(
                f"Provider '{self.name}' returned an unexpected response shape"
            ) from exc

        content_value = message.get("content") or ""
        if isinstance(content_value, str):
            content = content_value
        elif isinstance(content_value, list):
            content = "".join(
                str(part.get("text") or "")
                for part in content_value
                if isinstance(part, dict)
            )
        else:
            content = str(content_value)

        calls: list[ToolCall] = []
        for item in message.get("tool_calls") or []:
            if not isinstance(item, dict):
                continue
            function = item.get("function") or {}
            raw_arguments = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else dict(raw_arguments)
            except (json.JSONDecodeError, TypeError, ValueError):
                arguments = {"_raw": str(raw_arguments)}
            calls.append(
                ToolCall(
                    id=str(item.get("id") or f"call_{uuid.uuid4().hex}"),
                    name=str(function.get("name") or ""),
                    arguments=arguments,
                )
            )

        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return ModelResponse(
            content=content.strip(),
            provider=self.name,
            model=str(data.get("model") or selected_model),
            tool_calls=calls,
            usage=usage,
            stop_reason=str(choice.get("finish_reason") or "") or None,
            raw=data,
        )

    async def health(self) -> dict[str, Any]:
        if not self.enabled:
            return {
                "ok": False,
                "configured": False,
                "provider": self.name,
                "kind": "openai_compatible",
                "model": self.model,
                "local": self.local,
                "error": "Provider is disabled",
            }
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 10.0)) as client:
                response = await client.get(
                    f"{self.base_url}/models", headers=self._headers()
                )
                response.raise_for_status()
                data = response.json()
            raw_models = data.get("data") if isinstance(data, dict) else None
            if raw_models is None:
                raw_models = []
            if not isinstance(raw_models, list):
                raise ValueError("Provider model list was not an array")
            models = [
                item["id"]
                for item in raw_models
                if isinstance(item, dict) and item.get("id")
            ]
            return {
                "ok": True,
                "configured": True,
                "provider": self.name,
                "kind": "openai_compatible",
                "base_url": self.base_url,
                "model": self.model,
                "model_available": self.model in models,
                "available_models": models[:100],
                "local": self.local,
            }
        except Exception as exc:
            return {
                "ok": False,
                "configured": True,
                "provider": self.name,
                "kind": "openai_compatible",
                "base_url": self.base_url,
                "model": self.model,
                "local": self.local,
                "error": str(exc),
            }
