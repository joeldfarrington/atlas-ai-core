from __future__ import annotations

import os
from typing import Any

from atlas_core.config import AtlasConfig
from atlas_core.errors import ConfigurationError, ProviderError
from atlas_core.models.anthropic import AnthropicProvider
from atlas_core.models.base import ChatMessage, ModelProvider, ModelResponse, ToolDefinition
from atlas_core.models.mock import MockProvider
from atlas_core.models.openai_compatible import OpenAICompatibleProvider
from atlas_core.models.openai_responses import OpenAIResponsesProvider
from atlas_core.models.admission import ModelAdmissionRefused


class ModelRouter:
    def __init__(self, config: AtlasConfig) -> None:
        self.config = config
        self.providers: dict[str, ModelProvider] = {}
        self._local_admission_provider = None
        for name, item in config.providers.items():
            common = {
                "name": name,
                "model": item.model,
                "local": item.local,
                "enabled": item.enabled,
                "api_key_env": item.api_key_env,
            }
            if item.kind == "mock":
                provider: ModelProvider = MockProvider(**common)
            elif item.kind == "openai_compatible":
                provider = OpenAICompatibleProvider(
                    **common,
                    base_url=item.base_url or "",
                    timeout_seconds=item.timeout_seconds,
                    reasoning_effort=item.reasoning_effort,
                    default_max_tokens=item.max_tokens,
                )
            elif item.kind == "openai_responses":
                provider = OpenAIResponsesProvider(
                    **common,
                    base_url=item.base_url or "",
                    timeout_seconds=item.timeout_seconds,
                )
            elif item.kind == "anthropic":
                provider = AnthropicProvider(
                    **common,
                    base_url=item.base_url or "",
                    timeout_seconds=item.timeout_seconds,
                )
            else:
                raise ConfigurationError(f"Unsupported provider kind: {item.kind}")
            self.providers[name] = provider

    def get(self, name: str | None = None, *, local_only: bool = True) -> ModelProvider:
        selected_name = name or self.config.routing.default_provider
        provider = self.providers.get(selected_name)
        if (self._local_admission_provider is not None and provider is not None
                and provider.local and selected_name!=self._local_admission_provider):
            raise ModelAdmissionRefused('Local provider is outside the selected finite allocation.')
        if provider is None:
            raise ProviderError(f"Unknown provider: {selected_name}")
        if not provider.enabled:
            raise ProviderError(f"Provider '{selected_name}' is disabled")
        if local_only and not provider.local:
            raise ProviderError(
                f"Provider '{selected_name}' is not marked local; local_only blocked the request"
            )
        if provider.api_key_env and not provider.local and not os.getenv(provider.api_key_env):
            raise ProviderError(
                f"Provider '{selected_name}' requires environment variable {provider.api_key_env}"
            )
        return provider

    def bind_local_model_admission(self, admission, *, provider_name='local', lane='supplemental'):
        """Host-selected shared reservation; never inferred from a model goal."""
        provider=self.get(provider_name,local_only=True)
        if type(provider) is not OpenAICompatibleProvider:
            raise ValueError('Only the qualified local transport can share model admission')
        provider.bind_model_admission(admission,lane=lane)
        self._local_admission_provider=provider_name

    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[ToolDefinition] | None = None,
        provider_name: str | None = None,
        model: str | None = None,
        local_only: bool = True,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        allow_fallback: bool = True,
    ) -> ModelResponse:
        selected_name = provider_name or self.config.routing.default_provider
        candidates = [selected_name]
        if allow_fallback:
            candidates.extend(
                name
                for name in self.config.routing.fallback_providers
                if name not in candidates
            )
        errors: list[str] = []
        for candidate in candidates:
            try:
                provider = self.get(candidate, local_only=local_only)
                return await provider.generate(
                    messages,
                    tools=tools,
                    model=model if candidate == selected_name else None,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except ModelAdmissionRefused:
                # A busy, stopped or uncertain local request cannot silently
                # become an external/premium request or a budget reset.
                raise
            except ProviderError as exc:
                if getattr(self.providers.get(candidate),'_model_admission',None) is not None:
                    # Selection may fail before provider.generate (for example,
                    # when a bound provider becomes disabled). That must not
                    # bypass its finite resource scope through another provider.
                    raise ModelAdmissionRefused('Bound local provider unavailable; no fallback.') from None
                errors.append(f"{candidate}: {exc}")
                if candidate == selected_name and not allow_fallback:
                    raise
        raise ProviderError("All permitted providers failed: " + " | ".join(errors))

    def describe(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for name, provider in self.providers.items():
            config = self.config.providers[name]
            key_present = bool(os.getenv(provider.api_key_env)) if provider.api_key_env else True
            output.append(
                {
                    "name": name,
                    "model": provider.model,
                    "local": provider.local,
                    "enabled": provider.enabled,
                    "configured": provider.enabled and key_present,
                    "default": name == self.config.routing.default_provider,
                    "kind": config.kind,
                    "base_url": config.base_url,
                    "api_key_env": provider.api_key_env,
                }
            )
        return output

    async def health(self) -> list[dict[str, Any]]:
        return [await provider.health() for provider in self.providers.values()]
