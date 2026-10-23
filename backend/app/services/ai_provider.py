"""
AI Provider Abstraction Layer
Supports configured hosted LLMs (OpenAI-compatible API) or Gemini.
Credentials are loaded from server-side environment variables only.
API keys are never exposed to the frontend.
"""
import json
import logging
import time
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod

import httpx

from app.config import settings

logger = logging.getLogger("securesbom.ai_provider")


class AIProviderError(Exception):
    """Raised when the AI provider returns an error or is unavailable."""
    pass


class AIProviderTimeout(AIProviderError):
    """Raised on provider timeout."""
    pass


class AIProviderRateLimit(AIProviderError):
    """Raised when the provider rate-limits the request."""
    pass


class BaseAIProvider(ABC):
    """Abstract base for AI providers."""

    @abstractmethod
    async def complete(self, system_prompt: str, user_prompt: str, timeout: float = 60.0) -> str:
        """
        Send a chat completion request and return the raw text response.
        Raises AIProviderError subclasses on failure.
        """
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model identifier string."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider is configured and usable."""
        ...


class OpenAICompatibleProvider(BaseAIProvider):
    """
    Provider for OpenAI-compatible APIs (OpenAI, Azure OpenAI, Ollama, etc.)
    Configured via environment variables. Never exposes credentials to clients.
    """

    def __init__(self):
        self._api_key = settings.AI_API_KEY
        self._base_url = settings.AI_BASE_URL.rstrip("/")
        self._model = settings.AI_MODEL_NAME
        self._max_tokens = settings.AI_MAX_TOKENS

    @property
    def model_name(self) -> str:
        return self._model or "unknown-model"

    @property
    def is_available(self) -> bool:
        # Require at minimum a model name; key may be empty for local models
        return bool(self._model and self._base_url)

    async def complete(self, system_prompt: str, user_prompt: str, timeout: float = 60.0) -> str:
        if not self.is_available:
            raise AIProviderError("AI provider is not configured. Set AI_BASE_URL and AI_MODEL_NAME.")

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self._max_tokens,
            "temperature": 0.1,   # Low temperature for analytical tasks
        }

        url = f"{self._base_url}/chat/completions"

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise AIProviderTimeout(f"AI provider request timed out after {timeout}s") from exc
        except httpx.RequestError as exc:
            raise AIProviderError(f"AI provider connection error: {exc}") from exc

        if response.status_code == 429:
            raise AIProviderRateLimit("AI provider rate limit reached. Try again later.")

        if response.status_code >= 400:
            # Never log full response body (may contain provider-internal details)
            raise AIProviderError(
                f"AI provider returned HTTP {response.status_code}. Check credentials and endpoint."
            )

        try:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AIProviderError(f"Unexpected AI provider response format: {exc}") from exc


class GeminiProvider(BaseAIProvider):
    """
    Provider for Google Gemini via REST API.
    Configured via AI_API_KEY (Gemini API key) and AI_MODEL_NAME.
    """

    GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self):
        self._api_key = settings.AI_API_KEY
        self._model = settings.AI_MODEL_NAME or "gemini-1.5-flash"
        self._max_tokens = settings.AI_MAX_TOKENS

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_available(self) -> bool:
        return bool(self._api_key and self._model)

    async def complete(self, system_prompt: str, user_prompt: str, timeout: float = 60.0) -> str:
        if not self.is_available:
            raise AIProviderError("Gemini provider not configured. Set AI_API_KEY and AI_MODEL_NAME.")

        url = f"{self.GEMINI_BASE}/{self._model}:generateContent?key={self._api_key}"

        combined = f"{system_prompt}\n\n{user_prompt}"
        payload = {
            "contents": [{"parts": [{"text": combined}]}],
            "generationConfig": {
                "maxOutputTokens": self._max_tokens,
                "temperature": 0.1,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise AIProviderTimeout(f"Gemini request timed out after {timeout}s") from exc
        except httpx.RequestError as exc:
            raise AIProviderError(f"Gemini connection error: {exc}") from exc

        if response.status_code == 429:
            raise AIProviderRateLimit("Gemini rate limit reached.")

        if response.status_code >= 400:
            raise AIProviderError(f"Gemini returned HTTP {response.status_code}.")

        try:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AIProviderError(f"Unexpected Gemini response format: {exc}") from exc


class MockAIProvider(BaseAIProvider):
    """
    Mock AI Provider for automated tests, offline evaluation, and CI pipelines.
    Never calls external networks. Produces strictly schema-compliant assessments.
    """

    def __init__(self, response_text: Optional[str] = None):
        self._response_text = response_text
        self._model = "mock-security-llm"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_available(self) -> bool:
        return True

    async def complete(self, system_prompt: str, user_prompt: str, timeout: float = 60.0) -> str:
        if self._response_text:
            return self._response_text
        return json.dumps({
            "title": "Mock Assessment of Potential Dependency Weakness",
            "description": "Mock automated analysis grounded in retrieved package evidence.",
            "assessment_type": "emerging_advisory_analysis",
            "evidence": ["Retrieved advisory data matching installed version"],
            "evidence_sources": ["OSV PyPI advisory feed"],
            "potential_impact": "Medium impact if untrusted inputs reach affected components",
            "confidence": "medium",
            "confidence_explanation": "Advisory verified against installed version range",
            "verification_steps": ["Check installed package version against fixed releases"],
            "suggested_mitigations": ["Apply recommended package upgrade"],
            "related_advisory_ids": [],
            "limitations": "Mock assessment for testing and verification only."
        })


def get_ai_provider() -> BaseAIProvider:
    """
    Return the configured AI provider instance.
    Selection is driven entirely by server-side environment variables.
    """
    provider_type = (settings.AI_PROVIDER or "openai").lower()
    if provider_type == "mock":
        return MockAIProvider()
    if provider_type == "gemini":
        return GeminiProvider()
    return OpenAICompatibleProvider()
