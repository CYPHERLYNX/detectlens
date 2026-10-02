"""OpenAI-compatible chat adapter.

Works against api.openai.com and any local OpenAI-compatible server
(vLLM, LM Studio, llama.cpp server, etc.) exposing ``/chat/completions``.
"""

from __future__ import annotations

import httpx

from .base import AIError, ChatMessage, LLMAdapter


class OpenAICompatAdapter(LLMAdapter):
    name = "openai_compat"

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key  # never logged, never in messages
        self.model = model

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def chat(self, messages: list[ChatMessage], max_tokens: int = 1500,
             timeout: float = 60.0) -> str:
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        try:
            resp = httpx.post(url, json=body, headers=self._headers(), timeout=timeout)
        except httpx.TimeoutException:
            raise AIError(f"{self.name}: request timed out after {timeout}s")
        except httpx.HTTPError as e:
            raise AIError(f"{self.name}: connection failed ({type(e).__name__})")
        if resp.status_code != 200:
            raise AIError(f"{self.name}: HTTP {resp.status_code} from {url}")
        try:
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise AIError(f"{self.name}: unexpected response shape from {url}")

    def test_connection(self) -> tuple[bool, str]:
        """Probe GET /models: validates connectivity and the API key."""
        url = f"{self.base_url}/models"
        try:
            resp = httpx.get(url, headers=self._headers(), timeout=10.0)
        except Exception as e:  # never raise
            return False, f"{self.name}: connection failed ({type(e).__name__})"
        if resp.status_code == 200:
            return True, f"{self.name}: connected to {url}"
        if resp.status_code == 401:
            return False, f"{self.name}: authentication failed (HTTP 401); check DETECTLENS_LLM_KEY"
        return False, f"{self.name}: HTTP {resp.status_code} from {url}"
