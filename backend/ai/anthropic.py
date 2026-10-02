"""Anthropic Messages API adapter."""

from __future__ import annotations

import httpx

from .base import AIError, ChatMessage, LLMAdapter


class AnthropicAdapter(LLMAdapter):
    name = "anthropic"

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key  # never logged, never in messages
        self.model = model

    def _headers(self) -> dict:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    def _request_body(self, messages: list[ChatMessage], max_tokens: int) -> dict:
        system_parts = [m.content for m in messages if m.role == "system"]
        body: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in messages if m.role != "system"
            ],
        }
        if system_parts:
            body["system"] = system_parts[0]
        return body

    def chat(self, messages: list[ChatMessage], max_tokens: int = 1500,
             timeout: float = 60.0) -> str:
        url = f"{self.base_url}/v1/messages"
        try:
            resp = httpx.post(url, json=self._request_body(messages, max_tokens),
                              headers=self._headers(), timeout=timeout)
        except httpx.TimeoutException:
            raise AIError(f"{self.name}: request timed out after {timeout}s")
        except httpx.HTTPError as e:
            raise AIError(f"{self.name}: connection failed ({type(e).__name__})")
        if resp.status_code != 200:
            raise AIError(f"{self.name}: HTTP {resp.status_code} from {url}")
        try:
            data = resp.json()
            texts = [b.get("text", "") for b in data["content"]
                     if isinstance(b, dict) and b.get("type") == "text"]
            return "".join(texts)
        except (ValueError, KeyError, TypeError):
            raise AIError(f"{self.name}: unexpected response shape from {url}")

    def test_connection(self) -> tuple[bool, str]:
        """Minimal 1-token messages call: validates connectivity and the key."""
        try:
            reply = self.chat([ChatMessage(role="user", content="ping")],
                              max_tokens=1, timeout=15.0)
        except AIError as e:
            msg = str(e)
            if "401" in msg:
                return False, f"{self.name}: authentication failed (HTTP 401); check DETECTLENS_LLM_KEY"
            return False, f"{self.name}: {msg}"
        except Exception as e:  # never raise
            return False, f"{self.name}: connection failed ({type(e).__name__})"
        return True, f"{self.name}: connected (model {self.model})"
