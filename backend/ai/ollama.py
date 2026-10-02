"""Ollama local chat adapter.

No API key needed. Works fully offline against a local Ollama server.
"""

from __future__ import annotations

import httpx

from .base import AIError, ChatMessage, LLMAdapter


class OllamaAdapter(LLMAdapter):
    name = "ollama"

    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def chat(self, messages: list[ChatMessage], max_tokens: int = 1500,
             timeout: float = 60.0) -> str:
        url = f"{self.base_url}/api/chat"
        body = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": max_tokens},
        }
        try:
            resp = httpx.post(url, json=body, timeout=timeout)
        except httpx.TimeoutException:
            raise AIError(f"{self.name}: request timed out after {timeout}s")
        except httpx.HTTPError as e:
            raise AIError(f"{self.name}: connection failed ({type(e).__name__})")
        if resp.status_code != 200:
            raise AIError(f"{self.name}: HTTP {resp.status_code} from {url}")
        try:
            data = resp.json()
            return data["message"]["content"]
        except (ValueError, KeyError, TypeError):
            raise AIError(f"{self.name}: unexpected response shape from {url}")

    def test_connection(self) -> tuple[bool, str]:
        """Check the server is up and the configured model is present."""
        url = f"{self.base_url}/api/tags"
        try:
            resp = httpx.get(url, timeout=10.0)
        except Exception as e:  # never raise
            return False, f"{self.name}: connection failed ({type(e).__name__}); is Ollama running at {self.base_url}?"
        if resp.status_code != 200:
            return False, f"{self.name}: HTTP {resp.status_code} from {url}"
        try:
            models = [m.get("name", "") for m in resp.json().get("models", [])]
        except (ValueError, AttributeError, TypeError):
            return False, f"{self.name}: unexpected response shape from {url}"
        names = {m.split(":")[0] for m in models} | set(models)
        wanted = self.model.split(":")[0]
        if wanted not in names and self.model not in names:
            return False, (f"{self.name}: model '{self.model}' not found on server "
                           f"(available: {', '.join(sorted(models)) or 'none'}); "
                           f"run `ollama pull {self.model}`")
        return True, f"{self.name}: connected, model '{self.model}' available"
