"""DetectLens AI provider layer — base types and adapter factory.

The AI provider is optional: the rest of the system must treat a ``None``
adapter as "AI features unavailable" and degrade gracefully. Duck-typed
``config`` contract (do not import config.py here):

- ``provider``: "none" | "openai_compat" | "anthropic" | "ollama"
- ``base_url``: str | None
- ``model``: str | None
- ``api_key``: str | None  (sourced from the ``DETECTLENS_LLM_KEY`` env var)
- ``local_only``: bool

Key hygiene: the API key is never logged, never embedded in exception
messages, and never included in any returned text.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .openai_compat import OpenAICompatAdapter
    from .anthropic import AnthropicAdapter
    from .ollama import OllamaAdapter


class AIError(Exception):
    """Raised for any AI provider failure. Message is always key-safe."""


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


class LLMAdapter(ABC):
    """Common chat interface implemented by every provider adapter."""

    name: str

    def chat(self, messages: list[ChatMessage], max_tokens: int = 1500,
             timeout: float = 60.0) -> str:
        """Send messages and return the assistant's text reply.

        Raises AIError on any failure. Never leaks the API key.
        """
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """(ok, human-readable message). Must never raise."""

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(name={self.name!r})"


def _safe_str(config: Any, attr: str, default: Any = None) -> Any:
    return getattr(config, attr, default)


def get_adapter(config: Any) -> Optional[LLMAdapter]:
    """Build the configured adapter, or None when AI is unavailable.

    Returns None when: ``config.local_only`` is True, ``provider == "none"``,
    or the provider needs an API key and none is configured.
    """
    # Imported lazily to avoid circular imports (adapters import base).
    from .openai_compat import OpenAICompatAdapter
    from .anthropic import AnthropicAdapter
    from .ollama import OllamaAdapter

    if _safe_str(config, "local_only", False):
        return None

    provider = _safe_str(config, "provider", "none")
    if provider == "none":
        return None

    api_key = _safe_str(config, "api_key", None)
    base_url = _safe_str(config, "base_url", None)
    model = _safe_str(config, "model", None)

    if provider == "openai_compat":
        if not api_key:
            return None
        return OpenAICompatAdapter(
            base_url=(base_url or "https://api.openai.com/v1"),
            api_key=api_key,
            model=(model or "gpt-4o-mini"),
        )
    if provider == "anthropic":
        if not api_key:
            return None
        return AnthropicAdapter(
            base_url=(base_url or "https://api.anthropic.com"),
            api_key=api_key,
            model=(model or "claude-3-5-sonnet-latest"),
        )
    if provider == "ollama":
        # Ollama is local: works offline, no key needed.
        return OllamaAdapter(
            base_url=(base_url or "http://localhost:11434"),
            model=(model or "llama3.1"),
        )
    return None


def ai_available(config: Any) -> bool:
    """True when a working AI adapter can be constructed from config."""
    return get_adapter(config) is not None
