"""DetectLens AI provider layer: adapters, factory, and prompt templates."""

from .base import (
    AIError,
    ChatMessage,
    LLMAdapter,
    ai_available,
    get_adapter,
)
from .openai_compat import OpenAICompatAdapter
from .anthropic import AnthropicAdapter
from .ollama import OllamaAdapter
from .prompts import (
    build_redacted_context,
    draft_rule,
    explain_finding,
    explain_rule,
    nl_posture_query,
    redact_prompt_payload,
    report_narrative,
    suppression_proposal,
)

__all__ = [
    "AIError",
    "ChatMessage",
    "LLMAdapter",
    "ai_available",
    "get_adapter",
    "OpenAICompatAdapter",
    "AnthropicAdapter",
    "OllamaAdapter",
    "build_redacted_context",
    "draft_rule",
    "explain_finding",
    "explain_rule",
    "nl_posture_query",
    "redact_prompt_payload",
    "report_narrative",
    "suppression_proposal",
]
