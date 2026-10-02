"""Tests for the DetectLens AI provider layer. All network is mocked."""

import os
import sys
from types import SimpleNamespace

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ai.base import (
    AIError,
    ChatMessage,
    ai_available,
    get_adapter,
)
from backend.ai.openai_compat import OpenAICompatAdapter
from backend.ai.anthropic import AnthropicAdapter
from backend.ai.ollama import OllamaAdapter
from backend.ai.prompts import (
    build_redacted_context,
    draft_rule,
    explain_finding,
    explain_rule,
    nl_posture_query,
    redact_prompt_payload,
    report_narrative,
    suppression_proposal,
)

FAKE_KEY = "sk-test-FAKEKEY123"


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def msgs():
    return [ChatMessage(role="system", content="sys"),
            ChatMessage(role="user", content="hi")]


def _patch_post(monkeypatch, response=None, exc=None):
    def fake_post(*args, **kwargs):
        if exc is not None:
            raise exc
        return response
    monkeypatch.setattr(httpx, "post", fake_post)


def _patch_get(monkeypatch, response=None, exc=None):
    def fake_get(*args, **kwargs):
        if exc is not None:
            raise exc
        return response
    monkeypatch.setattr(httpx, "get", fake_get)


# --- openai_compat ---

def test_openai_chat_success(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(200, {
        "choices": [{"message": {"content": "hello from openai"}}]}))
    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "gpt-4o-mini")
    assert a.chat(msgs()) == "hello from openai"


def test_openai_chat_401_raises_aierror_no_key_leak(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(401, {"error": {"message": "bad key"}}))
    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "gpt-4o-mini")
    with pytest.raises(AIError) as ei:
        a.chat(msgs())
    assert FAKE_KEY not in str(ei.value)
    assert "401" in str(ei.value)


def test_openai_chat_timeout_raises_aierror(monkeypatch):
    _patch_post(monkeypatch, exc=httpx.ConnectTimeout("slow"))
    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "gpt-4o-mini")
    with pytest.raises(AIError) as ei:
        a.chat(msgs())
    assert "timed out" in str(ei.value)
    assert FAKE_KEY not in str(ei.value)


def test_openai_chat_bad_shape_raises_aierror(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(200, {"weird": True}))
    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "gpt-4o-mini")
    with pytest.raises(AIError):
        a.chat(msgs())


def test_openai_test_connection_ok(monkeypatch):
    _patch_get(monkeypatch, FakeResponse(200, {"data": []}))
    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "gpt-4o-mini")
    ok, msg = a.test_connection()
    assert ok is True
    assert FAKE_KEY not in msg


def test_openai_test_connection_401_no_raise_no_key_leak(monkeypatch):
    _patch_get(monkeypatch, FakeResponse(401, {}))
    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "gpt-4o-mini")
    ok, msg = a.test_connection()
    assert ok is False and isinstance(msg, str)
    assert FAKE_KEY not in msg
    assert "DETECTLENS_LLM_KEY" in msg


def test_openai_test_connection_unreachable_no_raise(monkeypatch):
    _patch_get(monkeypatch, exc=httpx.ConnectError("down"))
    a = OpenAICompatAdapter("http://127.0.0.1:9", FAKE_KEY, "gpt-4o-mini")
    ok, msg = a.test_connection()
    assert ok is False and isinstance(msg, str)


# --- anthropic ---

def test_anthropic_chat_success(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(200, {
        "content": [{"type": "text", "text": "hello "},
                    {"type": "text", "text": "from anthropic"}]}))
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "claude-3-5-sonnet-latest")
    assert a.chat(msgs()) == "hello from anthropic"


def test_anthropic_chat_401_no_key_leak(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(401, {"error": {"message": "bad"}}))
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "claude-3-5-sonnet-latest")
    with pytest.raises(AIError) as ei:
        a.chat(msgs())
    assert FAKE_KEY not in str(ei.value)


def test_anthropic_chat_timeout(monkeypatch):
    _patch_post(monkeypatch, exc=httpx.ReadTimeout("slow"))
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "claude-3-5-sonnet-latest")
    with pytest.raises(AIError) as ei:
        a.chat(msgs())
    assert FAKE_KEY not in str(ei.value)


def test_anthropic_system_msg_split(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        return FakeResponse(200, {"content": [{"type": "text", "text": "ok"}]})
    monkeypatch.setattr(httpx, "post", fake_post)
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "m")
    a.chat(msgs())
    assert captured["body"]["system"] == "sys"
    assert captured["body"]["messages"] == [{"role": "user", "content": "hi"}]


def test_anthropic_headers_carry_key_safely(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeResponse(200, {"content": [{"type": "text", "text": "ok"}]})
    monkeypatch.setattr(httpx, "post", fake_post)
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "m")
    a.chat(msgs())
    assert captured["headers"]["x-api-key"] == FAKE_KEY
    assert captured["headers"]["anthropic-version"] == "2023-06-01"


def test_anthropic_test_connection_ok(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(200, {"content": [{"type": "text", "text": "p"}]}))
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "m")
    ok, msg = a.test_connection()
    assert ok is True and FAKE_KEY not in msg


def test_anthropic_test_connection_401(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(401, {}))
    a = AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "m")
    ok, msg = a.test_connection()
    assert ok is False and FAKE_KEY not in msg and "401" in msg


# --- ollama ---

def test_ollama_chat_success(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(200, {"message": {"content": "local hello"}}))
    a = OllamaAdapter("http://localhost:11434", "llama3.1")
    assert a.chat(msgs()) == "local hello"


def test_ollama_chat_500(monkeypatch):
    _patch_post(monkeypatch, FakeResponse(500, {}))
    a = OllamaAdapter("http://localhost:11434", "llama3.1")
    with pytest.raises(AIError) as ei:
        a.chat(msgs())
    assert "500" in str(ei.value)


def test_ollama_chat_timeout(monkeypatch):
    _patch_post(monkeypatch, exc=httpx.ConnectTimeout("slow"))
    a = OllamaAdapter("http://localhost:11434", "llama3.1")
    with pytest.raises(AIError):
        a.chat(msgs())


def test_ollama_test_connection_model_found(monkeypatch):
    _patch_get(monkeypatch, FakeResponse(200, {"models": [{"name": "llama3.1:latest"}]}))
    a = OllamaAdapter("http://localhost:11434", "llama3.1")
    ok, msg = a.test_connection()
    assert ok is True


def test_ollama_test_connection_model_not_found(monkeypatch):
    _patch_get(monkeypatch, FakeResponse(200, {"models": [{"name": "mistral:latest"}]}))
    a = OllamaAdapter("http://localhost:11434", "llama3.1")
    ok, msg = a.test_connection()
    assert ok is False
    assert "not found" in msg and "llama3.1" in msg


def test_ollama_test_connection_server_down(monkeypatch):
    _patch_get(monkeypatch, exc=httpx.ConnectError("refused"))
    a = OllamaAdapter("http://localhost:11434", "llama3.1")
    ok, msg = a.test_connection()
    assert ok is False and isinstance(msg, str)


# --- get_adapter / ai_available ---

def _cfg(**kw):
    base = dict(provider="none", base_url=None, model=None, api_key=None,
                local_only=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_get_adapter_local_only_none():
    assert get_adapter(_cfg(local_only=True, provider="openai_compat", api_key=FAKE_KEY)) is None


def test_get_adapter_provider_none():
    assert get_adapter(_cfg(provider="none", api_key=FAKE_KEY)) is None


def test_get_adapter_openai_missing_key_none():
    assert get_adapter(_cfg(provider="openai_compat")) is None


def test_get_adapter_anthropic_missing_key_none():
    assert get_adapter(_cfg(provider="anthropic")) is None


def test_get_adapter_ollama_no_key_ok():
    a = get_adapter(_cfg(provider="ollama"))
    assert isinstance(a, OllamaAdapter)
    assert a.base_url == "http://localhost:11434"


def test_get_adapter_openai_defaults():
    a = get_adapter(_cfg(provider="openai_compat", api_key=FAKE_KEY))
    assert isinstance(a, OpenAICompatAdapter)
    assert a.base_url == "https://api.openai.com/v1"


def test_get_adapter_anthropic_defaults():
    a = get_adapter(_cfg(provider="anthropic", api_key=FAKE_KEY))
    assert isinstance(a, AnthropicAdapter)
    assert a.base_url == "https://api.anthropic.com"


def test_get_adapter_custom_base_url_model():
    a = get_adapter(_cfg(provider="openai_compat", api_key=FAKE_KEY,
                         base_url="http://127.0.0.1:8000/v1", model="local-model"))
    assert a.base_url == "http://127.0.0.1:8000/v1"
    assert a.model == "local-model"


def test_get_adapter_unknown_provider_none():
    assert get_adapter(_cfg(provider="weird", api_key=FAKE_KEY)) is None


def test_ai_available():
    assert ai_available(_cfg(provider="ollama")) is True
    assert ai_available(_cfg(provider="none")) is False
    assert ai_available(_cfg(provider="openai_compat")) is False


# --- prompts ---

def _text(prompt):
    return "\n".join(m.content for m in prompt)


def test_prompts_all_grounding_preamble():
    prompts = [
        explain_finding({"title": "t", "severity": "s", "rule_ids": [1],
                         "technique_ids": ["T1"], "counts": {"a": 1}}, {"T1": "n"}),
        draft_rule({"id": "T1", "name": "n"}, [], None),
        suppression_proposal({"id": 1}, [], 5),
        nl_posture_query("q", "fields"),
        explain_rule({"id": 1, "xml": "<rule/>"}),
        report_narrative({"score": 1}),
    ]
    for p in prompts:
        assert isinstance(p, list) and all(isinstance(m, ChatMessage) for m in p)
        assert p[0].role == "system"
        t = _text(p)
        assert "NEVER invent" in t
        assert "unknown" in t


def test_explain_finding_grounding():
    finding = {"title": "Suspicious PowerShell",
               "severity": "high",
               "rule_ids": [100002, 100100],
               "technique_ids": ["T1059.001"],
               "counts": {"alerts": 42, "agents": 7}}
    p = explain_finding(finding, {"T1059.001": "PowerShell"})
    t = _text(p)
    assert "Suspicious PowerShell" in t and "high" in t
    assert "rule 100002" in t and "rule 100100" in t
    assert "T1059.001" in t and "PowerShell" in t
    assert "alerts: 42" in t and "agents: 7" in t


def test_draft_rule_xml_only_and_unused_id():
    p = draft_rule({"id": "T1059.001", "name": "PowerShell",
                    "tactics": ["execution"], "description": "runs commands"},
                   [100100, 100101], "<rule id=\"100100\">")
    t = _text(p)
    assert "100102" in t  # next unused id >= 100100
    assert "100100" in t  # listed as taken
    assert "T1059.001" in t
    assert "Output ONLY the XML block" in t
    assert "NEVER be auto-applied" in t


def test_draft_rule_empty_existing_starts_at_100100():
    p = draft_rule({"id": "T1", "name": "n"}, [], None)
    assert "100100" in _text(p)


def test_suppression_proposal_conservative():
    rule = {"id": 100002, "description": "noisy rule", "level": 5}
    alerts = [{"agent": "a1", "srcip": "10.0.0.1", "user": "bob",
               "description": "fired"}]
    p = suppression_proposal(rule, alerts, 9001)
    t = _text(p)
    assert "100002" in t and "9001" in t
    assert "10.0.0.1" in t and "a1" in t
    assert "NEVER suggest disabling" in t


def test_nl_posture_query_json_only():
    p = nl_posture_query("which rules are dead?", "fields: rules.id, rules.status")
    t = _text(p)
    assert "which rules are dead?" in t
    assert "Output ONLY a JSON object" in t
    assert "shown to the user before it is run" in t


def test_explain_rule_grounding():
    p = explain_rule({"id": 100002, "level": 10, "description": "ssh brute force",
                      "xml": "<rule id=\"100002\" level=\"10\">"})
    t = _text(p)
    assert "100002" in t and "ssh brute force" in t
    assert "false positives" in t


def test_report_narrative_no_invented_numbers():
    summary = {"score": 62, "techniques_covered": 31, "techniques_total": 200,
               "dead_rules": 4, "noisy_rules": 9,
               "top_gaps": ["T1059.001", "T1078"]}
    t = _text(report_narrative(summary))
    for n in ["62", "31", "200", "4", "9", "T1059.001", "T1078"]:
        assert n in t
    assert "Do not invent any numbers" in t


def test_redact_helpers():
    def fake_redact(text, toggles):
        return text.replace("10.0.0.9", "[IP]") if toggles.get("redact_ips") else text

    toggles = {"redact_ips": True}
    assert redact_prompt_payload("hit 10.0.0.9 ok", toggles, fake_redact) == "hit [IP] ok"
    # no callable -> unchanged
    assert redact_prompt_payload("hit 10.0.0.9 ok", toggles) == "hit 10.0.0.9 ok"
    joined = build_redacted_context(["a 10.0.0.9", "b plain"], toggles, fake_redact)
    assert joined == "a [IP]\n\nb plain"


# --- key hygiene sweep ---

def test_key_never_in_outputs(monkeypatch):
    """The fake key must not appear in any exception or returned text."""
    outputs = []

    def fake_post(*args, **kwargs):
        # some adapters send the key in headers by design; echo it back
        # in the body to prove we never forward response content into errors
        return FakeResponse(200, {"choices": [{"message": {"content": "clean"}}]})
    monkeypatch.setattr(httpx, "post", fake_post)

    a = OpenAICompatAdapter("https://api.openai.com/v1", FAKE_KEY, "m")
    outputs.append(a.chat(msgs()))

    for adapter, url, model in [
        (AnthropicAdapter("https://api.anthropic.com", FAKE_KEY, "m"), None, None),
        (OllamaAdapter("http://localhost:11434", "m"), None, None),
    ]:
        if isinstance(adapter, AnthropicAdapter):
            monkeypatch.setattr(
                httpx, "post",
                lambda *a2, **k2: FakeResponse(
                    200, {"content": [{"type": "text", "text": "clean"}]}))
            outputs.append(adapter.chat(msgs()))
        else:
            monkeypatch.setattr(
                httpx, "post",
                lambda *a2, **k2: FakeResponse(200, {"message": {"content": "clean"}}))
            outputs.append(adapter.chat(msgs()))

    _patch_get(monkeypatch, FakeResponse(200, {"models": [{"name": "m:latest"}]}))
    for adapter in [OpenAICompatAdapter("https://x", FAKE_KEY, "m"),
                    AnthropicAdapter("https://x", FAKE_KEY, "m"),
                    OllamaAdapter("http://localhost:11434", "m")]:
        if isinstance(adapter, AnthropicAdapter):
            monkeypatch.setattr(
                httpx, "post",
                lambda *a2, **k2: FakeResponse(
                    200, {"content": [{"type": "text", "text": "p"}]}))
        ok, msg = adapter.test_connection()
        outputs.append(msg)

    # error paths
    _patch_post(monkeypatch, FakeResponse(403, {"error": "forbidden"}))
    for adapter in [OpenAICompatAdapter("https://x", FAKE_KEY, "m"),
                    AnthropicAdapter("https://x", FAKE_KEY, "m"),
                    OllamaAdapter("http://localhost:11434", "m")]:
        try:
            adapter.chat(msgs())
        except AIError as e:
            outputs.append(str(e))

    for o in outputs:
        assert FAKE_KEY not in o, f"key leaked in: {o!r}"
