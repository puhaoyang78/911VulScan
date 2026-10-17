"""Offline DeepSeek protocol, config migration, billing, and language tests."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import httpx
import openai
import pytest

from core.backend_identity import fingerprint_for_binding
from utilities.llm import (
    DEEPSEEK_DEFAULT, DEEPSEEK_PRO_DEFAULT, OPENANT_DEFAULT, PHASES,
    LLMAdapter, LLMAuthError, LLMNotFoundError, LLMRateLimitError, LLMRefusalError, LLMResponseError,
    Message, PhaseBinding, TextBlock, ToolDef, ToolResultBlock, ToolUseBlock,
    ProviderConfig, build_adapter, build_phase_registry, empty_config,
    parse_config, resolve_llm_config, resolve_provider, serialise_config,
)
from utilities.llm.language import ChineseOutputAdapter, CHINESE_OUTPUT_POLICY
from utilities.llm.providers import get_adapter_class, known_provider_types
from utilities.llm.providers.deepseek import DeepSeekAdapter, DEFAULT_BASE_URL
from utilities.rate_limiter import reset_rate_limiter


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "ANTHROPIC_API_KEY", "OPENANT_DEEPSEEK_API_KEY_OVERRIDE"):
        monkeypatch.delenv(name, raising=False)
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def response(text="回答", reasoning="private reasoning", tools=None, finish="stop",
             prompt_tokens=20, completion_tokens=10, **usage):
    return NS(choices=[NS(message=NS(content=text, reasoning_content=reasoning,
                                   tool_calls=tools), finish_reason=finish)],
              usage=NS(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, **usage))


def tool(id="call-1", args='{"path":"test.c"}'):
    return NS(id=id, type="function", function=NS(name="read_file", arguments=args))


def adapter(*responses, **kwargs):
    client = MagicMock()
    client.chat.completions.create.side_effect = list(responses)
    return DeepSeekAdapter(_client=client, **kwargs), client


def complete(a, history=None, **kwargs):
    return a.complete(model="deepseek-flash", system="system", max_tokens=4096,
                      messages=history or [Message("user", [TextBlock("检查代码")])], **kwargs)


def test_default_endpoint_env_key_and_no_openai_credential_leak(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "wrong-provider")
    with pytest.raises(LLMAuthError, match="缺少 DeepSeek API 密钥"):
        DeepSeekAdapter()
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-deepseek")
    with patch("utilities.llm.providers.deepseek.openai.OpenAI") as ctor:
        DeepSeekAdapter()
        assert ctor.call_args.kwargs["api_key"] == "test-deepseek"
        assert ctor.call_args.kwargs["base_url"] == DEFAULT_BASE_URL
        assert ctor.call_args.kwargs["organization"] == ""
        assert ctor.call_args.kwargs["timeout"] == 120


def test_explicit_key_endpoint_and_timeout_win(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://env.example/v1")
    with patch("utilities.llm.providers.deepseek.openai.OpenAI") as ctor:
        DeepSeekAdapter(api_key="explicit", base_url="https://proxy.example/v1", request_timeout=75)
    assert ctor.call_args.kwargs["api_key"] == "explicit"
    assert ctor.call_args.kwargs["base_url"] == "https://proxy.example/v1"
    assert ctor.call_args.kwargs["timeout"] == 75


def test_request_shape_and_native_cache_usage():
    a, client = adapter(response(prompt_cache_hit_tokens=12, prompt_cache_miss_tokens=8))
    result = complete(a, tools=[ToolDef("read_file", "read", {"type": "object"})])
    request = client.chat.completions.create.call_args.kwargs
    assert request["extra_body"] == {"thinking": {"type": "enabled"}}
    assert request["max_tokens"] == 4096
    assert request["messages"][0] == {"role": "system", "content": "system"}
    assert request["tools"][0]["function"]["name"] == "read_file"
    assert result.input_tokens == 20
    assert result.output_tokens == 10
    assert result.usage_details == {"cached_tokens": 12, "prompt_cache_miss_tokens": 8}
    assert "private reasoning" not in repr(result)
    assert [b.text for b in result.content if isinstance(b, TextBlock)] == ["回答"]


def test_reasoning_replayed_across_text_only_and_multiple_tool_turns():
    a, client = adapter(
        response(reasoning="first text reasoning"),
        response(None, "tool reasoning", [tool("a"), tool("b")], "tool_calls"),
        response("完成", "final reasoning"),
    )
    history = [Message("user", [TextBlock("检查代码")])]
    first = complete(a, history)
    # Exactly the Text/ToolUse filtering used by existing enhancer/verifier loops.
    history += [Message("assistant", [b for b in first.content if isinstance(b, (TextBlock, ToolUseBlock))]),
                Message("user", [TextBlock("继续")])]
    tools = [ToolDef("read_file", "read", {"type": "object"})]
    second = complete(a, history, tools=tools)
    history += [Message("assistant", list(second.content)),
                Message("user", [ToolResultBlock("a", "A"), ToolResultBlock("b", "B")])]
    complete(a, history, tools=tools)
    request = client.chat.completions.create.call_args.kwargs
    assistants = [m for m in request["messages"] if m["role"] == "assistant"]
    assert [m["reasoning_content"] for m in assistants] == ["first text reasoning", "tool reasoning"]
    assert len(assistants[1]["tool_calls"]) == 2
    assert [m["tool_call_id"] for m in request["messages"] if m["role"] == "tool"] == ["a", "b"]
    assert "reasoning_content" not in next(m for m in request["messages"] if m["role"] == "user")


def test_parallel_histories_remain_isolated():
    client = MagicMock()
    def reply(**kwargs):
        last = kwargs["messages"][-1]["content"]
        return response(last, "reasoning:" + last)
    client.chat.completions.create.side_effect = reply
    a = DeepSeekAdapter(_client=client)
    def run(label):
        first = complete(a, [Message("user", [TextBlock(label)])])
        history = [Message("assistant", first.content), Message("user", [TextBlock("continue:" + label)])]
        complete(a, history)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run, ["one", "two", "three", "four"]))
    for call in client.chat.completions.create.call_args_list:
        req = call.kwargs["messages"]
        assistants = [m for m in req if m["role"] == "assistant"]
        if assistants:
            label = req[-1]["content"].removeprefix("continue:")
            assert assistants[0]["reasoning_content"] == "reasoning:" + label


def test_non_thinking_explicitly_disables_and_does_not_echo_reasoning():
    a, client = adapter(response(), thinking={"type": "disabled"})
    complete(a, [Message("assistant", [TextBlock("prior")]), Message("user", [TextBlock("next")])])
    req = client.chat.completions.create.call_args.kwargs
    assert req["extra_body"] == {"thinking": {"type": "disabled"}}
    assert all("reasoning_content" not in m for m in req["messages"])


@pytest.mark.parametrize("policy", [{}, {"type": "adaptive"}, {"type": "enabled", "budget_tokens": 3}])
def test_invalid_thinking_policy_fails_before_network(policy):
    with pytest.raises(ValueError, match="DeepSeek thinking"):
        DeepSeekAdapter(_client=MagicMock(), thinking=policy)


@pytest.mark.parametrize("model", ["deepseek-chat", "deepseek-reasoner"])
def test_retired_model_rejected_without_network(model):
    a, client = adapter(response())
    with pytest.raises(LLMNotFoundError, match="退役"):
        a.validate(model)
    client.chat.completions.create.assert_not_called()


def test_probe_is_explicit_one_token_non_thinking():
    a, client = adapter(response(None, None, finish="length"))
    a.validate("deepseek-flash")
    req = client.chat.completions.create.call_args.kwargs
    assert req["max_tokens"] == 1
    assert req["extra_body"] == {"thinking": {"type": "disabled"}}


def test_402_is_nonretryable_quota_and_secret_redacted():
    exc = openai.APIStatusError("key=sk-123456789012345678901234", response=httpx.Response(
        402, request=httpx.Request("POST", DEFAULT_BASE_URL)), body={})
    a, _ = adapter(exc)
    with pytest.raises(LLMRateLimitError) as caught:
        complete(a)
    assert caught.value.kind == "quota"
    assert "123456789012345678901234" not in str(caught.value)


@pytest.mark.parametrize("args", ["not-json", "[]", "null"])
def test_invalid_tool_arguments_are_not_executed(args):
    a, _ = adapter(response(None, "reason", [tool(args=args)], "tool_calls"))
    with pytest.raises(LLMResponseError, match="工具参数不是有效 JSON"):
        complete(a)


def test_reasoning_only_truncation_remains_failure_with_billed_usage():
    a, _ = adapter(response(None, "private reasoning", finish="length", prompt_cache_hit_tokens=5))
    with pytest.raises(LLMResponseError) as caught:
        complete(a)
    assert caught.value.input_tokens == 20
    assert caught.value.usage_details == {"cached_tokens": 5}


def test_config_new_and_legacy_selection(monkeypatch):
    assert resolve_llm_config(empty_config(), None) is DEEPSEEK_DEFAULT
    assert resolve_llm_config(empty_config(), "deepseek-pro") is DEEPSEEK_PRO_DEFAULT
    assert resolve_llm_config(empty_config(), "openant-default") is OPENANT_DEFAULT
    for raw in ({"api_key": "legacy"}, {"default_model": "opus"},
                {"llm_providers": {"anthropic": {"type": "anthropic"}}}):
        assert parse_config(raw).default_llm == "openant-default"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "legacy-env")
    assert empty_config().default_llm == "openant-default"
    monkeypatch.setenv("DEEPSEEK_API_KEY", "new-env")
    assert empty_config().default_llm == "deepseek-default"
    assert parse_config({"default_llm": "openant-default"}).default_llm == "openant-default"


def test_provider_registration_and_thinking_roundtrip():
    assert get_adapter_class("deepseek") is DeepSeekAdapter
    assert "deepseek" in known_provider_types()
    assert resolve_provider(empty_config(), "deepseek").type == "deepseek"
    raw = {"llm_providers": {"deepseek": {"type": "deepseek", "thinking": {"type": "disabled"}}}}
    assert serialise_config(parse_config(raw))["llm_providers"]["deepseek"]["thinking"] == {"type": "disabled"}
    with patch("utilities.llm.providers.deepseek.openai.OpenAI"):
        built = build_adapter(ProviderConfig("deepseek", "deepseek", api_key="fake", thinking={"type": "disabled"}))
    assert built.thinking == {"type": "disabled"}


@pytest.mark.parametrize("name", ["deepseek-default", "deepseek-pro"])
def test_deepseek_builtins_are_reserved(name):
    with pytest.raises(Exception, match="built-in"):
        parse_config({"llm_configs": {name: {p: {"provider": "deepseek", "model": "deepseek-flash"} for p in PHASES}}})


def test_chinese_dispatch_is_global_and_cache_identity_changes():
    native = MagicMock()
    native.name = "test-provider"
    native.supports_tools = True
    native.thinking = None
    native.base_url = None
    with patch("utilities.llm.registry.build_adapter", return_value=native):
        registry = build_phase_registry(empty_config(), DEEPSEEK_DEFAULT)
    binding = registry.get("analyze")
    binding.adapter.complete(model="m", system="Return JSON keys unchanged", messages=[], max_tokens=99)
    assert native.complete.call_args.kwargs["system"] == "Return JSON keys unchanged\n\n" + CHINESE_OUTPUT_POLICY
    assert binding.adapter.supports_tools is True
    plain = PhaseBinding("analyze", native, binding.model, binding.provider_name)
    assert fingerprint_for_binding(binding, ["prompt"])["key_digest"] != fingerprint_for_binding(plain, ["prompt"])["key_digest"]
    assert isinstance(binding.adapter, ChineseOutputAdapter)
    assert isinstance(binding.adapter, LLMAdapter)


def test_deepseek_prices_include_native_cache_hit_rate():
    rates = DeepSeekAdapter.pricing
    assert rates["deepseek-flash"]["input"] == .3
    assert rates["deepseek-flash"]["cache_read"] == .02
    assert rates["deepseek-v4-pro"]["output"] == 3.96
    assert "deepseek-chat" not in rates


def test_per_job_override_takes_precedence_without_saving(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ambient")
    monkeypatch.setenv("OPENANT_DEEPSEEK_API_KEY_OVERRIDE", "one-job")
    with patch("utilities.llm.providers.deepseek.openai.OpenAI") as ctor:
        DeepSeekAdapter(api_key="saved")
    assert ctor.call_args.kwargs["api_key"] == "one-job"


def test_real_sdk_mock_transport_preserves_reasoning_and_custom_fields():
    import json
    # Use the transport dependency of the installed SDK (httpx on older
    # supported SDKs, httpx2 on current ones), never a real HTTP connection.
    import openai._base_client as sdk
    http = getattr(sdk, "httpx2", None) or sdk.httpx
    requests = []
    def handle(request):
        requests.append(json.loads(request.content))
        return http.Response(200, json={
            "id": "mock-1", "object": "chat.completion", "created": 1,
            "model": "deepseek-flash",
            "choices": [{"index": 0, "finish_reason": "tool_calls",
                         "message": {"role": "assistant", "content": None,
                                     "reasoning_content": "retained reasoning",
                                     "tool_calls": [{"id": "a", "type": "function",
                                                     "function": {"name": "read_file", "arguments": "{}"}}]}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30,
                      "prompt_cache_hit_tokens": 12, "prompt_cache_miss_tokens": 8},
        })
    with http.Client(transport=http.MockTransport(handle), trust_env=False) as http_client:
        client = openai.OpenAI(api_key="offline-test", base_url=DEFAULT_BASE_URL,
                               http_client=http_client)
        a = DeepSeekAdapter(_client=client)
        first = complete(a)
        complete(a, [Message("assistant", first.content), Message("user", [ToolResultBlock("a", "ok")])])
    assert requests[0]["thinking"] == {"type": "enabled"}
    assert requests[1]["messages"][1]["reasoning_content"] == "retained reasoning"
    assert first.usage_details["cached_tokens"] == 12


def test_deepseek_cache_accounting_is_inclusive_not_double_counted():
    from utilities.llm_client import TokenTracker
    a, _ = adapter(response(prompt_tokens=20000, completion_tokens=10000,
                            prompt_cache_hit_tokens=12000, prompt_cache_miss_tokens=8000))
    result = complete(a)
    record = TokenTracker().record_call(
        model="deepseek-flash", input_tokens=result.input_tokens,
        output_tokens=result.output_tokens, pricing=a.pricing["deepseek-flash"],
        usage_details=result.usage_details,
    )
    assert record["cost_usd"] == pytest.approx((8000 * .3 + 12000 * .006 + 10000 * 1.2) / 1_000_000)
    assert not record.get("cost_incomplete", False)


def test_refusal_is_chinese_and_keeps_billed_usage():
    a, _ = adapter(response(None, "private", finish="content_filter", prompt_cache_hit_tokens=5))
    with pytest.raises(LLMRefusalError, match="拒绝了本次请求") as caught:
        complete(a)
    assert caught.value.input_tokens == 20
    assert caught.value.output_tokens == 10
    assert caught.value.usage_details == {"cached_tokens": 5}
    assert "private" not in str(caught.value)
