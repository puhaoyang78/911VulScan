"""First-class DeepSeek Chat Completions adapter.

Official contract (checked 2026-10-17):
https://api-docs.deepseek.com/guides/thinking_mode/
https://api-docs.deepseek.com/quick_start/pricing/

Thinking is enabled by default. With tools, DeepSeek requires reasoning_content
from ALL historical assistant turns, including prose-only turns. Private
TextBlock/ToolUseBlock subclasses carry it without exposing it as visible text
or introducing a fourth content kind. The existing agent loops preserve these
instances when echoing content. There is no shared history or tool-ID cache,
so concurrent scans cannot leak reasoning into each other's requests.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import openai

from ..adapter import (
    CompletionResult, LLMAuthError, LLMConnectionError, LLMNotFoundError, LLMRateLimitError,
    LLMRefusalError, LLMResponseError, Message, TextBlock, ToolDef, ToolUseBlock,
)
from .._pricing import LazyProviderPricing
from .._redact import redact_secrets, redacted_cause_from
from ._ratelimit import wait_for_rate_limit
from .openai import (
    _map_openai_exception, _messages_to_openai, _response_to_unified,
    _extract_usage_details_chat, _tool_to_openai,
)

DEFAULT_BASE_URL = "https://api.deepseek.com"
_RETIRED_MODELS = frozenset({"deepseek-chat", "deepseek-reasoner"})


@dataclass(frozen=True)
class _ReasoningTextBlock(TextBlock):
    _deepseek_reasoning_content: str = field(default="", repr=False, compare=False)


@dataclass(frozen=True)
class _ReasoningToolUseBlock(ToolUseBlock):
    _deepseek_reasoning_content: str = field(default="", repr=False, compare=False)


def _check_model(model: str) -> None:
    if model in _RETIRED_MODELS:
        raise LLMNotFoundError(
            f"DeepSeek 模型 {model!r} 已于 2026-07-24 退役。"
            "请使用 deepseek-flash 或 deepseek-v4-pro。"
        )


def _messages_to_deepseek(messages, system, *, thinking: bool):
    # DeepSeek always uses system (never OpenAI's model-name-based developer
    # role heuristic). The empty model avoids interpreting custom gateway IDs.
    native = _messages_to_openai(messages, system, "")
    assistants = (m for m in messages if m.role == "assistant")
    for item in native:
        if item["role"] != "assistant":
            continue
        source = next(assistants)
        reasoning = next((
            block._deepseek_reasoning_content
            for block in source.content
            if isinstance(block, (_ReasoningTextBlock, _ReasoningToolUseBlock))
        ), "")
        if thinking:
            item["reasoning_content"] = reasoning
    return native


def _usage_details(usage: Any) -> dict | None:
    details = _extract_usage_details_chat(usage) or {}
    # DeepSeek's flat cache-hit counter is INCLUDED in prompt_tokens. Map it
    # to the existing inclusive cache accounting field; never add it again.
    hit = getattr(usage, "prompt_cache_hit_tokens", None)
    if hit is not None:
        details["cached_tokens"] = hit
    miss = getattr(usage, "prompt_cache_miss_tokens", None)
    if miss is not None:
        details["prompt_cache_miss_tokens"] = miss
    return details or None


def _response_to_deepseek(response: Any) -> CompletionResult:
    usage = getattr(response, "usage", None)
    details = _usage_details(usage)
    try:
        result = _response_to_unified(response, adapter="DeepSeekAdapter")
    except LLMResponseError as exc:
        # Preserve billed usage even on a refusal, empty, or truncated reply.
        exc.input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        exc.output_tokens = getattr(usage, "completion_tokens", 0) or 0
        exc.usage_details = details
        choices = getattr(response, "choices", None) or []
        finish = getattr(choices[0], "finish_reason", None) if choices else None
        if isinstance(exc, LLMRefusalError):
            message = "DeepSeek 拒绝了本次请求（content_filter）"
        elif finish == "length":
            message = "DeepSeek 输出已达到 max_tokens 上限，未返回可用文本或工具调用；分析未完成"
        else:
            message = "DeepSeek 未返回可用文本或工具调用；请求可能被过滤，或响应格式无效"
        exc.args = (message,)
        raise
    message = response.choices[0].message
    for call in getattr(message, "tool_calls", None) or []:
        try:
            args = json.loads(call.function.arguments or "{}")
            if not isinstance(args, dict):
                raise ValueError("tool arguments must be a JSON object")
        except (ValueError, TypeError) as exc:
            raise LLMResponseError(
                "DeepSeek 返回的工具参数不是有效 JSON 对象；已停止执行不完整的工具调用",
                input_tokens=result.input_tokens, output_tokens=result.output_tokens,
                usage_details=details,
            ) from exc
    reasoning = getattr(message, "reasoning_content", None)
    if reasoning is not None and not isinstance(reasoning, str):
        raise LLMResponseError(
            "DeepSeek 返回的 reasoning_content 无效（必须是字符串或 null）",
            input_tokens=result.input_tokens, output_tokens=result.output_tokens,
            usage_details=details,
        )
    # A missing field can occur on a non-thinking route. Echo the empty string
    # rather than manufacturing reasoning or changing the visible answer.
    reasoning = reasoning or ""
    result.content = tuple(
        _ReasoningTextBlock(b.text, reasoning) if isinstance(b, TextBlock)
        else _ReasoningToolUseBlock(b.id, b.name, b.input, reasoning)
        if isinstance(b, ToolUseBlock) else b
        for b in result.content
    )
    result.usage_details = details
    return result


def _classify_error(exc: Exception, *, report_rl: bool):
    # DeepSeek documents 402 as insufficient balance. It is not a transient
    # throttle: do not arm global backoff or repeatedly charge retries.
    if getattr(exc, "status_code", None) == 402:
        return LLMRateLimitError(
            "DeepSeek 账户余额不足（HTTP 402）：" + redact_secrets(str(exc)),
            kind="quota",
        )
    mapped = _map_openai_exception(exc, report_rl=report_rl)
    labels = {
        LLMAuthError: "身份验证失败", LLMNotFoundError: "模型或接口地址不存在",
        LLMRateLimitError: "请求受到限流", LLMConnectionError: "无法连接 API",
        LLMResponseError: "API 响应错误",
    }
    mapped.args = (f"DeepSeek {labels.get(type(mapped), '调用失败')}：{mapped}",)
    return mapped


class DeepSeekAdapter:
    name = "deepseek"
    supports_tools = True
    pricing = LazyProviderPricing("deepseek")

    def __init__(self, *, api_key=None, base_url=None, max_retries=2,
                 request_timeout=120, thinking=None, _client=None):
        self.thinking = dict(thinking) if thinking is not None else {"type": "enabled"}
        if self.thinking not in ({"type": "enabled"}, {"type": "disabled"}):
            raise ValueError("DeepSeek thinking 必须为 {\"type\": \"enabled\"} 或 {\"type\": \"disabled\"}")
        if request_timeout <= 0:
            raise ValueError("DeepSeek request_timeout 必须为正数")
        self.base_url = base_url or os.environ.get("DEEPSEEK_BASE_URL") or DEFAULT_BASE_URL
        if _client is not None:
            self._client = _client
            return
        # The web UI passes an explicitly entered one-job key in this isolated
        # child-only variable. It must override a saved key without rewriting it.
        override = os.environ.get("OPENANT_DEEPSEEK_API_KEY_OVERRIDE", "").strip()
        key = override or (api_key if api_key is not None else os.environ.get("DEEPSEEK_API_KEY"))
        if not key or not key.strip():
            raise LLMAuthError(
                "缺少 DeepSeek API 密钥。请设置 DEEPSEEK_API_KEY 或 "
                "llm_providers.deepseek.api_key；不会使用 OpenAI/Anthropic 的密钥。"
            )
        self._client = openai.OpenAI(
            api_key=key, base_url=self.base_url, max_retries=max_retries,
            timeout=request_timeout, organization="", project="",
        )

    def complete(self, *, model: str, system: str | None, messages: list[Message],
                 max_tokens: int, tools: list[ToolDef] | None = None) -> CompletionResult:
        _check_model(model)
        request = {
            "model": model, "max_tokens": max_tokens,
            "messages": _messages_to_deepseek(
                messages, system, thinking=self.thinking["type"] == "enabled"),
            "extra_body": {"thinking": dict(self.thinking)},
        }
        if tools:
            request["tools"] = [_tool_to_openai(tool) for tool in tools]
        wait_for_rate_limit()
        try:
            response = self._client.chat.completions.create(**request)
        except (openai.APIStatusError, openai.APIConnectionError) as exc:
            raise _classify_error(exc, report_rl=True) from redacted_cause_from(exc)
        return _response_to_deepseek(response)

    def validate(self, model: str) -> None:
        _check_model(model)
        # Cheap credential/model probe. Explicitly disable thinking for this
        # one-token ping; no scan content is transmitted by validation.
        try:
            response = self._client.chat.completions.create(
                model=model, max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
                extra_body={"thinking": {"type": "disabled"}},
            )
        except (openai.APIStatusError, openai.APIConnectionError) as exc:
            raise _classify_error(exc, report_rl=False) from redacted_cause_from(exc)
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise LLMResponseError("DeepSeek 密钥验证未返回 choices，响应无效")
        if getattr(choices[0], "finish_reason", None) == "content_filter":
            raise LLMRefusalError("DeepSeek 拒绝了密钥验证请求（content_filter）")
