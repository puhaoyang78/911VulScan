"""Chinese narrative policy for every registry-routed provider and phase."""
from __future__ import annotations

from .adapter import LLMAdapter
from prompts.report_language import CHINESE_REPORT_INSTRUCTION

CHINESE_OUTPUT_POLICY = CHINESE_REPORT_INSTRUCTION.strip()


def with_chinese_output(system: str | None) -> str:
    """Append once, leaving the existing schema and domain instructions intact."""
    if system and CHINESE_OUTPUT_POLICY in system:
        return system
    return f"{system}\n\n{CHINESE_OUTPUT_POLICY}" if system else CHINESE_OUTPUT_POLICY


class ChineseOutputAdapter:
    """Transparent dispatch wrapper; credentials and provider metadata stay native."""

    system_policy = CHINESE_OUTPUT_POLICY

    def __init__(self, adapter: LLMAdapter):
        self._adapter = adapter

    @property
    def name(self):
        return self._adapter.name

    @property
    def supports_tools(self):
        return self._adapter.supports_tools

    def __getattr__(self, name):
        return getattr(self._adapter, name)

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return self._adapter.complete(
            model=model, system=with_chinese_output(system), messages=messages,
            max_tokens=max_tokens, tools=tools,
        )

    def validate(self, model):
        return self._adapter.validate(model)
