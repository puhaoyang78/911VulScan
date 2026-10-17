"""Chinese narrative policy for every registry-routed provider and phase."""
from __future__ import annotations

from .adapter import LLMAdapter

CHINESE_OUTPUT_POLICY = (
    "输出语言要求：所有面向用户的自然语言内容必须使用简体中文，"
    "包括漏洞描述、诊断、结论、解释、修复建议、报告、摘要和工具参数中的叙述文本。"
    "保持约定的 JSON 字段名、枚举值、标识符、代码、命令、文件路径、URL、"
    "模型名、漏洞编号和机器可读协议不变；不要翻译这些结构化内容。"
    "遵循原有输出格式，不要添加格式之外的说明。"
)


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
