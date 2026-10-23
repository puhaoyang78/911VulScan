"""Run the shared chat contract scenarios through the DeepSeek adapter."""
from utilities.llm.providers.deepseek import DeepSeekAdapter
from .openai import make_adapter as make_openai_adapter


def make_adapter(scenario):
    return DeepSeekAdapter(_client=make_openai_adapter(scenario)._client)
