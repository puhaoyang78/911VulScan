# Modified 2026-10-23 for the VulScan-only product namespace.
"""Immutable built-in profiles.

Fresh installations use deepseek-default (Flash); deepseek-pro is the optional
Pro profile. vulscan-default and get_builtin_default() retain historical Claude
bindings so explicit legacy selections never silently switch providers.
Provider credentials/endpoints remain user-configurable. Model IDs come from
utilities.model_config and pricing from config/models.json.
"""

from __future__ import annotations

from ..model_config import CLAUDE_OPUS, CLAUDE_SONNET, DEEPSEEK_FLASH, DEEPSEEK_PRO
from .config import LLMConfig, PhaseRef, PHASES


# Provider name referenced by every phase. Synthesised from the
# legacy ``api_key`` field by the migrator, or set via
# ``vulscan set-api-key``.
_ANTHROPIC_PROVIDER = "anthropic"


# Per-phase Claude defaults — preserves today's behavior on upgrade.
# When this file changes, the CHANGELOG must say so, because every
# existing user without a custom llm-config picks up the new IDs on
# the next ``vulscan scan``.
VULSCAN_DEFAULT = LLMConfig(
    name="vulscan-default",
    phases={
        # Stage 1 detection. Opus by historical default.
        "analyze": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Context enhancement (agentic + single-shot). Sonnet for cost.
        "enhance": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_SONNET),
        # Stage 2 attacker simulation. Opus, uses tool calling.
        "verify": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Disclosure + summary + remediation HTML generation. Opus —
        # matches master's report/generator.py report-generator default.
        # The refactor briefly moved this to Sonnet; restored so the
        # report output (incl. the HTML-remediation sub-call) stays on
        # Opus on a fresh, config-less install.
        "report": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Docker exploit-test generation. Sonnet.
        "dynamic_test": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_SONNET),
        # LLM-driven reachability review (opt-in stage). Opus.
        "llm_reach": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Application-context classification (web_app / cli_tool / etc).
        # Single-shot, runs once per scan during ``vulscan scan``. Sonnet.
        "app_context": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_SONNET),
    },
)


# Public, callable accessor so callers don't accidentally mutate the
# module-level dict. The dataclass is frozen so the dict-mutation
# foot-gun is mostly hypothetical, but this gives us a single hook
# if we ever want to load the default from disk for testing.
def get_builtin_default() -> LLMConfig:
    """Historical named profile accessor; use resolve_llm_config for selection."""
    return VULSCAN_DEFAULT


# Keep vulscan-default immutable for existing Anthropic users. Fresh installs
# select deepseek-default in config.py; a named profile always wins.
DEEPSEEK_DEFAULT = LLMConfig(
    name="deepseek-default",
    phases={phase: PhaseRef(provider="deepseek", model=DEEPSEEK_FLASH) for phase in PHASES},
)
DEEPSEEK_PRO_DEFAULT = LLMConfig(
    name="deepseek-pro",
    phases={phase: PhaseRef(provider="deepseek", model=DEEPSEEK_PRO) for phase in PHASES},
)
BUILTIN_CONFIGS = {config.name: config for config in (
    DEEPSEEK_DEFAULT, DEEPSEEK_PRO_DEFAULT, VULSCAN_DEFAULT,
)}
