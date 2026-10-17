package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/knostic/open-ant-cli/internal/models"
)

const (
	DeepSeekDefaultLLM = "deepseek-default"
	DeepSeekProLLM     = "deepseek-pro"
	LegacyDefaultLLM   = "openant-default"
	DeepSeekModel      = "deepseek-flash"
	DeepSeekProModel   = "deepseek-v4-pro"
	DeepSeekBaseURL    = "https://api.deepseek.com"
)

// IsBuiltinLLM reports reserved profile names. Keep this in sync with the
// Python pipeline's utilities/llm/builtins.py.
func IsBuiltinLLM(name string) bool {
	return name == DeepSeekDefaultLLM || name == DeepSeekProLLM || name == LegacyDefaultLLM
}

// DefaultLLM mirrors Python's profile selection. Explicit selections always
// win. Existing Anthropic configuration (including env-only installations)
// keeps its previous behavior; fresh installations use DeepSeek.
func (c *Config) DefaultLLM() string {
	if c != nil {
		if name, ok := c.raw["default_llm"].(string); ok && name != "" {
			return name
		}
		if strings.TrimSpace(c.APIKey) != "" || strings.TrimSpace(c.DefaultModel) != "" {
			return LegacyDefaultLLM
		}
		if _, ok := c.GetProvider("anthropic"); ok {
			return LegacyDefaultLLM
		}
	}
	if strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) != "" && strings.TrimSpace(os.Getenv("DEEPSEEK_API_KEY")) == "" {
		return LegacyDefaultLLM
	}
	return DeepSeekDefaultLLM
}

// LLMPhase resolves a built-in or user-authored phase for display and setup.
// An empty name selects DefaultLLM; unknown or incomplete profiles fail closed.
// It does not call a provider or validate credentials.
func (c *Config) LLMPhase(name, phase string) (LLMPhaseRef, bool) {
	if name == "" {
		name = c.DefaultLLM()
	}
	switch phase {
	case "analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach", "app_context":
	default:
		return LLMPhaseRef{}, false
	}
	switch name {
	case DeepSeekDefaultLLM:
		return LLMPhaseRef{Provider: "deepseek", Model: DeepSeekModel}, true
	case DeepSeekProLLM:
		return LLMPhaseRef{Provider: "deepseek", Model: DeepSeekProModel}, true
	case LegacyDefaultLLM:
		// The historical report phase uses the strong model, while the
		// custom-config wizard suggests the light model for reports.
		modelPhase := phase
		if phase == "report" {
			modelPhase = "analyze"
		}
		model, err := models.DefaultModel("anthropic", modelPhase)
		return LLMPhaseRef{Provider: "anthropic", Model: model}, err == nil
	}
	if c == nil {
		return LLMPhaseRef{}, false
	}
	profiles, _ := c.raw["llm_configs"].(map[string]any)
	profile, _ := profiles[name].(map[string]any)
	entry, _ := profile[phase].(map[string]any)
	provider, _ := entry["provider"].(string)
	model, _ := entry["model"].(string)
	return LLMPhaseRef{Provider: provider, Model: model}, provider != "" && model != ""
}

// EffectiveProvider resolves built-in entries and environment fallbacks. The
// returned key is sensitive: callers must only expose a masked value or a
// readiness boolean. Explicit provider credentials take priority over env.
func (c *Config) EffectiveProvider(name string) (ProviderEntry, bool) {
	var entry ProviderEntry
	var exists bool
	if c != nil {
		entry, exists = c.GetProvider(name)
	}
	if !exists {
		switch name {
		case "deepseek", "anthropic":
			entry.Type = name
		default:
			return ProviderEntry{}, false
		}
		if name == "anthropic" && c != nil {
			// Python only migrates the legacy key before schema v2. The
			// Go invoker also forwards it when there are no v2 providers.
			version, _ := strconv.ParseFloat(fmt.Sprint(c.raw["$schema_version"]), 64)
			if version < 2 || !c.HasV2Providers() {
				entry.APIKey = strings.TrimSpace(c.APIKey)
			}
		}
	}
	entry.APIKey = strings.TrimSpace(entry.APIKey)
	entry.BaseURL = strings.TrimSpace(entry.BaseURL)
	if entry.APIKey == "" {
		keyEnv := map[string]string{
			"deepseek": "DEEPSEEK_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
			"openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY",
			"google": "GOOGLE_API_KEY",
		}
		if env := keyEnv[entry.Type]; env != "" {
			entry.APIKey = os.Getenv(env)
		}
		if entry.Type == "google" && entry.APIKey == "" {
			entry.APIKey = os.Getenv("GEMINI_API_KEY")
		}
	}
	if entry.Type == "deepseek" && entry.BaseURL == "" {
		entry.BaseURL = os.Getenv("DEEPSEEK_BASE_URL")
		if entry.BaseURL == "" {
			entry.BaseURL = DeepSeekBaseURL
		}
	}
	return entry, true
}

// SetProviderAPIKey rotates one named provider without copying its key to
// another provider. Legacy Anthropic keys retain their top-level mirror.
// Other provider settings and explicit default_llm selections are preserved.
func (c *Config) SetProviderAPIKey(name, providerType, key string) error {
	if name == "" || (providerType != "deepseek" && providerType != "anthropic") {
		return fmt.Errorf("unsupported API-key provider %q; use deepseek or anthropic", providerType)
	}
	if existing, ok := c.GetProvider(name); ok && existing.Type != providerType {
		return fmt.Errorf("provider %q has type %q, not %q", name, existing.Type, providerType)
	}
	_, defaultAuthored := c.raw["default_llm"]
	pinFreshDeepSeek := !defaultAuthored && name == "deepseek" && providerType == "deepseek" && c.DefaultLLM() == DeepSeekDefaultLLM
	if c.raw == nil {
		c.raw = map[string]any{}
	}
	providers, _ := c.raw["llm_providers"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
		c.raw["llm_providers"] = providers
	}
	// Adding a v2 provider must not strand a preexisting legacy key when
	// the schema marker disables Python's v1 migration.
	if _, ok := providers["anthropic"]; !ok && c.APIKey != "" {
		providers["anthropic"] = map[string]any{"type": "anthropic", "api_key": c.APIKey}
	}
	entry, _ := providers[name].(map[string]any)
	if entry == nil {
		entry = map[string]any{}
	}
	entry["type"] = providerType
	entry["api_key"] = key
	providers[name] = entry
	c.raw["$schema_version"] = 2
	if pinFreshDeepSeek {
		// Persist the fresh installation's selection so an unrelated
		// Anthropic-only environment in a later shell cannot switch it.
		c.raw["default_llm"] = DeepSeekDefaultLLM
	}
	if name == "anthropic" && providerType == "anthropic" {
		c.APIKey = key
	}
	return nil
}
