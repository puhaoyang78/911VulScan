package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDefaultLLMDeepSeekAndLegacyPrecedence(t *testing.T) {
	for _, tc := range []struct{ name, raw, anthropic, deepseek, want string }{
		{"fresh", `{}`, "", "", DeepSeekDefaultLLM},
		{"project", `{"active_project":"org/repo"}`, "", "", DeepSeekDefaultLLM},
		{"custom", `{"default_llm":"custom","api_key":"old"}`, "", "", "custom"},
		{"explicit deepseek", `{"default_llm":"deepseek-default","api_key":"old"}`, "old", "", DeepSeekDefaultLLM},
		{"explicit pro", `{"default_llm":"deepseek-pro"}`, "old", "", DeepSeekProLLM},
		{"explicit legacy", `{"default_llm":"openant-default"}`, "", "new", LegacyDefaultLLM},
		{"legacy key", `{"api_key":"old"}`, "", "new", LegacyDefaultLLM},
		{"legacy model", `{"default_model":"claude"}`, "", "", LegacyDefaultLLM},
		{"legacy provider", `{"llm_providers":{"anthropic":{"type":"anthropic"}}}`, "", "", LegacyDefaultLLM},
		{"deepseek provider", `{"llm_providers":{"deepseek":{"type":"deepseek"}}}`, "", "", DeepSeekDefaultLLM},
		{"legacy env", `{}`, "old", "", LegacyDefaultLLM},
		{"both env", `{}`, "old", "new", DeepSeekDefaultLLM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ANTHROPIC_API_KEY", tc.anthropic)
			t.Setenv("DEEPSEEK_API_KEY", tc.deepseek)
			withConfigJSON(t, tc.raw)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.DefaultLLM(); got != tc.want {
				t.Fatalf("default = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeepSeekBuiltinPhaseResolution(t *testing.T) {
	cfg := &Config{}
	for _, name := range []string{DeepSeekDefaultLLM, DeepSeekProLLM, LegacyDefaultLLM} {
		if !IsBuiltinLLM(name) {
			t.Errorf("%q not reserved", name)
		}
		for _, phase := range []string{"analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach", "app_context"} {
			ref, ok := cfg.LLMPhase(name, phase)
			if !ok || ref.Provider == "" || ref.Model == "" {
				t.Fatalf("incomplete %s/%s: %+v", name, phase, ref)
			}
			if name == DeepSeekDefaultLLM && ref != (LLMPhaseRef{Provider: "deepseek", Model: DeepSeekModel}) {
				t.Error(ref)
			}
			if name == DeepSeekProLLM && ref != (LLMPhaseRef{Provider: "deepseek", Model: DeepSeekProModel}) {
				t.Error(ref)
			}
		}
	}
	if _, ok := cfg.LLMPhase(DeepSeekDefaultLLM, "typo"); ok {
		t.Error("unknown phase accepted")
	}
	if _, ok := cfg.LLMPhase("unknown", "analyze"); ok {
		t.Error("unknown config accepted")
	}
	cfg.WriteLLMConfig("custom", map[string]LLMPhaseRef{"analyze": {Provider: "proxy", Model: "model"}}, nil, true)
	if ref, ok := cfg.LLMPhase("", "analyze"); !ok || ref.Model != "model" {
		t.Error(ref)
	}
	if _, ok := cfg.LLMPhase("custom", "verify"); ok {
		t.Error("missing phase silently replaced")
	}
}

func TestEffectiveDeepSeekProviderDoesNotCrossKeys(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "deepseek-env-fixture")
	t.Setenv("DEEPSEEK_BASE_URL", "https://example.test/v1")
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-env-fixture")
	cfg := &Config{APIKey: "legacy-fixture"}
	p, ok := cfg.EffectiveProvider("deepseek")
	if !ok || p.APIKey != "deepseek-env-fixture" || p.BaseURL != "https://example.test/v1" {
		t.Fatal(p)
	}
	if err := cfg.SetProviderAPIKey("deepseek", "deepseek", "deepseek-stored-fixture"); err != nil {
		t.Fatal(err)
	}
	p, _ = cfg.EffectiveProvider("deepseek")
	if p.APIKey != "deepseek-stored-fixture" {
		t.Fatal("environment replaced stored key")
	}
	anth, _ := cfg.EffectiveProvider("anthropic")
	if anth.APIKey != "legacy-fixture" {
		t.Fatal("cross-provider key changed")
	}
	if _, ok := cfg.EffectiveProvider("missing"); ok {
		t.Error("unknown provider synthesized")
	}
}

func TestSetDeepSeekKeyPreservesLegacyAndUnknownSettings(t *testing.T) {
	withConfigJSON(t, `{"api_key":"legacy-fixture","default_llm":"custom","llm_providers":{"deepseek":{"type":"deepseek","api_key":"old","base_url":"https://example.test/v1","thinking":{"type":"disabled"},"request_timeout":123}},"future":{"keep":true}}`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetProviderAPIKey("deepseek", "deepseek", "new-fixture"); err != nil {
		t.Fatal(err)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	path, _ := Path()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["default_llm"] != "custom" || got["api_key"] != "legacy-fixture" || got["future"] == nil {
		t.Fatal("unrelated config lost")
	}
	providers := got["llm_providers"].(map[string]any)
	p := providers["deepseek"].(map[string]any)
	if p["api_key"] != "new-fixture" || p["base_url"] != "https://example.test/v1" || p["thinking"] == nil || p["request_timeout"] != float64(123) {
		t.Fatal(p)
	}
	if providers["anthropic"].(map[string]any)["api_key"] != "legacy-fixture" {
		t.Fatal("legacy key stranded by v2 marker")
	}
	if err := cfg.SetProviderAPIKey("deepseek", "anthropic", "wrong-fixture"); err == nil {
		t.Error("mismatched type accepted")
	}
}

func TestFreshDeepSeekKeyNeverPopulatesAnthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	cfg := &Config{}
	if err := cfg.SetProviderAPIKey("deepseek", "deepseek", "fixture"); err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "" {
		t.Fatal("key copied into legacy field")
	}
	if _, ok := cfg.GetProvider("anthropic"); ok {
		t.Fatal("Anthropic provider created")
	}
	t.Setenv("ANTHROPIC_API_KEY", "unrelated-later-shell-fixture")
	if cfg.DefaultLLM() != DeepSeekDefaultLLM {
		t.Fatal("fresh saved DeepSeek selection switched with an unrelated environment")
	}
}

func TestEffectiveProviderDoesNotReviveStrandedV2LegacyKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	withConfigJSON(t, `{"$schema_version":2,"api_key":"stranded-fixture","llm_providers":{"deepseek":{"type":"deepseek"}}}`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.EffectiveProvider("anthropic")
	if !ok || p.APIKey != "" {
		t.Fatal("schema2 legacy key incorrectly marked active")
	}
}
