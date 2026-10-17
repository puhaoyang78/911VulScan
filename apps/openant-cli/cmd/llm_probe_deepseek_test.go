package cmd

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
)

func TestDeepSeekEndpointRootV1AndEnvironment(t *testing.T) {
	t.Setenv("DEEPSEEK_BASE_URL", "")
	orig := deepseekAPIBase
	deepseekAPIBase = config.DeepSeekBaseURL
	t.Cleanup(func() { deepseekAPIBase = orig })
	for base, want := range map[string]string{"": "https://api.deepseek.com/chat/completions", "https://example.test/v1/": "https://example.test/v1/chat/completions", "https://example.test/": "https://example.test/chat/completions"} {
		if got := deepseekEndpoint(base); got != want {
			t.Errorf("%q => %q, want %q", base, got, want)
		}
	}
	t.Setenv("DEEPSEEK_BASE_URL", "https://env.example.test/v1")
	if got := deepseekEndpoint(""); got != "https://env.example.test/v1/chat/completions" {
		t.Error(got)
	}
	if got := deepseekEndpoint("https://explicit.test"); got != "https://explicit.test/chat/completions" {
		t.Error(got)
	}
}

func TestProbeDeepSeekRequestAndStatus(t *testing.T) {
	for _, status := range []int{200, 401, 402, 403, 404, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/chat/completions" {
					t.Error(r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer fixture" {
					t.Error("missing bearer key")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if payload["model"] != config.DeepSeekModel || payload["max_tokens"] != float64(1) {
					t.Error(payload)
				}
				if payload["thinking"].(map[string]any)["type"] != "disabled" {
					t.Error("thinking enabled")
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			err := probeDeepSeek("fixture", server.URL+"/v1", config.DeepSeekModel)
			if status == 200 && err != nil {
				t.Fatal(err)
			}
			if status != 200 {
				pe, ok := asProbeError(err)
				if !ok || pe.Status != status {
					t.Fatalf("%d: %v", status, err)
				}
				if status == 402 && !strings.Contains(err.Error(), "余额不足") {
					t.Error(err)
				}
			}
		})
	}
}

func TestSetAPIKeyFreshDefaultsToDeepSeek(t *testing.T) {
	withFakeConfigHome(t)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	t.Setenv("DEEPSEEK_BASE_URL", "")
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.URL.Path != "/chat/completions" {
			t.Error(r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	origBase, origProvider := deepseekAPIBase, setAPIKeyProvider
	deepseekAPIBase, setAPIKeyProvider = server.URL, ""
	t.Cleanup(func() { deepseekAPIBase, setAPIKeyProvider = origBase, origProvider })
	runSetAPIKey(setAPIKeyCmd, []string{"fixture-deepseek-key"})
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.GetProvider("deepseek")
	if !ok || p.APIKey != "fixture-deepseek-key" || cfg.APIKey != "" || cfg.DefaultLLM() != config.DeepSeekDefaultLLM {
		t.Fatal("wrong persisted provider/default")
	}
	if count != 1 {
		t.Fatal(count)
	}
}

func TestSetupDeepSeekDefaultAndReservedNames(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	cfg := &config.Config{}
	if got := defaultStartingProvider(cfg); got != "deepseek" {
		t.Fatal(got)
	}
	if !stringSliceContains(supportedProviderTypes, "deepseek") {
		t.Fatal("missing DeepSeek")
	}
	reader := bufio.NewReader(strings.NewReader("deepseek-default\ndeepseek-pro\nopenant-default\ncustom\n"))
	name, ok, err := promptLLMConfigName(reader, cfg)
	if err != nil || !ok || name != "custom" {
		t.Fatalf("%q %v %v", name, ok, err)
	}
}

func TestResolveKeyProviderRespectsLegacyAndExplicitSelection(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	cfg := &config.Config{APIKey: "legacy-fixture"}
	name, p, err := resolveKeyProvider(cfg, "")
	if err != nil || name != "anthropic" || p.Type != "anthropic" {
		t.Fatalf("%s %+v %v", name, p, err)
	}
	name, p, err = resolveKeyProvider(cfg, "deepseek")
	if err != nil || name != "deepseek" || p.Type != "deepseek" {
		t.Fatalf("%s %+v %v", name, p, err)
	}
	if _, _, err := resolveKeyProvider(cfg, "typo"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestSetupLLMWizardDeepSeekFreshProfile(t *testing.T) {
	path := withFakeConfigHome(t)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	t.Setenv("DEEPSEEK_BASE_URL", "")
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.URL.Path != "/chat/completions" {
			t.Error(r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	orig := deepseekAPIBase
	deepseekAPIBase = server.URL
	t.Cleanup(func() { deepseekAPIBase = orig })
	lines := []string{"my-deepseek", "", "", "fixture", "", ""}
	for range len(setupLLMPhases) - 1 {
		lines = append(lines, "", "")
	}
	lines = append(lines, "y")
	withScriptedStdin(t, strings.Join(lines, "\n")+"\n")
	runSetupLLM(nil, nil)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"deepseek"`) || strings.Contains(string(data), `"anthropic"`) {
		t.Fatal("wrong provider")
	}
	if count != 1 {
		t.Fatal(count)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range setupLLMPhases {
		ref, ok := cfg.LLMPhase("my-deepseek", phase.name)
		if !ok || ref != (config.LLMPhaseRef{Provider: "deepseek", Model: config.DeepSeekModel}) {
			t.Fatalf("blank input did not select Flash for %s: %+v", phase.name, ref)
		}
	}
}

func TestSetupAndKeySelectionPreserveExplicitCustomProfile(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "legacy-fixture")
	t.Setenv("DEEPSEEK_API_KEY", "")
	cfg := &config.Config{APIKey: "old-fixture"}
	cfg.WriteLLMConfig("team", map[string]config.LLMPhaseRef{"analyze": {Provider: "team-deepseek", Model: "custom-model"}}, map[string]config.ProviderEntry{"team-deepseek": {Type: "deepseek", BaseURL: "https://example.test/v1"}}, true)
	if got := defaultStartingProvider(cfg); got != "team-deepseek" {
		t.Fatal(got)
	}
	name, p, err := resolveKeyProvider(cfg, "")
	if err != nil || name != "team-deepseek" || p.Type != "deepseek" || p.BaseURL != "https://example.test/v1" {
		t.Fatalf("%s %+v %v", name, p, err)
	}
	if err := cfg.SetProviderAPIKey(name, p.Type, "rotated-fixture"); err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultLLM() != "team" {
		t.Fatal("explicit profile replaced by key update")
	}
}
