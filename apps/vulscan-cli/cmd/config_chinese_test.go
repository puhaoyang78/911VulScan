// Modified 2026-10-23 for the VulScan-only product namespace.
package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/config"
)

func TestConfigDisplayFreshDeepSeekHasNoSecret(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "complete-secret-never-display")
	text := fmt.Sprint(configDisplayRows(&config.Config{}))
	for _, want := range []string{"deepseek-default", "deepseek / deepseek-flash", "密钥已配置，未验证", "报告生成"} {
		if !strings.Contains(text, want) {
			t.Errorf("configuration display missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "complete-secret") {
		t.Fatal("configuration display leaks key material")
	}
}

func TestConfigDisplayRespectsCustomPhaseBindings(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	cfg := &config.Config{APIKey: "legacy-secret"}
	cfg.WriteLLMConfig("mixed-profile", map[string]config.LLMPhaseRef{
		"analyze": {Provider: "deepseek", Model: "deepseek-v4-pro"},
		"report":  {Provider: "local", Model: "my-local-model"},
	}, map[string]config.ProviderEntry{
		"deepseek": {Type: "deepseek", APIKey: "custom-secret"},
		"local":    {Type: "ollama"},
	}, true)
	text := fmt.Sprint(configDisplayRows(cfg))
	for _, want := range []string{"mixed-profile", "deepseek / deepseek-v4-pro", "local / my-local-model", "本地服务，不要求 API 密钥", "无法解析模型绑定", "旧版 Anthropic"} {
		if !strings.Contains(text, want) {
			t.Errorf("custom configuration display missing %q: %s", want, text)
		}
	}
	for _, secret := range []string{"custom-secret", "legacy-secret"} {
		if strings.Contains(text, secret) {
			t.Fatal("secret rendered in configuration display")
		}
	}
}
