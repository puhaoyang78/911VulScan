package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLegacyAPIKeyFlagRejectsDeepSeekSelection(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	old := apiKeyFlag
	defer func() { apiKeyFlag = old }()
	apiKeyFlag = "test-only-placeholder"
	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().String("llm-config", "", "")
	if err := validateLegacyKeyFlag(cmd, nil); err == nil || !strings.Contains(err.Error(), "DEEPSEEK_API_KEY") {
		t.Fatalf("fresh DeepSeek selection must explain the legacy key flag: %v", err)
	}
	if err := cmd.Flags().Set("llm-config", "openant-default"); err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyKeyFlag(cmd, nil); err != nil {
		t.Fatalf("explicit legacy profile must remain supported: %v", err)
	}
}

func TestRequireAPIKeyAllowsProviderOwnedEnvironment(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DEEPSEEK_API_KEY", "test-only-placeholder")
	old := apiKeyFlag
	defer func() { apiKeyFlag = old }()
	apiKeyFlag = ""
	if got := requireAPIKey(); got != "" {
		t.Fatal("DeepSeek credentials must never become the legacy Anthropic argument")
	}
}
