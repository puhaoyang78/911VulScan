package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

// validateAPIKey is the back-compat wrapper for “openant set-api-key“.
// Delegates to the shared “probeAnthropic“ helper which is also used by
// “openant setup llm“ so both code paths agree on what "the key works"
// means.
func validateAPIKey(key string) error {
	err := probeAnthropic(key, "", "claude-haiku-4-5-20251001")
	if err == nil {
		return nil
	}
	pe, ok := asProbeError(err)
	if !ok {
		return err
	}
	// A 404 (model_not_found) means the key AUTHENTICATED — auth is
	// checked before model resolution — but this account can't see the
	// probe model (e.g. enterprise/allow-listed orgs without Haiku
	// access). The key is valid, so don't reject it over the model.
	if pe.Kind == "model_not_found" {
		return nil
	}
	// Transient server-side failures (429 rate-limit, 5xx) are NOT a
	// verdict on the key — rejecting here would refuse a likely-valid
	// key just because Anthropic was busy. Soft-pass and save it; the
	// next real call will surface a genuinely bad key. Only a
	// conclusive auth failure (401/403, Kind=="auth") should reject.
	if pe.Status == http.StatusTooManyRequests || pe.Status >= http.StatusInternalServerError {
		return nil
	}
	return err
}

var setAPIKeyProvider string

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key [key]",
	Short: "保存 DeepSeek 或 Anthropic API 密钥",
	Long: `保存当前模型服务商的 API 密钥。

首次使用默认选择 DeepSeek；已有 Anthropic 配置继续使用 Anthropic。
使用 --provider 可明确指定服务商或已配置的服务商名称：

  openant set-api-key --provider deepseek
  openant set-api-key --provider anthropic

不传 key 参数时，交互提示不会回显密钥。密钥保存在
~/.config/openant/config.json，文件权限为 0600。
也可设置 DEEPSEEK_API_KEY 或 ANTHROPIC_API_KEY 环境变量。
DeepSeek 自定义端点可通过 DEEPSEEK_BASE_URL 设置。

API 密钥：https://platform.deepseek.com/api_keys
Anthropic：https://console.anthropic.com/settings/keys

兼容位置参数传入密钥，但这会暴露在 shell 历史和进程列表中。
建议使用不回显的交互输入。验证会发起一个最小 API 请求，可能计费。`,
	Args: cobra.MaximumNArgs(1),
	Run:  runSetAPIKey,
}

func init() {
	setAPIKeyCmd.Flags().StringVar(&setAPIKeyProvider, "provider", "", "服务商名称（默认使用当前配置，首次使用为 deepseek）")
}

// resolveKeyProvider never infers a provider from secret contents. Explicit
// provider names win; otherwise use the active analyze-phase binding.
func resolveKeyProvider(cfg *config.Config, requested string) (string, config.ProviderEntry, error) {
	name := strings.TrimSpace(requested)
	if name == "" {
		// Credential setup for a built-in profile must not require finding
		// the external model registry, which older standalone installs may
		// not have shipped next to the binary.
		switch cfg.DefaultLLM() {
		case config.DeepSeekDefaultLLM, config.DeepSeekProLLM:
			name = "deepseek"
		case config.LegacyDefaultLLM:
			name = "anthropic"
		default:
			ref, ok := cfg.LLMPhase("", "analyze")
			if !ok {
				return "", config.ProviderEntry{}, fmt.Errorf("无法解析默认模型配置 %q；请使用 --provider deepseek 或 --provider anthropic", cfg.DefaultLLM())
			}
			name = ref.Provider
		}
	}
	entry, exists := cfg.GetProvider(name)
	if !exists && (name == "deepseek" || name == "anthropic") {
		entry.Type = name
		exists = true
	}
	if !exists || (entry.Type != "deepseek" && entry.Type != "anthropic") {
		return "", config.ProviderEntry{}, fmt.Errorf("服务商 %q 不支持此密钥命令；请使用 openant setup llm 配置", name)
	}
	return name, entry, nil
}

func runSetAPIKey(cmd *cobra.Command, args []string) {
	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	providerName, provider, err := resolveKeyProvider(cfg, setAPIKeyProvider)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	var key string
	if len(args) == 1 {
		key = strings.TrimSpace(args[0])
	} else {
		reader := bufio.NewReader(os.Stdin)
		k, err := promptSecret(reader, providerName+" API 密钥")
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(1)
		}
		key = strings.TrimSpace(k)
	}
	if key == "" {
		output.PrintError("API 密钥不能为空")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "正在向 %s 验证 API 密钥（最小请求，可能计费）... ", providerName)
	if provider.Type == "deepseek" {
		err = probeDeepSeek(key, provider.BaseURL, config.DeepSeekModel)
	} else if provider.BaseURL != "" || providerName != "anthropic" {
		err = probeAnthropic(key, provider.BaseURL, "claude-haiku-4-5-20251001")
	} else {
		err = validateAPIKey(key)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr)
		output.PrintError(err.Error())
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "完成")

	if err := cfg.SetProviderAPIKey(providerName, provider.Type, key); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr)
	output.PrintSuccess(fmt.Sprintf("%s API 密钥已保存（%s）", providerName, config.MaskKey(key)))
	fmt.Fprintln(os.Stderr)
}
