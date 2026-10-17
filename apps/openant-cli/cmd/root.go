// Package cmd implements the Cobra CLI commands for OpenAnt.
package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags.
var version = "dev"

// Persistent flags shared across commands.
var (
	jsonOutput  bool
	quiet       bool
	apiKeyFlag  string
	projectFlag string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:               "openant",
	Short:             "911VulScan：大语言模型驱动的代码漏洞扫描",
	PersistentPreRunE: validateLegacyKeyFlag,
	Long: `911VulScan 基于 OpenAnt，默认使用 DeepSeek 分析代码漏洞。
支持 Python、JavaScript/TypeScript、Go、C/C++ 等语言。

第一阶段：分析代码并识别潜在漏洞
第二阶段：模拟攻击者复核，减少误报
动态验证：在 Docker 隔离环境中运行复现测试

常用命令：
  serve             启动中文网页工作台
  setup llm         配置模型供应商与 API 密钥
  scan              完整扫描：解析 → 增强 → 检测 → 验证 → 报告
  diff              扫描与基准提交或 GitHub PR 相比发生变化的代码
  parse             从代码库提取代码单元
  generate-context  生成应用安全上下文
  enhance           增强已解析代码的安全上下文
  analyze           执行第一阶段漏洞检测
  verify            执行第二阶段攻击验证
  build-output      汇总 pipeline_output.json
  dynamic-test      在 Docker 中隔离执行动态验证
  report            生成中文报告
  config            管理配置

首次使用建议：openant setup llm
也可设置 DEEPSEEK_API_KEY 后运行扫描。`,
}

// validateLegacyKeyFlag keeps the historical flag provider-scoped. DeepSeek
// credentials are configured separately, so an old flag cannot be silently
// ignored or routed to an unintended provider.
func validateLegacyKeyFlag(cmd *cobra.Command, _ []string) error {
	if apiKeyFlag == "" || cmd.Name() == "patch" {
		// Auto Patcher retains its own explicit legacy provider selector.
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	profile := ""
	if flag := cmd.Flags().Lookup("llm-config"); flag != nil {
		profile = flag.Value.String()
	}
	if phase, ok := cfg.LLMPhase(profile, "analyze"); ok {
		if provider, ok := cfg.EffectiveProvider(phase.Provider); ok && provider.Type == "deepseek" {
			return fmt.Errorf("--api-key 仅用于旧版 Anthropic 配置；DeepSeek 请使用 DEEPSEEK_API_KEY 或 openant set-api-key --provider deepseek")
		}
	}
	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	localizeCommandHelp(rootCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

// resolveAPIKeyFor returns the API key the Python subprocess should
// receive as “ANTHROPIC_API_KEY“ env, with v2-aware gating.
//
// Takes a pre-loaded “*config.Config“ so a caller that already has
// one (“requireAPIKey“) doesn't pay for a second “Load()“.
//
// Precedence:
//
//  1. “--api-key“ flag — always wins.
//  2. If the config has an “llm_providers“ section, return “""“.
//     Python reads per-provider keys from the file itself; injecting
//     the legacy “api_key“ here would override an explicit
//     “llm_providers["anthropic"].api_key=null“ and potentially
//     leak an Anthropic key to an OpenRouter-pointed provider.
//  3. Otherwise (v1-only / fresh-install path), return the legacy
//     “api_key“ field so the Python migration finds it.
func resolveAPIKeyFor(cfg *config.Config) string {
	if apiKeyFlag != "" {
		return apiKeyFlag
	}
	if cfg == nil {
		return ""
	}
	if cfg.HasV2Providers() {
		return ""
	}
	return cfg.APIKey
}

// resolvedAPIKey is the public surface that callers use when they
// don't already have a loaded “Config“. It does one “Load()“
// and delegates to :func:`resolveAPIKeyFor`. Errors loading config
// fall through to an empty string — same as the previous behavior.
func resolvedAPIKey() string {
	cfg, err := config.Load()
	if err != nil {
		// Honor the flag even when config is unreadable so an
		// emergency one-off invocation still works.
		if apiKeyFlag != "" {
			return apiKeyFlag
		}
		return ""
	}
	return resolveAPIKeyFor(cfg)
}

// requireAPIKey returns the resolved API key or exits with a helpful error
// telling the user how to configure one. Use this in commands that make
// LLM calls (enhance, analyze, verify, scan, dynamic-test).
//
// When the user has authored a v2 “llm_providers“ section, we
// trust them to have configured keys per provider and don't fail
// here: Python will surface a clear error from
// “registry.validate()“ at scan start if any of those keys are
// missing or wrong.
func requireAPIKey() string {
	cfg, _ := config.Load()
	if cfg != nil && cfg.HasV2Providers() {
		// v2 path: Python reads keys from the providers entries.
		// Honor the --api-key flag override if present, otherwise
		// stay out of the way.
		return apiKeyFlag
	}
	// Provider SDKs read their own environment. Never pass a DeepSeek key
	// through the legacy Anthropic-only positional apiKey argument.
	if os.Getenv("DEEPSEEK_API_KEY") != "" || os.Getenv("ANTHROPIC_API_KEY") != "" {
		return apiKeyFlag
	}
	// Reuse the loaded cfg — don't pay for a second config.Load().
	key := resolveAPIKeyFor(cfg)
	if key != "" {
		return key
	}
	fmt.Fprintln(os.Stderr, "错误：尚未配置模型 API 密钥。")
	fmt.Fprintln(os.Stderr, "运行 openant setup llm 配置 DeepSeek，或设置 DEEPSEEK_API_KEY 环境变量。")
	fmt.Fprintln(os.Stderr, "也可在 config.json 的 llm_providers 中配置其他供应商。")
	fmt.Fprintln(os.Stderr, "DeepSeek API 密钥管理：https://platform.deepseek.com/api_keys")
	os.Exit(2)
	return "" // unreachable
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "输出原始 JSON（供程序读取，字段名与枚举保持兼容）")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "隐藏进度输出")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "旧版 Anthropic 密钥覆盖（仅传给 ANTHROPIC_API_KEY）；DeepSeek 请使用 DEEPSEEK_API_KEY 或 setup llm")
	rootCmd.PersistentFlags().StringVarP(&projectFlag, "project", "p", "", "指定项目（覆盖当前项目，例如 grafana/grafana）")

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(generateContextCmd)
	rootCmd.AddCommand(enhanceCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(buildOutputCmd)
	rootCmd.AddCommand(dynamicTestCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(patchCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(setAPIKeyCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(versionCmd)
}
