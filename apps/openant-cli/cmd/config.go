package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "查看和管理命令行配置",
	Long: `查看和更新 911VulScan / OpenAnt 命令行配置。

配置文件位于 ~/.config/openant/config.json。
新安装默认使用 DeepSeek；已有模型配置继续保留。

示例：
  openant config show                    查看生效配置、各阶段模型和密钥状态
  openant set-api-key --provider deepseek 保存 DeepSeek 密钥（推荐）
  openant setup llm                      设置模型服务商和各阶段模型
  openant config set api-key             设置旧版 Anthropic api_key 字段
  openant config unset api-key           仅移除旧版 Anthropic api_key 字段
  openant config path                    显示配置文件路径`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key>",
	Short: "设置旧版兼容配置项",
	Long: `设置旧版兼容配置字段：api-key、default-model。

api-key 仅指旧版 Anthropic 顶层密钥，不用于 DeepSeek，
也不修改 llm_providers 中独立保存的服务商密钥。
default-model 是旧版兼容字段；各阶段模型请使用 openant setup llm。

密钥从标准输入读取，不要把真实密钥写进命令参数或 shell 历史。
此兼容输入方式可能在终端回显，推荐改用不回显的专用命令：
  openant set-api-key --provider deepseek
  openant set-api-key --provider anthropic

使用 --stdin 可从管道读取值。`,
	Args: cobra.ExactArgs(1),
	Run:  runConfigSet,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "显示当前生效模型配置与密钥状态",
	Run:   runConfigShow,
}

var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "移除旧版兼容配置项",
	Args:  cobra.ExactArgs(1),
	Run:   runConfigUnset,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "显示配置文件路径",
	Run:   runConfigPath,
}

var configStdin bool

func init() {
	configSetCmd.Flags().BoolVar(&configStdin, "stdin", false, "从标准输入读取值（用于管道输入）")

	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configUnsetCmd)
	configCmd.AddCommand(configPathCmd)
}

func runConfigSet(cmd *cobra.Command, args []string) {
	key := args[0]

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	var value string

	switch key {
	case "api-key":
		if configStdin {
			// Read from stdin (piped)
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			// Interactive prompt
			fmt.Fprint(os.Stderr, "请输入旧版 Anthropic API 密钥（终端可能回显）：")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("未提供配置值")
			os.Exit(1)
		}

		cfg.APIKey = value

	case "default-model":
		if configStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			fmt.Fprint(os.Stderr, "请输入旧版默认模型名称：")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("未提供配置值")
			os.Exit(1)
		}

		cfg.DefaultModel = value

	default:
		output.PrintError(fmt.Sprintf("未知配置项：%s\n支持旧版兼容项：api-key（Anthropic）、default-model", key))
		os.Exit(1)
	}

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	path, _ := config.Path()
	output.PrintSuccess(fmt.Sprintf("%s 已保存至 %s", key, path))
}

func runConfigShow(cmd *cobra.Command, args []string) {
	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	path, _ := config.Path()

	output.PrintHeader("当前配置")
	for _, row := range configDisplayRows(cfg) {
		output.PrintKeyValue(row[0], row[1])
	}
	if cfg.DefaultModel != "" {
		output.PrintKeyValue("旧版 default_model（兼容字段）", cfg.DefaultModel)
	}
	if cfg.ActiveProject != "" {
		output.PrintKeyValue("当前项目", cfg.ActiveProject)
	}
	output.PrintKeyValue("配置文件", path)
	fmt.Println("  密钥状态仅表示已配置，不代表已通过服务商验证；未显示任何密钥内容。")
	fmt.Println()
}

// configDisplayRows renders provider/model readiness without exposing even a
// masked credential. Phase bindings may differ in a user-authored profile.
func configDisplayRows(cfg *config.Config) [][2]string {
	rows := [][2]string{{"默认模型配置", cfg.DefaultLLM()}}
	phases := [][2]string{{"app_context", "项目上下文"}, {"enhance", "上下文增强"}, {"analyze", "漏洞分析"}, {"verify", "模拟验证"}, {"llm_reach", "可达性复核"}, {"dynamic_test", "动态测试"}, {"report", "报告生成"}}
	for _, phase := range phases {
		ref, ok := cfg.LLMPhase("", phase[0])
		if !ok {
			rows = append(rows, [2]string{phase[1], "无法解析模型绑定，请检查配置"})
			continue
		}
		readiness := "服务商配置不存在"
		if provider, found := cfg.EffectiveProvider(ref.Provider); found {
			switch {
			case strings.TrimSpace(provider.APIKey) != "":
				readiness = "密钥已配置，未验证"
			case provider.Type == "ollama":
				readiness = "本地服务，不要求 API 密钥"
			case provider.Type == "bedrock":
				readiness = "使用 AWS 凭据链，未验证"
			default:
				readiness = "尚未配置 API 密钥"
			}
		}
		rows = append(rows, [2]string{phase[1], fmt.Sprintf("%s / %s · %s", ref.Provider, ref.Model, readiness)})
	}
	legacy := "未设置"
	if cfg.APIKey != "" {
		legacy = "已设置（仅旧版 Anthropic 兼容字段）"
	}
	return append(rows, [2]string{"旧版 Anthropic api_key", legacy})
}

func runConfigUnset(cmd *cobra.Command, args []string) {
	key := args[0]

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	switch key {
	case "api-key":
		cfg.APIKey = ""
	case "default-model":
		cfg.DefaultModel = ""
	default:
		output.PrintError(fmt.Sprintf("未知配置项：%s\n支持旧版兼容项：api-key（Anthropic）、default-model", key))
		os.Exit(1)
	}

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	output.PrintSuccess(fmt.Sprintf("已移除旧版兼容字段 %s", key))
	if key == "api-key" {
		fmt.Println("  llm_providers 中的服务商密钥及环境变量未受影响。")
	}
}

func runConfigPath(cmd *cobra.Command, args []string) {
	path, err := config.Path()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	fmt.Println(path)
}
