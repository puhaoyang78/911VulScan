package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Localize presentation only. Command names, flag names and enum values remain
// unchanged so scripts and shell completion keep their existing interface.
func localizeCommandHelp(root *cobra.Command) {
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	short := map[string]string{
		"analyze": "分析已解析代码中的潜在漏洞", "build-output": "汇总已验证结果为 pipeline_output.json",
		"completion": "生成指定终端的命令补全脚本", "diff": "只扫描与基准相比变更的代码",
		"enhance": "补充代码安全上下文", "generate-context": "生成应用安全上下文",
		"help": "查看命令帮助", "init": "初始化待扫描项目", "mode": "查看或切换模型运行模式",
		"parse": "解析代码库并提取代码单元", "patch": "生成并评估漏洞修复补丁",
		"project": "管理项目与扫描记录", "report": "从分析结果生成中文报告",
		"scan": "执行完整漏洞扫描流水线", "uninstall": "卸载本工具及所选本地数据",
		"verify": "执行第二阶段攻击者模拟验证", "version": "查看版本与运行时信息",
	}
	usage := map[string]string{
		"help": "显示帮助", "output": "输出目录或文件路径", "language": "扫描语言（如 c、python、javascript、go）",
		"level": "处理层级：all、reachable、codeql 或 exploitable", "verify": "启用第二阶段攻击者模拟验证",
		"no-context": "跳过应用上下文生成", "no-enhance": "跳过上下文增强", "enhance-mode": "增强模式：agentic（全面）或 single-shot（快速）",
		"no-report": "跳过报告生成", "skip-dynamic-test": "跳过 Docker 动态测试（默认执行）",
		"limit":      "最大分析及增强单元数，0 为不限；LLM 可达性复核仍覆盖全部代码",
		"llm-config": "模型配置名称；沿用已有默认值，新安装默认 deepseek-default",
		"workers":    "模型阶段并行工作数", "backoff": "遭遇限流后的等待秒数",
		"full": "强制完整扫描（不能与增量选项并用）", "incremental": "相对于上次成功扫描进行增量分析",
		"diff-base": "增量比较的 Git 基准，如 origin/main 或 HEAD~5", "pr": "增量比较的 GitHub PR 编号（需要 gh）",
		"staged": "比较暂存区与 HEAD（不能与 diff-base 或 pr 并用）", "diff-scope": "差异范围：changed_files、changed_functions 或 callers",
		"repo-name": "写入报告的仓库名称（org/repo）", "repo-url": "写入报告的仓库地址", "commit-sha": "写入报告的提交 SHA",
		"llm-reachability":                "启用 LLM 可达性复核，额外费用随完整代码库规模增长",
		"llm-reachability-max-code-bytes": "可达性复核每个单元最多发送的代码字节数；增大将增加费用",
		"library-mode":                    "将库的公开 API 作为可达入口，可能显著扩大扫描范围",
		"include-intentional":             "按靶场扫描，保留刻意设置的教学漏洞",
		"format":                          "报告格式", "name": "项目名称（org/repo）", "commit": "固定扫描的提交 SHA",
		"force": "强制重新执行该操作", "stdin": "从标准输入读取值", "max-retries": "每项发现失败后的最大重试次数",
		"repo-path": "真实目标仓库路径", "repo-root": "目标仓库根目录", "finding-id": "待修复发现的 ID（不能与 cve 并用）",
		"cve": "从 NVD 获取并修复的 CVE 编号（不能与 finding-id 并用）", "verbose": "显示详细进度、解析记录及错误信息",
		"context-budget-policy": "已弃用，仅保留兼容；不再控制发送给模型的证据", "max-context-budget-windows": "已弃用，仅保留兼容；不再限制上下文窗口数",
		"analyzer-output": "第一阶段分析结果路径", "verify-output": "第二阶段验证结果路径",
		"skip-tests": "跳过测试代码", "all": "包含全部项目或记录", "yes": "跳过交互确认（请先核对命令作用范围）",
	}
	translateFlags := func(flags *pflag.FlagSet) {
		flags.VisitAll(func(flag *pflag.Flag) {
			if value, ok := usage[flag.Name]; ok {
				flag.Usage = value
			}
		})
	}
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		command.InitDefaultHelpFlag()
		if label, ok := short[command.Name()]; ok {
			command.Short = label
		}
		translateFlags(command.Flags())
		translateFlags(command.PersistentFlags())
		for _, child := range command.Commands() {
			visit(child)
		}
	}
	visit(root)
	replacer := strings.NewReplacer("Usage:", "用法：", "Aliases:", "别名：",
		"Examples:", "示例：", "Available Commands:", "可用命令：", "Additional Commands:", "其他命令：",
		"Global Flags:", "全局选项：", "Flags:", "选项：", "Use \"", "使用 \"",
		"for more information about a command.", "查看对应命令的详细说明。")
	root.SetUsageTemplate(replacer.Replace(root.UsageTemplate()))
}
