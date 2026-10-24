// Modified 2026-10-23 for 911VulScan product branding; new-only namespace.
package cmd

import (
	"fmt"
	"os"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/checkpoint"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/output"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/python"
	"github.com/spf13/cobra"
)

var dynamicTestCmd = &cobra.Command{
	Use:   "dynamic-test [pipeline-output-path]",
	Short: "在 Docker 沙箱中执行动态漏洞验证",
	Long: `对静态分析发现执行 Docker 隔离动态验证，每项发现独立构建和运行。

需要已安装并启动 Docker，以及 build-output 或 scan 生成的 pipeline_output.json。
C/C++ 使用真实 GCC/G++ 与 ASan/UBSan 模板，需提供 --repo-path 或活动项目仓库。
未提供结果路径时，使用活动项目的 pipeline_output.json。`,
	Args: cobra.MaximumNArgs(1),
	Run:  runDynamicTest,
}

var (
	dynamicTestOutput      string
	dynamicTestMaxRetries  int
	dynamicTestLLMConfig   string
	dynamicTestRepoPath    string
	dynamicTestDockerProxy string
)

func init() {
	dynamicTestCmd.Flags().StringVarP(&dynamicTestOutput, "output", "o", "", "结果输出目录")
	dynamicTestCmd.Flags().IntVar(&dynamicTestMaxRetries, "max-retries", 3, "每项发现出错后的最大重试次数")
	dynamicTestCmd.Flags().StringVar(&dynamicTestLLMConfig, "llm-config", "", "模型配置名称（默认使用配置文件的 default_llm 或内置 vulscan-default）")
	dynamicTestCmd.Flags().StringVar(&dynamicTestRepoPath, "repo-path", "", "真实目标仓库路径（C/C++ 验证必需；默认使用活动项目）")
	dynamicTestCmd.Flags().StringVar(&dynamicTestDockerProxy, "docker-proxy", "", "可选 Docker 构建代理：http://IP:端口")
}

func runDynamicTest(cmd *cobra.Command, args []string) {
	pipelineOutputPath, ctx, err := resolveFileArg(args, "pipeline_output.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Check pipeline_output.json exists before launching Python
	if _, err := os.Stat(pipelineOutputPath); err != nil {
		output.PrintError("未找到 pipeline_output.json，请先运行 vulscan build-output。")
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if dynamicTestOutput == "" {
			dynamicTestOutput = ctx.ScanDir
		}
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Auto-detect checkpoints from a previous interrupted run
	if ctx != nil {
		if cpInfo := checkpoint.DetectViaPython(rt.Path, ctx.ScanDir, "dynamic_test"); cpInfo != nil {
			if checkpoint.PromptResume(cpInfo, "dynamic-test", quiet) {
				// Resume — Python auto-detects checkpoint dir in output dir
			} else {
				_ = checkpoint.Clean(cpInfo.Dir)
			}
		}
	}

	pyArgs := []string{"dynamic-test", pipelineOutputPath}
	if dynamicTestDockerProxy != "" {
		pyArgs = append(pyArgs, "--docker-proxy="+dynamicTestDockerProxy)
	}
	if dynamicTestOutput != "" {
		pyArgs = append(pyArgs, "--output", dynamicTestOutput)
	}
	if dynamicTestMaxRetries != 3 {
		pyArgs = append(pyArgs, "--max-retries", fmt.Sprintf("%d", dynamicTestMaxRetries))
	}

	// Pass repo path so the dynamic tester can pre-stage source files into
	// the Docker build context.
	if dynamicTestRepoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", dynamicTestRepoPath)
	} else if ctx != nil && ctx.Project != nil && ctx.RepoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", ctx.RepoPath)
	}
	if dynamicTestLLMConfig != "" {
		pyArgs = append(pyArgs, "--llm-config", dynamicTestLLMConfig)
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, requireAPIKey(), nil)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if result.Envelope.Status == "interrupted" {
		os.Exit(130)
	} else if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintDynamicTestSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
