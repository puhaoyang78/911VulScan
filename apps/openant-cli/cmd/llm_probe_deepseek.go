package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
)

// Kept injectable for mock-only tests, as with the other provider probes.
var deepseekAPIBase = config.DeepSeekBaseURL

// DeepSeek accepts either its root or /v1 base URL. Append exactly one
// /chat/completions suffix, matching the Python SDK's base URL handling.
func deepseekEndpoint(baseURL string) string {
	if baseURL == "" {
		baseURL = os.Getenv("DEEPSEEK_BASE_URL")
	}
	if baseURL == "" {
		baseURL = deepseekAPIBase
	}
	return strings.TrimRight(baseURL, "/") + "/chat/completions"
}

func probeDeepSeek(apiKey, baseURL, model string) error {
	payload := fmt.Sprintf(
		`{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_tokens":1,"thinking":{"type":"disabled"}}`,
		model,
	)
	err := probeChatCompletionsPayloadAt(apiKey, deepseekEndpoint(baseURL), model, payload)
	if pe, ok := asProbeError(err); ok {
		switch {
		case pe.Status == 402:
			pe.Message = "DeepSeek API 余额不足（HTTP 402），请检查 API 账户余额后重试"
		case pe.Kind == "auth":
			pe.Message = fmt.Sprintf("DeepSeek 身份验证失败（HTTP %d），请检查 API 密钥", pe.Status)
		case pe.Kind == "model_not_found":
			pe.Message = fmt.Sprintf("DeepSeek 模型 %q 或 API 地址不存在（HTTP 404），请检查模型名称与基础地址", model)
		case pe.Kind == "timeout":
			pe.Message = "DeepSeek 验证请求超时，请重试或检查 API 基础地址与网络"
		case pe.Kind == "network":
			pe.Message = "无法连接 DeepSeek API，请检查 API 基础地址与网络：" + pe.Message
		case pe.Status != 0:
			pe.Message = fmt.Sprintf("DeepSeek 验证请求失败（HTTP %d），请检查服务状态后重试", pe.Status)
		}
	}
	return err
}
