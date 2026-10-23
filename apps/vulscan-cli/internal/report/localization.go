package report

import "strings"

// displayLabel translates known display values without mutating machine-readable
// verdicts, statuses or identifiers. Unknown values remain visible and are still
// escaped by html/template at their output context.
func displayLabel(value string) string {
	if label, ok := chineseLabels[strings.ToLower(strings.TrimSpace(value))]; ok {
		return label
	}
	return value
}

var chineseLabels = map[string]string{
	"module_unavailable": "模块不可用", "docker_unavailable": "Docker 不可用", "no_candidates": "没有候选项", "not_requested": "未请求此步骤", "scan": "扫描", "app-context": "应用上下文", "llm-reachability": "模型可达性分析",
	"vulnerable": "存在漏洞", "bypassable": "防护可绕过", "safe": "安全", "secure": "安全",
	"protected": "已防护", "inconclusive": "无法确定", "insufficient_context": "上下文不足",
	"unverified": "未验证", "confirmed": "已确认", "agreed": "确认一致", "disagreed": "未确认",
	"not_reproduced": "未复现", "blocked": "测试受阻", "skipped": "已跳过", "error": "错误",
	"success": "成功", "failed": "失败", "interrupted": "已中断", "partial": "部分完成", "pending": "待处理",
	"unknown": "未知", "not tested": "未测试", "test error": "测试错误", "not reproduced": "未复现",
	"needs review": "需要复核", "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
	"corrected": "纠正后评估", "report-data": "报告数据生成", "generate-context": "上下文生成", "build-output": "结果整理", "patch": "修复生成", "detect": "漏洞检测",
	"model": "模型评估", "derived": "规则推导", "parse": "代码解析", "context": "上下文分析",
	"app_context": "应用上下文", "application_context": "应用上下文", "enhance": "上下文增强",
	"analyze": "漏洞分析", "verify": "漏洞验证", "report": "报告生成", "dynamic_test": "动态测试",
	"dynamic-test": "动态测试", "dynamic_testing": "动态测试", "dedup": "去重", "reachability": "可达性分析",
	"llm_reachability": "模型可达性分析", "security analysis report": "安全分析报告",
	"code contains an exploitable security vulnerability with no effective protection. immediate remediation required.": "代码存在可利用的安全漏洞，且缺少有效防护，需要立即修复。",
	"security controls exist but can be circumvented under certain conditions. review and strengthen protections.":      "已有安全控制可在特定条件下被绕过，需要检查并加强防护。",
	"security posture could not be determined. manual review recommended to assess risk.":                               "无法确定安全状态，建议人工复核风险。",
	"code handles potentially dangerous operations but has effective security controls in place.":                       "代码涉及潜在危险操作，但已有有效安全控制。",
	"code does not involve security-sensitive operations or poses no security risk.":                                    "代码不涉及安全敏感操作，或未发现安全风险。",
}

func displayLabels(values []string) []string {
	labels := make([]string, len(values))
	for i, value := range values {
		labels[i] = displayLabel(value)
	}
	return labels
}
