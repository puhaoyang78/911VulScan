package report

import "strings"

func verdictColor(value string) string {
	switch strings.ToLower(value) {
	case "vulnerable", "confirmed":
		return "#ac292e"
	case "bypassable", "inconclusive", "insufficient_context":
		return "#89520d"
	case "safe", "protected":
		return "#246345"
	default:
		return "#526477"
	}
}

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
	"protected": "已防护", "inconclusive": "无法确定", "insufficient_context": "信息不足",
	"unverified": "复核未完成", "confirmed": "复核保留", "agreed": "复核一致", "disagreed": "复核后更正",
	"not_reproduced": "未复现", "blocked": "测试受阻", "skipped": "已跳过", "error": "错误",
	"success": "成功", "failed": "失败", "interrupted": "已中断", "partial": "部分完成", "pending": "待处理",
	"unknown": "未知", "not tested": "未测试", "test error": "测试错误", "not reproduced": "未复现",
	"needs review": "需要复核", "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
	"corrected": "复核后更正", "report-data": "报告数据生成", "generate-context": "上下文生成", "build-output": "结果整理", "patch": "修复生成", "detect": "漏洞检测",
	"model": "模型评估", "derived": "规则推导", "parse": "代码解析", "context": "上下文分析",
	"app_context": "应用上下文", "application_context": "应用上下文", "enhance": "上下文增强",
	"analyze": "漏洞分析", "verify": "模型复核", "report": "报告生成", "dynamic_test": "动态测试",
	"dynamic-test": "动态测试", "dynamic_testing": "动态测试", "dedup": "去重", "reachability": "可达性分析",
	"llm_reachability": "模型可达性分析", "security analysis report": "安全分析报告",
	"code contains an exploitable security vulnerability with no effective protection. immediate remediation required.": "代码存在可利用的安全漏洞，且缺少有效防护，需要立即修复。",
	"security controls exist but can be circumvented under certain conditions. review and strengthen protections.":      "已有安全控制可在特定条件下被绕过，需要检查并加强防护。",
	"security posture could not be determined. manual review recommended to assess risk.":                               "分析未得出明确结论，需进一步检查。",
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

// The same spelling "confirmed" has different semantics on the two axes.
// Only the dynamic-test field uses this vocabulary.
func dynamicLabel(value string) string {
	switch strings.ToUpper(value) {
	case "CONFIRMED":
		return "已复现"
	case "NOT_REPRODUCED":
		return "未复现"
	case "BLOCKED":
		return "测试受阻"
	case "INCONCLUSIVE":
		return "无法确定"
	case "ERROR":
		return "测试错误"
	case "SKIPPED":
		return "已跳过"
	case "":
		return "尚未记录动态测试"
	default:
		return "未知动态状态：" + value
	}
}

func dynamicGroupLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "confirmed", "已复现", "动态已复现":
		return "动态测试已复现"
	case "not reproduced", "未复现":
		return "动态测试未复现"
	case "test error", "测试错误":
		return "动态测试出错"
	case "not tested", "未测试或状态未知":
		return "未做动态测试"
	default:
		return displayLabel(value)
	}
}

func (f Finding) ModelReviewLabel() string {
	switch f.ModelReviewStatus {
	case "retained":
		return "复核保留"
	case "excluded":
		return "复核排除"
	case "error":
		return "复核错误"
	case "inconclusive":
		return "无法确定"
	case "pending":
		return "待复核"
	case "unreviewed":
		return "未记录复核"
	default:
		return "未记录复核"
	}
}
