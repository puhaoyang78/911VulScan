"""Chinese labels at report-rendering boundaries; serialized enums stay intact."""

_LABELS = {
    "vulnerable": "存在漏洞", "bypassable": "防护可绕过", "safe": "安全",
    "protected": "已防护", "inconclusive": "无法确定", "insufficient_context": "上下文不足",
    "confirmed": "已确认", "agreed": "确认一致", "disagreed": "未确认", "unverified": "未验证",
    "error": "错误", "not_reproduced": "未复现", "blocked": "测试受阻", "skipped": "已跳过",
    "success": "成功", "failed": "失败", "interrupted": "已中断", "unknown": "未知",
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
    "report-data": "报告数据生成", "generate-context": "上下文生成", "build-output": "结果整理", "patch": "修复生成", "detect": "漏洞检测",
    "app-context": "应用上下文", "llm-reachability": "模型可达性分析",
    "parse": "代码解析", "context": "上下文分析", "app_context": "应用上下文",
    "application_context": "应用上下文", "enhance": "上下文增强", "analyze": "漏洞分析",
    "verify": "漏洞验证", "report": "报告生成", "dynamic_test": "动态测试",
    "dynamic-test": "动态测试", "dynamic_testing": "动态测试", "dedup": "去重",
    "reachability": "可达性分析", "llm_reachability": "模型可达性分析",
    "file_read": "文件读取", "http_response": "HTTP 响应", "command_output": "命令输出",
    "network_capture": "网络捕获",
}


def display_label(value: object) -> str:
    """Return a translated known label; preserve unknown values and identifiers."""
    text = str(value) if value is not None else ""
    return _LABELS.get(text.strip().lower(), text)
