"""报告里的中文用词，只翻译展示层，机器可读的枚举与字段名保持原样。

用词以安全行业报告的习惯为准，不用模型内部的抽象说法：

* 代码按「函数」「文件」「代码位置」描述，不说「代码单元」；
* 复现过程产生的输出叫「测试输出」，不叫「证据」；
* 对结果的判断叫「结论」，不叫「判定」或「裁决」；
* 待确认的对象叫「漏洞」或「疑似漏洞」，不叫「发现项」。

Go 侧 ``internal/report/localization.go`` 与前端 ``ui/static/scan.js`` 维护同一套
键值；三处必须同时改，否则同一个状态在不同页面会显示成两个说法。
"""

_LABELS = {
    # 漏洞结论（finding verdict）
    "vulnerable": "存在漏洞", "bypassable": "防护可绕过", "safe": "安全",
    "protected": "已防护", "inconclusive": "无法确定", "insufficient_context": "信息不足",
    # 模型复核（stage 2）
    "confirmed": "复核保留", "agreed": "复核一致", "disagreed": "复核后更正",
    "unverified": "复核未完成",
    # 动态测试（容器内复现）
    "not_reproduced": "未复现", "blocked": "测试受阻", "skipped": "已跳过",
    "not tested": "未测试", "test error": "测试错误", "not reproduced": "未复现",
    # 通用状态
    "error": "错误", "success": "成功", "failed": "失败", "interrupted": "已中断",
    "unknown": "未知", "partial": "部分完成", "pending": "待处理",
    "needs review": "需要复核", "corrected": "复核后更正", "unreviewed": "未记录复核",
    "retained": "复核保留", "excluded": "复核排除",
    # 严重程度
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
    # 步骤
    "report-data": "报告数据生成", "generate-context": "上下文生成", "build-output": "结果整理",
    "patch": "修复生成", "detect": "漏洞检测", "app-context": "应用上下文",
    "llm-reachability": "模型可达性分析", "parse": "代码解析", "context": "上下文分析",
    "app_context": "应用上下文", "application_context": "应用上下文", "enhance": "上下文增强",
    "analyze": "漏洞分析", "verify": "模型复核", "report": "报告生成",
    "dynamic_test": "动态测试", "dynamic-test": "动态测试", "dynamic_testing": "动态测试",
    "dedup": "去重", "reachability": "可达性分析", "llm_reachability": "模型可达性分析",
    # 测试输出的类型
    "file_read": "文件读取", "http_response": "HTTP 响应", "command_output": "命令输出",
    "network_capture": "网络捕获", "sanitizer": "运行时检测",
    # 跳过原因
    "no_candidates": "没有可用漏洞", "docker_unavailable": "Docker 不可用",
    "module_unavailable": "模块不可用", "not_requested": "未请求此步骤",
}


def display_label(value: object) -> str:
    """返回已知条目的中文说法；未知值原样保留，避免把标识符译坏。"""
    text = str(value) if value is not None else ""
    return _LABELS.get(text.strip().lower(), text)


def dynamic_label(value: object) -> str:
    """Dynamic results have their own meaning, separate from model review."""
    text = str(value or "").strip()
    return {
        "CONFIRMED": "已复现", "NOT_REPRODUCED": "未复现", "BLOCKED": "测试受阻",
        "INCONCLUSIVE": "无法确定", "ERROR": "测试错误", "SKIPPED": "已跳过",
        "": "尚未记录动态测试",
    }.get(text.upper(), "未知动态状态：" + text)
