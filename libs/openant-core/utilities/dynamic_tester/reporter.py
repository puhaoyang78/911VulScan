"""Markdown report generation for dynamic test results."""

from datetime import datetime, timezone

from utilities.dynamic_tester.models import DynamicTestResult
from report.localization import display_label


def generate_report(
    results: list[DynamicTestResult],
    repo_name: str = "unknown",
    total_cost_usd: float = 0.0,
) -> str:
    """Generate a DYNAMIC_TEST_RESULTS.md markdown report.

    Args:
        results: List of DynamicTestResult objects
        repo_name: Repository name for the header
        total_cost_usd: Total cost of test generation

    Returns:
        Markdown report string
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    confirmed = counts.get("CONFIRMED", 0)
    not_reproduced = counts.get("NOT_REPRODUCED", 0)
    blocked = counts.get("BLOCKED", 0)
    inconclusive = counts.get("INCONCLUSIVE", 0)
    error = counts.get("ERROR", 0)
    skipped = counts.get("SKIPPED", 0)
    total = len(results)

    lines = [
        f"# 动态测试结果： {repo_name}",
        "",
        f"**日期：** {now}",
        f"**已测试的发现项总数：** {total - skipped}",
        f"**已跳过（该语言没有 Docker 模板）：** {skipped}",
        f"**预估总费用：** ${total_cost_usd:.4f}",
        "",
        "费用按配置中的模型费率估算，最终以供应商账单为准。",
        "",
        "## 摘要",
        "",
        "| 状态 | 数量 |",
        "|--------|-------|",
        f"| 已确认 | {confirmed} |",
        f"| 未复现 | {not_reproduced} |",
        f"| 测试受阻 | {blocked} |",
        f"| 无法确定 | {inconclusive} |",
        f"| 错误 | {error} |",
        f"| 已跳过 | {skipped} |",
        f"| **合计** | **{total}** |",
        "",
    ]

    # Detail sections by status priority
    status_order = ["CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"]

    for status in status_order:
        status_results = [r for r in results if r.status == status]
        if not status_results:
            continue

        lines.extend([
            f"## {display_label(status)} ({len(status_results)})",
            "",
        ])

        for r in status_results:
            lines.extend([
                f"### {r.finding_id}",
                "",
                f"**状态：** {display_label(r.status)}",
                f"**详情：** {r.details}",
                f"**耗时：** {r.elapsed_seconds:.1f} 秒",
                f"**生成预估费用：** ${r.generation_cost_usd:.4f}",
                "",
            ])

            if r.evidence:
                lines.append("**证据：**")
                lines.append("")
                for e in r.evidence:
                    lines.extend([
                        f"- **{display_label(e.type)}：**",
                        "```",
                        e.content[:2000],
                        "```",
                        "",
                    ])

            if r.test_code:
                lines.extend([
                    "<details>",
                    "<summary>生成的测试代码</summary>",
                    "",
                    "```python",
                    r.test_code,
                    "```",
                    "",
                    "</details>",
                    "",
                ])

    return "\n".join(lines)
