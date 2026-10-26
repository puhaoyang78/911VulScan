"""同一状态在 Python 报告、Go 报告与网页里必须叫同一个词。

三份词表（``report/localization.py``、``internal/report/localization.go``、
``ui/static/scan.js``）各自独立维护，最容易出现「同一个 INCONCLUSIVE 在报告里
叫『无法确定』、在网页筛选项里叫『无法判定』」。这个测试把它们对齐。
"""

import re
from pathlib import Path

import pytest

from report.localization import _LABELS

ROOT = Path(__file__).resolve().parents[3]
GO_TABLE = ROOT / "apps/vulscan-cli/internal/report/localization.go"
JS_TABLE = ROOT / "apps/vulscan-cli/ui/static/scan.js"

# 语义相同、必须同名的键。新增状态时先在这里登记，再改三处词表。
SHARED_KEYS = (
    "vulnerable", "bypassable", "safe", "protected", "inconclusive",
    "insufficient_context", "confirmed", "agreed", "disagreed", "unverified",
    "not_reproduced", "blocked", "skipped", "not tested", "test error",
    "success", "failed", "interrupted", "unknown", "needs review",
    "critical", "high", "medium", "low",
    "parse", "analyze", "verify", "report", "dynamic-test", "app-context",
)


def _go_labels() -> dict[str, str]:
    text = GO_TABLE.read_text(encoding="utf-8")
    block = text.split("var chineseLabels = map[string]string{", 1)[1].split("\n}", 1)[0]
    return dict(re.findall(r'"([a-z0-9 _-]+)":\s*"([^"]+)"', block))


def _js_labels() -> dict[str, str]:
    text = JS_TABLE.read_text(encoding="utf-8")
    labels: dict[str, str] = {}
    for name in ("statuses", "reviews", "dynamics", "severities"):
        match = re.search(rf"const {name}=\{{(.*?)\}};", text, re.S)
        if not match:
            continue
        labels.update(dict(re.findall(r"([a-z_]+):'([^']+)'", match.group(1))))
    return labels


@pytest.mark.parametrize("key", SHARED_KEYS)
def test_python_and_go_labels_agree(key):
    go = _go_labels()
    assert key in _LABELS, f"Python 词表缺少 {key}"
    assert key in go, f"Go 词表缺少 {key}"
    assert _LABELS[key] == go[key], f"{key}: Python={_LABELS[key]!r} Go={go[key]!r}"


def test_dynamic_status_words_are_the_same_everywhere():
    js = _js_labels()
    assert js["reproduced"] == "已复现"
    assert js["not_reproduced"] == _LABELS["not_reproduced"]
    assert js["inconclusive"] == _LABELS["inconclusive"], "INCONCLUSIVE 只能有一个说法"
    assert js["blocked"] == _LABELS["blocked"]


def test_no_stiff_words_survive_in_user_facing_tables():
    banned = ("代码单元", "证据", "裁决", "发现项", "无法判定")
    for path in (ROOT / "libs/vulscan-core/report", ROOT / "libs/vulscan-core/core",
                 ROOT / "apps/vulscan-cli/internal/report",
                 ROOT / "apps/vulscan-cli/ui"):
        for file in path.rglob("*"):
            if file.suffix not in {".py", ".go", ".html", ".gohtml", ".js"} or not file.is_file():
                continue
            # 词表本身的文档字符串要写出「旧词 → 新词」，这是唯一允许出现的例外。
            if file.name == "localization.py":
                continue
            text = file.read_text(encoding="utf-8", errors="replace")
            for word in banned:
                assert word not in text, f"{file.relative_to(ROOT)} 仍在使用「{word}」"
