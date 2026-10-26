"""识别"刻意保留漏洞"的靶场/教学仓库。

这类仓库（DVWA、DSVW、OWASP Juice Shop、各种 damn-vulnerable-*）把漏洞当作
功能来演示。旧的上下文生成会把「这是教学演示」写进 ``not_a_vulnerability``，第
1 阶段的提示词再原样拼成 "Do NOT flag as vulnerable"，结果是**靶场里所有真正的
漏洞都不上报**——这正是本模块要解决的问题。

判断放在这里而不是只靠模型，是因为这件事必须可复现、可解释：命中哪个关键词、
出现在哪个文件，都要能写进扫描记录；模型下一次采样换了结论，也不该影响它。
"""

import os
import re
from pathlib import Path

# (关键词, 依据说明)。英文按词边界匹配，中文按子串匹配。
_SIGNALS: tuple[tuple[str, str], ...] = (
    ("intentionally vulnerable", "声明故意保留漏洞"),
    ("deliberately vulnerable", "声明故意保留漏洞"),
    ("purposefully vulnerable", "声明故意保留漏洞"),
    ("vulnerable by design", "声明漏洞是设计的一部分"),
    ("insecure by design", "声明漏洞是设计的一部分"),
    ("intentionally insecure", "声明故意不安全"),
    ("deliberately insecure", "声明故意不安全"),
    ("damn vulnerable", "项目名即“故意有漏洞”"),
    ("training application", "练习用应用"),
    ("educational purposes", "教学用途"),
    ("for learning purposes", "教学用途"),
    ("practice your hacking", "练习用途"),
    ("capture the flag", "CTF 靶场"),
    ("ctf challenge", "CTF 靶场"),
    ("owasp webgoat", "OWASP WebGoat 靶场"),
    ("owasp juice shop", "OWASP Juice Shop 靶场"),
    ("owasp mutillidae", "OWASP Mutillidae 靶场"),
    ("dvwa", "DVWA 靶场"),
    ("靶场", "中文说明：靶场"),
    ("练手", "中文说明：练手项目"),
    ("教学演示", "中文说明：教学演示"),
    ("故意保留", "中文说明：故意保留缺陷"),
    ("刻意保留", "中文说明：刻意保留缺陷"),
    ("漏洞练习", "中文说明：漏洞练习"),
)

_README_NAMES = ("readme.md", "readme.rst", "readme.txt", "readme", "readme.zh-cn.md")
_MAX_BYTES = 8000
# 仓库目录名里的信号词（整词匹配，避免 "invaluable" 之类误判）。
_REPO_NAME_SIGNALS = ("vulnerable", "dvwa", "dvw", "dvcp", "goat", "insecure", "vulnapp")


def _read_head(path: Path) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(_MAX_BYTES).decode("utf-8", "replace").lower()
    except OSError:
        return ""


def _matches(text: str, needle: str) -> bool:
    """英文按词边界匹配，中文按子串匹配。"""
    if not needle.isascii():
        return needle in text
    return re.search(r"(?<![a-z])" + re.escape(needle) + r"(?![a-z])", text) is not None


def detect_intentional_vulnerabilities(repo_path: str | Path) -> tuple[bool, list[str]]:
    """返回 (是否靶场, 判定依据)。依据写进扫描记录，便于人工核对。"""
    root = Path(repo_path)
    evidence: list[str] = []
    try:
        entries = sorted(os.listdir(root))[:200]
    except OSError:
        return False, []

    for entry in entries:
        if entry.lower() not in _README_NAMES:
            continue
        text = _read_head(root / entry)
        for needle, reason in _SIGNALS:
            if _matches(text, needle):
                note = f"{entry}: {reason}（{needle}）"
                if note not in evidence:
                    evidence.append(note)

    name = root.name.lower()
    for signal in _REPO_NAME_SIGNALS:
        if _matches(name, signal):
            evidence.append(f"目录名 {root.name}: 名称含 {signal}")
            break

    return bool(evidence), evidence[:6]
