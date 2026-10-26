#!/usr/bin/env python3
# Modified 2026-10-23 for 911VulScan: the VulScan-only product namespace.
"""
Generate interactive HTML security report from 911VulScan experiment results.

Produces a comprehensive HTML report with:
    - Stats overview cards (total units, files, findings by category)
    - Interactive pie charts showing distribution (Chart.js)
    - Category explanation table
    - LLM-generated prioritized remediation guidance
    - Sortable findings table with all results

The report calls Claude (Sonnet) to generate actionable remediation guidance
based on the vulnerability findings. This requires an API key.

Requirements:
    - ANTHROPIC_API_KEY environment variable or .env file
    - Internet connection for Chart.js CDN

Usage:
    python generate_report.py <experiment_json> <dataset_json> [output_html]

Example:
    python generate_report.py experiment_flowise.json datasets/flowise/dataset.json report.html
"""

import argparse
import json
import html
import os
from datetime import datetime

from dotenv import load_dotenv
from prompts.report_language import CHINESE_REPORT_INSTRUCTION
from report.localization import display_label
from core.verdict_taxonomy import fold_legacy_finding, FINDING_VERDICT_ORDER, ERROR_VERDICT
from utilities.file_io import normalize_results, read_json
from utilities.llm import (
    build_phase_registry,
    load_config_file,
    probe_registry_or_raise,
    resolve_llm_config,
    simple_text,
)

load_dotenv()


MAX_TOKENS = 4096


def load_json(path: str) -> dict:
    """Load JSON file."""
    return read_json(path)


def extract_file(unit_id: str) -> str:
    """Extract file path from unit ID."""
    if ':' in unit_id:
        return unit_id.rsplit(':', 1)[0]
    return unit_id


def _display_verdict(verdict: str) -> str:
    """#623: fold the legacy INSUFFICIENT_CONTEXT value to inconclusive's
    synonym at the display reads (both the per-row listing and the aggregate
    counts) so this report is self-consistent with the metrics fold. The
    row's stored values keep the legacy verdict for provenance. The fold
    itself lives in core.verdict_taxonomy (the one-home rule)."""
    return fold_legacy_finding(verdict)


def get_verdict_priority(verdict: str) -> int:
    """Get priority order for verdict (lower = more urgent)."""
    priorities = {
        'vulnerable': 1,
        'bypassable': 2,
        'inconclusive': 3,
        'protected': 4,
        'safe': 5
    }
    return priorities.get(verdict, 3)


def _short_sha(sha: str | None) -> str:
    """Return the first 8 characters of a SHA, or empty if input is None."""
    if not sha:
        return ""
    return sha[:8]


def _load_pipeline_metadata(experiment_path: str) -> tuple[dict | None, dict | None]:
    """Auto-detect pipeline_output.json next to the experiment file.

    Returns (repository, diff) blocks or (None, None) if not found / unreadable.
    Used to render repo identity and incremental-scan range in the HTML header.
    """
    exp_dir = os.path.dirname(os.path.abspath(experiment_path))
    candidate = os.path.join(exp_dir, "pipeline_output.json")
    if not os.path.exists(candidate):
        return None, None
    try:
        data = read_json(candidate)
    except (json.JSONDecodeError, OSError):
        return None, None
    return data.get("repository"), data.get("diff")


def _build_header_subtitle(
    timestamp: str,
    repository: dict | None,
    diff: dict | None,
) -> str:
    """Build the HTML header subtitle.

    Full scan: "<repo> @ <sha8> · Generated <ts>"
    Incremental: "<repo> · Incremental: <base8>..<head8> · N/M units · Generated <ts>"
    No metadata: "Generated <ts>" (preserves prior behavior)
    """
    if not repository:
        return f"生成时间：{html.escape(timestamp)}"

    repo_name = html.escape(repository.get("name") or "未知")

    if diff and diff.get("mode") == "incremental":
        base = _short_sha(diff.get("base_sha"))
        head = _short_sha(diff.get("head_sha"))
        units_in = diff.get("units_in_diff")
        units_total = diff.get("units_total_parsed")
        units_str = ""
        if units_in is not None and units_total is not None:
            units_str = f" · {units_in}/{units_total} 个函数"
        return (
            f'<span class="incremental-badge">增量扫描</span> '
            f'{repo_name} · {html.escape(base)}..{html.escape(head)}{html.escape(units_str)} · '
            f'生成时间：{html.escape(timestamp)}'
        )

    sha = _short_sha(repository.get("commit_sha"))
    sha_str = f" @ {html.escape(sha)}" if sha else ""
    return f"{repo_name}{sha_str} · 生成时间：{html.escape(timestamp)}"


def get_verdict_color(verdict: str) -> str:
    """Get color for verdict."""
    colors = {
        'vulnerable': '#dc3545',
        'bypassable': '#fd7e14',
        'inconclusive': '#6c757d',
        'protected': '#28a745',
        'safe': '#20c997'
    }
    return colors.get(verdict, '#6c757d')


def prepare_findings_summary(experiment: dict, dataset: dict) -> list:
    """Prepare findings for LLM analysis."""
    units_by_id = {u['id']: u for u in dataset.get('units', [])}

    findings = []
    # FAM-ROBUST (fa16): `results` is model-supplied; a non-Anthropic model can
    # emit a bare string/number where a result dict is expected. Drop non-dict
    # elements at loop entry so every `.get()` below is safe (mirrors the fa15
    # guard in core/reporter.py).
    for result in [r for r in experiment.get('results', []) if isinstance(r, dict)]:
        route_key = result.get('route_key', '')
        unit = units_by_id.get(route_key, {})
        # #326 (wave r1): agentic mode (the default) writes agent_context;
        # read both keys with the analyzer's precedence, mapping the
        # agentic key name (classification_reasoning).
        # famBCR panel (sonnet): the isinstance(dict) guard the same PR
        # added in csv_export — a truthy non-dict context (a model emitting
        # the string "agreed") crashes .get here with AttributeError.
        _ctx = unit.get('agent_context') or unit.get('llm_context')
        ctx = _ctx if isinstance(_ctx, dict) else {}
        unit_desc = str(ctx.get('classification_reasoning') or ctx.get('reasoning') or '')
        verification = result.get('verification') or {}

        findings.append({
            'file': extract_file(route_key),
            'unit_id': route_key,
            # Fall back to raw ``verdict`` when ``finding`` is absent (see
            # verdict-count site below); keeps finding-less vulns actionable.
            # #623: the legacy INSUFFICIENT_CONTEXT value folds to
            # inconclusive's synonym at the display read (the aggregate site
            # below folds the same way; the row's stored values keep the
            # legacy verdict for provenance).
            'verdict': _display_verdict(
                str(result.get('finding') or result.get('verdict', '')).lower()),
            'attack_vector': result.get('attack_vector', ''),
            'stage1_reasoning': result.get('reasoning') or '',
            'stage2_explanation': verification.get('explanation', ''),
            'description': unit_desc[:300]
        })

    # Sort by priority
    findings.sort(key=lambda x: get_verdict_priority(x['verdict']))
    return findings


def generate_remediation_guidance(findings: list) -> str:
    """Call LLM to generate prioritization and remediation guidance."""
    # Filter to actionable findings only
    actionable = [f for f in findings if f['verdict'] in ('vulnerable', 'bypassable', 'inconclusive')]

    if not actionable:
        errored = sum(1 for f in findings if f['verdict'] == 'error')
        if errored:
            return (f"<p>未确认任何漏洞，但有 {errored} 个函数分析出错，需要人工复核。</p>")
        return "<p>未发现漏洞或安全问题，所有函数均安全或已有适当防护。</p>"

    # Build prompt
    findings_text = ""
    for i, f in enumerate(actionable, 1):
        findings_text += f"""
### Finding {i}: {f['unit_id']}
- **Verdict**: {f['verdict']}
- **Attack Vector**: {f['attack_vector'] or 'Not specified'}
- **Analysis**: {f['stage2_explanation'][:500] if f['stage2_explanation'] else f['stage1_reasoning'][:500]}
"""

    prompt = CHINESE_REPORT_INSTRUCTION + f"""Analyze these security findings and provide:

1. **Executive Summary**: A brief overview of the security posture (2-3 sentences)

2. **Prioritized Action Items**: List specific remediation steps in order of urgency. For each item:
   - What to fix
   - Why it's important
   - How to fix it (concrete steps)

3. **Quick Wins**: Any simple fixes that would immediately improve security

Format your response as HTML (use <h3>, <p>, <ul>, <li>, <strong> tags). Do not include ```html markers.

## Findings to Analyze:
{findings_text}
"""

    # Resolve the report-phase binding from the active config.
    # Probe upfront so bad keys / typo'd model IDs fail with the
    # standardised "llm-config 'X' failed validation: ..." preamble
    # instead of a raw SDK error on the first real call.
    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, None))
    probe_registry_or_raise(registry)
    binding = registry.get("report")

    return simple_text(binding, prompt, max_tokens=MAX_TOKENS)


def _build_pipeline_costs_html(step_reports: list[dict]) -> str:
    """Build an HTML table with pipeline step costs and durations."""
    if not step_reports:
        return ""

    # Sort by timestamp (or keep as-is)
    rows = ""
    total_cost = 0.0
    total_duration = 0.0

    for sr in sorted(step_reports, key=lambda s: s.get("timestamp", "")):
        step = sr.get("step", "unknown")
        duration = sr.get("duration_seconds", 0)
        cost = sr.get("cost_usd", 0)
        status = sr.get("status", "unknown")

        total_cost += cost
        total_duration += duration

        # Format duration
        if duration >= 60:
            dur_str = f"{duration / 60:.1f}m"
        else:
            dur_str = f"{duration:.1f}s"

        cost_str = f"${cost:.4f}" if cost > 0 else "-"
        status_color = "#28a745" if status == "success" else "#dc3545" if status == "error" else "#6c757d"

        rows += f"""
        <tr>
            <td>{html.escape(display_label(step))}</td>
            <td>{dur_str}</td>
            <td>{cost_str}</td>
            <td><span style="color: {status_color}">{html.escape(display_label(status))}</span></td>
        </tr>"""

    # Total row
    total_dur_str = f"{total_duration / 60:.1f}m" if total_duration >= 60 else f"{total_duration:.1f}s"

    return f"""
        <section class="section">
            <h2>扫描步骤预估费用与耗时</h2>
            <p>费用按配置中的模型费率估算，最终以供应商账单为准。</p>
            <table>
                <thead>
                    <tr>
                        <th>步骤</th>
                        <th>耗时</th>
                        <th>预估费用</th>
                        <th>状态</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                    <tr style="border-top: 2px solid var(--border); font-weight: bold">
                        <td>合计</td>
                        <td>{total_dur_str}</td>
                        <td>${total_cost:.4f}</td>
                        <td></td>
                    </tr>
                </tbody>
            </table>
        </section>"""


def generate_html_report(
    experiment: dict,
    dataset: dict,
    remediation_html: str,
    output_path: str,
    step_reports: list[dict] | None = None,
    repository: dict | None = None,
    diff: dict | None = None,
):
    """Generate the HTML report.

    DEV-ONLY. This renderer interpolates ``remediation_html`` (untrusted, LLM-authored
    from scanned-repo findings) RAW into the template — it is NOT XSS-safe on its own.
    It is dead on every shipped path: production ``vulscan report -f html`` returns an
    error and defers HTML rendering to the Go CLI, which sanitizes remediation HTML
    through a bluemonday strict allowlist (apps/vulscan-cli/internal/report/types.go
    ``SafeRemediation``). Only ``__main__``/tests reach this function. Do NOT re-wire it
    into a live command without adding equivalent sanitization — see
    tests/test_report_html_sink_is_dead.py, which guards this boundary.

    repository / diff are usually loaded from pipeline_output.json by the
    caller (see ``_load_pipeline_metadata``). When present, the header
    renders the repo identity and, for incremental scans, the
    base..head range.
    """
    # Prepare data
    units_by_id = {u['id']: u for u in dataset.get('units', [])}

    # Count by verdict
    verdict_counts = {}
    file_verdicts = {}  # file -> worst verdict
    findings_data = []

    # FAM-ROBUST (fa16): `results` is model-supplied; a non-Anthropic model can
    # emit a bare string/number where a result dict is expected. Drop non-dict
    # elements at loop entry so every `.get()` below is safe (mirrors the fa15
    # guard in core/reporter.py).
    for result in [r for r in experiment.get('results', []) if isinstance(r, dict)]:
        route_key = result.get('route_key', '')
        # Fall back to the raw ``verdict`` field when a result has no normalized
        # ``finding`` key, else finding-less vulnerable results are dropped from
        # the count. Mirrors the canonical read in reporter.py / verifier.py.
        verdict = str(result.get('finding') or result.get('verdict', '')).lower()
        # #623: the legacy INSUFFICIENT_CONTEXT value is inconclusive's
        # legacy synonym at every display aggregate (the cli.py twin) — the
        # row's stored values keep the legacy verdict for provenance.
        verdict = _display_verdict(verdict)
        file_path = extract_file(route_key)
        unit = units_by_id.get(route_key, {})
        # #326 (wave r1): agentic mode (the default) writes agent_context;
        # read both keys with the analyzer's precedence, mapping the
        # agentic key name (classification_reasoning).
        # famBCR panel (sonnet): the isinstance(dict) guard the same PR
        # added in csv_export — a truthy non-dict context (a model emitting
        # the string "agreed") crashes .get here with AttributeError.
        _ctx = unit.get('agent_context') or unit.get('llm_context')
        ctx = _ctx if isinstance(_ctx, dict) else {}
        unit_desc = str(ctx.get('classification_reasoning') or ctx.get('reasoning') or '')
        verification = result.get('verification') or {}

        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        # Track worst verdict per file
        if file_path not in file_verdicts:
            file_verdicts[file_path] = verdict
        elif get_verdict_priority(verdict) < get_verdict_priority(file_verdicts[file_path]):
            file_verdicts[file_path] = verdict

        # Collect finding data
        findings_data.append({
            'file': file_path,
            'unit_id': route_key,
            'verdict': verdict,
            'priority': get_verdict_priority(verdict),
            'color': get_verdict_color(verdict),
            'attack_vector': html.escape(result.get('attack_vector', '') or ''),
            'description': html.escape(unit_desc[:200]),
            'justification': html.escape(verification.get('explanation', '')[:300] if verification.get('explanation') else (result.get('reasoning') or '')[:300])
        })

    # Sort findings by priority
    findings_data.sort(key=lambda x: x['priority'])

    # Count files by worst verdict
    file_verdict_counts = {}
    for v in file_verdicts.values():
        file_verdict_counts[v] = file_verdict_counts.get(v, 0) + 1

    # Prepare chart data
    verdict_order = list(FINDING_VERDICT_ORDER)
    # Surface the errored/unanalyzed sentinel in the charts too (a silent false-negative) —
    # but ONLY the known ERROR_VERDICT literal, never arbitrary model-supplied verdict
    # strings: those are attacker-controlled and would inject unescaped into the
    # json.dumps chart labels (re-opening the verdict-badge injection). Unknown verdicts still appear in the
    # findings table with an html.escape'd badge.
    if ERROR_VERDICT in verdict_counts or ERROR_VERDICT in file_verdict_counts:
        verdict_order.append(ERROR_VERDICT)
    unit_chart_labels = json.dumps([display_label(v) for v in verdict_order if v in verdict_counts], ensure_ascii=False)
    unit_chart_data = json.dumps([verdict_counts.get(v, 0) for v in verdict_order if v in verdict_counts])
    unit_chart_colors = json.dumps([get_verdict_color(v) for v in verdict_order if v in verdict_counts])

    file_chart_labels = json.dumps([display_label(v) for v in verdict_order if v in file_verdict_counts], ensure_ascii=False)
    file_chart_data = json.dumps([file_verdict_counts.get(v, 0) for v in verdict_order if v in file_verdict_counts])
    file_chart_colors = json.dumps([get_verdict_color(v) for v in verdict_order if v in file_verdict_counts])

    # Build findings table rows
    findings_rows = ""
    for f in findings_data:
        findings_rows += f"""
        <tr>
            <td><span class="verdict-badge" style="background-color: {f['color']}">{html.escape(display_label(f['verdict']))}</span></td>
            <td><code>{html.escape(f['file'])}</code></td>
            <td title="{html.escape(f['unit_id'])}">{html.escape(f['unit_id'].split(':')[-1] if ':' in f['unit_id'] else f['unit_id'])}</td>
            <td>{f['attack_vector'] or '-'}</td>
            <td class="truncate">{f['justification']}</td>
        </tr>
"""

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_units = len(findings_data)
    total_files = len(file_verdicts)

    # Build HTML
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全分析报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js" integrity="sha256-SERKgtTty1vsDxll+qzd4Y2cF9swY9BCq62i9wXJ9Uo=" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.2.0/dist/chartjs-plugin-datalabels.min.js" integrity="sha256-IMCPPZxtLvdt9tam8RJ8ABMzn+Mq3SQiInbDmMYwjDg=" crossorigin="anonymous"></script>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --border: #333;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: var(--accent);
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}

        .incremental-badge {{
            display: inline-block;
            background: var(--accent);
            color: #fff;
            padding: 0.1rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            margin-right: 0.5rem;
            vertical-align: middle;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent);
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}

        h2 {{
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            border-bottom: 2px solid var(--accent);
            padding-bottom: 0.5rem;
        }}

        h3 {{
            font-size: 1.2rem;
            margin: 1.5rem 0 1rem 0;
            color: var(--text-primary);
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 2rem;
            max-width: 700px;
            margin: 0 auto;
        }}

        .chart-container {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1rem;
            max-width: 300px;
            margin: 0 auto;
        }}

        .category-table {{
            margin-top: 2rem;
            max-width: 800px;
            margin-left: auto;
            margin-right: auto;
        }}

        .category-table th {{
            background: var(--bg-card);
        }}

        .category-table td:first-child {{
            width: 120px;
            text-align: center;
        }}

        .chart-title {{
            text-align: center;
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}

        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}

        th {{
            background: var(--bg-card);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
            color: var(--text-secondary);
        }}

        tr:hover {{
            background: rgba(233, 69, 96, 0.1);
        }}

        .verdict-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }}

        code {{
            background: var(--bg-card);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}

        .truncate {{
            max-width: 400px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .remediation {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
        }}

        .remediation ul {{
            margin-left: 1.5rem;
            margin-top: 0.5rem;
            margin-bottom: 1rem;
        }}

        .remediation li {{
            margin-bottom: 0.5rem;
        }}

        .remediation p {{
            margin-bottom: 1rem;
        }}

        .legend {{
            display: flex;
            justify-content: center;
            gap: 1.5rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
        }}

        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 4px;
        }}

        footer {{
            text-align: center;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>安全分析报告</h1>
            <p class="subtitle">{_build_header_subtitle(timestamp, repository, diff)}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_units}</div>
                <div class="stat-label">函数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_files}</div>
                <div class="stat-label">文件</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #dc3545">{verdict_counts.get('vulnerable', 0)}</div>
                <div class="stat-label">存在漏洞</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #fd7e14">{verdict_counts.get('bypassable', 0)}</div>
                <div class="stat-label">防护可绕过</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #28a745">{verdict_counts.get('protected', 0) + verdict_counts.get('safe', 0)}</div>
                <div class="stat-label">安全</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #6c757d">{verdict_counts.get('error', 0)}</div>
                <div class="stat-label">出错（未完成分析）</div>
            </div>
        </div>

        <section class="section">
            <h2>结果分布</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <div class="chart-title">按函数</div>
                    <canvas id="unitChart"></canvas>
                </div>
                <div class="chart-container">
                    <div class="chart-title">按文件（最高风险结论）</div>
                    <canvas id="fileChart"></canvas>
                </div>
            </div>
            <table class="category-table">
                <thead>
                    <tr>
                        <th>类别</th>
                        <th>说明</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #dc3545">存在漏洞</span></td>
                        <td>代码存在可利用的安全漏洞，且缺少有效防护，需要立即修复。</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #fd7e14">防护可绕过</span></td>
                        <td>已有安全控制可在特定条件下被绕过，需要检查并加强防护。</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #6c757d">无法确定</span></td>
                        <td>无法确定安全状态，建议人工复核风险。</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #28a745">已防护</span></td>
                        <td>代码涉及潜在危险操作，但已有有效安全控制。</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #20c997">安全</span></td>
                        <td>代码不涉及安全敏感操作，或未发现安全风险。</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="section">
            <h2>修复建议</h2>
            <div class="remediation">
                {remediation_html}
            </div>
        </section>

        {_build_pipeline_costs_html(step_reports or [])}

        <section class="section">
            <h2>全部漏洞</h2>
            <table>
                <thead>
                    <tr>
                        <th>结论</th>
                        <th>文件</th>
                        <th>函数</th>
                        <th>攻击方式</th>
                        <th>Analysis</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </section>

        <footer>
            <p>由 911VulScan 安全分析工具生成</p>
        </footer>
    </div>

    <script>
        Chart.register(ChartDataLabels);

        const chartOptions = {{
            responsive: true,
            maintainAspectRatio: true,
            plugins: {{
                legend: {{
                    display: false
                }},
                datalabels: {{
                    color: '#fff',
                    font: {{
                        weight: 'bold',
                        size: 11
                    }},
                    formatter: (value, ctx) => {{
                        const dataset = ctx.chart.data.datasets[0];
                        const total = dataset.data.reduce((a, b) => a + b, 0);
                        const percentage = Math.round((value / total) * 100);
                        const label = ctx.chart.data.labels[ctx.dataIndex];
                        return label + '\\n' + percentage + '%';
                    }},
                    textAlign: 'center'
                }}
            }}
        }};

        // Unit distribution chart
        new Chart(document.getElementById('unitChart'), {{
            type: 'pie',
            data: {{
                labels: {unit_chart_labels},
                datasets: [{{
                    data: {unit_chart_data},
                    backgroundColor: {unit_chart_colors},
                    borderWidth: 2,
                    borderColor: '#16213e'
                }}]
            }},
            options: chartOptions
        }});

        // File distribution chart
        new Chart(document.getElementById('fileChart'), {{
            type: 'pie',
            data: {{
                labels: {file_chart_labels},
                datasets: [{{
                    data: {file_chart_data},
                    backgroundColor: {file_chart_colors},
                    borderWidth: 2,
                    borderColor: '#16213e'
                }}]
            }},
            options: chartOptions
        }});
    </script>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"报告已生成： {output_path}")


def _load_step_reports_from_dir(directory: str) -> list[dict]:
    """Load all {step}.report.json files from a directory."""
    import glob
    reports = []
    for path in glob.glob(os.path.join(directory, "*.report.json")):
        try:
            reports.append(load_json(path))
        except Exception:
            continue
    return reports


def main():
    parser = argparse.ArgumentParser(description='生成 HTML 安全报告')
    parser.add_argument('experiment', help='实验结果 JSON 文件路径')
    parser.add_argument('dataset', help='数据集 JSON 文件路径')
    parser.add_argument('output', nargs='?', default='report.html', help='HTML 输出路径（默认：report.html）')
    parser.add_argument('--step-reports-dir', help='包含 *.report.json 步骤报告的目录')

    args = parser.parse_args()

    print("正在加载数据…")
    experiment = load_json(args.experiment)
    # fa17 TRUST BOUNDARY: normalize model-supplied `results` to dicts-only once
    # at load. `experiment` is passed by reference into prepare_findings_summary
    # and generate_html_report, so both iterators see the filtered list.
    normalize_results(experiment)
    dataset = load_json(args.dataset)

    # Load step reports if available
    step_reports = []
    if args.step_reports_dir:
        step_reports = _load_step_reports_from_dir(args.step_reports_dir)
    else:
        # Try to auto-detect from experiment path's directory
        exp_dir = os.path.dirname(os.path.abspath(args.experiment))
        step_reports = _load_step_reports_from_dir(exp_dir)

    print("正在整理漏洞…")
    findings = prepare_findings_summary(experiment, dataset)

    print("正在调用大语言模型生成修复建议…")
    remediation_html = generate_remediation_guidance(findings)

    repository, diff = _load_pipeline_metadata(args.experiment)

    print("正在构建 HTML 报告…")
    generate_html_report(
        experiment,
        dataset,
        remediation_html,
        args.output,
        step_reports=step_reports,
        repository=repository,
        diff=diff,
    )

    # Print summary
    verdict_counts = {}
    for f in findings:
        v = f['verdict']
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
    print("摘要：" + "，".join(f"{display_label(k)}：{v}" for k, v in verdict_counts.items()))


if __name__ == '__main__':
    main()
