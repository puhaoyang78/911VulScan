"""
CLI entry point for report module.

Usage:
    python -m report --help
    python -m report summary pipeline_output.json -o report.md
    python -m report disclosures pipeline_output.json -o disclosures/
    python -m report all pipeline_output.json -o output/
"""

import argparse
import os
import sys
from pathlib import Path

from core.verdict_taxonomy import DISCLOSURE_ELIGIBLE
from .generator import generate_summary_report, generate_disclosure, generate_all
from .schema import validate_pipeline_output, ValidationError
from utilities.file_io import normalize_results, open_utf8, read_json
from utilities.llm import (
    PhaseBinding,
    build_phase_registry,
    load_config_file,
    probe_registry_or_raise,
    resolve_llm_config,
)


def _build_report_binding(llm_config_name: str | None = None) -> PhaseBinding:
    """Resolve the ``report``-phase binding for a standalone CLI invocation.

    ``generate_summary_report`` / ``generate_disclosure`` now require a
    :class:`PhaseBinding` (issue #65). Mirror the registry-build pattern
    used by ``report.generator.generate_all`` and ``core.scanner`` so the
    standalone ``python -m report`` commands resolve the same per-phase
    model — and surface a clean LLMError on a bad key / typo'd model via
    the 1-token probe, rather than crashing mid-generation.
    """
    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    probe_registry_or_raise(registry)
    return registry.get("report")


def cmd_summary(args):
    """Generate summary report."""
    pipeline_data = read_json(args.input)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load
    # (presence-guarded) before validation / iteration.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"验证错误： {e}", file=sys.stderr)
        sys.exit(1)

    report_binding = _build_report_binding()

    print("正在生成摘要报告…")
    report, usage = generate_summary_report(pipeline_data, report_binding)

    output_path = Path(args.output) if args.output else Path("SUMMARY_REPORT.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_utf8(output_path, "w") as f:
        f.write(report)
    print(f"  -> {output_path}")
    print(f"  预估费用： ${usage['cost_usd']:.4f} ({usage['total_tokens']:,} tokens)")


def cmd_disclosures(args):
    """Generate disclosure documents."""
    pipeline_data = read_json(args.input)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load
    # (presence-guarded) before validation / the disclosure enumerate.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"验证错误： {e}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output) if args.output else Path("disclosures")
    output_dir.mkdir(parents=True, exist_ok=True)

    report_binding = _build_report_binding()

    product_name = pipeline_data["repository"]["name"]
    count = 0

    for i, finding in enumerate(pipeline_data["findings"], 1):
        # Disclosure eligibility is defined once in
        # core.verdict_taxonomy.DISCLOSURE_ELIGIBLE -- consistent with
        # core/reporter and report/generator.
        if finding.get("stage2_verdict") not in DISCLOSURE_ELIGIBLE:
            continue

        print(f"正在为 {finding['short_name']} 生成披露文档…")
        disclosure, _usage = generate_disclosure(finding, product_name, report_binding)

        # Coerce to str, fall back to id, and basename so a null/typed/traversal
        # short_name can't crash disclosure generation (mirrors report/generator.py).
        safe_name = (os.path.basename(str(finding.get("short_name") or finding.get("id") or "finding"))
                     or "finding").replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        with open_utf8(output_dir / filename, "w") as f:
            f.write(disclosure)
        print(f"  -> {output_dir / filename}")
        count += 1

    if count == 0:
        print("没有可生成披露文档的已确认漏洞。")
    else:
        print(f"已生成 {count} 份披露文档。")


def cmd_all(args):
    """Generate all reports."""
    generate_all(args.input, args.output or "output")
    print("完成。")


def main():
    parser = argparse.ArgumentParser(
        prog="report",
        description="根据 OpenAnt 扫描结果生成安全报告和漏洞披露文档。"
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # summary command
    summary_parser = subparsers.add_parser("summary", help="生成摘要报告")
    summary_parser.add_argument("input", help="扫描结果 JSON 文件")
    summary_parser.add_argument("-o", "--output", help="输出文件（默认：SUMMARY_REPORT.md）")
    summary_parser.set_defaults(func=cmd_summary)

    # disclosures command
    disclosures_parser = subparsers.add_parser("disclosures", help="生成漏洞披露文档")
    disclosures_parser.add_argument("input", help="扫描结果 JSON 文件")
    disclosures_parser.add_argument("-o", "--output", help="输出目录（默认：disclosures/）")
    disclosures_parser.set_defaults(func=cmd_disclosures)

    # all command
    all_parser = subparsers.add_parser("all", help="生成全部报告（摘要和披露文档）")
    all_parser.add_argument("input", help="扫描结果 JSON 文件")
    all_parser.add_argument("-o", "--output", help="输出目录（默认：output/）")
    all_parser.set_defaults(func=cmd_all)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
