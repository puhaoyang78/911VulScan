# Modified 2026-10-23 for the VulScan-only product namespace.
"""Dynamic testing module for VulScan.

Takes pipeline_output.json from the static analysis pipeline and dynamically
tests all detected vulnerabilities using Docker containers.

Supports checkpoint/resume: each completed finding is saved to a per-unit
checkpoint file so interrupted runs can resume automatically.

Public API:
    run_dynamic_tests(pipeline_output_path, output_dir) -> list[DynamicTestResult]
"""

import json
import os
import sys

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence
from utilities.dynamic_tester.test_generator import generate_test, regenerate_test
from utilities.dynamic_tester.docker_executor import run_single_container
from utilities.dynamic_tester.result_collector import collect_result
from utilities.dynamic_tester.reporter import generate_report
from utilities.dynamic_tester.diagnostics import (
    bounded_diagnostic, error_feedback, failed_attempt_key,
)
from utilities.llm_client import (get_global_tracker,
                                  unpriced_kinds_from)
from utilities.llm import (
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    resolve_llm_config,
)
from utilities.file_io import normalize_results, read_json, open_utf8



def should_skip_for_language(file_path: str, scan_language: str | None) -> tuple[bool, str]:
    """Whether a finding should be skipped for lack of a Docker template.

    Args:
        file_path: The finding's file, which decides its language.
        scan_language: Scan-wide language, used when the path has no
            recognizable extension.

    Returns:
        ``(skip, reason)``. ``reason`` names the language so a skipped finding
        leaves an auditable trail rather than an unexplained gap.
    """
    from core.language_registry import language_for_path
    from utilities.dynamic_tester.test_generator import resolve_docker_template

    if resolve_docker_template(file_path, scan_language) is not None:
        return False, ""
    language = language_for_path(file_path) or scan_language or "unknown"
    return True, (
        f"语言 {language} 暂无动态测试 Docker 模板，已跳过；未执行漏洞验证。"
    )

def _summary_counts_from_checkpoints(checkpointed) -> dict:
    """#311: derive write_summary's counts from the SAVED UNIT FILES.

    The loop previously accumulated `_completed`/`_errors` locally, which
    (a) bypassed the generation-failure `continue` — an errored run wrote
    `errors: 0` — and (b) counted errors as a SUBSET of completed while
    `StepCheckpoint.status()` recomputes them as DISJOINT, so the two
    sources disagreed even without the bypass. Deriving from the same
    source `status()` reads makes the two structurally incapable of
    drifting. The retry contract is unchanged: an ERROR checkpoint is
    still classified not-done and retried on resume.

    #432: also derive error_breakdown — the error_type -> count dict the
    summary schema supports and the analyze pipeline populates, which this
    stage hardcoded to {} (a live content-filtered run produced 5 errors
    with an EMPTY breakdown, forcing a post-mortem to open every unit file
    to learn they were all generation failures). The category comes from
    the details prefixes result_collector.py writes: `Test generation ...`
    -> generation; `Docker build failed` -> build; `Container execution
    timed out` -> timeout; the remaining execution shapes -> execution;
    anything else (including absent details) -> other.
    """
    if not checkpointed:
        return {"completed": 0, "errors": 1 if checkpointed is False else 0,
                "error_breakdown": {}}
    completed = errors = 0
    breakdown: dict = {}
    for cp in checkpointed.values():
        if not isinstance(cp, dict):
            continue
        if cp.get("status") == "ERROR":
            errors += 1
            cat = _error_category(cp.get("details"))
            breakdown[cat] = breakdown.get(cat, 0) + 1
        else:
            completed += 1
            # wave r1 (sonnet): the collector writes "Container execution
            # timed out" with status INCONCLUSIVE, never ERROR — the timeout
            # bucket was dead code (real timeouts invisible in BOTH errors
            # and the breakdown). A timed-out unit is a timeout for triage
            # regardless of its terminal status: counted here WITHOUT
            # inflating `errors` (it is not an error; the counts stay the
            # #311 disjoint semantics).
            det = cp.get("details")
            if isinstance(det, str) and det.strip().startswith(("Container execution timed out", "容器执行超时", "C/C++ 测试执行超时")):
                breakdown["timeout"] = breakdown.get("timeout", 0) + 1
    return {"completed": completed, "errors": errors, "error_breakdown": breakdown}


def _error_category(details) -> str:
    """Bucket an ERROR unit file by its failure stage (#432)."""
    if not isinstance(details, str) or not details:
        return "other"
    d = details.strip()
    if d.startswith(("Test generation", "测试生成")):
        return "generation"
    if d.startswith(("Docker build failed", "Docker 构建失败", "Docker 构建超时",
                     "Docker 基础镜像不可用", "基础镜像 ", "共享工具链镜像 ",
                     "Docker 工具链不可用", "C/C++ 编译")):
        return "build"
    if d.startswith(("Container execution timed out", "容器执行超时", "C/C++ 测试执行超时")):
        # famD panel (opus, documented-not-deleted): today the collector
        # writes this details prefix with status INCONCLUSIVE (counted on
        # the completed side by the wave-r1 timeout bucket, not as an
        # error) — this branch is unreachable for the CURRENT collector.
        # Kept as a defensive fallback: if a future collector ever writes
        # an ERROR row with this prefix, it must bucket to timeout, not
        # "other".
        return "timeout"
    if (d.startswith("Docker execution was not attempted")
            or d.startswith(("Container did not produce valid JSON output", "容器未输出", "容器异常退出",
                              "未执行 Docker 测试", "测试文件准备失败", "测试执行准备失败",
                              "Docker 环境不可用", "Docker 资源清理失败",
                              "C/C++ sanitizer", "C/C++ 测试配置"))):
        return "execution"
    return "other"


def _retry_stop_reason(execution) -> str:
    """把执行器的失败分类翻译成一句可操作的停止原因。

    旧代码在这里只说“执行超时”：构建超时（容器根本没跑）与容器执行超时共用
    同一句话，运维无法判断该改网络还是改测试。
    """
    from utilities.docker_build import (
        BUILD_TIMEOUT, CLEANUP, ENVIRONMENT, FAILURE_LABELS, IMAGE, RUN_TIMEOUT,
        TOOLCHAIN,
    )
    kind = getattr(execution, "failure_kind", None)
    label = FAILURE_LABELS.get(kind or "", "执行失败")
    hint = {
        BUILD_TIMEOUT: "容器尚未执行，请为 Docker 构建配置代理或检查网络",
        TOOLCHAIN: "共享工具链镜像无法准备，属于宿主环境问题",
        IMAGE: "基础镜像无法拉取，请为 Docker 守护进程配置代理或预先拉取",
        ENVIRONMENT: "Docker 环境不可用，属于宿主环境问题",
        RUN_TIMEOUT: "容器执行超时",
        CLEANUP: "Docker 资源回收失败，需要人工核对",
    }.get(kind, "重写测试无法修复")
    return f"{label}（{hint}）"


def run_dynamic_tests(
    pipeline_output_path: str,
    output_dir: str | None = None,
    max_retries: int = 3,
    checkpoint_path: str | None = None,
    repo_path: str | None = None,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
    usage_baseline: dict | None = None,
    docker_proxy: str | None = None,
) -> list[DynamicTestResult]:
    """Run dynamic tests for all findings in a pipeline output file.

    Args:
        pipeline_output_path: Path to pipeline_output.json
        output_dir: Directory for output files. Defaults to same directory
                    as pipeline_output_path.
        max_retries: Max retries per finding on error (default 3).
        checkpoint_path: Path to checkpoint directory for resume support.
        repo_path: Repository root, staged under repository/ with its headers,
            modules, resources and manifests, excluding credentials and caches.
        docker_proxy: Optional http://IP:port proxy for build dependencies.

    Returns:
        List of DynamicTestResult objects
    """
    from utilities.docker_build import BuildPolicy, parse_docker_proxy
    docker_proxy = parse_docker_proxy(docker_proxy)
    # 预算在阶段入口解析一次：非法环境变量在这里失败，而不是每条发现各失败一次。
    policy = BuildPolicy.from_environment()
    # Resolve the dynamic_test phase binding from the registry once and
    # reuse it across every finding. Standalone-invocation path
    # validates upfront; scanner-driven calls trust the scanner's probe.
    if registry is None:
        from utilities.llm import probe_registry_or_raise

        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
        probe_registry_or_raise(registry)
    dynamic_test_binding = registry.get("dynamic_test")

    # Load pipeline output
    pipeline = read_json(pipeline_output_path)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load
    # (presence-guarded) so the DYNAMIC_TESTABLE filter's `f.get(...)` is safe.
    if "findings" in pipeline:
        normalize_results(pipeline, "findings")
    findings = pipeline.get("findings", [])
    # Enforce the dynamic-testability filter at the execution site. Only
    # findings asserted vulnerable are worth an active Docker reproduction;
    # core/dynamic_tester.py computes the same filter for reporting, but the
    # per-finding loop lives here, so without this every finding (regardless
    # of stage2_verdict) was dynamically tested anyway.
    from core.verdict_taxonomy import DYNAMIC_TESTABLE
    findings = [f for f in findings
                if f.get("stage2_verdict") in DYNAMIC_TESTABLE]
    repo_info = {
        "name": pipeline.get("repository", {}).get("name", "unknown"),
        # No default language. The previous "Python" fallback silently told the
        # generator that an unknown-language repo was Python; an explicit
        # "unknown" lets per-finding resolution decide and makes the gap visible.
        "language": pipeline.get("repository", {}).get("language") or "unknown",
        "application_type": pipeline.get("application_type", "unknown"),
    }
    # #521: the declared-runtime channel — mechanically derived from the repo
    # root's manifests (go.mod / .python-version / requires-python / engines /
    # .tool-versions), allowlist-validated, degrade-to-absent on anything else.
    # NEVER raises (that would abort the whole dynamic-test step before any
    # finding is tested); absent repo_path (the None default) derives {}.
    from utilities.dynamic_tester.declared_runtime import derive_declared_runtimes
    repo_info["declared_runtimes"] = derive_declared_runtimes(repo_path)
    from utilities.dynamic_tester.source_context import describe_repository
    repo_info["source_context"] = describe_repository(repo_path)

    if not findings:
        print("没有需要动态测试的发现。", file=sys.stderr)
        return []

    # 预检：守护进程、buildx 与代理可达性。放在任何模型调用之前，宿主问题只报
    # 一次并给出可操作的说明，而不是让每条发现各自耗尽构建预算。
    from utilities.docker_build.preflight import verify_build_environment
    from utilities.dynamic_tester.docker_executor import _run_command
    environment = verify_build_environment(docker_proxy, _run_command)
    from utilities.docker_build import (
        available_images, build_proxy_arguments, dockerfile_bases,
        ensure_base_images, ensure_toolchain, native_toolchain,
    )
    from utilities import docker_resources
    from utilities.dynamic_tester.test_generator import resolve_native_language

    # 已缓存镜像确实进入生成提示词；此前只有消费者，没有赋值入口。
    repo_info["base_images"] = available_images(_run_command)

    # C/C++ 共用工具链，必须在任何模型生成调用之前只准备一次。
    # 这样拉取/工具链构建失败会在阶段入口明确报错，不会逐项消耗
    # 模型费用或重复等待 1800 秒。
    if any(resolve_native_language(
            f["location"]["file"] if isinstance(f.get("location"), dict)
            and isinstance(f["location"].get("file"), str) else "",
            repo_info["language"],
        ) for f in findings):
        toolchain = native_toolchain("c")
        with docker_resources.build_admission(timeout=policy.build_timeout, runner=_run_command):
            with build_proxy_arguments(docker_proxy, _run_command) as proxy_args:
                ensure_base_images(dockerfile_bases(toolchain.context), _run_command,
                                   timeout=policy.pull_timeout)
                ensure_toolchain(toolchain, _run_command, proxy_arguments=proxy_args,
                                 timeout=policy.toolchain_timeout)

    print(f"  Docker 构建环境：server {environment['server_version']}，"
          f"{environment['proxy_description']}", file=sys.stderr)
    print(f"  Docker 时间预算：构建 {policy.build_timeout}s / "
          f"容器 {policy.run_timeout}s / 工具链 {policy.toolchain_timeout}s",
          file=sys.stderr)

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(pipeline_output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Set up checkpoint support
    checkpoint = None
    checkpointed = {}
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "dynamic_test_checkpoints")

    from core.checkpoint import StepCheckpoint
    checkpoint = StepCheckpoint("dynamic_test", output_dir)
    checkpoint.dir = checkpoint_path
    if checkpoint.exists:
        checkpointed = checkpoint.load()

    # Count successful vs errored checkpoints. Errored ones are NOT "already
    # done" — they'll be retried with fresh test generation on resume.
    successful_ids = {fid for fid, cp in checkpointed.items()
                      if cp.get("status") != "ERROR"}
    errored_ids = {fid for fid in checkpointed.keys() if fid not in successful_ids}

    if successful_ids:
        print(f"已从检查点恢复 {len(successful_ids)} 项测试结果",
              file=sys.stderr, flush=True)
    if errored_ids:
        print(f"准备重试之前出错的 {len(errored_ids)} 项发现",
              file=sys.stderr, flush=True)

    # Use the global tracker so step_context captures dynamic-test cost in
    # dynamic-test.report.json (same as enhance/analyze/verify).
    tracker = get_global_tracker()
    # #333: the tracker is SHARED with the earlier LLM phases of a full scan,
    # so a raw read at the end is the whole RUN's cost. Snapshot now — at step
    # entry, BEFORE the checkpoint prior-usage injection below (those injected
    # costs are this step's OWN spend from earlier attempts, meant to show
    # "total cost across runs") — and report the delta, mirroring
    # core/step_report.py:63. The markdown `**预估总费用：**` line and
    # dynamic_test_results.json were the two of the step's three cost outputs
    # still reading the cumulative (#280 fixed the console lines only).
    _baseline_cost_usd = tracker.total_cost_usd

    # #608: the summary's stage-local usage — the DELTA from the pre-stage
    # baseline: the stage's OWN spend across runs (the restored attempts'
    # prior usage [the #333 injection] + this run's fresh calls), EXCLUDING
    # the earlier phases' spend on the shared tracker. The baseline snapshot
    # PRECEDES the injection (NOT refreshed after it — the family contract:
    # every _summary.json writer — enhance, analyze, verify, llm — publishes
    # prior+fresh; the CONSOLE line refreshes its baseline separately at
    # the #333 block so its delta excludes the restored spend that the
    # original run's console line already printed — two channels, two
    # figures, both correct). On a resumed run the pass-start snapshot
    # therefore carries the restored units' spend — never completed=N at
    # usage=0 (the "$0 for the whole stage" shape this issue exists to
    # remove).
    _summary_baseline: dict | None = None
    try:
        _summary_baseline = dict(tracker.get_totals())
    except Exception:  # noqa: BLE001 — None publishes usage=None (the honest
        # absence, matching the llr sibling), never a cumulative-as-delta
        _summary_baseline = None

    # Inject prior usage from ALL existing checkpoints (both successful and
    # errored) so the report shows total cost across runs. The errored
    # entries will be retried — their initial attempt cost is preserved,
    # and the retry API calls get added on top.
    _prior_input = 0
    _prior_output = 0
    _prior_cost = 0.0
    _prior_unpriced: set[str] = set()  # #598: forward the marker on resume
    # #626/PR#661 hunt F4: the cache kind, forwarded the same way.
    _prior_unpriced_cache: set[str] = set()
    for _cp in checkpointed.values():
        _prior_cost += _cp.get("generation_cost_usd", 0) or 0
        _prior_input += _cp.get("generation_input_tokens", 0) or 0
        _prior_output += _cp.get("generation_output_tokens", 0) or 0
        _u, _c = unpriced_kinds_from(_cp)
        _prior_unpriced.update(_u)
        _prior_unpriced_cache.update(_c)
    if _prior_cost > 0 or _prior_input > 0 or _prior_output > 0 \
            or _prior_unpriced or _prior_unpriced_cache:
        # (#598 review: the unpriced term keeps this guard in agreement
        # with its three sibling resume blocks — a zero-token unpriced
        # checkpoint must still forward the marker. #626: the cache term
        # joins it for the same reason.)
        tracker.add_prior_usage(
            _prior_input, _prior_output, _prior_cost,
            unpriced_models=sorted(_prior_unpriced) or None,
            unpriced_cache_models=sorted(_prior_unpriced_cache) or None)
        # #333 (wave r1 opus): refresh the caller's phase-line baseline AT
        # the injection — the restored checkpoints' spend was reported by
        # their ORIGINAL run's console line, and a pre-injection snapshot
        # double-counted it here (the #281 cross-phase contract, extended to
        # the dynamic-test step). NOTE: ONLY the console baseline refreshes
        # — the _summary.json baseline above stays pre-injection (the family
        # contract: the summary publishes prior+fresh; the console excludes
        # the restored spend).
        if usage_baseline is not None:
            _tot = tracker.get_totals()
            usage_baseline["cost_usd"] = _tot.get("total_cost_usd",
                                                 usage_baseline["cost_usd"])
            usage_baseline["tokens"] = _tot.get("total_tokens",
                                                usage_baseline["tokens"])
            usage_baseline["calls"] = _tot.get("total_calls",
                                               usage_baseline["calls"])
            # #624: the turns refresh — same phase-scoping contract.
            usage_baseline["turns"] = _tot.get("total_turns",
                                               usage_baseline.get("turns", 0))

    def _summary_usage():
        # #608: a baseline that could not be snapshotted publishes usage=None
        # (the honest absence — the llr sibling's degraded path), never the
        # raw run-cumulative misread as a stage delta.
        if _summary_baseline is None:
            return None
        try:
            t = tracker.get_totals()
            u = {
                "input_tokens": t.get("total_input_tokens", 0)
                - _summary_baseline.get("total_input_tokens", 0),
                "output_tokens": t.get("total_output_tokens", 0)
                - _summary_baseline.get("total_output_tokens", 0),
                "cost_usd": round(t.get("total_cost_usd", 0.0)
                                  - _summary_baseline.get("total_cost_usd", 0.0), 6),
            }
            # #216: the incomplete-cost markers survive; #605: the counter.
            # (Run-cumulative — the accepted trade in step_report.py:147-163,
            # the same parenthetical the llr sibling carries.)
            if t.get("cost_incomplete"):
                u["cost_incomplete"] = True
                u["unpriced_models"] = t.get("unpriced_models") or []
                # #626/PR#661 hunt F4: the cache kind, present-only (the
                # llr sibling carries the identical pair).
                if t.get("unpriced_cache_models"):
                    u["unpriced_cache_models"] = t["unpriced_cache_models"]
            if t.get("accounting_errors"):
                u["accounting_errors"] = t.get("accounting_errors")
            return u
        except Exception:  # noqa: BLE001 — a usage read must never kill the stage
            return None

    results: list[DynamicTestResult] = []

    total = len(findings)
    restored = len(successful_ids)
    remaining = total - restored

    # Write initial summary so Go CLI can show accurate counts.
    # #311: DERIVED from the saved unit files (the same source status()
    # recomputes from) — not loop-local accumulators, which bypassed the
    # generation-failure path and wrote errors: 0 for errored runs.
    _counts = _summary_counts_from_checkpoints(checkpointed)
    _completed = _counts["completed"]
    _errors = _counts["errors"]
    checkpoint.ensure_dir()
    checkpoint.write_summary(total, _completed, _errors, _counts["error_breakdown"], phase="in_progress", usage=_summary_usage())

    print(f"正在动态测试仓库 {repo_info['name']} 的 {total} 项发现 "
          f"（已完成 {restored} 项，剩余 {remaining} 项）",
          file=sys.stderr)

    try:
      for i, finding in enumerate(findings):
        # str() at the boundary: id is repo/JSON-derived and may be non-str; it flows
        # to run_single_container's finding_id.lower() and checkpoint's safe_filename,
        # both of which would raise on a non-str and abort the whole run.
        finding_id = str(finding.get("id", f"FINDING-{i+1}"))

        # Skip already-checkpointed findings, but ONLY if they succeeded.
        # Errored findings fall through to fresh test generation + Docker run,
        # so code/prompt fixes take effect on resume.

        cp_data = checkpointed.get(finding_id)
        if cp_data and cp_data.get("status") != "ERROR":
            result = DynamicTestResult(
                finding_id=finding_id,
                # #314: thread the identity through resume so a checkpointed
                # verdict merges on the same key as a fresh one.
                identity_key=finding.get("identity_key", ""),
                status=cp_data.get("status", "ERROR"),
                details=cp_data.get("details", ""),
                elapsed_seconds=cp_data.get("elapsed_seconds", 0),
                generation_cost_usd=cp_data.get("generation_cost_usd", 0),
                generation_input_tokens=cp_data.get("generation_input_tokens", 0),
                generation_output_tokens=cp_data.get("generation_output_tokens", 0),
                # #598: restore the per-unit unpriced ids too — the fresh
                # rows carry them; a resumed run's results JSON must not
                # contradict its own checkpoint rows.
                unpriced_models=list(cp_data.get("unpriced_models") or []),
                # #626: the cache kind too — a resumed run's results JSON
                # must not contradict its own checkpoint rows for either
                # kind.
                unpriced_cache_models=list(
                    cp_data.get("unpriced_cache_models") or []),
                retry_count=cp_data.get("retry_count", 0),
                test_code=cp_data.get("test_code", ""),
                dockerfile=cp_data.get("dockerfile", ""),
                docker_compose=cp_data.get("docker_compose", ""),
                reproduction=(cp_data.get("reproduction")
                              if isinstance(cp_data.get("reproduction"), dict) else {}),
                # Reconstruct the exploit-proof evidence too — it's serialized in the
                # checkpoint but was dropped on resume, so a restored CONFIRMED finding
                # silently lost its command_output/file_read/http_response proof.
                evidence=[
                    TestEvidence(type=e.get("type", ""), content=e.get("content", ""))
                    for e in cp_data.get("evidence", []) if isinstance(e, dict)
                ],
            )
            results.append(result)
            continue

        # Skip findings whose language has no Docker template, BEFORE spending
        # an LLM call generating a test the harness cannot usefully run.
        # Placed AFTER the checkpoint hit: a finding CONFIRMED by an
        # earlier run must keep that verdict on resume, not be downgraded
        # to SKIPPED and lose its exploit evidence.
        _loc = finding.get("location")
        _file = _loc.get("file") if isinstance(_loc, dict) else None
        _file = _file if isinstance(_file, str) else ""  # location.file may be non-str (JSON)
        _skip, _reason = should_skip_for_language(_file, repo_info.get("language"))
        if _skip:
            print(f"\n[{i+1}/{total}] 跳过 {finding_id}（SKIPPED）：{_reason}", file=sys.stderr)
            results.append(DynamicTestResult(
                finding_id=finding_id,
                identity_key=finding.get("identity_key", ""),
                status="SKIPPED", details=_reason,
                elapsed_seconds=0,
            ))
            continue

        print(f"\n[{i+1}/{total}] 正在测试 {finding_id}："
              f"{finding.get('name', 'unknown')}...", file=sys.stderr)

        # Begin per-unit tracking so we can capture token counts for this
        # finding in addition to cost.
        tracker.start_unit_tracking()

        # Step 1: Generate test. #431: a RAISED exception (live repro: the
        # adapter hit the provider content filter and raised LLMResponseError
        # after its internal retries) previously escaped unhandled — it
        # aborted the whole loop (remaining findings never attempted) and the
        # on-disk _summary.json kept errors: 0, the exact #311 defect on the
        # raise route. Treat a raise exactly like a None return: record the
        # ERROR unit file, derive the summary from the files, continue.
        print("  正在生成测试……", file=sys.stderr)
        try:
            generation = generate_test(finding, repo_info, dynamic_test_binding, tracker)
        except Exception as gen_exc:
            generation = None
            print(f"  测试生成发生异常：{type(gen_exc).__name__}", file=sys.stderr)
            _gen_exc_message = bounded_diagnostic(str(gen_exc), 2000)
            _gen_exc_raised = True
        else:
            _gen_exc_raised = False
            _gen_exc_message = ""
        unit_usage = tracker.get_unit_usage()
        generation_cost = unit_usage["cost_usd"]

        if generation is None:
            print("  测试生成失败。", file=sys.stderr)
            result = collect_result(finding, None, None, generation_cost)
            if _gen_exc_raised:
                # keep the raised exception's own words (the None path has none)
                result.details = f"测试生成异常：{_gen_exc_message[:2000]}"
            result.generation_input_tokens = unit_usage["input_tokens"]
            result.generation_output_tokens = unit_usage["output_tokens"]
            # #598 + #626: persist the generation spend's unpriced ids,
            # BOTH kinds (the resume reader was wired for the first key and
            # nothing wrote it; the second key had no field at all).
            (result.unpriced_models,
             result.unpriced_cache_models) = unpriced_kinds_from(unit_usage)
            results.append(result)
            if checkpoint:
                checkpoint.save(finding_id, result.to_dict())
                # #311: the saved ERROR unit file IS the count — derive the
                # summary from the unit files so this branch can no longer
                # write errors: 0 for an errored run.
                _counts = _summary_counts_from_checkpoints(checkpoint.load())
                _completed = _counts["completed"]
                _errors = _counts["errors"]
                checkpoint.write_summary(total, _completed, _errors, _counts["error_breakdown"],
                                         phase="in_progress",
                                         usage=_summary_usage())
            continue

        # #786 (the #608 contract: get_totals reads are SANCTIONED readers
        # only — this line reads the unit's OWN usage, which never calls
        # get_totals and already carries the unpriced ids per #216/#598)
        from core.tracking import cost_marker
        print(f"  测试已生成（${generation_cost:.4f}"
              f"{cost_marker(unit_usage)}），正在 Docker 内执行……",
              file=sys.stderr)

        # Resolve the vulnerable source file for pre-staging. location.file is a
        # DETERMINISTIC repo-derived path (reporter.py sets it to route_key.split(":")[0],
        # the parser's repo-relative path of the unit) — repo-author-controlled, and in a
        # standalone run the findings JSON is fully caller-supplied. A `..`/absolute value,
        # or an in-repo symlink pointing outside, would make the copy escape repo_path and
        # read a HOST file into the Docker build context (read/exfil). Confine the resolved
        # path under repo_path (realpath also blocks the symlink case); skip on escape —
        # source_file stays None, the already-supported no-source path. Guard the types too:
        # `location` may be a non-dict and `file` a non-str (JSON), which must not raise
        # (an unwrapped raise aborts the whole run — see docker_executor._refuse_compose).
        source_file = None
        if repo_path:
            _loc = finding.get("location")
            rel_path = _loc.get("file", "") if isinstance(_loc, dict) else ""
            if isinstance(rel_path, str) and rel_path:
                repo_root = os.path.realpath(repo_path)
                resolved = os.path.realpath(os.path.join(repo_path, rel_path))
                if ((resolved == repo_root or resolved.startswith(repo_root + os.sep))
                        and os.path.isfile(resolved)):
                    source_file = resolved

        # Step 2: Execute in Docker and retry on errors
        execution = run_single_container(generation, finding_id,
                                         source_file=source_file, repo_path=repo_path,
                                         docker_proxy=docker_proxy, policy=policy)
        result = collect_result(finding, generation, execution, generation_cost)
        retry_count = 0
        failed_attempts: set[str] = set()

        while result.status == "ERROR" and retry_count < max_retries:
            failure_kind = getattr(execution, "failure_kind", None)
            if failure_kind is None and getattr(execution, "execution_error", None):
                # 未分类的执行错误（旧调用方或自定义执行器）：保守停止，
                # 保持既有契约；已分类的 STAGING 仍可重试。
                print("  Docker 环境或测试配置不可用，不再请求模型重试。", file=sys.stderr)
                break
            if not getattr(execution, "retryable", True):
                print(f"  {_retry_stop_reason(execution)}，不再请求模型重试。",
                      file=sys.stderr)
                break
            if getattr(execution, "infrastructure_error", False):
                print("  Docker 环境或测试配置不可用，不再请求模型重试。", file=sys.stderr)
                break
            if execution.timed_out:
                print("  容器执行超时，不再重试。", file=sys.stderr)
                break

            attempt_key = failed_attempt_key(generation, execution)
            if attempt_key in failed_attempts:
                # A changed test is allowed even for the same error. An exact
                # duplicate gets one execution (transient errors may clear),
                # but must not consume the rest of the model retry budget.
                result.details += " 同一测试配置重复出现相同错误，已停止自动重试；未完成验证。"
                print("  测试配置和错误均未变化，停止重复重试。", file=sys.stderr)
                break
            failed_attempts.add(attempt_key)
            error_msg = error_feedback(result, execution)
            error_type = ("构建" if execution.build_error or _error_category(result.details) == "build"
                          else "运行时" if execution.exit_code != 0 else "应用")

            retry_count += 1
            print(f"  {error_type}出错，正在第 {retry_count}/{max_retries} 次重试，"
                  f"已附带错误反馈……", file=sys.stderr)

            retry_failure = ""
            try:
                retry_gen = regenerate_test(
                    finding, repo_info, generation,
                    error_msg, dynamic_test_binding, tracker,
                )
            except Exception as retry_exc:
                # Match initial-generation isolation: one provider failure must
                # not abort later findings or leave the current unit unsaved.
                retry_gen = None
                retry_failure = (f"测试生成异常（重试）：{type(retry_exc).__name__}: "
                                 f"{bounded_diagnostic(str(retry_exc), 2000)}")
                print(f"  重试生成发生异常：{type(retry_exc).__name__}", file=sys.stderr)
            # Refresh unit usage after retry (tracker accumulates across calls
            # on the same thread).
            unit_usage = tracker.get_unit_usage()
            generation_cost = unit_usage["cost_usd"]

            if retry_gen is None:
                # Preserve the last executed artifacts/evidence and ERROR;
                # expose the generation failure separately in the details.
                result.details = (retry_failure or "测试生成失败（重试）：模型未返回有效测试代码。") + (
                    " 上一执行错误：" + bounded_diagnostic(result.details, 2000))
                print("  重试生成失败。", file=sys.stderr)
                break

            generation = retry_gen
            execution = run_single_container(generation, finding_id,
                                             source_file=source_file, repo_path=repo_path,
                                             docker_proxy=docker_proxy, policy=policy)
            result = collect_result(finding, generation, execution, generation_cost)
            print(f"  第 {retry_count} 次重试结果：{result.status} "
                  f"(${generation_cost:.4f})", file=sys.stderr)

        result.retry_count = retry_count
        # Failed/raised regeneration still spends tokens; no new collect_result
        # call occurs on those paths, so refresh the cost on the retained result.
        result.generation_cost_usd = generation_cost
        result.generation_input_tokens = unit_usage["input_tokens"]
        result.generation_output_tokens = unit_usage["output_tokens"]
        # #598 + #626: persist the generation spend's unpriced ids, BOTH
        # kinds (see the sibling fold above).
        (result.unpriced_models,
         result.unpriced_cache_models) = unpriced_kinds_from(unit_usage)
        results.append(result)

        # Save checkpoint and update summary after each finding.
        # #311: the counts are re-derived from the saved unit files (the
        # checkpoint was just saved, so the derivation includes it).
        if checkpoint:
            checkpoint.save(finding_id, result.to_dict())
            _counts = _summary_counts_from_checkpoints(checkpoint.load())
            _completed = _counts["completed"]
            _errors = _counts["errors"]
            checkpoint.write_summary(total, _completed, _errors, _counts["error_breakdown"], phase="in_progress", usage=_summary_usage())

        print(f"  结果：{result.status}（{result.elapsed_seconds:.1f} 秒）",
              file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[动态测试] 已中断，进度已保存到检查点",
              file=sys.stderr, flush=True)
        # #419 (the #417 class): `return results` here swallowed the
        # interrupt AND handed the caller partial results, which then wrote
        # DYNAMIC_TEST_RESULTS.md as a completion artifact for an
        # interrupted run. The checkpoints hold the progress (every
        # completed finding is saved as it completes — the resume story);
        # the interrupt itself PROPAGATES so the CLI exits 130 with an
        # interrupted envelope, never a success one.
        raise

    # Generate report
    # #333: the STEP's cost (the entry-snapshot delta), not the run's
    # cumulative — prior-phase spend on the shared tracker must not appear
    # here (the JSON step-report on the same run already reads the delta).
    total_cost = tracker.total_cost_usd - _baseline_cost_usd
    # #786 (T1 round-2 F-A): the total marker reads the tracker's run-set
    # via the #608-sanctioned accessor (never get_totals) and passes it as
    # the render input — the RESULT ROWS ARE NEVER MUTATED (the JSON stays
    # the honest per-unit record; a union fold would fabricate ids on rows
    # whose units were priced, and a run-cumulative set against a
    # phase-scoped figure is exactly the F1 class). The conservative
    # direction: the total figure is not provably complete when the
    # run-set is non-empty.
    _total_unpriced = tracker.cost_incomplete_models() or None
    report_md = generate_report(results, repo_info["name"], total_cost,
                                total_unpriced=_total_unpriced)

    report_path = os.path.join(output_dir, "DYNAMIC_TEST_RESULTS.md")
    with open_utf8(report_path, "w") as f:
        f.write(report_md)
    print(f"\n报告已写入 {report_path}", file=sys.stderr)

    # Save structured results JSON
    results_path = os.path.join(output_dir, "dynamic_test_results.json")
    with open_utf8(results_path, "w") as f:
        json.dump({
            "repository": repo_info["name"],
            "total_findings": len(findings),
            "total_cost_usd": round(total_cost, 6),
            "results": [r.to_dict() for r in results],
        }, f, indent=2, ensure_ascii=False)
    print(f"JSON 结果已写入 {results_path}", file=sys.stderr)

    # Mark done. Checkpoints are preserved as a permanent artifact alongside
    # results — allows retroactive retry of errored findings after fixes.
    if checkpoint:
        # #311: the final summary derives from the unit files too — the
        # authoritative record, structurally identical to status().
        _counts = _summary_counts_from_checkpoints(checkpoint.load())
        checkpoint.write_summary(total, _counts["completed"],
                                 _counts["errors"], _counts["error_breakdown"], phase="done",
                                 usage=_summary_usage())

    return results
