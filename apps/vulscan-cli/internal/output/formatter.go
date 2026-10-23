// Modified 2026-10-23 for 911VulScan product branding; attribution in distribution notices.
// Package output handles terminal output formatting.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/types"
)

var (
	bold   = color.New(color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	cyan   = color.New(color.FgCyan)
	dim    = color.New(color.Faint)
)

// PrintJSON outputs the raw JSON envelope to stdout.
func PrintJSON(envelope types.Envelope) {
	data, _ := json.MarshalIndent(envelope, "", "  ")
	fmt.Println(string(data))
}

// PrintError outputs an error message to stderr.
func PrintError(msg string) {
	red.Fprintf(os.Stderr, "错误：")
	fmt.Fprintln(os.Stderr, msg)
}

// PrintErrors outputs multiple error messages to stderr.
func PrintErrors(errors []string) {
	for _, e := range errors {
		PrintError(e)
	}
}

// PrintSuccess outputs a success message.
func PrintSuccess(msg string) {
	green.Print("✓ ")
	fmt.Println(msg)
}

// PrintWarning outputs a warning message to stderr.
func PrintWarning(msg string) {
	yellow.Fprintf(os.Stderr, "警告：")
	fmt.Fprintln(os.Stderr, msg)
}

// PrintHeader outputs a section header.
func PrintHeader(msg string) {
	fmt.Println()
	bold.Println(msg)
	fmt.Println(strings.Repeat("─", len(msg)))
}

// PrintKeyValue outputs a key-value pair.
func PrintKeyValue(key, value string) {
	cyan.Printf("  %s: ", key)
	fmt.Println(value)
}

// stringIDs extracts the string ids from a decoded JSON list, skipping any
// non-string element (the usage envelope arrives as map[string]any).
func stringIDs(raw []any) []string {
	ids := make([]string, 0, len(raw))
	for _, u := range raw {
		if id, ok := u.(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// renderCostBlock prints the Cost line and the incompleteness detail lines —
// the one home for all three summary renderers. #598: an incomplete figure
// must never read as complete, and a $0 incomplete figure must not vanish
// the cost line entirely (the report renderer's old cost>0 gate did exactly
// that).
//
// There are TWO kinds of incompleteness and they are NOT interchangeable, so
// they get two labels and two lines — never one merged list:
//
//	unpriced_models        the model has NO pricing record. Its spend is
//	                       attributed $0, so the figure is a LOWER bound
//	                       (#216/#598). That direction IS knowable here.
//	unpriced_cache_models  the model IS priced; only its cache multipliers
//	                       are absent (#626). Its error DIRECTION depends on
//	                       the provider's field shape and is OPPOSITE for the
//	                       two shapes, so it is NOT knowable from this
//	                       envelope — see below.
//
// Merging them (the F661-2 shape) told the operator a priced model such as
// gpt-4o (input $2.50 / output $10.00) was "unpriced", and made a bounded
// over-estimate indistinguishable from an altogether missing figure.
//
// PR#661 hunt F1 — why the cache kind carries NO direction claim. The
// round-1 wording said "upper bound". That is true only for the INCLUSIVE
// provider field shapes (openai cached_tokens, google
// cached_content_token_count): those cached tokens are already inside the
// reported input count, so an absent multiplier bills them at the full input
// rate — an over-estimate. For the EXCLUSIVE shapes (anthropic/bedrock
// cache_read_input_tokens / cache_creation_input_tokens) the cached tokens
// are DISJOINT from input_tokens, so an absent multiplier contributes $0 and
// the figure is a LOWER bound. Executed against the shipped registry:
//
//	us.anthropic.claude-sonnet-4-6, 10k in / 1k out / 90k cache-read
//	formula $0.049500   real bill $0.079200   ratio 0.625
//
// All 11 bedrock records ship priced with no cache block and the bedrock
// adapter does emit the exclusive fields (it reuses anthropic.py's
// _response_to_unified), so "upper bound" was false for the whole bedrock
// census — an operator read "the bill is at most $0.0495" against a real
// $0.0792. The usage envelope carries no inclusion-shape discriminator, so
// this renderer states the CONDITION and that the figure may be under- or
// over-stated, and never a direction it cannot derive. (Surfacing the
// derived direction is a named follow-up: it needs a tri-state that survives
// the step-report, scan-report and resume hops.)
func renderCostBlock(usage map[string]any) {
	cost := floatFromAny(usage["total_cost_usd"])
	incomplete, _ := usage["cost_incomplete"].(bool)
	rawUnpriced, _ := usage["unpriced_models"].([]any)
	rawCacheUnpriced, _ := usage["unpriced_cache_models"].([]any)
	unpriced := stringIDs(rawUnpriced)
	cacheUnpriced := stringIDs(rawCacheUnpriced)

	// The cost label names the condition(s) that actually hold. The
	// pricing-absent wording is unchanged from #598 so that case renders
	// byte-identically to before.
	costLabel := "预估费用"
	switch {
	case len(unpriced) > 0 && len(cacheUnpriced) > 0:
		costLabel = "预估费用（估算不完整：部分模型无定价；" +
			"缓存费率未配置）"
	case len(unpriced) > 0:
		costLabel = "预估费用（估算不完整：部分模型无定价）"
	case len(cacheUnpriced) > 0:
		costLabel = "预估费用（估算不完整：缓存费率未配置）"
	case incomplete:
		// cost_incomplete without either id list: keep the #598 promise
		// that an incomplete figure never reads as complete.
		costLabel = "预估费用（估算不完整：部分模型无定价）"
	}
	PrintKeyValue(costLabel, fmt.Sprintf("$%.4f", cost))

	if len(unpriced) > 0 {
		PrintKeyValue("未定价模型", strings.Join(unpriced, ", "))
	}
	if len(cacheUnpriced) > 0 {
		PrintKeyValue("未配置缓存费率",
			strings.Join(cacheUnpriced, ", ")+
				"（这些模型已有基础定价；缓存用量尚未按缓存费率"+
				"计算，因此当前估算可能偏低"+
				"或偏高）")
	}
}

// renderTokensLine prints the token line for all three summary renderers —
// the one home, the renderCostBlock pattern.
//
// PR#661 hunt L1: the two summary renderers printed "N input / M output"
// only. On the EXCLUSIVE provider shapes (anthropic/bedrock) the cached
// tokens are a SEPARATE line item that is deliberately never folded into
// total_input_tokens — the uncached/cached split is the
// billing-reconciliation shape — so an anthropic run displayed "10000
// input" beside a cost covering 100000 tokens of real traffic, with the
// 90000 invisible. The typed UsageInfo and every JSON artifact carried the
// counts; nothing rendered them.
//
// Present-only PER FIELD, mirroring the Python envelope (core/schemas.py
// UsageInfo.to_dict) and the Go struct's omitempty: a run with no cache
// traffic prints the pre-#626 line byte-for-byte, and a READ-ONLY cache run
// does not assert a cache-write zero it never measured (the FIX-1 rule).
func renderTokensLine(usage map[string]any) {
	segments := []string{
		fmt.Sprintf("输入 %d", intFromAny(usage["total_input_tokens"])),
		fmt.Sprintf("输出 %d", intFromAny(usage["total_output_tokens"])),
	}
	if _, present := usage["total_cache_read_tokens"]; present {
		segments = append(segments, fmt.Sprintf("缓存读取 %d",
			intFromAny(usage["total_cache_read_tokens"])))
	}
	if _, present := usage["total_cache_write_tokens"]; present {
		segments = append(segments, fmt.Sprintf("缓存写入 %d",
			intFromAny(usage["total_cache_write_tokens"])))
	}
	PrintKeyValue("令牌用量", strings.Join(segments, " / "))
}

// PrintScanSummary outputs a formatted summary of scan results.
func PrintScanSummary(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		return
	}

	PrintHeader("扫描结果")

	total := intFromAny(metrics["total"])
	vulnerable := intFromAny(metrics["vulnerable"])
	safe := intFromAny(metrics["safe"])
	unclear := intFromAny(metrics["inconclusive"])
	verified := intFromAny(metrics["verified"])
	falsePos := intFromAny(metrics["stage2_disagreed"])
	// #622: the protected split of the disagreed count — a correction to
	// protected-by-controls is NOT a false positive; without the companion
	// line the "eliminated" number silently shrinks when they split out.
	reclassifiedProtected := intFromAny(metrics["stage2_disagreed_protected"])

	PrintKeyValue("已分析代码单元", fmt.Sprintf("%d", total))

	if vulnerable > 0 {
		red.Printf("  存在漏洞：")
		fmt.Printf("%d", vulnerable)
		if verified > 0 {
			fmt.Printf("（已验证 %d 个）", verified)
		}
		fmt.Println()
	} else {
		green.Printf("  存在漏洞：")
		fmt.Println("0")
	}

	PrintKeyValue("未发现漏洞", fmt.Sprintf("%d", safe))

	if unclear > 0 {
		yellow.Printf("  尚不明确：")
		fmt.Printf("%d\n", unclear)
	}

	if falsePos > 0 {
		PrintKeyValue("已排除误报", fmt.Sprintf("%d", falsePos))
	}
	if reclassifiedProtected > 0 {
		PrintKeyValue("重新归类为已防护（已验证控制措施）",
			fmt.Sprintf("%d", reclassifiedProtected))
	}

	// Usage info
	if usage, ok := data["usage"].(map[string]any); ok {
		PrintHeader("用量")
		renderCostBlock(usage)
		renderTokensLine(usage)
	}

	// Report paths
	if reports, ok := data["reports"].(map[string]any); ok {
		PrintHeader("报告")
		if html, ok := reports["html_path"].(string); ok && html != "" {
			PrintKeyValue("HTML", html)
		}
		if csv, ok := reports["csv_path"].(string); ok && csv != "" {
			PrintKeyValue("CSV", csv)
		}
		if summary, ok := reports["summary_path"].(string); ok && summary != "" {
			PrintKeyValue("摘要", summary)
		}
	}

	fmt.Println()

	// Final verdict
	if vulnerable > 0 {
		red.Printf("⚠ 发现 %d 个漏洞\n", vulnerable)
	} else {
		green.Println("✓ 本次扫描未发现漏洞")
	}
}

// PrintParseSummary outputs a formatted summary of parse results.
func PrintParseSummary(data map[string]any) {
	PrintHeader("解析结果")
	if lang, ok := data["language"].(string); ok {
		PrintKeyValue("语言", lang)
	}
	if level, ok := data["processing_level"].(string); ok {
		PrintKeyValue("处理层级", level)
	}
	if units := intFromAny(data["units_count"]); units > 0 {
		PrintKeyValue("已提取代码单元", fmt.Sprintf("%d", units))
	}
	if path, ok := data["dataset_path"].(string); ok {
		PrintKeyValue("输出位置", path)
	}
	fmt.Println()
}

// PrintAnalyzeSummary outputs a formatted summary of analysis results.
func PrintAnalyzeSummary(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		return
	}

	PrintHeader("分析结果")
	total := intFromAny(metrics["total"])
	vulnerable := intFromAny(metrics["vulnerable"])
	bypassable := intFromAny(metrics["bypassable"])
	protected := intFromAny(metrics["protected"])
	safe := intFromAny(metrics["safe"])
	inconclusive := intFromAny(metrics["inconclusive"])
	errors := intFromAny(metrics["errors"])

	PrintKeyValue("代码单元总数", fmt.Sprintf("%d", total))

	combined := vulnerable + bypassable
	if combined > 0 {
		red.Printf("  存在漏洞：%d\n", combined)
	} else {
		green.Printf("  存在漏洞：0\n")
	}
	PrintKeyValue("已有防护", fmt.Sprintf("%d", protected))
	PrintKeyValue("未发现漏洞", fmt.Sprintf("%d", safe))
	if inconclusive > 0 {
		yellow.Printf("  结论不明确：%d\n", inconclusive)
	}
	if errors > 0 {
		yellow.Printf("  错误：%d\n", errors)
	}

	if path, ok := data["results_path"].(string); ok {
		PrintKeyValue("输出位置", path)
	}
	fmt.Println()
}

// PrintAnalyzeResult renders the summary for the `analyze` command's envelope
// data. When --verify chained into Stage 2, the Python backend returns a
// VerifyResult (which has no "metrics" key) instead of the AnalysisResult, so
// route to the verify summary — otherwise PrintAnalyzeSummary's missing-metrics
// early-return silently drops the entire Stage-2 outcome. If verification was
// requested but skipped (e.g. no --analyzer-output), the backend still returns
// an AnalysisResult with "metrics", so fall back to the analyze summary.
func PrintAnalyzeResult(data map[string]any, verify bool) {
	if _, hasMetrics := data["metrics"]; verify && !hasMetrics {
		PrintVerifySummary(data)
		return
	}
	PrintAnalyzeSummary(data)
}

// PrintReportSummary outputs a formatted summary of report generation.
func PrintReportSummary(data map[string]any) {
	PrintHeader("报告已生成")
	if format, ok := data["format"].(string); ok && format != "" {
		PrintKeyValue("格式", format)
	}
	if path, ok := data["output_path"].(string); ok && path != "" {
		PrintKeyValue("输出位置", path)
	}
	if path, ok := data["reskin_path"].(string); ok && path != "" {
		PrintKeyValue("新版报告", path)
	}
	if usage, ok := data["usage"].(map[string]any); ok {
		// #598: the report envelope's usage carries the incompleteness
		// metadata — render it (the old cost>0 gate vanished an
		// incomplete $0 entirely).
		renderCostBlock(usage)
	}
	fmt.Println()
}

// PrintEnhanceSummary outputs a formatted summary of enhancement results.
func PrintEnhanceSummary(data map[string]any) {
	PrintHeader("上下文增强结果")

	units := intFromAny(data["units_enhanced"])
	errors := intFromAny(data["error_count"])
	PrintKeyValue("已增强代码单元", fmt.Sprintf("%d", units))
	if errors > 0 {
		yellow.Printf("  错误：%d\n", errors)
	}

	if classifications, ok := data["classifications"].(map[string]any); ok {
		PrintHeader("分类")
		for cls, count := range classifications {
			PrintKeyValue(cls, fmt.Sprintf("%d", intFromAny(count)))
		}
	}

	if path, ok := data["enhanced_dataset_path"].(string); ok {
		PrintKeyValue("输出位置", path)
	}
	fmt.Println()
}

// PrintVerifySummary outputs a formatted summary of verification results.
func PrintVerifySummary(data map[string]any) {
	PrintHeader("验证结果（第二阶段）")

	input := intFromAny(data["findings_input"])
	verified := intFromAny(data["findings_verified"])
	agreed := intFromAny(data["agreed"])
	disagreed := intFromAny(data["disagreed"])
	confirmed := intFromAny(data["confirmed_vulnerabilities"])
	// #622: the reclassification siblings ride the VerifyResult.to_dict
	// envelope — the companion lines keep "Disagreed (eliminated)" honest
	// (a protected-by-controls correction is not an eliminated false
	// positive, and an explicitly-unconfirmable one is not either).
	reclassifiedProtected := intFromAny(data["disagreed_protected"])
	reclassifiedInconclusive := intFromAny(data["disagreed_inconclusive"])

	PrintKeyValue("待验证发现", fmt.Sprintf("%d", input))
	PrintKeyValue("已验证发现", fmt.Sprintf("%d", verified))

	if agreed > 0 {
		red.Printf("  确认存在：%d\n", agreed)
	}
	if disagreed > 0 {
		green.Printf("  已排除：%d\n", disagreed)
	}
	if reclassifiedProtected > 0 {
		green.Printf("  重新归类为已防护（已验证控制措施）：%d\n",
			reclassifiedProtected)
	}
	if reclassifiedInconclusive > 0 {
		yellow.Printf("  重新归类为结论不明确（无法确认）：%d\n",
			reclassifiedInconclusive)
	}

	fmt.Println()
	if confirmed > 0 {
		red.Printf("⚠ 已确认 %d 个漏洞\n", confirmed)
	} else {
		green.Println("✓ 暂无已确认漏洞")
	}

	if path, ok := data["verified_results_path"].(string); ok {
		PrintKeyValue("输出位置", path)
	}
	fmt.Println()
}

// PrintDynamicTestSummary outputs a formatted summary of dynamic test results.
func PrintDynamicTestSummary(data map[string]any) {
	PrintHeader("动态测试结果")

	tested := intFromAny(data["findings_tested"])
	confirmed := intFromAny(data["confirmed"])
	notReproduced := intFromAny(data["not_reproduced"])
	blocked := intFromAny(data["blocked"])
	inconclusive := intFromAny(data["inconclusive"])
	errors := intFromAny(data["errors"])

	PrintKeyValue("已测试发现", fmt.Sprintf("%d", tested))

	if confirmed > 0 {
		red.Printf("  已确认：%d\n", confirmed)
	}
	if notReproduced > 0 {
		green.Printf("  未复现：%d\n", notReproduced)
	}
	if blocked > 0 {
		yellow.Printf("  受阻：%d\n", blocked)
	}
	if inconclusive > 0 {
		yellow.Printf("  结论不明确：%d\n", inconclusive)
	}
	if errors > 0 {
		red.Printf("  错误：%d\n", errors)
	}

	if path, ok := data["results_json_path"].(string); ok {
		PrintKeyValue("结果文件", path)
	}
	fmt.Println()
}

// PrintPatchSummary outputs a formatted summary of a patch-trust run.
func PrintPatchSummary(data map[string]any) {
	PrintHeader("补丁可信度报告")

	// finding_id holds either a Finding id or a CVE id (backward-compatible
	// field reuse -- see core/patch.py's PatchStepResult); input_type
	// discriminates which, so the label printed here matches what's
	// actually in it instead of always saying "漏洞发现".
	label := "漏洞发现"
	if inputType, ok := data["input_type"].(string); ok && inputType == "cve" {
		label = "CVE"
	}
	if id, ok := data["finding_id"].(string); ok {
		PrintKeyValue(label, id)
	}
	if path, ok := data["trust_report_path"].(string); ok {
		PrintKeyValue("报告", path)
	}
	fmt.Println()
}

// PrintBuildOutputSummary outputs a formatted summary of pipeline output generation.
func PrintBuildOutputSummary(data map[string]any) {
	PrintHeader("流水线输出")

	findings := intFromAny(data["findings_count"])
	PrintKeyValue("已收录发现", fmt.Sprintf("%d", findings))

	if path, ok := data["pipeline_output_path"].(string); ok {
		PrintKeyValue("输出位置", path)
	}
	fmt.Println()
}

// PrintScanSummaryV2 outputs a formatted summary of scan results using the
// updated pipeline output schema (Phase 9+).
func PrintScanSummaryV2(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		// Fall back to legacy format
		PrintScanSummary(data)
		return
	}

	PrintHeader("扫描结果")

	// Mode line: surfaces incremental-scan range so the user sees
	// "what was compared" without diving into pipeline_output.json.
	if diff, ok := data["diff"].(map[string]any); ok && diff != nil {
		if mode, _ := diff["mode"].(string); mode == "incremental" {
			base := shortSHA8(diff["base_sha"])
			head := shortSHA8(diff["head_sha"])
			unitsIn := intFromAny(diff["units_in_diff"])
			unitsTotal := intFromAny(diff["units_total_parsed"])
			modeLine := fmt.Sprintf("增量扫描（%s..%s，%d/%d 个代码单元）", base, head, unitsIn, unitsTotal)
			PrintKeyValue("模式", modeLine)
		} else {
			PrintKeyValue("模式", "完整扫描")
		}
	}

	total := intFromAny(metrics["total"])
	vulnerable := intFromAny(metrics["vulnerable"])
	bypassable := intFromAny(metrics["bypassable"])
	protected := intFromAny(metrics["protected"])
	safe := intFromAny(metrics["safe"])
	inconclusive := intFromAny(metrics["inconclusive"])
	errors := intFromAny(metrics["errors"])
	verified := intFromAny(metrics["verified"])

	PrintKeyValue("已分析代码单元", fmt.Sprintf("%d", total))

	// #323: the reachability advisory, in the Scan Results section (wave r1:
	// it landed under Output Files before — a coverage number beside the
	// report paths, not beside the unit counts). The blackout warning
	// previously reached only an artifact field + an LLM instruction; the
	// terminal never said anything, so a blacked-out scan looked like a
	// small clean run. Deterministic (printed from the envelope's block).
	// The reduction uses the envelope's OWN float — the integer recompute
	// truncated (wave r1: 2/3 printed 34%, the artifacts said 33.3%).
	if reach, ok := data["reachability"].(map[string]any); ok && reach != nil {
		reachable := intFromAny(reach["reachable_units"])
		original := intFromAny(reach["original_units"])
		if original > 0 {
			// the envelope's OWN float when present (the exact figure the
			// artifacts print); the recompute is only the fallback for a
			// hand-built map without it.
			pct := float64(100*original-100*reachable) / float64(original)
			if f, ok := reach["reachability_reduction_percentage"].(float64); ok {
				pct = f
			}
			PrintKeyValue("可达性范围", fmt.Sprintf(
				"纳入 %d/%d 个代码单元（减少 %.1f%%）", reachable, original, pct))
		} else {
			PrintKeyValue("可达性范围", fmt.Sprintf("纳入 %d 个代码单元", reachable))
		}
		if warns, ok := reach["reachability_warnings"].([]any); ok {
			for _, wn := range warns {
				if s, ok := wn.(string); ok && s != "" {
					yellow.Printf("  ⚠ %s\n", s)
				}
			}
		}
	}

	combined := vulnerable + bypassable
	if combined > 0 {
		red.Printf("  存在漏洞：%d\n", combined)
	} else {
		green.Printf("  存在漏洞：0\n")
	}
	PrintKeyValue("已有防护", fmt.Sprintf("%d", protected))
	PrintKeyValue("未发现漏洞", fmt.Sprintf("%d", safe))
	if inconclusive > 0 {
		yellow.Printf("  结论不明确：%d\n", inconclusive)
	}
	if errors > 0 {
		yellow.Printf("  错误：%d\n", errors)
	}
	if verified > 0 {
		agreed := intFromAny(metrics["stage2_agreed"])
		disagreed := intFromAny(metrics["stage2_disagreed"])
		PrintKeyValue("已验证（第二阶段）", fmt.Sprintf("%d（确认 %d，排除 %d）",
			verified, agreed, disagreed))
		// #622: the companion line states the split DISJOINTLY — the
		// reclassified figure is carved OUT of the disagreed count above,
		// so "of which" would wrongly imply a subset.
		if reclassifiedProtected := intFromAny(metrics["stage2_disagreed_protected"]); reclassifiedProtected > 0 {
			PrintKeyValue("重新归类为已防护",
				fmt.Sprintf("%d（已验证控制措施；未计入已排除项）",
					reclassifiedProtected))
		}
	}

	// Usage info
	if usage, ok := data["usage"].(map[string]any); ok {
		PrintHeader("用量")
		renderCostBlock(usage)
		renderTokensLine(usage)
	}

	// Output paths
	PrintHeader("输出文件")
	if dir, ok := data["output_dir"].(string); ok {
		PrintKeyValue("目录", dir)
	}
	if path, ok := data["pipeline_output_path"].(string); ok && path != "" {
		PrintKeyValue("流水线输出", path)
	}
	if path, ok := data["summary_path"].(string); ok && path != "" {
		PrintKeyValue("摘要报告", path)
	}

	// Skipped steps
	if skipped, ok := data["skipped_steps"].([]any); ok && len(skipped) > 0 {
		names := make([]string, 0, len(skipped))
		for _, s := range skipped {
			if name, ok := s.(string); ok {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			dim.Printf("  已跳过：%s\n", strings.Join(names, ", "))
		}
	}

	fmt.Println()

	// Final verdict
	if combined > 0 {
		red.Printf("⚠ 发现 %d 个漏洞\n", combined)
	} else {
		green.Println("✓ 本次扫描未发现漏洞")
	}
}

// PrintVersion outputs version info.
func PrintVersion(version, goVersion, pythonVersion string) {
	bold.Printf("911VulScan ")
	fmt.Println(version)
	dim.Printf("  Go:     %s\n", goVersion)
	if pythonVersion != "" {
		dim.Printf("  Python: %s\n", pythonVersion)
	}
}

// intFromAny extracts an int from a JSON-decoded any value (which is float64).
func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

// shortSHA8 returns the first 8 characters of a SHA from a JSON-decoded
// string field. Returns "?" for missing/empty input so the rendered Mode
// line never looks malformed.
func shortSHA8(v any) string {
	s, _ := v.(string)
	if len(s) >= 8 {
		return s[:8]
	}
	if s == "" {
		return "?"
	}
	return s
}

// floatFromAny extracts a float64 from a JSON-decoded any value.
func floatFromAny(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		return 0
	}
}
