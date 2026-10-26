// Modified 2026-10-23 for the VulScan-only product namespace.
// Package report provides HTML report generation from pre-computed data.
package report

import (
	"fmt"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/remoteurl"
	"html/template"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// ReportData holds all pre-computed data needed to render the HTML overview report.
// This struct maps 1:1 to the JSON output of the Python `report-data` subcommand.
type ReportData struct {
	Title             string         `json:"title"`
	Timestamp         string         `json:"timestamp"`
	RepoName          string         `json:"repo_name"`
	CommitSHA         string         `json:"commit_sha"`
	Language          string         `json:"language"`
	RepoURL           string         `json:"repo_url"`
	TotalDurationS    float64        `json:"total_duration_seconds"`
	TotalCostUSD      float64        `json:"total_cost_usd"`
	Stats             Stats          `json:"stats"`
	UnitChart         ChartData      `json:"unit_chart"`
	FileChart         ChartData      `json:"file_chart"`
	RemediationHTML   string         `json:"remediation_html"`
	Findings          []Finding      `json:"findings"`
	FindingsByVerdict []FindingGroup `json:"findings_by_verdict"`
	StepReports       []StepReport   `json:"step_reports"`
	// #305: excluded languages reach the SARIF notifications.
	ExcludedLanguages []string   `json:"excluded_languages"`
	Categories        []Category `json:"categories"`
	Diff              *DiffInfo  `json:"diff,omitempty"`
}

// DiffInfo carries the incremental-scan range info to the report templates.
// Nil for full scans. Mirrors the "diff" block on pipeline_output.json,
// trimmed to the fields the templates actually render.
type DiffInfo struct {
	Mode             string `json:"mode"` // "incremental"
	BaseSHA          string `json:"base_sha"`
	HeadSHA          string `json:"head_sha"`
	Scope            string `json:"scope"`
	UnitsInDiff      int    `json:"units_in_diff"`
	UnitsTotalParsed int    `json:"units_total_parsed"`
	ChangedFiles     int    `json:"changed_files"`
	PRNumber         int    `json:"pr_number,omitempty"`
}

// IsIncremental reports whether this report is for an incremental scan.
// Templates check this to decide between the "full" and "incremental"
// header renderings.
func (d ReportData) IsIncremental() bool {
	return d.Diff != nil && d.Diff.Mode == "incremental"
}

// ShortBaseSHA returns the first 8 characters of the diff base SHA, or "".
func (d ReportData) ShortBaseSHA() string {
	if d.Diff == nil {
		return ""
	}
	if len(d.Diff.BaseSHA) > 8 {
		return d.Diff.BaseSHA[:8]
	}
	return d.Diff.BaseSHA
}

// ShortHeadSHA returns the first 8 characters of the diff head SHA, or "".
func (d ReportData) ShortHeadSHA() string {
	if d.Diff == nil {
		return ""
	}
	if len(d.Diff.HeadSHA) > 8 {
		return d.Diff.HeadSHA[:8]
	}
	return d.Diff.HeadSHA
}

// DiffRange returns the git-style "<base8>..<head8>" string, or "".
func (d ReportData) DiffRange() string {
	if d.Diff == nil {
		return ""
	}
	return d.ShortBaseSHA() + ".." + d.ShortHeadSHA()
}

// remediationPolicy is a strict allowlist for the LLM-authored remediation
// HTML. That text is generated from untrusted scanned-repo findings, so it is
// treated as hostile: only inert formatting tags survive — no scripts, event
// handlers, styles, images, SVG, forms, or embeds — and links may only be
// http(s). Without this, a malicious repo could inject <script>/onerror into
// the rendered report (served live by `vulscan serve` and by `report -f html`).
var remediationPolicy = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements(
		"p", "br", "hr", "span", "blockquote",
		"ul", "ol", "li",
		"strong", "em", "b", "i", "u", "code", "pre", "kbd", "samp",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"table", "thead", "tbody", "tr", "th", "td",
	)
	p.AllowAttrs("href").OnElements("a")
	p.AllowURLSchemes("http", "https")
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	return p
}()

// SafeRemediation sanitizes the LLM-authored remediation HTML against a strict
// allowlist, then returns it as template.HTML so html/template does not
// re-escape the now-safe markup.
func (d ReportData) SafeRemediation() template.HTML {
	return template.HTML(remediationPolicy.Sanitize(d.RemediationHTML))
}

// FormatDuration returns TotalDurationS as a human-readable string
// like "1d 2h 3m 4s", omitting leading zero components.
func (d ReportData) FormatDuration() string {
	total := int(d.TotalDurationS)
	if total <= 0 {
		return ""
	}
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	secs := total % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if mins > 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	return strings.Join(parts, " ")
}

// FormatTotalCost returns TotalCostUSD as "$X.XX", or "-" if zero.
func (d ReportData) FormatTotalCost() string {
	if d.TotalCostUSD <= 0 {
		return "-"
	}
	return fmt.Sprintf("$%.2f", d.TotalCostUSD)
}

// ShortCommit returns the first 10 characters of CommitSHA, or empty.
func (d ReportData) ShortCommit() string {
	if len(d.CommitSHA) > 10 {
		return d.CommitSHA[:10]
	}
	return d.CommitSHA
}

// FileURL constructs a browseable URL for a file path in the repo.
// Returns empty string if repo URL or commit SHA is missing.
func (d ReportData) FileURL(filePath string) string {
	if d.RepoURL == "" || d.CommitSHA == "" {
		return ""
	}
	// #568: normalize defensively — an artifact (or a caller) may carry a
	// raw remote form (scp/credential-bearing); the render boundary never
	// persists or leaks it.
	base := remoteurl.Normalize(d.RepoURL)
	base = strings.TrimSuffix(base, ".git")
	if base == "" {
		return ""
	}
	return base + "/blob/" + d.CommitSHA + "/" + filePath
}

// BrowseURL returns the normalized browse form of the repo URL — the #568
// render-boundary contract: a raw remote (scp-form, credential-bearing)
// never reaches a rendered link. Returns "" when the URL cannot be
// normalized safely (the honest absence).
func (d ReportData) BrowseURL() string {
	return remoteurl.Normalize(d.RepoURL)
}

// HasStepReports returns true if there are step reports to display.
func (d ReportData) HasStepReports() bool {
	return len(d.StepReports) > 0
}

// HasFindings returns true if there are findings to display.
func (d ReportData) HasFindings() bool {
	return len(d.Findings) > 0
}

// HasFindingGroups returns true if there are grouped findings to display.
func (d ReportData) HasFindingGroups() bool {
	return len(d.FindingsByVerdict) > 0
}

// FindingCounts is a projection of recorded identities, not a sum of the
// overlapping pipeline summary fields. Legacy rows stay explicitly unknown.
func (d ReportData) FindingCounts() map[string]string {
	out := map[string]string{"candidates": "—", "retained": "—", "excluded": "—", "reproduced": "—"}
	rows := d.Findings
	if rows == nil {
		for _, g := range d.FindingsByVerdict {
			if g.HasSubgroups {
				for _, sg := range g.Subgroups {
					rows = append(rows, sg.Findings...)
				}
			} else {
				rows = append(rows, g.Findings...)
			}
		}
	}
	known := rows != nil
	reviewKnown, dynamicKnown := false, false
	values := map[string]int{}
	seen := map[string]bool{}
	for _, f := range rows {
		if f.ID == "" || f.Candidate == nil {
			known = false
		}
		id := f.ID
		if id == "" && f.File != "" && f.Function != "" {
			id = f.File + ":" + f.Function
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if f.Candidate != nil && *f.Candidate {
			values["candidates"]++
		}
		if f.ModelReviewStatus == "retained" || f.ModelReviewStatus == "excluded" || f.ModelReviewStatus == "inconclusive" || f.ModelReviewStatus == "error" {
			reviewKnown = true
			values[f.ModelReviewStatus]++
		}
		if f.DynamicTestStatus == "CONFIRMED" || f.DynamicTestStatus == "NOT_REPRODUCED" || f.DynamicTestStatus == "BLOCKED" || f.DynamicTestStatus == "ERROR" || f.DynamicTestStatus == "INCONCLUSIVE" {
			dynamicKnown = true
			if f.DynamicTestStatus == "CONFIRMED" {
				values["reproduced"]++
			}
		}
	}
	if known {
		out["candidates"] = fmt.Sprint(values["candidates"])
	}
	if reviewKnown {
		out["retained"] = fmt.Sprint(values["retained"])
		out["excluded"] = fmt.Sprint(values["excluded"])
	}
	if dynamicKnown {
		out["reproduced"] = fmt.Sprint(values["reproduced"])
	}
	return out
}

// Stats holds the summary statistics for the report header cards.
type Stats struct {
	TotalUnits int `json:"total_units"`
	TotalFiles int `json:"total_files"`
	Vulnerable int `json:"vulnerable"`
	Bypassable int `json:"bypassable"`
	Secure     int `json:"secure"`
}

// ChartData holds the data for a Chart.js pie chart.
type ChartData struct {
	Labels []string `json:"labels"`
	Data   []int    `json:"data"`
	Colors []string `json:"colors"`
}

// FindingGroup holds findings grouped by verdict for collapsible sections.
type FindingGroup struct {
	Verdict       string            `json:"verdict"`
	VerdictColor  string            `json:"verdict_color"`
	Count         int               `json:"count"`
	OpenByDefault bool              `json:"open_by_default"`
	Findings      []Finding         `json:"findings"`
	Subgroups     []FindingSubgroup `json:"subgroups"`
	HasSubgroups  bool              `json:"has_subgroups"`
}

// FindingSubgroup holds findings within a verdict group, sub-grouped by
// dynamic test outcome (e.g. "Confirmed", "Test error", "Not tested").
type FindingSubgroup struct {
	Label    string    `json:"label"`
	Findings []Finding `json:"findings"`
}

// Finding represents a single finding row in the report table.
type Finding struct {
	ID                 string `json:"finding_id"`
	Title              string `json:"title"`
	Candidate          *bool  `json:"candidate"`
	ModelReviewStatus  string `json:"model_review_status"`
	Number             int    `json:"number"`
	Verdict            string `json:"verdict"`
	VerdictColor       string `json:"verdict_color"`
	File               string `json:"file"`
	Function           string `json:"function"`
	AttackVector       string `json:"attack_vector"`
	Analysis           string `json:"analysis"`
	DynamicTestStatus  string `json:"dynamic_test_status"`
	DynamicTestDetails string `json:"dynamic_test_details"`
	// Optional, display-only report fields. Old report-data JSON remains valid;
	// absence is rendered as an evidence gap, never a verified result.
	Description        string `json:"description"`
	CWEID              string `json:"cwe_id"`
	CWEName            string `json:"cwe_name"`
	Impact             string `json:"impact"`
	Remediation        string `json:"remediation"`
	VulnerableCode     string `json:"vulnerable_code"`
	SuggestedFix       string `json:"suggested_fix"`
	StepsToReproduce   string `json:"steps_to_reproduce"`
	Stage2Verification string `json:"stage2_verification"`
	Reproduction       string `json:"reproduction"`
	// #305: the parsers emit start_line in primary_origin and it survived
	// enhancement — it was dropped at the report boundary. Threaded so the
	// SARIF region can anchor the alert to the real row (0 = unknown: emit
	// no region, never a synthetic line).
	StartLine int `json:"start_line"`
	// #215: a rankable severity (critical/high/medium/low; empty = unknown
	// — old artifacts) + its provenance (model | derived).
	Severity       string `json:"severity"`
	SeveritySource string `json:"severity_source"`
	// #745: the delegation-dismissed SAFE row's followable edge. The
	// concern went elsewhere: Scope names the analysis scoping
	// (function_local — the pipeline assembles each unit as "ANALYZE THIS
	// FUNCTION ONLY"), DeferredTo carries the unit's dataset call edges in
	// BOTH directions (the corpus's delegations go UP — "the risk exists at
	// the callers" — and DOWN — "the dangerous operation lives in a
	// helper this unit calls"), the same ids the result rows key on), and
	// DeferredRowless names the deferred units with NO result row (pruned
	// by the reachability pass or never analyzed — the evaporation case,
	// distinguishable from an examined-and-safe one). Empty on non-safe
	// verdicts: the concern is in the row's own function.
	Scope           string   `json:"scope"`
	DeferredTo      []string `json:"deferred_to"`
	DeferredRowless []string `json:"deferred_rowless"`
}

// HasReportDetails keeps the legacy compact display for non-findings, while
// vulnerable/bypassable rows always show the required sections and honest gaps.
func (f Finding) HasReportDetails() bool {
	return f.IsHighSeverity() || f.Impact != "" || f.Remediation != "" || f.SuggestedFix != ""
}

func (f Finding) InFindingNavigation() bool {
	if f.Candidate != nil {
		return *f.Candidate
	}
	return f.IsHighSeverity()
}

// DisplayTitle keeps generated payloads and verdict tokens out of headings.
// The original title and attack vector remain in the evidence and search index.
func (f Finding) DisplayTitle() string {
	title := strings.TrimSpace(f.Title)
	switch strings.ToLower(title) {
	case "vulnerable", "bypassable", "safe", "error", "候选问题（未提供标题）":
		title = ""
	}
	if title != "" && len([]rune(title)) <= 96 {
		return title
	}
	location := f.Function
	if location == "" {
		location = f.File
	}
	if location == "" {
		location = "候选问题"
	}
	if f.CWEName != "" {
		return f.CWEName + " · " + location
	}
	return location
}

func (d ReportData) NavigationFindings() []Finding {
	rows := d.Findings
	if len(d.FindingsByVerdict) > 0 {
		rows = nil
		for _, group := range d.FindingsByVerdict {
			if group.HasSubgroups {
				for _, subgroup := range group.Subgroups {
					rows = append(rows, subgroup.Findings...)
				}
			} else {
				rows = append(rows, group.Findings...)
			}
		}
	}
	var out []Finding
	for _, f := range rows {
		if f.InFindingNavigation() {
			out = append(out, f)
		}
	}
	return out
}

// CWELabel displays the recorded classification without inventing one for
// legacy artifacts. This string is escaped by html/template like all evidence.
func (f Finding) CWELabel() string {
	id := strings.TrimSpace(f.CWEID)
	if id == "" || id == "0" {
		id = "CWE 未提供"
	} else if !strings.HasPrefix(strings.ToUpper(id), "CWE-") {
		id = "CWE-" + id
	}
	if f.CWEName != "" {
		return id + " · " + f.CWEName
	}
	return id
}

// SeverityColor returns the badge color for the severity. Unknown values
// fall back to the neutral gray (the badge itself is conditional on
// Severity being one of the canonical labels).
func (f Finding) SeverityColor() string {
	switch f.Severity {
	case "critical":
		return "#721c24"
	case "high":
		return "#b4232a"
	case "medium":
		return "#89520d"
	case "low":
		return "#6c757d"
	}
	return "#6c757d"
}

// HasDynamicTest returns true if this finding has dynamic test results.
func (f Finding) HasDynamicTest() bool {
	return f.DynamicTestStatus != ""
}

func (f Finding) DynamicSummary() string {
	line := strings.SplitN(f.DynamicTestDetails, "\n", 2)[0]
	// Build diagnostics include the entire CLI transcript after the cause.
	for _, prefix := range []string{"Docker 构建超时", "Docker 构建失败", "Docker 环境不可用", "Docker 基础镜像不可用", "容器执行失败", "容器执行超时"} {
		if strings.HasPrefix(line, prefix) {
			return prefix
		}
	}
	if text := []rune(line); len(text) > 160 {
		return string(text[:160]) + "…"
	}
	return line
}

// DynamicTestColor returns a color for the dynamic test status badge.
func (f Finding) DynamicTestColor() string {
	switch f.DynamicTestStatus {
	case "CONFIRMED":
		return "#dc3545"
	case "NOT_REPRODUCED":
		return "#64748b"
	case "BLOCKED":
		return "#8a5a10"
	case "ERROR":
		return "#6c757d"
	case "INCONCLUSIVE":
		return "#89520d"
	default:
		return "#6c757d"
	}
}

// IsHighSeverity returns true for vulnerable/bypassable findings,
// used to auto-open their <details> accordion in the HTML report.
func (f Finding) IsHighSeverity() bool {
	switch f.Verdict {
	case "vulnerable", "bypassable":
		return true
	default:
		return false
	}
}

// StepReport holds display-ready data for a pipeline step.
type StepReport struct {
	Step      string `json:"step"`
	Duration  string `json:"duration"`
	Cost      string `json:"cost"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	// #305: the degradation channel — per-step failures and the
	// disambiguated skip reason, threaded by the report-data projection so
	// the SARIF invocations block (and any honest CI gate) can see them.
	ErrorCount    int      `json:"error_count"`
	Errors        []string `json:"errors"`
	SkippedReason string   `json:"skipped_reason"`
}

// StatusColor returns a Tailwind text color class based on step status.
func (s StepReport) StatusColor() string {
	switch s.Status {
	case "success":
		return "text-green-400"
	case "error":
		return "text-red-400"
	default:
		return "text-gray-400"
	}
}

// Category holds a verdict category description for the legend table.
type Category struct {
	Verdict     string `json:"verdict"`
	Color       string `json:"color"`
	Description string `json:"description"`
}
