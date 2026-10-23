// Modified 2026-10-23 for the VulScan-only product namespace.
package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func readableFinding() Finding {
	return Finding{
		Number: 1, Verdict: "vulnerable", File: "src/example.c", Function: "copy_name",
		Analysis: "原始分析", Description: "复制前未检查目标容量。", CWEID: "120",
		CWEName: "缓冲区复制未检查输入大小", Impact: "超长输入可能破坏内存。",
		Remediation:    "复制前验证长度，拒绝超出容量的输入。",
		VulnerableCode: "copy(dst, input);", SuggestedFix: "if (length >= capacity) return ERROR;",
		StepsToReproduce:   "使用超出目标容量的合成输入。",
		Stage2Verification: "静态复核已完成；不等于动态复现。",
		Reproduction:       "构建：fixture-build\n运行：fixture-run\n预期：拒绝输入\n实际证据：exit status 1\nAddressSanitizer: synthetic fixture only",
	}
}

// Both layouts and both reskin grouping paths must receive the same details.
func TestFindingDetailsRenderAcrossLayouts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		render    func(ReportData, io.Writer) error
		subgroups bool
	}{
		{"overview", RenderOverview, false},
		{"reskin", RenderReskin, false},
		{"reskin-subgroups", RenderReskin, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := readableFinding()
			d := baseReportData()
			g := FindingGroup{Verdict: "vulnerable", Count: 1, Findings: []Finding{f}}
			if tc.subgroups {
				g.HasSubgroups = true
				g.Subgroups = []FindingSubgroup{{Label: "Confirmed", Findings: []Finding{f}}}
			}
			d.FindingsByVerdict = []FindingGroup{g}
			var out bytes.Buffer
			if err := tc.render(d, &out); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"发现项描述", f.Description, "CWE-120", f.CWEName, "影响（分析评估）", f.Impact,
				"修复建议", f.Remediation, f.VulnerableCode, "建议修复示例（未测试）", "if (length &gt;= capacity) return ERROR;",
				f.StepsToReproduce, f.Stage2Verification, "PoC 构建、运行与证据", "exit status 1",
				"AddressSanitizer: synthetic fixture only", "不代表已执行验证",
			} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing report detail %q", want)
				}
			}
		})
	}
}

func TestFindingDetailsEscapeUntrustedFields(t *testing.T) {
	payload := `<script>alert("repo")</script><img src=x onerror=alert(1)>`
	f := Finding{Number: 1, Verdict: "vulnerable", Description: payload, CWEID: payload,
		CWEName: payload, Impact: payload, Remediation: payload, VulnerableCode: payload,
		SuggestedFix: payload, StepsToReproduce: payload, Stage2Verification: payload, Reproduction: payload}
	for name, render := range map[string]func(ReportData, io.Writer) error{"overview": RenderOverview, "reskin": RenderReskin} {
		t.Run(name, func(t *testing.T) {
			d := baseReportData()
			d.FindingsByVerdict = []FindingGroup{{Verdict: "vulnerable", Findings: []Finding{f}}}
			var out bytes.Buffer
			if err := render(d, &out); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), payload) || strings.Contains(out.String(), `<img src=x`) {
				t.Fatal("untrusted finding text became active HTML")
			}
			if count := strings.Count(out.String(), "&lt;script&gt;"); count < 10 {
				t.Errorf("want all 10 detail fields escaped, found %d", count)
			}
		})
	}
}

func TestLegacyFindingShowsEvidenceGaps(t *testing.T) {
	var f Finding
	if err := json.Unmarshal([]byte(`{"number":1,"verdict":"vulnerable","analysis":"旧版分析"}`), &f); err != nil {
		t.Fatal(err)
	}
	d := baseReportData()
	d.FindingsByVerdict = []FindingGroup{{Verdict: "vulnerable", Findings: []Finding{f}}}
	var out bytes.Buffer
	if err := RenderOverview(d, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"旧版分析", "CWE 未提供", "未提供影响评估", "未提供修复建议", "未提供代码片段", "未提供可用的修复代码示例", "不能视为已验证", "不据此宣称已复现"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing legacy evidence gap %q", want)
		}
	}
	if (Finding{Verdict: "safe", Analysis: "安全", Description: "安全", VulnerableCode: "source", Stage2Verification: "未确认", Reproduction: "无执行记录"}).HasReportDetails() {
		t.Error("legacy safe rows should retain the compact display")
	}
}

func TestSARIFReadableDetailsAreAdditiveAndUntested(t *testing.T) {
	f := readableFinding()
	d := baseReportData()
	d.Findings = []Finding{f}
	log := BuildSARIF(d, SARIFOptions{})
	run := log["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]map[string]any)[0]
	props := result["properties"].(map[string]any)
	for key, want := range map[string]string{
		"description": f.Description, "cwe_id": f.CWEID, "cwe_name": f.CWEName,
		"impact": f.Impact, "remediation": f.Remediation,
		"vulnerable_code": f.VulnerableCode, "suggested_fix": f.SuggestedFix,
		"steps_to_reproduce": f.StepsToReproduce, "stage2_verification": f.Stage2Verification,
		"reproduction": f.Reproduction, "suggested_fix_validation": "not_tested",
	} {
		if props[key] != want {
			t.Errorf("%s = %v, want %q", key, props[key], want)
		}
	}
	if _, exists := result["fixes"]; exists {
		t.Error("untested examples must not be represented as SARIF fixes")
	}
	if result["ruleId"] != "vulscan.verdict.vulnerable" {
		t.Error("report detail fields must not change alert identity")
	}
	for _, want := range []string{f.Description, "CWE-120", f.Impact, f.Remediation, "未测试"} {
		if !strings.Contains(result["message"].(map[string]any)["text"].(string), want) {
			t.Errorf("missing SARIF message detail %q", want)
		}
	}
}

func TestCWELabelKeepsClassificationAndMissingState(t *testing.T) {
	for _, tc := range []struct{ id, name, want string }{
		{"120", "缓冲区复制未检查输入大小", "CWE-120 · 缓冲区复制未检查输入大小"},
		{"CWE-79", "", "CWE-79"},
		{"  22  ", "路径遍历", "CWE-22 · 路径遍历"},
		{"", "", "CWE 未提供"},
		{"0", "未知", "CWE 未提供 · 未知"},
	} {
		if got := (Finding{CWEID: tc.id, CWEName: tc.name}).CWELabel(); got != tc.want {
			t.Errorf("CWELabel(%q, %q) = %q, want %q", tc.id, tc.name, got, tc.want)
		}
	}
}
