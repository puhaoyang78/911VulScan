package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestChineseReportsKeepMachineValues(t *testing.T) {
	finding := Finding{Number: 1, Verdict: "vulnerable", Severity: "high", SeveritySource: "model", File: "src/处理.py", Function: "handle", DynamicTestStatus: "CONFIRMED", Analysis: "攻击者可读取未授权文件。"}
	data := baseReportData()
	data.Findings = []Finding{finding}
	data.FindingsByVerdict = []FindingGroup{{Verdict: "vulnerable", Count: 1, Findings: []Finding{finding}}}
	data.StepReports = []StepReport{{Step: "verify", Status: "success", Duration: "1.0s"}}
	data.UnitChart = ChartData{Labels: []string{"vulnerable", "safe"}, Data: []int{1, 0}, Colors: []string{"#dc3545", "#20c997"}}
	data.FileChart = data.UnitChart
	before, _ := json.Marshal(data)
	for name, render := range map[string]func(ReportData, io.Writer) error{"overview": RenderOverview, "reskin": RenderReskin} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := render(data, &out); err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{`lang="zh-CN"`, "安全分析报告", "结果分布", "修复建议", "存在漏洞", "高危", "已确认", "漏洞验证", "成功", "src/处理.py"} {
				if !strings.Contains(out.String(), expected) {
					t.Errorf("missing Chinese display value %q", expected)
				}
			}
			for _, oldLabel := range []string{">Vulnerable Units<", ">Remediation Guidance<", ">CONFIRMED<", ">high<", ">success<"} {
				if strings.Contains(out.String(), oldLabel) {
					t.Errorf("untranslated label %q", oldLabel)
				}
			}
		})
	}
	after, _ := json.Marshal(data)
	if !bytes.Equal(before, after) {
		t.Fatal("rendering changed serialized machine values")
	}
	sarif := BuildSARIF(data, SARIFOptions{})
	run := sarif["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]map[string]any)[0]
	if result["ruleId"] != "openant.verdict.vulnerable" {
		t.Fatalf("changed SARIF identity: %v", result["ruleId"])
	}
	if data.Findings[0].DynamicTestStatus != "CONFIRMED" || data.StepReports[0].Status != "success" {
		t.Fatal("machine enum translated")
	}
}

func TestChineseSARIFTruncationPreservesUTF8(t *testing.T) {
	message := findingMessage(Finding{Analysis: strings.Repeat("漏洞描述。", 2000)})
	if !utf8.ValidString(message) {
		t.Fatal("Chinese narrative cut inside a UTF-8 character")
	}
	if len(message) > 4096 || !strings.HasSuffix(message, "…") {
		t.Fatalf("invalid truncation length %d", len(message))
	}
}

func TestChineseLabelsStillEscapeUntrustedValues(t *testing.T) {
	data := baseReportData()
	data.Categories = []Category{{Verdict: `<svg onload="alert(1)">`, Description: `<img src=x onerror="alert(1)">`}}
	var out bytes.Buffer
	if err := RenderOverview(data, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<svg onload=") || strings.Contains(out.String(), "<img src=x") {
		t.Fatal("localization bypassed HTML escaping")
	}
}
