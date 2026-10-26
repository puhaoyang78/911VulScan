package server

import (
	"encoding/json"
	"fmt"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/report"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// All fixture jobs use the production reducer and handlers. No Python process,
// model, repository clone or Docker container is started.
func seedUIFixtures(t *testing.T, s *Server) {
	t.Helper()
	// Captured public-project payload that previously overflowed the dialog.
	var payload uiFinding
	b, err := os.ReadFile("testdata/browser-smoke/payload-finding.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatal(err)
	}
	const longFile = "src/包含中文注释/very-long-component-name/very-long-component-name/very-long-component-name/request_handler.c"
	states := []struct {
		id, status string
		rich       bool
	}{
		{"f0000001", StatusQueued, false}, {"f0000002", StatusRunning, true}, {"f0000003", StatusCancelling, true},
		{"f0000004", StatusCancelled, true}, {"f0000005", StatusTimeout, true}, {"f0000006", StatusError, true},
		{"f0000007", StatusDone, true}, {"f0000008", StatusRunning, false}, {"f0000009", StatusDone, false},
	}
	for _, item := range states {
		dir := filepath.Join(s.outDir, item.id)
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatal(err)
		}
		j := &Job{ID: item.id, Repo: "/fixtures/安全示例-project", Status: item.status, StartedAt: time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC), outDir: dir}
		j.Snapshot = newJobSnapshot(j, false)
		j.Snapshot.Branch = "演示分支"
		j.Snapshot.Commit = "0123456789abcdef0123456789abcdef01234567"
		if item.id == "f0000009" {
			j.addLog(eventLine(j.ID, 1, "discovery.started", nil))
			zero := 0
			j.addLog(eventLine(j.ID, 2, "progress.updated", func(e *uiEvent) { e.Stage = "analyze"; e.Processed = &zero; e.Total = &zero; e.Unit = "函数" }))
		}
		if item.rich {
			var seq uint64
			emit := func(kind string, update func(*uiEvent)) { seq++; j.addLog(eventLine(j.ID, seq, kind, update)) }
			emit("scan.started", func(e *uiEvent) { e.Message = "扫描器启动" })
			emit("stage.changed", func(e *uiEvent) { e.Stage = "analyze"; e.Status = "running"; e.Message = "漏洞分析开始" })
			emit("discovery.started", nil)
			processed, total := 94, 987
			elapsed, eta := 191.0, 1823.0
			emit("progress.updated", func(e *uiEvent) {
				e.Stage = "analyze"
				e.Processed = &processed
				e.Total = &total
				e.Elapsed = &elapsed
				e.ETA = &eta
				e.Unit = "函数"
				e.Message = "正在分析 " + longFile
			})
			review := []string{"retained", "excluded", "retained", "pending", "retained", "inconclusive"}
			dynamic := []string{"reproduced", "skipped", "not_reproduced", "pending", "environment_error", "skipped"}
			for i := 0; i < 6; i++ {
				id := fmt.Sprintf("src/issue_%d.c:copy_%d", i+1, i+1)
				emit("finding.upsert", func(e *uiEvent) {
					e.Stage = "analyze"
					e.FindingID = id
					e.Message = "新增候选问题"
					e.Finding = &uiFinding{ID: id, ReportID: fmt.Sprintf("VULN-%03d", i+1), Title: []string{"用户输入长度未校验", "复核排除：调用者已限制输入", "动态未复现：条件未满足", "等待模型复核", "依赖构建失败，尚未判定", "验证条件不足，已跳过"}[i], File: longFile, Function: fmt.Sprintf("copy_%d", i+1), CWE: "120", CWEName: "Buffer Copy", Severity: []string{"high", "medium", "high", "low", "medium", "low"}[i], ModelReview: review[i], Description: "这是确定性 UI fixture，未扫描真实项目。\n<script>window.__fixtureInjected=true</script>", ReviewDetails: "模型复核只表示分析判定。"}
					if i == 3 {
						e.Finding.Title = payload.Title
						e.Finding.Description = payload.Description
						e.Finding.ReviewDetails = payload.ReviewDetails
					}
				})
				emit("validation.updated", func(e *uiEvent) {
					e.Stage = "dynamic-test"
					e.FindingID = id
					e.Attempt = 2
					e.Status = dynamic[i]
					e.Message = "动态测试结果"
					e.Details = "实际输出：fixture only；未调用模型。"
					e.Finding = &uiFinding{ID: id, Dynamic: dynamic[i], DynamicDetails: e.Details, Attempt: 2}
					if i == 4 {
						e.Phase = "build"
						e.Finding.FailurePhase = "build"
					}
				})
			}
			// Duplicate and out-of-order replay of real updates must not inflate counts.
			seq++
			later := eventLine(j.ID, seq+1, "activity", func(e *uiEvent) { e.Stage = "report"; e.Message = "乱序事件已恢复" })
			earlier := eventLine(j.ID, seq, "activity", func(e *uiEvent) { e.Stage = "report"; e.Message = "已保存部分材料" })
			j.addLog(later)
			j.addLog(earlier)
			j.addLog(later)
			seq++
			j.addLog(eventLine("other-parallel-job", seq+1, "finding.upsert", func(e *uiEvent) {
				e.FindingID = "foreign"
				e.Finding = &uiFinding{ID: "foreign", Dynamic: "reproduced"}
			}))
			if item.id == "f0000006" {
				emit("error", func(e *uiEvent) {
					e.Stage = "report"
					e.Status = "partial"
					e.Message = "报告步骤部分失败"
					e.Details = "fixture 构建阶段错误：dependency unavailable"
				})
			}
			if item.id == "f0000002" {
				for i := 0; i < 1500; i++ {
					j.addLog(fmt.Sprintf("08:00:%02d [Detect] %d/987 中文注释 source/error_handler.c::failed_call <script>literal only</script>", i%60, i))
				}
			}
		}
		if !scanActive(item.status) {
			end := j.StartedAt.Add(8 * time.Minute)
			j.Snapshot.FinishedAt = &end
			j.Snapshot.UpdatedAt = end
		}
		meta, _ := json.Marshal(jobMeta{ID: j.ID, Repo: j.Repo, Status: j.Status, StartedAt: j.StartedAt})
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0640); err != nil {
			t.Fatal(err)
		}
		if item.rich {
			code := `// 中文注释：保持原始缩进与操作符
int copy(const char *input) {
	if (input[0] == '"') return -1;
	return input[0] < 3 && input[1] != 0;
}
` + strings.Repeat("// 长代码块，允许局部滚动，不影响页面宽度\n", 30)
			yes := true
			f := report.Finding{Number: 1, ID: "src/issue_1.c:copy_1", Title: "用户输入长度未校验", Candidate: &yes, ModelReviewStatus: "retained", Verdict: "vulnerable", File: longFile, Function: "copy_1", CWEID: "120", CWEName: "Buffer Copy", Severity: "high", SeveritySource: "model", Description: "确定性 UI 示例，含中文与长路径。", Analysis: "模型分析记录；不代表已执行验证。", VulnerableCode: code, StartLine: 42, SuggestedFix: "if (length >= capacity) return ERROR;\n", Impact: "示例影响说明。", Remediation: "校验长度与目标容量。", Stage2Verification: "模型复核同意；不等于动态复现。", DynamicTestStatus: "CONFIRMED", DynamicTestDetails: "fixture: controlled reproduction", Reproduction: "构建：fixture-build\n运行：fixture-run\n实际结果：controlled fixture"}
			data := report.ReportData{RemediationHTML: "<h5>修复优先级</h5><blockquote>需结合实际版本</blockquote><table><tr><th>组件</th><td>请求处理器</td></tr></table>", Title: "Security Analysis Report", RepoName: "安全示例-project", CommitSHA: j.Snapshot.Commit, Language: "c", Timestamp: "2026-10-25", Stats: report.Stats{TotalUnits: 94, TotalFiles: 8, Vulnerable: 1}, Findings: []report.Finding{f}, FindingsByVerdict: []report.FindingGroup{{Verdict: "vulnerable", Count: 1, OpenByDefault: true, Findings: []report.Finding{f}}}, UnitChart: report.ChartData{Labels: []string{"vulnerable", "safe"}, Data: []int{1, 93}, Colors: []string{"#ac292e", "#64748b"}}, FileChart: report.ChartData{Labels: []string{"request_handler.c"}, Data: []int{1}, Colors: []string{"#0664bd"}}}
			j.ReportPath = filepath.Join(dir, "report.html")
			if err := report.GenerateReskin(data, j.ReportPath); err != nil {
				t.Fatal(err)
			}
			overview := filepath.Join(dir, "overview.html")
			if err := report.GenerateOverview(data, overview); err != nil {
				t.Fatal(err)
			}
			md := "# 安全分析摘要\n\n## 结论\n\n这是 UI fixture；数量分别按候选、模型复核、动态测试统计。\n\n## 影响\n\n验证记录只涵盖示例条件。\n\n## 复现条件\n\n使用 fixture 数据。\n\n## 步骤\n\n1. 打开材料。\n2. 核对记录。\n\n## 实际结果\n\n未发起任何真实扫描。\n\n## 修复建议\n\n校验输入长度。\n\n```c\n" + code + "```\n\n```unknown-language\n<script>alert('literal')</script>\n    untouched <>&\n```\n\n<img src=x onerror=alert(1)><script>alert('blocked')</script>\n"
			j.SummaryPath = filepath.Join(dir, "SUMMARY_REPORT.md")
			if err := os.WriteFile(j.SummaryPath, []byte(md), 0640); err != nil {
				t.Fatal(err)
			}
			disclosure := filepath.Join(dir, "report", "disclosures", "DISCLOSURE_01_FIXTURE.md")
			if err := os.MkdirAll(filepath.Dir(disclosure), 0750); err != nil {
				t.Fatal(err)
			}
			disc := "> **所属发现：** VULN-001\n> **目标版本：** " + j.Snapshot.Commit + "\n> **验证状态：** 模型复核保留\n> **动态测试：** fixture 已复现\n\n" + md
			if err := os.WriteFile(disclosure, []byte(disc), 0640); err != nil {
				t.Fatal(err)
			}
			j.DisclosurePaths = []string{disclosure}
			if capture := os.Getenv("VULSCAN_SCREENSHOTS"); capture != "" && item.id == "f0000007" {
				for _, name := range []string{"report.html", "overview.html"} {
					b, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(capture, "offline-"+name), b, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		j.persistSnapshotLocked()
		s.mgr.add(j)
	}
	// Exercise the actual restart path, not an independently fabricated object.
	recovered := &Server{outDir: s.outDir, mgr: newManager(s.outDir)}
	recovered.recoverJobs()
	history, _ := recovered.mgr.get("f0000007")
	s.mgr.add(history)
}

// Optional read-only replay of a real public-project job for screenshot review.
// Only derived fixture copies under t.TempDir are served; no scan is launched.
func seedReviewJob(t *testing.T, s *Server) {
	t.Helper()
	source := os.Getenv("VULSCAN_REVIEW_SOURCE_DIR")
	if source == "" {
		return
	}
	id := filepath.Base(source)
	dest := filepath.Join(s.outDir, id)
	if err := os.MkdirAll(dest, 0750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"meta.json", "snapshot.json", "logs.txt", "report.html"} {
		b, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dest, name), b, 0640); err != nil {
			t.Fatal(err)
		}
	}
	var data report.ReportData
	raw, err := os.ReadFile(os.Getenv("VULSCAN_REVIEW_REPORT_DATA"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(filepath.Join(source, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	guidance, err := report.ExistingRemediation(original)
	original.Close()
	if err != nil {
		t.Fatal(err)
	}
	data.RemediationHTML = guidance
	raw, err = json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "report-data.json"), raw, 0640); err != nil {
		t.Fatal(err)
	}
	var meta jobMeta
	raw, err = os.ReadFile(filepath.Join(dest, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	j := &Job{ID: id, Repo: meta.Repo, Status: meta.Status, StartedAt: meta.StartedAt, outDir: dest, ReportPath: filepath.Join(dest, "report.html"), done: make(chan struct{})}
	raw, err = os.ReadFile(filepath.Join(dest, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &j.Snapshot); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dest, "logs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	j.LogBuf = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	close(j.done)
	s.mgr.add(j)
}
