package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/report"
)

func TestGenerateHTMLUsesSavedResultsWithoutModelCalls(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"results_verified.json": "{}", "dataset_enhanced.json": "{}",
		"response.json": `{"status":"success","data":{"repo_name":"fixture/saved-results","findings":[]}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(dir, "python")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\ncat \"$(dirname \"$0\")/response.json\"\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{pythonPath: script}
	path := filepath.Join(dir, "report.html")
	if err := s.generateHTMLReport(context.Background(), dir, path, func(string) {}); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--no-llm") || strings.Contains(string(args), "--llm-config") {
		t.Fatalf("HTML projection unexpectedly requested model generation: %s", args)
	}
	for _, name := range []string{"report.html", "report-data.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !strings.Contains(string(data), "fixture/saved-results") {
			t.Fatalf("saved-results projection missing %s: %v", name, err)
		}
	}
}

func TestHistoricalReportUsesCurrentReaderWithoutModelOrOriginalWrites(t *testing.T) {
	root := t.TempDir()
	const id = "0123456789abcdef"
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	original := `<html><body><div class="remediation-content"><h3>历史修复建议</h3><p>保留原有分析</p><script>alert('unsafe')</script></div></body></html>`
	for name, content := range map[string]string{"report.html": original, "results_verified.json": "{}", "dataset_enhanced.json": "{}"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(root, "calls")
	payload, err := json.Marshal(map[string]any{"status": "success", "data": report.ReportData{RepoName: "fixture/project", Timestamp: "2026-10-25", RemediationHTML: "new guidance must not replace old text"}})
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "python")
	body := fmt.Sprintf("#!/bin/sh\nprintf 'CALL\\n' >> %s\nprintf '%%s\\n' \"$@\" >> %s\ncat <<'REPORT_JSON'\n%s\nREPORT_JSON\n", strconv.Quote(calls), strconv.Quote(calls), payload)
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: root, pythonPath: script, mgr: newManager(root)}
	job := &Job{ID: id, Status: StatusDone, StartedAt: time.Now(), ReportPath: filepath.Join(dir, "report.html"), outDir: dir}
	s.mgr.add(job)
	for _, method := range []string{"GET", "HEAD"} {
		request := httptest.NewRequest(method, "/report/"+id, nil)
		request.SetPathValue("id", id)
		response := httptest.NewRecorder()
		s.reportCSP(s.handleReport)(response, request)
		if response.Code != 200 {
			t.Fatalf("%s: %d %s", method, response.Code, response.Body.String())
		}
		if method == "GET" {
			html := response.Body.String()
			for _, want := range []string{"report-layout", "fixture/project", "历史修复建议", "保留原有分析"} {
				if !strings.Contains(html, want) {
					t.Errorf("current view missing %s", want)
				}
			}
			if strings.Contains(html, "<script>alert('unsafe')</script>") {
				t.Fatal("old guidance bypassed SafeRemediation")
			}
		}
	}
	args, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(args), "CALL\n") != 1 || !strings.Contains(string(args), "--no-llm") {
		t.Fatalf("historical view must project once without a model: %s", args)
	}
	after, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != original {
		t.Fatal("historical artifact was overwritten")
	}
}
