// Modified 2026-10-23 for the VulScan-only product namespace.
package server

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/config"
	uifiles "github.com/puhaoyang78/911VulScan/apps/vulscan-cli/ui"
)

func isolatedModelConfig(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DEEPSEEK_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "legacy-env-must-stay-separate")
}

func modelRequest(t *testing.T, values url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "127.0.0.1"
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScanModelSettingsDeepSeekDefaultsAndIsolation(t *testing.T) {
	isolatedModelConfig(t)
	if err := config.Save(&config.Config{APIKey: "legacy-saved-key"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ model, want string }{{"", "deepseek-default"}, {"deepseek-flash", "deepseek-default"}, {"deepseek-v4-pro", "deepseek-pro"}} {
		profile, env, err := scanModelSettings(modelRequest(t, url.Values{"model": {tc.model}, "api_key": {"per-job-deepseek-key"}}))
		if err != nil {
			t.Fatal(err)
		}
		if profile != tc.want {
			t.Errorf("model %q profile = %q, want %q", tc.model, profile, tc.want)
		}
		wantEnv := map[string]string{"DEEPSEEK_API_KEY": "per-job-deepseek-key", "VULSCAN_LOCAL_CLAUDE": "false", "VULSCAN_DEEPSEEK_API_KEY_OVERRIDE": "per-job-deepseek-key"}
		if !reflect.DeepEqual(env, wantEnv) {
			t.Errorf("credential routing = %#v", env)
		}
	}
	_, env, err := scanModelSettings(modelRequest(t, url.Values{}))
	if err != nil {
		t.Fatal(err)
	}
	if env["DEEPSEEK_API_KEY"] != "" || env["ANTHROPIC_API_KEY"] != "" {
		t.Error("legacy Anthropic credentials reused by DeepSeek")
	}
	if os.Getenv("DEEPSEEK_API_KEY") != "" || os.Getenv("ANTHROPIC_API_KEY") != "legacy-env-must-stay-separate" {
		t.Error("per-job credentials changed server environment")
	}
	cfg, _ := config.Load()
	if cfg.APIKey != "legacy-saved-key" {
		t.Error("form rewrote persistent configuration")
	}
}

func TestScanModelSettingsConfiguredProfilesAndValidation(t *testing.T) {
	isolatedModelConfig(t)
	cfg := &config.Config{}
	cfg.WriteLLMConfig("my-profile", map[string]config.LLMPhaseRef{"detect": {Provider: "deepseek", Model: "deepseek-flash"}}, map[string]config.ProviderEntry{"deepseek": {Type: "deepseek", APIKey: "saved-deepseek-key"}}, false)
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	_, env, err := scanModelSettings(modelRequest(t, url.Values{}))
	if err != nil || env["DEEPSEEK_API_KEY"] != "saved-deepseek-key" {
		t.Fatalf("saved provider key not selected: %v", err)
	}
	t.Setenv("DEEPSEEK_API_KEY", "environment-deepseek-key")
	_, env, err = scanModelSettings(modelRequest(t, url.Values{}))
	if err != nil || env["DEEPSEEK_API_KEY"] != "saved-deepseek-key" {
		t.Fatalf("explicit provider key must precede environment: %v", err)
	}
	for _, name := range []string{"", "my-profile", "vulscan-default", "deepseek-default", "deepseek-pro"} {
		profile, env, err := scanModelSettings(modelRequest(t, url.Values{"provider": {"configured"}, "llm_config": {name}}))
		if err != nil || profile != name || len(env) != 1 || env["VULSCAN_DEEPSEEK_API_KEY_OVERRIDE"] != "" {
			t.Errorf("configured profile %q not preserved, env=%v err=%v", name, env, err)
		}
	}
	for _, bad := range []url.Values{
		{"provider": {"unknown"}}, {"model": {"--output=/tmp/escape"}},
		{"provider": {"configured"}, "llm_config": {"unknown"}},
		{"provider": {"configured"}, "api_key": {"do-not-send-to-custom-provider"}},
	} {
		if _, _, err := scanModelSettings(modelRequest(t, bad)); err == nil {
			t.Errorf("accepted invalid selection %v", bad)
		}
	}
	cfg.WriteLLMConfig("other", nil, map[string]config.ProviderEntry{"deepseek": {Type: "openai", APIKey: "another-provider-key"}}, false)
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scanModelSettings(modelRequest(t, url.Values{"api_key": {"deepseek-only"}})); err == nil {
		t.Error("pasted DeepSeek key accepted for incompatible provider type")
	}
}

func TestStartScanKeepsDeepSeekSecretOutOfArtifacts(t *testing.T) {
	isolatedModelConfig(t)
	s, err := New("unused-python", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Hold every execution slot; inspect the queued job without invoking a model.
	for n := 0; n < cap(s.sem); n++ {
		s.sem <- struct{}{}
	}
	values := url.Values{"csrf": {s.csrfToken}, "repo": {"/authorized/project"}, "provider": {"deepseek"}, "model": {"deepseek-v4-pro"}, "api_key": {"unique-secret-for-this-job"}}
	rec := httptest.NewRecorder()
	s.handleStartScan(rec, modelRequest(t, values))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /scan = %d: %s", rec.Code, rec.Body.String())
	}
	jobs := s.mgr.all()
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs", len(jobs))
	}
	job := jobs[0]
	if job.llmConfig != "deepseek-pro" || job.keyEnv["DEEPSEEK_API_KEY"] != "unique-secret-for-this-job" {
		t.Fatal("job lost provider/model/key selection")
	}
	job.addLog("provider accidentally echoed unique-secret-for-this-job")
	job.Cancel()
	select {
	case <-job.done:
	case <-time.After(time.Second):
		t.Fatal("queued cancellation stuck")
	}
	for _, name := range []string{"meta.json", "logs.txt"} {
		data, err := os.ReadFile(filepath.Join(s.outDir, job.ID, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "unique-secret-for-this-job") {
			t.Errorf("secret persisted in %s", name)
		}
	}
	if job.keyEnv != nil {
		t.Error("finished job retained per-run credentials")
	}
}

func TestChineseDashboardUsesSafeDefaultsAndNoSecretValues(t *testing.T) {
	isolatedModelConfig(t)
	t.Setenv("DEEPSEEK_API_KEY", "never-render-this-key")
	s, err := New("unused", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range []*Job{{ID: "a1", Repo: "<script>alert('repo')</script>", Status: StatusRunning}, {ID: "a2", Repo: "done", Status: StatusDone, ReportPath: "report.html"}, {ID: "a3", Repo: "failed", Status: StatusError}} {
		s.mgr.add(j)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("dashboard = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`lang="zh-CN"`, "911VulScan", "安全扫描工作台", "最近扫描", `value="deepseek" selected`, "deepseek-v4-pro", `id="stat-running">1`, `id="stat-done">1`, `id="stat-attention">1`, "DEEPSEEK_API_KEY"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	budgetSelect := regexp.MustCompile(`(?s)<select id="scan-timeout" name="scan_timeout"[^>]*>(.*?)</select>`).FindStringSubmatch(body)
	if len(budgetSelect) != 2 {
		t.Fatal("missing submitted scan time budget selector")
	}
	options := regexp.MustCompile(`<option value="([^"]+)"([^>]*)>`).FindAllStringSubmatch(budgetSelect[1], -1)
	var budgets, defaults []string
	for _, option := range options {
		budgets = append(budgets, option[1])
		if strings.Contains(option[2], "selected") {
			defaults = append(defaults, option[1])
		}
	}
	if !reflect.DeepEqual(budgets, []string{"30m", "1h", "2h", "4h", "8h", "24h"}) || !reflect.DeepEqual(defaults, []string{"2h"}) {
		t.Fatalf("scan budgets = %v, defaults = %v", budgets, defaults)
	}
	for _, want := range []string{"总时间预算", "不是每个阶段的预计耗时", "不含排队", "辅助调用使用独立时间上限"} {
		if !strings.Contains(body, want) {
			t.Errorf("scan budget lacks scope explanation %q", want)
		}
	}
	// The UI deliberately offers a subset of the backend's supported languages.
	// Keep the submitted IDs stable, including "c" for the shared C/C++ parser.
	inputs := regexp.MustCompile(`<input type="checkbox" name="languages" value="([^"]+)"[^>]*>`).FindAllStringSubmatch(body, -1)
	var languageIDs []string
	for _, input := range inputs {
		languageIDs = append(languageIDs, input[1])
		if strings.Contains(input[0], "checked") {
			t.Error("language default must remain automatic (no selection)")
		}
		if !supportedLanguages[input[1]] {
			t.Errorf("UI language %q is not accepted by the scan handler", input[1])
		}
	}
	if want := []string{"c", "python", "javascript", "go"}; !reflect.DeepEqual(languageIDs, want) {
		t.Errorf("selectable languages = %v, want %v", languageIDs, want)
	}
	for _, bad := range []string{"never-render-this-key", "<script>alert('repo')</script>", "Anthropic API Key", "localStorage"} {
		// A comment documents that storage must not be used; forbid calls only.
		if bad == "localStorage" {
			bad = "localStorage."
		}
		if strings.Contains(body, bad) {
			t.Errorf("unsafe/obsolete content %q", bad)
		}
	}
}

func TestRenderedChinesePagesJavaScriptSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is needed for the static JavaScript syntax check")
	}
	for _, tc := range []struct {
		name string
		data any
	}{
		{"index.html", indexData{CSRF: "token", Nonce: "nonce"}},
		{"scan.html", scanPageData{ID: "deadbeef", Repo: "测试项目", Nonce: "nonce"}},
		{"summary.html", summaryData{ID: "deadbeef", MarkdownJSON: template.JS(`"# 中文摘要"`), Nonce: "nonce"}},
		{"disclosure.html", disclosureData{ID: "deadbeef", Name: "安全披露", MarkdownJSON: template.JS(`"# 中文披露"`), Nonce: "nonce"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.ParseFS(uifiles.FS, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := tmpl.Execute(&out, tc.data); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), `lang="zh-CN"`) {
				t.Error("missing Chinese document language")
			}
			footer := regexp.MustCompile(`(?s)<footer[^>]*>(.*?)</footer>`).FindStringSubmatch(out.String())
			if len(footer) != 2 || !strings.Contains(footer[1], "911VulScan") {
				t.Fatal("missing product footer")
			}
			if strings.Contains(footer[1], "Knostic") || strings.Contains(footer[1], "OpenAnt") {
				t.Error("obsolete upstream attribution remains in the visible footer")
			}
			scripts := regexp.MustCompile(`(?s)<script nonce="[^"]*">(.*?)</script>`).FindAllStringSubmatch(out.String(), -1)
			if len(scripts) == 0 {
				t.Fatal("no inline scripts checked")
			}
			for _, script := range scripts {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, node, "--check")
				cmd.Stdin = strings.NewReader(script[1])
				if result, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("JavaScript syntax: %v\n%s", err, result)
				}
			}
		})
	}
}

func TestDeepSeekEndpointOriginDisclosure(t *testing.T) {
	isolatedModelConfig(t)
	t.Setenv("DEEPSEEK_BASE_URL", "")
	if got := deepSeekEndpointOrigin(nil); got != "https://api.deepseek.com" {
		t.Fatalf("default endpoint=%q", got)
	}
	t.Setenv("DEEPSEEK_BASE_URL", "https://env.example/v1")
	if got := deepSeekEndpointOrigin(nil); got != "https://env.example" {
		t.Fatalf("environment endpoint=%q", got)
	}
	cfg := &config.Config{}
	cfg.WriteLLMConfig("custom", nil, map[string]config.ProviderEntry{"deepseek": {Type: "deepseek", BaseURL: "https://user:secret@gateway.example:8443/private-secret-path?token=query-secret"}}, false)
	if got := deepSeekEndpointOrigin(cfg); got != "https://gateway.example:8443" {
		t.Fatalf("endpoint origin leaks credentials/path or ignores config precedence: %q", got)
	}
}

// This is a deterministic JavaScript state test, not a visual/browser test.
// It checks the actual Python scanner's numbered messages, including degraded
// and skipped stages; it deliberately uses no network, browser, or live model.
func TestChineseProgressHandlesActualScannerMessages(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is needed for JavaScript state tests")
	}
	tmpl, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err := tmpl.Execute(&page, scanPageData{ID: "deadbeef", Nonce: "nonce"}); err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?s)<script nonce="[^"]*">(.*?)</script>`).FindStringSubmatch(page.String())
	if len(matches) != 2 {
		t.Fatal("scan page script not found")
	}
	prelude := `
const assert = require('node:assert/strict');
class Element {
 constructor() { this.textContent='阶段'; this.attrs={}; this.dataset={}; const values=new Set(); this.classList={add:v=>values.add(v),remove:v=>values.delete(v),contains:v=>values.has(v)}; }
 addEventListener(){}
 setAttribute(k,v){this.attrs[k]=v;} removeAttribute(k){delete this.attrs[k];}
}
const elements={};
global.document={getElementById:id=>elements[id]||(elements[id]=new Element()),querySelector:selector=>selector==='.step.failed' ? Object.values(elements).find(e=>e.classList.contains('failed')) : null};
global.window={addEventListener(){}};
global.EventSource=class { static CLOSED=2; static CONNECTING=0; constructor(){EventSource.last=this;} addEventListener(){} close(){} };
global.fetch=async()=>({ok:true,json:async()=>[]});
`
	checks := `
const stream=EventSource.last; stream.readyState=EventSource.CONNECTING; stream.onerror();
assert.equal(elements['status-text'].dataset.state,'reconnecting');
stream.onopen(); assert.equal(elements['status-text'].dataset.state,'running');
updateSteps('[1/8] Parsing repository...');
assert(stepEls.parse.classList.contains('active'));
updateSteps('[2/8] Generating application context...');
assert(stepEls.parse.classList.contains('done'));
assert(stepEls.enhance.classList.contains('active'));
updateSteps('[3/8] Enhancing dataset...');
updateSteps('  WARNING: Enhancement failed: temporary provider error');
assert(stepEls.enhance.classList.contains('failed'));
updateSteps('[4/8] Running vulnerability detection (Stage 1)...');
assert(stepEls.analyze.classList.contains('active'));
updateSteps('  - Skipping verification (no vulnerable findings).');
assert(stepEls.verify.classList.contains('skipped'));
updateSteps('  - Skipping dynamic test (Docker not found).');
assert(stepEls.dynamic.classList.contains('skipped'));
assert.equal(countEls.dynamic.textContent,'未找到 Docker');
updateSteps('[8/8] Generating reports...');
onDone('done');
assert(stepEls.report.classList.contains('done'));
assert(!stepEls.verify.classList.contains('done'));
assert(!stepEls.enhance.classList.contains('done'));
assert(elements['status-text'].textContent.includes('警告'));
assert(elements['btn-report'].classList.contains('ready'));
stream.readyState=EventSource.CLOSED; stream.onerror();
assert.equal(elements['status-text'].dataset.state,'done');
assert(presentLog('[1/8] Parsing repository...').includes('正在解析仓库'));
assert.equal(presentLog('source.c: unsafe_call(x)'), 'source.c: unsafe_call(x)');
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node)
	cmd.Stdin = strings.NewReader(prelude + matches[1] + checks)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("progress state regression: %v\n%s", err, out)
	}
}

func TestRunJobForwardsDeepSeekProfileToScanAndReportFallbacks(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell fixture requires sh")
	}
	isolatedModelConfig(t)
	trace := filepath.Join(t.TempDir(), "calls.txt")
	t.Setenv("UI_TEST_TRACE", trace)
	dir := t.TempDir()
	script := filepath.Join(t.TempDir(), "fake-python")
	fixture := `#!/bin/sh
printf '%s|%s|%s|%s\n' "$*" "$DEEPSEEK_API_KEY" "$VULSCAN_DEEPSEEK_API_KEY_OVERRIDE" "$ANTHROPIC_API_KEY" >> "$UI_TEST_TRACE"
command="$4"
shift 4
out=''
while [ "$#" -gt 0 ]; do
 if [ "$1" = '--output' ]; then shift; out="$1"; fi
 shift
done
if [ "$command" = 'scan' ]; then
 printf '{}' > "$out/results.json"
 printf '{}' > "$out/dataset.json"
 printf '{"status":"success","data":{}}\n'
elif [ "$command" = 'report-data' ]; then
 printf '{"status":"success","data":{"title":"中文测试报告","unit_chart":{"labels":[],"data":[]},"verdict_chart":{"labels":[],"data":[]}}}\n'
elif [ "$command" = 'report' ]; then
 printf '# 中文测试摘要\n' > "$out"
else
 exit 2
fi
`
	if err := os.WriteFile(script, []byte(fixture), 0700); err != nil {
		t.Fatal(err)
	}
	s, err := New(script, dir)
	if err != nil {
		t.Fatal(err)
	}
	const id = "aabbccdd"
	if err := os.MkdirAll(filepath.Join(dir, id), 0750); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	job := &Job{ID: id, Repo: "/authorized/local-repo", Status: StatusRunning, ctx: ctx, done: make(chan struct{}), llmConfig: "deepseek-pro", keyEnv: map[string]string{"DEEPSEEK_API_KEY": "fixture-deepseek-key", "VULSCAN_DEEPSEEK_API_KEY_OVERRIDE": "fixture-deepseek-key"}}
	s.wg.Add(1)
	s.runJob(job)
	if job.Status != StatusDone {
		t.Fatalf("fixture scan status=%q logs=%v", job.Status, job.LogBuf)
	}
	data, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected scan+HTML report-data+summary calls, got %q", data)
	}
	for i, line := range lines {
		if !strings.Contains(line, "-P -m vulscan "+[]string{"scan", "report-data", "report"}[i]+" ") {
			t.Errorf("unexpected subprocess order: %s", line)
		}
		if !strings.Contains(line, "--llm-config=deepseek-pro") {
			t.Errorf("model profile not forwarded: %s", line)
		}
		if !strings.HasSuffix(line, "|fixture-deepseek-key|fixture-deepseek-key|legacy-env-must-stay-separate") {
			t.Errorf("provider credentials cross-wired: %s", line)
		}
		if strings.Contains(strings.Split(line, "|")[0], "fixture-deepseek-key") {
			t.Error("key leaked in subprocess argv")
		}
	}
}

func TestScanPageShowsSelectedTimeBudget(t *testing.T) {
	tmpl, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ value, want string }{{"2h", "2h"}, {"8h", "8h"}, {"", "未记录（旧任务）"}} {
		var out bytes.Buffer
		if err := tmpl.Execute(&out, scanPageData{ID: "fixture", ScanTimeout: tc.value}); err != nil {
			t.Fatal(err)
		}
		budget := regexp.MustCompile(`(?s)<p id="scan-timeout-budget">(.*?)</p>`).FindStringSubmatch(out.String())
		if len(budget) != 2 || !strings.Contains(budget[1], tc.want) || !strings.Contains(budget[1], "非单阶段 ETA") {
			t.Fatalf("budget %q not accurately displayed: %v", tc.value, budget)
		}
		if strings.Contains(out.String(), "可设置 VULSCAN_INVOKE_TIMEOUT") {
			t.Error("web timeout guidance still directs users to a global environment setting")
		}
	}
}
