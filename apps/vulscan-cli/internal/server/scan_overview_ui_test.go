package server

import (
	"bytes"
	uifiles "github.com/puhaoyang78/911VulScan/apps/vulscan-cli/ui"
	"html/template"
	"os/exec"
	"strings"
	"testing"
)

// DOM interactions (cancellation, reconnect, focus and pagination) are exercised
// by browser_smoke.mjs against the real production handlers. These helpers run
// without a DOM so classification/search regressions also fail the normal suite.
func TestScanOverviewProgressAndCancellation(t *testing.T) {
	tmpl, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err = tmpl.Execute(&page, scanPageData{ID: "fixture", Nonce: "nonce", CSRF: "tok"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"cancel-dialog", "cancel-confirm", "cancel-dismiss", "overview-panel", "stage-progress", "finding-rows", "activity-groups", "terminal-panel", "log-copy", "log-latest"} {
		if !strings.Contains(page.String(), `id="`+id+`"`) {
			t.Errorf("missing production control %s", id)
		}
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	js, err := uifiles.FS.ReadFile("static/scan.js")
	if err != nil {
		t.Fatal(err)
	}
	checks := `
const assert=require('node:assert/strict');const ui=VulscanScan;
assert.equal(ui.classifyLine('11:22:33 [Enhance] 94/987 src/typecheck.c::tc_error neutral 7.5s (elapsed 3m11s, ETA ~30m23s, $0.0064)'),'progress');
assert.equal(ui.classifyLine('source/error_handler.c::failed_call'),'other');
assert.equal(ui.classifyLine('WARNING: provider failed'),'warning');
assert.equal(ui.classifyLine('11:22:33 [error] failed'),'error');
assert.equal(ui.stageFromLog('[Detect] 1/2 unit'),'analyze');
assert.equal(ui.stageFromLog('random source mentions verification failed'),'other');
const f={finding_id:'src/a.c:copy',title:'中文候选',cwe:'120',cwe_name:'Buffer Copy',file:'src/a.c',function:'copy',model_review:'excluded',dynamic:'skipped'};
for(const term of ['src/a.c','copy','120','cwe-120','buffer','中文候选'])assert(ui.matchesFinding(f,term,'',''));
assert(ui.matchesFinding(f,'','excluded','skipped'));
assert(!ui.matchesFinding(f,'','retained',''));
assert(!ui.matchesFinding(f,'','excluded','reproduced'));
assert(!ui.matchesFinding(f,'nonexistent','',''));
`
	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(string(js) + checks)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("UI helper regression: %v\n%s", err, out)
	}
}
