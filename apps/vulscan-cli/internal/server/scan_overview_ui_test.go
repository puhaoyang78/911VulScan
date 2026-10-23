package server

import (
	"bytes"
	uifiles "github.com/puhaoyang78/911VulScan/apps/vulscan-cli/ui"
	"html/template"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Execute the rendered production script with a minimal DOM, no browser/network.
func TestScanOverviewProgressAndCancellation(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	tmpl, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err := tmpl.Execute(&page, scanPageData{ID: "fixture", Nonce: "nonce", CSRF: "tok"}); err != nil {
		t.Fatal(err)
	}
	scripts := regexp.MustCompile(`(?s)<script nonce="[^"]*">(.*?)</script>`).FindStringSubmatch(page.String())
	prelude := `
const assert=require('node:assert/strict');
class Element {
 constructor(){this.textContent='';this.style={};this.attrs={};this.dataset={};this.events={};this.children=[];this.content='tok';this.checked=true;const s=new Set();this.classList={add:x=>s.add(x),remove:x=>s.delete(x),contains:x=>s.has(x)};}
 setAttribute(k,v){this.attrs[k]=v;} removeAttribute(k){delete this.attrs[k];}
 addEventListener(k,v){this.events[k]=v;} appendChild(v){this.children.push(v);} remove(){} focus(){} 
}
const elements={};
global.document={getElementById:id=>elements[id]||(elements[id]=new Element()),createElement:()=>new Element(),querySelector:s=>s==='.step.failed'?null:new Element()};
global.window={addEventListener(){},confirm:()=>true};
global.EventSource=class {static CONNECTING=0;static CLOSED=2;constructor(){EventSource.last=this;this.events={};} addEventListener(k,v){this.events[k]=v;}close(){}};
let calls=0;global.fetch=async()=>{calls++;return {ok:true,json:async()=>({status:'cancelling'})};};
`
	checks := `
(async()=>{
showView('terminal');assert.equal(elements['terminal-panel'].hidden,false);assert.equal(elements['tab-overview'].attrs['aria-selected'],'false');
showView('overview');assert.equal(elements['terminal-panel'].hidden,true);
assert.equal(classifyLine('11:22:33 [Enhance] 94/987 src/typecheck.c::tc_error neutral 7.5s (elapsed 3m11s, ETA ~30m23s, $0.0064)'),'progress');
assert.equal(classifyLine('source/error_handler.c::failed_call'),'');
assert.equal(classifyLine('WARNING: provider failed'),'warning');assert.equal(classifyLine('11:22:33 [error] failed'),'error');
assert(extractProgress('[Enhance] 94/987 src/typecheck.c::tc_error neutral 7.5s (elapsed 3m11s, ETA ~30m23s, $0.0064)'));
assert.equal(elements['overview-count'].textContent,'94 / 987');assert.equal(elements['overview-elapsed'].textContent,'3m11s');assert.equal(elements['overview-eta'].textContent,'~30m23s');
assert(extractProgress('[Enhance] --- 100/987 (10.1%) | avg 1.3s/unit | elapsed 3m20s | ETA ~30m0s | cost $0.10 ---'));
assert.equal(elements['overview-count'].textContent,'100 / 987');assert.equal(elements['overview-eta'].textContent,'~30m0s');
updateSteps('[4/8] Running vulnerability detection (Stage 1)...');assert.equal(elements['stage-progress'].hidden,true);assert.equal(elements['overview-eta'].textContent,'尚未报告');
assert(!extractProgress('[Detect] 1/0 bad'));
const es=EventSource.last;
es.onmessage({lastEventId:'0',data:'[Enhance] 1/2 <img src=x onerror=alert(1)> neutral (elapsed 1s, ETA ~1s, $0)'});
const count=elements['log-body'].children.length;
es.onmessage({lastEventId:'0',data:'duplicate'});assert.equal(elements['log-body'].children.length,count);
assert(elements['overview-task'].textContent.includes('<img'));assert.equal(elements['overview-task'].children.length,0);
es.readyState=EventSource.CONNECTING;es.onerror();assert.equal(elements['status-text'].dataset.state,'reconnecting');es.onopen();
window.confirm=()=>false;await elements['btn-cancel'].events.click();assert.equal(calls,0);
window.confirm=()=>true;
global.fetch=async()=>{throw new Error('network');};await elements['btn-cancel'].events.click();assert.equal(elements['btn-cancel'].disabled,false);assert.equal(elements['status-text'].dataset.state,'cancel-unknown');
global.fetch=async(url,options)=>{calls++;assert.equal(options.headers['X-CSRF-Token'],'tok');return {ok:true,json:async()=>({status:'cancelling'})};};
const pending=elements['btn-cancel'].events.click();await elements['btn-cancel'].events.click();await pending;
assert.equal(calls,1);cancelPending=false;appendLine('[cancel] User requested cancellation; waiting for cleanup');assert.equal(cancelPending,true);assert.equal(elements['btn-cancel'].disabled,true);assert.equal(elements['status-text'].dataset.state,'cancelling');
es.onopen();assert.equal(elements['status-text'].dataset.state,'cancelling');
// A terminal POST response must not cut off final SSE replay.
cancelPending=false;global.fetch=async()=>({ok:true,json:async()=>({status:'cancelled'})});await elements['btn-cancel'].events.click();assert.equal(terminalStatus,'');
es.onmessage({lastEventId:'1',data:'final preserved log'});assert.equal(elements['log-body'].children.length,count+2);
es.events.done({data:'cancelled'});assert.equal(elements['status-text'].dataset.state,'cancelled');assert.equal(elements['btn-cancel'].disabled,true);assert.equal(elements['overview-eta'].textContent,'任务已结束');
terminalStatus='';onDone('timeout');assert(elements['status-text'].textContent.includes('超时来源及对应时间设置'));assert(elements['error-banner'].textContent.includes('新建扫描'));assert(!elements['error-banner'].textContent.includes('VULSCAN_INVOKE_TIMEOUT'));
})().catch(e=>{console.error(e);process.exitCode=1;});
`
	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(prelude + scripts[1] + checks)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("UI state regression: %v\n%s", err, out)
	}
}
