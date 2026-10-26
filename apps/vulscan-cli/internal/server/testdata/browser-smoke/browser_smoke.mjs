// The browser-smoke script (Playwright + a real Chromium): the CSP's first
// real-browser enforcement pass over the VulScan UI pages + /report, plus
// the golden render oracle for vendored marked/DOMPurify bumps.
//
// argv: node browser_smoke.mjs <baseURL> <goldenExpectedPath>
// env:  VULSCAN_UPDATE_GOLDEN=1 re-captures the golden instead of comparing.
//
// FAILURE SEMANTICS (the consult's convergence): FAIL on any
// securitypolicyviolation; any pageerror; any same-origin response >= 400
// (except /favicon.ico); any same-origin requestfailed except
// net::ERR_ABORTED (the scan page's es.close() aborts its own SSE stream —
// page-initiated, never a CSP/network failure); any missing readiness; the
// canaries; the golden mismatch (in compare mode). The console handler
// also FAILs on "Refused to" text — Chromium logs every CSP block as a
// console error, so it is the backstop if the init-script listener ever
// silently fails to attach.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { chromium } from 'playwright';

const [baseURL, goldenPath] = process.argv.slice(2);
if (!baseURL || !goldenPath) {
  console.error('usage: node browser_smoke.mjs <baseURL> <goldenExpectedPath>');
  process.exit(2);
}
const update = process.env.VULSCAN_UPDATE_GOLDEN === '1';
const origin = new URL(baseURL).origin;

// VULSCAN_BROWSER_CHANNEL=chrome drives the system-installed Chrome
// (a local convenience when the bundled-Chromium CDN download is slow);
// CI uses the default bundled chromium. Same engine family, same policy.
const launchOpts = process.env.VULSCAN_BROWSER_EXECUTABLE
  ? { executablePath:process.env.VULSCAN_BROWSER_EXECUTABLE }
  : process.env.VULSCAN_BROWSER_CHANNEL
  ? { channel: process.env.VULSCAN_BROWSER_CHANNEL }
  : {};
const browser = await chromium.launch(launchOpts);
const context = await browser.newContext({reducedMotion:'reduce'});
await context.grantPermissions(['clipboard-read','clipboard-write']);
await context.addInitScript(() => {Date.now=()=>new Date('2026-10-25T08:10:00Z').getTime();});
context.on('request',request=>{const u=new URL(request.url());if(['http:','https:'].includes(u.protocol)&&u.origin!==origin)note('network','unexpected external request: '+u.href);});
// The violation listener BEFORE any navigation (context-level init script);
// addInitScript runs via CDP and is CSP-exempt — never addScriptTag.
await context.addInitScript(() => {
  window.__violations = [];
  window.addEventListener('securitypolicyviolation', (e) => {
    window.__violations.push(
      `${e.violatedDirective} blocked=${e.blockedURI} at ${(e.sourceFile || '')}:${e.lineNumber}`);
  });
});

const failures = [];
const screenshotDir = process.env.VULSCAN_SCREENSHOTS;
if (screenshotDir) mkdirSync(screenshotDir, {recursive:true});
let violationsSeen = 0;
const note = (page, msg) => failures.push(`[${page}] ${msg}`);

const settleLayout=page=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
const waitCharts=async page=>{
 await settleLayout(page);
 await page.waitForFunction(()=>[...document.querySelectorAll('canvas')].every(canvas=>{
  const chart=globalThis.Chart?.getChart(canvas);if(!chart||chart.width<2||chart.height<2)return false;
  if(!chart.data.datasets.some(d=>d.data.some(n=>n>0)))return true;
  const pixels=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height).data;
  for(let i=3;i<pixels.length;i+=4)if(pixels[i]>0)return true;
  return false;
 }));
};

async function visit(name, path) {
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  page.on('pageerror', (e) => note(name, `pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && m.text().includes('Refused to')) {
      // The known allowance, console channel: DOMPurify's self-test style
      // (see the drain) also logs 'Refused to apply inline style ...' here
      // on bundled Chromium builds (version-dependent emission — system
      // Chrome 152 logs only the event). The filter is NON-LOSSY: the
      // only inline styles on these pages are the nonced template styles
      // (never refused) and DOMPurify's probe (counted via the event
      // channel); a REAL inline-style leak from the markdown path would
      // trip the style= canary independently of this channel. Any other
      // 'Refused to' — inline script, load, connect — still fails.
      if (!m.text().includes('Refused to apply inline style')) {
        note(name, `console: ${m.text()}`);
      }
    }
  });
  page.on('response', (r) => {
    const u = new URL(r.url());
    if (u.origin === origin && r.status() >= 400 && !u.pathname.endsWith('favicon.ico')) {
      note(name, `HTTP ${r.status()} on ${u.pathname}`);
    }
  });
  page.on('requestfailed', (r) => {
    const u = new URL(r.url());
    if (u.origin === origin && !(r.failure()?.errorText || '').includes('ERR_ABORTED')) {
      note(name, `requestfailed: ${u.pathname} ${r.failure()?.errorText}`);
    }
  });
  const resp = await page.goto(baseURL + path, { waitUntil: 'networkidle' });
  await page.evaluate(()=>document.fonts.ready);
  if (screenshotDir) {
    for (const width of [1440, 1920, 768, 360]) {
      await page.setViewportSize({width, height:1000});
      await settleLayout(page);
      if(path.startsWith('/report/'))await waitCharts(page);
      await page.screenshot({path:`${screenshotDir}/${name}-${width}.png`, fullPage:true});
      const overflow=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,width:document.documentElement.clientWidth}));
      if(overflow.scroll>overflow.width+1)note(name,`page overflow at ${width}: ${JSON.stringify(overflow)}`);
    }
  }
  // Zero violations alone does not prove enforcement — a missing policy also
  // passes. Assert the enforcing header on every navigation response.
  const csp = resp.headers()['content-security-policy'] || '';
  if (!csp.includes("default-src 'none'")) {
    note(name, `the navigation response carries no enforcing CSP: ${csp.slice(0, 90)}`);
  }
  if (['index', 'scan', 'summary', 'disclosure'].includes(name)) {
    const footer = await page.locator('footer').innerText();
    if (!footer.includes('911VulScan') || /Knostic|OpenAnt/.test(footer)) {
      note(name, `unexpected product footer: ${footer}`);
    }
  }
  return { page, csp };
}

const overflowDetails=page=>page.evaluate(()=>({viewport:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,items:[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().right>innerWidth+2).slice(0,8).map(e=>({tag:e.tagName,cls:e.className,right:Math.round(e.getBoundingClientRect().right),width:Math.round(e.getBoundingClientRect().width)}))}));
const checkContrast=async(page,label,selectors)=>{
 const bad=await page.evaluate(selectors=>{
  // Computed CSS can be color(srgb 1 1 1), not only rgb(255,255,255).
  // Resolve through the browser's own color parser and composite alpha layers.
  const canvas=document.createElement('canvas');canvas.width=canvas.height=1;const paint=canvas.getContext('2d',{willReadFrequently:true});
  const parse=s=>{paint.clearRect(0,0,1,1);paint.fillStyle=s;paint.fillRect(0,0,1,1);return [...paint.getImageData(0,0,1,1).data];};
  const over=(fg,bg)=>fg.slice(0,3).map((v,i)=>v*fg[3]/255+bg[i]*(1-fg[3]/255));
  const luminance=rgb=>{const c=rgb.slice(0,3).map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return .2126*c[0]+.7152*c[1]+.0722*c[2];};
  const bad=[];
  for(const selector of selectors){for(const element of [...document.querySelectorAll(selector)].slice(0,12)){
   if(!element.getClientRects().length)continue;
   let parent=element;const layers=[];
   while(parent){const color=parse(getComputedStyle(parent).backgroundColor);layers.push(color);if(color[3]===255)break;parent=parent.parentElement;}
   let bg=[255,255,255];for(const layer of layers.reverse())bg=over(layer,bg);
   const color=over(parse(getComputedStyle(element).color),bg),a=luminance(color),b=luminance(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
   if(ratio<4.5)bad.push({selector,text:element.textContent.slice(0,25),ratio:ratio.toFixed(2),color,bg});
  }}return bad;
 },selectors);
 if(bad.length)throw Error(label+' contrast below 4.5: '+JSON.stringify(bad));
};
const ready = async (page, name, fn) => { try { await fn(); } catch (e) { const state=await page.evaluate(()=>({status:document.getElementById('status-text')?.dataset.state,logCount:document.getElementById('log-count')?.textContent,follow:document.getElementById('auto-scroll')?.checked,newLogs:document.getElementById('log-new')?.textContent}));note(name, `readiness: ${e.message.split('\n')[0]} ${JSON.stringify(state)}`); } };

// The violation DRAIN (the review round's catch): the init-script listener
// pushes into window.__violations — read it AFTER the async work settles
// (readiness + networkidle) and BEFORE page.close(), or the events die with
// the page. Without this the listener is dead code and enforcement rests
// only on the console-'Refused to' backstop.
const drain = async (page, name) => {
  const viols = await page.evaluate(() => window.__violations || []);
  for (const v of viols) {
    // The KNOWN allowance, and only this shape: DOMPurify 3.4.15's own
    // load-time self-test creates an inline <style> (reported as
    // style-src-elem blocked=inline sourced from the vendored blob) —
    // our style-src 'nonce' policy blocks it on every page load. The
    // empirical evidence the blocking is harmless to sanitization: the
    // golden matched and every canary clean WITH the probe blocked (the
    // entire prior verification stack — the 16-vector battery, the
    // jsdom differentials, the golden — ran under exactly this policy).
    // The filter is NARROW: style-src-elem sourced from the dompurify
    // ASSET only; any other style-src-elem — including one sourced from
    // the PAGE itself (an injected inline style surviving the markdown
    // path) — still fails.
    if (v.startsWith('style-src-elem') && v.includes('/assets/dompurify-')) {
      dompurifyProbeBlocked++;
      continue;
    }
    // The SECOND half of the same probe, reported by Chromium >= 156 (the
    // playwright 1.64.1 bump): DOMPurify's load-time self-test also sets an
    // inline ATTRIBUTE on its throwaway element, which the pages'
    // `script-src 'self' 'nonce-...'` policy blocks as script-src-attr.
    // Chromium 153 reported only the style half. THE NARROWNESS IS THE WHOLE
    // POINT and is one clause tighter than the style arm above: the directive
    // AND `blocked=inline` AND the vendored dompurify ASSET as the source.
    // A real inline-handler leak surviving the markdown path is sourced from
    // the PAGE, so it still fails here -- and independently trips the
    // `onerror`/`onclick` ABSENT canaries and the console 'Refused to execute
    // inline event handler' backstop, neither of which this filter touches.
    if (v.startsWith('script-src-attr blocked=inline')
        && v.includes('/assets/dompurify-')) {
      dompurifyProbeBlocked++;
      continue;
    }
    note(name, 'csp violation: ' + v);
    violationsSeen++;
  }
  return viols.length;
};
let dompurifyProbeBlocked = 0;

// --- / (index): the nonced inline script executed; NO click (accepting the
// delete confirm would destroy the seeded job for every later page).
{
  const { page } = await visit('index', '/');
  await ready(page, 'index', () => page.waitForFunction(() => typeof deleteScan === 'function'));
  const hasRows = await page.locator('#scans-list .scan-row').count();
  if (hasRows < 1) note('index', 'the seeded scan row is not rendered');
  await ready(page,'index task filters',async()=>{
    const states=await page.locator('#job-status option').evaluateAll(options=>options.map(o=>o.value));
    if(JSON.stringify(states)!==JSON.stringify(['','queued','running','cancelling','cancelled','done','timeout','error']))throw Error('task state filter options missing');
    await page.selectOption('#job-status','queued');if(await page.locator('#scans-list .scan-row:visible').count()!==1)throw Error('queued task filtering failed');
    await page.selectOption('#job-status','');await page.fill('#job-query','f0000005');if(await page.locator('#scans-list .scan-row:visible').count()!==1)throw Error('task identifier search failed');
    await page.fill('#job-query','');if(await page.locator('#scans-list .scan-row:visible').count()!==hasRows)throw Error('clearing task search did not restore rows');
  });
  await ready(page, 'index language selection', async () => {
    const inputs = page.locator('input[name="languages"]');
    const actual = await inputs.evaluateAll(nodes => nodes.map(n => [n.value, n.closest('label').textContent.trim()]));
    const expected = [['c', 'C / C++'], ['python', 'Python'], ['javascript', 'JavaScript'], ['go', 'Go']];
    if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`unexpected languages: ${JSON.stringify(actual)}`);
    const submitted = () => page.locator('#scan-form').evaluate(form => new FormData(form).getAll('languages'));
    if ((await submitted()).length) throw new Error('default must remain auto detection');
    for (const [id] of expected) {
      const input = page.locator(`input[name="languages"][value="${id}"]`);
      await input.check();
      if (JSON.stringify(await submitted()) !== JSON.stringify([id])) throw new Error(`incorrect submitted ID: ${id}`);
      await input.uncheck();
    }
    for (const [id] of expected) await page.locator(`input[name="languages"][value="${id}"]`).check();
    if (JSON.stringify(await submitted()) !== JSON.stringify(expected.map(([id]) => id))) throw new Error('multi-selection IDs changed');
    for (const [id] of expected) await page.locator(`input[name="languages"][value="${id}"]`).uncheck();
    if ((await submitted()).length) throw new Error('clearing selection did not restore auto detection');
  });
  await ready(page, 'index scan time budget', async () => {
    const selected = () => page.locator('#scan-form').evaluate(form => new FormData(form).get('scan_timeout'));
    if (await selected() !== '2h') throw new Error('scan budget must default to 2h');
    const options = await page.locator('#scan-timeout option').evaluateAll(nodes => nodes.map(n => n.value));
    if (JSON.stringify(options) !== JSON.stringify(['30m','1h','2h','4h','8h','24h'])) throw new Error('unexpected scan budgets');
    for (const value of options) {
      await page.selectOption('#scan-timeout', value);
      if (await selected() !== value) throw new Error(`incorrect submitted scan budget: ${value}`);
    }
    await page.selectOption('#scan-timeout', '4h');
  });
  await ready(page, 'index model switch', async () => {
    await page.selectOption('#provider', 'configured');
    if (!(await page.locator('#api_key').isDisabled()) || !(await page.locator('#model').isDisabled())) throw new Error('configured profile leaves DeepSeek fields enabled');
    if (!(await page.locator('#llm_config').isEnabled())) throw new Error('profile selector remains disabled');
    await page.selectOption('#provider', 'deepseek');
    await page.selectOption('#model', 'deepseek-v4-pro');
    if (!(await page.locator('#api_key').isEnabled()) || !(await page.locator('#llm_config').isDisabled())) throw new Error('DeepSeek mode does not isolate profile fields');
  });
  await ready(page, 'index repeated submission and recoverable response', async () => {
    let submissions = 0;
    let submittedBudget = null;
    await page.route('**/scan', async route => {
      submissions++;
      submittedBudget = new URLSearchParams(route.request().postData()).get('scan_timeout');
      await new Promise(resolve => setTimeout(resolve, 100));
      await route.fulfill({ status:200, contentType:'text/plain', body:'模拟未跳转响应' });
    });
    await page.fill('#repo', '/fixture-only-no-real-scan');
    await page.evaluate(() => { const form=document.getElementById('scan-form'); form.requestSubmit(); form.requestSubmit(); });
    await page.waitForFunction(() => !document.getElementById('start-button').disabled && document.getElementById('form-feedback').textContent.includes('任务响应异常'));
    if (submissions !== 1) throw new Error(`duplicate form submissions: ${submissions}`);
    if (submittedBudget !== '4h') throw new Error(`request lost scan budget: ${submittedBudget}`);
    await page.unroute('**/scan');
  });
  await ready(page, 'index back navigation clears one-run key', async () => {
    await page.fill('#api_key', 'smoke-fixture-not-a-real-key');
    await page.locator('a[href="/scan/jx"]').click();
    await page.waitForFunction(() => document.getElementById('status-text')?.dataset.state === 'done');
    await page.goBack({ waitUntil:'networkidle' });
    await page.waitForFunction(() => document.getElementById('api_key')?.value === '' && !document.getElementById('start-button').disabled);
  });
  await drain(page, 'index');
  await page.close();
}

// --- /scan/jx: the live page for a done job — the SSE done event + the
// post-done fetches are the only real connect-src 'self' exercise.
{
  const { page } = await visit('scan', '/scan/jx');
  await ready(page, 'scan', () => page.waitForSelector('#btn-summary.ready',{state:'attached'}));
  await ready(page, 'scan', () => page.waitForFunction(
    () => document.querySelectorAll('#disclosure-links a').length >= 1));
  await ready(page, 'scan', () => page.waitForFunction(
    () => document.getElementById('status-text').dataset.state === 'done'));
  await ready(page, 'scan', async () => {
    await page.locator('.task-settings > summary').click();
    if (!(await page.locator('#scan-timeout-budget').innerText()).includes('未记录（旧任务）')) throw new Error('legacy scan budget misrepresented');
    await page.locator('.task-settings > summary').click();
    if (!(await page.locator('#overview-panel').isVisible())) throw new Error('overview is not the default');
    await page.getByRole('tab', {name:'原始日志'}).click();
    if (!(await page.locator('#terminal-panel').isVisible())) throw new Error('terminal tab did not open');
    await page.getByRole('tab', {name:'原始日志'}).press('Home');
    if (!(await page.locator('#overview-panel').isVisible())) throw new Error('keyboard tab switch failed');
    if (!(await page.locator('#btn-cancel').isDisabled())) throw new Error('completed scan can still be cancelled');
    const result = await page.evaluate(() => {
      const line='11:22:33 [Enhance] 94/987 source.c::tc_error neutral';
      VulscanScan.applySnapshot({version:1,job_id:'jx',revision:999,status:'done',legacy:false,coverage:'unknown',started_at:'2026-10-25T08:00:00Z',finished_at:'2026-10-25T08:10:00Z',updated_at:'2026-10-25T08:10:00Z',stage:'enhance',stages:{enhance:{status:'success',processed:95,total:987,unit:'代码单元',elapsed_seconds:192,eta_seconds:1800,activity:'<img src=x onerror=alert(1)>'}},findings:{},counts:{},activity:[]});
      return {severity:VulscanScan.classifyLine(line),warning:VulscanScan.classifyLine('WARNING: failed'),count:document.getElementById('overview-count').textContent,injected:document.querySelector('#overview-task img')!==null};
    });
    if(result.severity!=='progress'||result.warning!=='warning'||!result.count.startsWith('95 / 987')||result.injected)throw new Error('structured progress/severity/XSS regression');
  });
  await drain(page, 'scan');
  await page.close();
}

// Cancellation UI: controlled SSE/fetch, never starts or cancels a real job.
{
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.EventSource = class {
      static CONNECTING=0; static CLOSED=2;
      constructor(url){window.testStreams??={};window.testStreams[url.endsWith('/events')?'state':'logs']=this;this.handlers={};setTimeout(()=>this.onopen?.(),0);}
      addEventListener(name, fn){this.handlers[name]=fn;} close(){}
    };
  });
  let requests=0;
  await page.route('**/scan/jx/cancel', async route => {
    requests++;
    await route.fulfill({status:202,contentType:'application/json',body:'{"status":"cancelling"}'});
  });
  await page.goto(baseURL+'/scan/jx');
  await ready(page, 'scan-cancel', async () => {
    await page.evaluate(() => {
      testStreams.logs.onmessage({lastEventId:'0',data:'[Enhance] 1/2 source.c::tc_error neutral (elapsed 1s, ETA ~1s, $0)'});
      testStreams.logs.onmessage({lastEventId:'0',data:'duplicate'});
      testStreams.logs.readyState=EventSource.CONNECTING;testStreams.logs.onerror();
    });
    await page.waitForFunction(()=>document.querySelectorAll('.log-line').length===1);
    if (await page.locator('.log-line').count()!==1) throw new Error('replay duplicated log');
    if (await page.locator('#connection-status').getAttribute('data-state')!=='reconnecting') throw new Error('reconnect state missing');
    await page.locator('#btn-cancel').click();
    if (!(await page.locator('#cancel-dialog').isVisible())) throw new Error('custom cancel dialog did not open');
    await page.locator('#cancel-dismiss').click();
    if (await page.locator('#cancel-dialog').isVisible()) throw new Error('dismissed cancel dialog remains open');
    if(requests!==0) throw new Error('dismissed confirmation submitted');
    await page.locator('#btn-cancel').click();
    await page.locator('#cancel-confirm').click();
    await page.waitForFunction(()=>document.getElementById('status-text').dataset.state==='cancelling');
    if (!(await page.locator('#btn-cancel').isDisabled())) throw new Error('repeat cancel enabled');
    await page.evaluate(()=>{testStreams.logs.onopen();testStreams.logs.onmessage({lastEventId:'1',data:'final log'});testStreams.logs.handlers.done({data:'cancelled'});});
    await page.waitForFunction(()=>document.getElementById('status-text').dataset.state==='cancelled');
    await page.waitForFunction(()=>document.querySelectorAll('.log-line').length===2);
    if(requests!==1 || await page.locator('.log-line').count()!==2) throw new Error('cancel request/log preservation regression');
  });
  await drain(page,'scan-cancel'); await page.close();
}

// A failed request is retryable; even a terminal POST reply must wait for the
// final log-stream event before publishing the terminal state.
{
 const page=await context.newPage();let requests=0;
 page.on('pageerror',e=>note('scan-cancel-retry',e.message));
 await page.addInitScript(()=>{window.EventSource=class{
  static CONNECTING=0;static CLOSED=2;
  constructor(url){window.testStreams??={};testStreams[url.endsWith('/events')?'state':'logs']=this;this.handlers={};setTimeout(()=>this.onopen?.(),0);}
  addEventListener(name,fn){this.handlers[name]=fn;}close(){this.closed=true;}
 };});
 await page.route('**/scan/jx/cancel',async route=>{requests++;await route.fulfill({status:requests===1?503:200,contentType:'application/json',body:requests===1?'{}':'{"status":"cancelled"}'});});
 await ready(page,'scan-cancel-retry',async()=>{
  await page.goto(baseURL+'/scan/jx');
  await page.evaluate(()=>VulscanScan.applySnapshot({version:1,job_id:'jx',revision:1,status:'running',legacy:false,started_at:'2026-10-25T08:00:00Z',updated_at:'2026-10-25T08:01:00Z',stages:{},findings:{},counts:{},activity:[]}));
  await page.locator('#btn-cancel').click();await page.locator('#cancel-confirm').click();
  await page.waitForFunction(()=>document.getElementById('cancel-feedback').textContent.includes('未确认')&&!document.getElementById('btn-cancel').disabled);
  if(await page.locator('#status-text').getAttribute('data-state')!=='running')throw Error('cancel request failure changed actual job state');
  await page.locator('#btn-cancel').click();await page.locator('#cancel-confirm').click();
  await page.waitForFunction(()=>document.getElementById('cancel-feedback').textContent.includes('等待服务端终态'));
  if(await page.locator('#status-text').getAttribute('data-state')!=='running'||await page.evaluate(()=>!!testStreams.logs.closed))throw Error('POST reply ended job/logs before cleanup finished');
  await page.evaluate(()=>{testStreams.logs.onmessage({lastEventId:'0',data:'cleanup has actually completed'});testStreams.logs.handlers.done({data:'cancelled'});});
  await page.waitForFunction(()=>document.getElementById('status-text').dataset.state==='cancelled'&&document.querySelectorAll('.log-line').length===1);
  if(requests!==2)throw Error('failed cancellation was not retried exactly once');
 });
 await drain(page,'scan-cancel-retry');await page.close();
}

// --- /summary/jx: the render path — readiness, the CANARIES (hard,
// --update-golden cannot touch them), then the golden.
let summaryHTML = '';
{
  const { page } = await visit('summary', '/summary/jx');
  await ready(page, 'summary', () => page.waitForFunction(
    () => document.getElementById('content').children.length >= 1
      && document.getElementById('content').textContent.trim().length > 0
      && document.getElementById('content').dataset.renderState === 'ready'));
  summaryHTML = await page.$eval('#content', (el) => el.innerHTML);

  const ABSENT = ['<img', '<form', '<input', '<style', '<script', 'javascript:',
    ' href="data:', ' src="data:', 'style=', 'src=', 'onerror', 'onclick'];
  const PRESENT = ['<table', '<strong>Repository:</strong>', '<code>',
    '<a href="https://example.com/docs"', 'unchecked task', 'completed task'];
  for (const bad of ABSENT) {
    if (summaryHTML.toLowerCase().includes(bad)) note('summary', `canary ABSENT failed: ${bad} reached the DOM`);
  }
  for (const good of PRESENT) {
    if (!summaryHTML.includes(good)) note('summary', `canary PRESENT failed: ${good} missing from the DOM`);
  }
  await drain(page, 'summary');
  await page.close();
}

// --- /disclosure/jx/d.md: the same render path on the second channel.
{
  const { page } = await visit('disclosure', '/disclosure/jx/d.md');
  await ready(page, 'disclosure', () => page.waitForFunction(
    () => document.getElementById('content').children.length >= 1
      && document.getElementById('content').dataset.renderState === 'ready'));
  await drain(page, 'disclosure');
  await page.close();
}

// --- /report/jx: a REAL generated report (report.GenerateReskin) — the
// runtime proof that Chart.js + datalabels run INLINE under script-src
// 'unsafe-inline' with no unsafe-eval (the header assertion csp_test
// deliberately declines to make).
{
  const { page } = await visit('report', '/report/jx');
  await ready(page, 'report', () => page.waitForFunction(() => typeof Chart === 'function'));
  await ready(page, 'report', () => page.waitForSelector('#unitChart'));
  await drain(page, 'report');
  await page.close();
}

// Deterministic state fixtures: counts, reload, real EventSource reconnect,
// parallel jobs, bounded logs, filters, keyboard focus and offline code readers.
{
 const page=await context.newPage();
 page.on('pageerror',e=>note('fixtures',e.message));
 const goto=async id=>{await page.goto(baseURL+'/scan/'+id,{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>['queued','running','cancelling','cancelled','timeout','error','done'].includes(document.getElementById('status-text')?.dataset.state));};
 await ready(page,'state fixtures',async()=>{
  for(const [id,status] of [['f0000001','queued'],['f0000003','cancelling'],['f0000004','cancelled'],['f0000005','timeout'],['f0000006','error'],['f0000007','done']]){
   await goto(id);
   if(await page.locator('#status-text').getAttribute('data-state')!==status)throw Error('incorrect task state '+id);
   if(status!=='queued'&&await page.locator('#count-candidates').innerText()!=='6')throw Error('fixture cardinality lost '+id);
   if(['cancelling','cancelled','timeout','error','done'].includes(status)&&!(await page.locator('#btn-cancel').isDisabled()))throw Error('terminal/stopping task can be cancelled again');
  }
  await goto('f0000001');if(await page.locator('#count-candidates').innerText()!=='—')throw Error('unstarted discovery was fabricated as zero');
  await goto('f0000009');if(await page.locator('#count-candidates').innerText()!=='0'||await page.locator('#count-retained').innerText()!=='—'||await page.locator('#count-reproduced').innerText()!=='—')throw Error('known empty discovery and unproduced verification were conflated');
  await page.locator('#tab-findings').click();if(!(await page.locator('#findings-empty').innerText()).includes('尚未发现候选'))throw Error('known empty finding list is unclear');
  await goto('f0000006');await page.locator('#tab-activity').click();await page.selectOption('#activity-stage','report');if(!(await page.locator('#activity-groups').innerText()).includes('报告步骤部分失败')||await page.locator('.activity-row:visible details[open]').count()<1)throw Error('failure phase/output not visible in activity');
  await goto('f0000002');
  for(const [key,n]of[['candidates',6],['retained',3],['excluded',1],['reproduced',1]])if(await page.locator('#count-'+key).innerText()!==String(n))throw Error('incorrect projection '+key);
  if(!(await page.locator('#overview-count').innerText()).startsWith('94 / 987'))throw Error('processing denominator became finding count');
  await page.locator('#tab-findings').click();
  if(await page.locator('#finding-rows tr').count()!==6)throw Error('finding details disagree with aggregate');
  await page.selectOption('#dynamic-filter','environment_error');if(await page.locator('#finding-rows tr:visible').count()!==1)throw Error('environment-error filter');
  await page.locator('#clear-findings').click();await page.fill('#finding-query','Buffer Copy');if(await page.locator('#finding-rows tr:visible').count()!==6)throw Error('CWE/type search does not index all rows');
  await page.fill('#finding-query','复核排除');if(await page.locator('#finding-rows tr:visible').count()!==1)throw Error('title search');
  await page.locator('#finding-rows tr:visible .finding-title').click();if(!(await page.locator('#finding-dialog').innerText()).includes('复核排除'))throw Error('finding detail does not open');
  if(await page.evaluate(()=>!!window.__fixtureInjected||!!document.querySelector('#finding-detail script')))throw Error('finding text became executable HTML');
  await page.keyboard.press('Escape');if(await page.locator('#finding-dialog').isVisible())throw Error('Escape does not close detail');
  if(!(await page.evaluate(()=>document.activeElement?.classList.contains('finding-title'))))throw Error('dialog did not restore keyboard focus');
  await page.locator('#clear-findings').click();
  await page.locator('#finding-rows .finding-title').nth(3).click();
  for(const width of [1440,768,360]){
   await page.setViewportSize({width,height:1000});
   const dimensions=await page.locator('#finding-dialog').evaluate(d=>({client:d.clientWidth,scroll:d.scrollWidth,left:d.scrollLeft,top:d.getBoundingClientRect().top,bottom:d.getBoundingClientRect().bottom,height:innerHeight,title:document.getElementById('finding-title').textContent,prose:!!document.querySelector('#finding-detail .markdown-prose code')}));
   if(dimensions.scroll>dimensions.client+1||dimensions.left>1||dimensions.top<0||dimensions.bottom>dimensions.height+1||!dimensions.prose||dimensions.title.length>96)throw Error('payload dialog regression '+JSON.stringify(dimensions));
   if(await page.locator('#finding-detail script,#finding-detail img,#finding-detail [onerror]').count())throw Error('payload Markdown active HTML');
  }
  if(!(await page.locator('#finding-detail').textContent()).includes('AUTH_COOKIE='))throw Error('original payload was discarded');
  await page.keyboard.press('Escape');await page.setViewportSize({width:1440,height:1000});
  await page.selectOption('#finding-sort','title');const titles=await page.locator('#finding-rows .finding-title').allTextContents();if(JSON.stringify(titles)!==JSON.stringify([...titles].sort((a,b)=>a.localeCompare(b,'zh-CN'))))throw Error('title sort does not match displayed titles');await page.selectOption('#finding-sort','first');
  await page.locator('#tab-activity').click();await page.fill('#activity-finding','VULN-005');if(await page.locator('.activity-row:visible').count()!==2)throw Error('finding activity filter lost records');if(!(await page.locator('.activity-row:visible').last().innerText()).includes('构建'))throw Error('build failure phase is missing');await page.locator('#clear-activity').click();await page.locator('#tab-findings').click();
  const focus=await page.locator('#finding-rows .finding-title').first();await focus.focus();
  await page.evaluate(async()=>{const s=await(await fetch('/scan/f0000002/snapshot')).json();s.revision+=1;s.findings[Object.keys(s.findings)[0]].dynamic='not_reproduced';VulscanScan.applySnapshot(s);});
  if(!(await page.evaluate(()=>document.activeElement?.classList.contains('finding-title'))))throw Error('live update stole reading focus');
  await page.reload({waitUntil:'domcontentloaded'});await page.waitForFunction(()=>document.getElementById('count-reproduced')?.textContent==='1');
  await page.locator('#tab-terminal').click();await page.waitForFunction(()=>document.getElementById('log-count').textContent.includes(' / 1520 行'));
  const count=await page.locator('#log-count').innerText();if(!/1[,.]?5\d\d/.test(count.replaceAll(',','')))throw Error('long-log fixture was not fully received: '+count);
  if(await page.locator('.log-line').count()>250)throw Error('raw log DOM is unbounded');
  await page.fill('#log-query','中文注释');await page.waitForFunction(()=>document.getElementById('log-count').textContent.startsWith('匹配 1507 /'));
  await page.fill('#log-query','中文注释 source/error_handler.c');await page.waitForFunction(()=>document.getElementById('log-count').textContent.startsWith('匹配 1500 /'));
  await page.locator('#log-copy').click();const copiedLogs=await page.evaluate(()=>navigator.clipboard.readText());if(copiedLogs.split('\n').length!==1500||!copiedLogs.includes('<script>literal only</script>'))throw Error('log copy changed or omitted hidden raw records');
  if(await page.locator('.log-line').count()!==250)throw Error('search missed hidden log pages');
  await page.locator('#log-next').click();if(!(await page.locator('#log-count').innerText()).includes('第 251–500 行'))throw Error('log pagination');
  await page.locator('#log-clear').click();await page.locator('#log-latest').click();
  await page.locator('#log-body').hover();await page.mouse.wheel(0,-600);await page.waitForFunction(()=>!document.getElementById('auto-scroll').checked);
  await page.evaluate(()=>VulscanScan.appendLine('new while reading'));await page.waitForFunction(()=>document.getElementById('log-new').textContent.includes('1'));
  await page.locator('#log-latest').click();if(await page.locator('#log-new').innerText()!=='')throw Error('new-log counter did not clear');
  await checkContrast(page,'dark log',['.log-line .body','.log-line .ts']);
  await page.locator('#tab-terminal').press('Home');if(!(await page.locator('#overview-panel').isVisible()))throw Error('keyboard tab navigation');
  await checkContrast(page,'scan',['.meta','.overview-note','.status-pill','.summary-stat span']);
  for(const width of [1440,1920,768,360]){await page.setViewportSize({width,height:1000});if(screenshotDir)await page.screenshot({path:`${screenshotDir}/scan-running-${width}.png`,fullPage:true});const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1);if(overflow)throw Error('running page overflow '+width+' '+JSON.stringify(await overflowDetails(page)));}
 });
 await drain(page,'fixtures');await page.close();
}
{
 const page=await context.newPage();let streams=0;
 await page.route('**/scan/f0000002/events',async route=>{streams++;if(streams===1){const r=await context.request.get(baseURL+'/scan/f0000002/snapshot');await route.fulfill({status:200,contentType:'text/event-stream',body:'retry: 1000\nevent: snapshot\ndata: '+JSON.stringify(await r.json())+'\n\n'});}else await route.continue();});
 await ready(page,'real reconnect',async()=>{await page.goto(baseURL+'/scan/f0000002',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>document.getElementById('connection-status').textContent.includes('重连'));if(await page.locator('#status-text').getAttribute('data-state')!=='running')throw Error('connection drop became task failure');await page.waitForFunction(()=>document.getElementById('connection-status').dataset.state==='connected');if(streams<2||await page.locator('#count-candidates').innerText()!=='6')throw Error('reconnect lost or duplicated state');});
 const other=await context.newPage();await ready(other,'parallel isolation',async()=>{await other.goto(baseURL+'/scan/f0000008',{waitUntil:'domcontentloaded'});await other.waitForFunction(()=>document.getElementById('status-text').dataset.state==='running');if(await other.locator('#count-candidates').innerText()!=='—')throw Error('other job inherited counters');await other.evaluate(()=>VulscanScan.applySnapshot({version:1,job_id:'f0000002',revision:999,counts:{candidates:99},findings:{},stages:{}}));if(await other.locator('#count-candidates').innerText()!=='—')throw Error('cross-job snapshot accepted');});
 await drain(page,'reconnect');await drain(other,'parallel');await page.close();await other.close();
}
for(const [name,path]of[['summary-rich','/summary/f0000007'],['disclosure-rich','/disclosure/f0000007/DISCLOSURE_01_FIXTURE.md'],['report-rich','/report/f0000007']]){
 const {page}=await visit(name,path);
 await ready(page,name,async()=>{
  if(name==='report-rich'){await page.fill('#finding-query','CWE-120');if(await page.locator('details[id^="finding-"]:visible').count()!==1)throw Error('report CWE search failed');await page.fill('#finding-query','Buffer Copy');if(await page.locator('details[id^="finding-"]:visible').count()!==1)throw Error('report type search failed');await page.fill('#finding-query','');await page.locator('#finding-expand').click();}
  await page.waitForSelector('.code-reader');
  const code=page.locator('.code-reader').first();const original=await code.locator('pre code').textContent();
  if(!original.includes('中文注释')||!original.includes('\tif')||!original.includes('&&'))throw Error('source text/indentation changed');
  await code.getByRole('button',{name:'复制代码原文',exact:true}).click();if(await page.evaluate(()=>navigator.clipboard.readText())!==original)throw Error('code copy added line numbers or changed original bytes');
  if(await page.locator('.notice-toast[data-tone=success]').filter({hasText:'代码原文已复制。'}).count()!==1)throw Error('code copy has no success component');
  if(name==='report-rich'&&!(await code.innerText()).includes('源码行号'))throw Error('real source coordinates missing');
  if(name!=='report-rich'&&!(await code.innerText()).includes('片段行号'))throw Error('snippet coordinates misrepresented as source');
  if(await code.locator('.hljs-comment').count()<1)throw Error('known code language was not highlighted');
  await code.getByRole('button',{name:'换行：关',exact:true}).click();if(!(await code.getAttribute('class')).includes('is-wrapped'))throw Error('wrap toggle');
  await code.getByRole('button',{name:'展开长代码',exact:true}).click();if((await code.getAttribute('class')).includes('is-collapsed'))throw Error('long code cannot expand');
  if(name!=='report-rich'){const [download]=await Promise.all([page.waitForEvent('download'),page.locator('#document-download').click()]);const expected=await page.evaluate(()=>markdown);if(readFileSync(await download.path(),'utf8')!==expected)throw Error('Markdown download changed original bytes');if(await page.locator('.notice-toast[data-tone=info]').filter({hasText:'已开始下载 Markdown。'}).count()!==1)throw Error('download has no feedback component');await page.locator('#document-copy').click();if(await page.evaluate(()=>navigator.clipboard.readText())!==expected)throw Error('Markdown copy changed original bytes');if(await page.locator('.notice-toast[data-tone=success]').filter({hasText:'原始 Markdown 已复制。'}).count()!==1)throw Error('Markdown copy has no feedback component');const unknown=page.locator('.code-reader').filter({hasText:'untouched <>&'});if(!(await unknown.locator('code').getAttribute('class')).includes('plaintext'))throw Error('unknown language was guessed');if(await page.locator('#content img,#content script,#content form,#content [onerror]').count())throw Error('unsafe Markdown reached DOM');}
  await checkContrast(page,'code',['.code-toolbar button','.code-lines','.hljs-comment','.hljs-keyword','.status-pill']);
  if(name==='report-rich'){await page.locator('#remediation > details > summary').click();await checkContrast(page,'remediation typography',['.remediation-content h5','.remediation-content blockquote','.remediation-content td']);}
  const fontState=await page.evaluate(async()=>{await document.fonts.ready;return [...document.fonts].filter(f=>['Inter','JetBrains Mono'].includes(f.family.replaceAll('"',''))).map(f=>f.status);});if(fontState.filter(s=>s==='loaded').length<2)throw Error('actual packaged body/code fonts did not load');
 });
 await drain(page,name);await page.close();
}
// Theme preference is applied before paint, survives navigation and stays in
// sync across open tabs. The OS theme does not replace the light default.
{
 const page=await context.newPage(),peer=await context.newPage();
 page.on('pageerror',e=>note('theme',e.message));peer.on('pageerror',e=>note('theme peer',e.message));
 await ready(page,'theme preference and motion',async()=>{
  await page.emulateMedia({colorScheme:'dark',reducedMotion:'no-preference'});
  await page.goto(baseURL+'/',{waitUntil:'domcontentloaded'});
  if(await page.locator('html').getAttribute('data-bs-theme')!=='light')throw Error('default must remain light');
  await page.locator('[data-theme-toggle]').focus();await page.keyboard.press('Enter');
  await page.waitForFunction(()=>document.documentElement.dataset.bsTheme==='dark');
  if(await page.locator('[data-theme-toggle]').getAttribute('aria-pressed')!=='true')throw Error('theme toggle accessible state');
  if(await page.locator('[data-theme-toggle]').getAttribute('aria-label')!=='深色主题')throw Error('theme toggle lacks a stable accessible name');
  await peer.goto(baseURL+'/summary/f0000007',{waitUntil:'domcontentloaded'});
  if(await peer.locator('html').getAttribute('data-bs-theme')!=='dark')throw Error('theme lost on navigation');
  await page.reload({waitUntil:'domcontentloaded'});
  if(await page.locator('html').getAttribute('data-bs-theme')!=='dark')throw Error('theme lost on refresh');
  await page.locator('[data-theme-toggle]').click();
  await peer.waitForFunction(()=>document.documentElement.dataset.bsTheme==='light');
  await page.locator('[data-theme-toggle]').click();
  await peer.waitForFunction(()=>document.documentElement.dataset.bsTheme==='dark');
  await page.locator('.delete-btn').first().click();
  await page.evaluate(()=>VulscanUI.notify('动效检查',{tone:'info'}));
  const durations=await page.evaluate(()=>['.main','.dialog[open]','.notice-toast','body'].map(selector=>{const element=document.querySelector(selector);if(!element)throw Error('missing motion component '+selector);const s=getComputedStyle(element);return [selector,s.animationDuration,s.transitionDuration];}));
  for(const [selector,...values]of durations)for(const value of values)for(const duration of value.split(','))if(parseFloat(duration)>.18)throw Error('slow interface motion '+selector+': '+value);
  if(!durations.some(([,animation])=>parseFloat(animation)>0))throw Error('normal motion was not enabled');
  await page.keyboard.press('Escape');await page.waitForSelector('#delete-dialog',{state:'hidden'});
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.locator('.delete-btn').first().click();
  const reduced=await page.evaluate(()=>['.main','.dialog[open]','.notice-toast'].map(s=>getComputedStyle(document.querySelector(s)).animationName));
  if(reduced.some(name=>name!=='none'))throw Error('reduced motion ignored');
  await page.keyboard.press('Escape');
 });
 await drain(page,'theme');await drain(peer,'theme peer');await page.close();await peer.close();
}
for(const [name,path]of[['index','/'],['scan','/scan/f0000002'],['report','/report/f0000007'],['summary','/summary/f0000007'],['disclosure','/disclosure/f0000007/DISCLOSURE_01_FIXTURE.md']]){
 const {page}=await visit('dark-'+name,path);
 await ready(page,'dark '+name,async()=>{
  if(await page.locator('html').getAttribute('data-bs-theme')!=='dark')throw Error('missing shared dark theme');
  if(name==='report'){await page.locator('#finding-expand').click();await page.locator('#remediation > details > summary').click();}
  await checkContrast(page,'dark '+name,['body','h1','h2','h3','p','a','label','input','select','code','.btn','.hint','.meta','.badge','.status-pill','.findings-table th','.report-toc a','.remediation-content blockquote','.remediation-content td','.code-toolbar button','.code-lines','.hljs-comment','footer']);
  const aligned=await page.locator('footer').evaluate(footer=>{const range=document.createRange();range.selectNodeContents(footer.querySelector('span')||footer);return Math.abs(range.getBoundingClientRect().right-footer.getBoundingClientRect().right)<3;});
  if(!aligned)throw Error('footer brand is not aligned right');
  if(name==='report'){
   await page.locator('[data-theme-toggle]').click();await page.locator('[data-theme-toggle]').click();
   const borders=await page.evaluate(()=>['unitChart','fileChart'].map(id=>Chart.getChart(id).data.datasets[0].borderColor));
   const paper=await page.evaluate(()=>getComputedStyle(document.documentElement).getPropertyValue('--paper').trim());
   if(borders.some(color=>color!==paper))throw Error('chart border did not follow theme');
  }
 });
 await drain(page,'dark-'+name);await page.close();
}
// Destructive action feedback uses only intercepted requests: no seeded or
// real task is deleted. Exercise pending, cleanup conflict, retry and success.
{
 const page=await context.newPage();let requests=0,releaseFirst;
 const firstResponse=new Promise(resolve=>{releaseFirst=resolve;});
 page.on('pageerror',e=>note('interaction feedback',e.message));
 await page.emulateMedia({reducedMotion:'no-preference'});await page.setViewportSize({width:1440,height:1000});
 await page.route('**/scan/f0000007',async route=>{
  if(route.request().method()!=='DELETE'){await route.continue();return;}
  requests++;if(requests===1){await firstResponse;await route.fulfill({status:409,body:'任务仍在清理'});}
  else await route.fulfill({status:204,body:''});
 });
 await ready(page,'action components',async()=>{
  await page.goto(baseURL+'/',{waitUntil:'domcontentloaded'});
  const total=await page.locator('.scan-row').count(),button=page.locator('#row-f0000007 .delete-btn');
  const nextFocus=await button.evaluate(button=>{const rows=[...document.querySelectorAll('.scan-row:not([hidden])')],position=rows.indexOf(button.closest('.scan-row'));return (rows[position+1]||rows[position-1])?.id||'';});
  await button.click();
  if(!await page.locator('#delete-dismiss').evaluate(e=>e===document.activeElement))throw Error('delete dialog does not focus the safe action');
  if(!await page.locator('#delete-target').innerText()||await page.locator('#delete-job-id').innerText()!=='f0000007')throw Error('delete target not identified');
  for(const width of [1440,360]){await page.setViewportSize({width,height:1000});if(screenshotDir)await page.screenshot({path:`${screenshotDir}/delete-dialog-dark-${width}.png`});if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1))throw Error('delete dialog overflow');}
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#delete-confirm').click();
  await page.waitForFunction(()=>document.getElementById('delete-dialog').getAttribute('aria-busy')==='true');
  if(!await page.locator('#delete-confirm').isDisabled()||!await page.locator('#delete-dismiss').isDisabled())throw Error('repeat deletion is enabled while pending');
  await page.keyboard.press('Escape');if(!await page.locator('#delete-dialog').isVisible())throw Error('pending deletion lost its feedback');
  await page.locator('#delete-confirm').evaluate(e=>e.click());
  if(requests!==1||await page.locator('.scan-row').count()!==total)throw Error('pending delete repeated or removed a row early');
  releaseFirst();await page.waitForFunction(()=>document.getElementById('delete-feedback').textContent.includes('清理'));
  if(!await page.locator('#delete-dialog').isVisible()||await page.locator('#delete-confirm').isDisabled())throw Error('cleanup failure has no retry in dialog');
  if(screenshotDir)await page.screenshot({path:`${screenshotDir}/delete-retry-dark.png`});
  const scrollBefore=await page.evaluate(()=>scrollY);
  await page.locator('#delete-confirm').click();await page.waitForSelector('#delete-dialog',{state:'hidden'});
  await page.waitForFunction(()=>[...document.querySelectorAll('.notice-message')].some(e=>e.textContent==='扫描及其结果已删除。'));
  if(requests!==2||await page.locator('.scan-row').count()!==total-1||await page.locator('#stat-total').innerText()!==String(total-1))throw Error('successful delete did not update list and count');
  const focusResult=await page.evaluate(()=>({row:document.activeElement.closest('.scan-row')?.id||'',query:document.activeElement.id==='job-query'}));
  if(nextFocus?focusResult.row!==nextFocus:!focusResult.query)throw Error('delete completion lost focus on the neighboring task');
  if(Math.abs(await page.evaluate(()=>scrollY)-scrollBefore)>250)throw Error('delete completion jumped away from the current task');
  await page.evaluate(()=>scrollTo(0,0));
  if(screenshotDir)await page.screenshot({path:`${screenshotDir}/delete-success-dark.png`});
  const copy=page.locator('.copy-btn').first();await copy.click();
  const copied=page.locator('.notice-toast').filter({hasText:'仓库地址已复制。'});
  await copied.locator('.notice-close').focus();await page.waitForTimeout(3200);
  if(!await copied.isVisible())throw Error('notification expired while keyboard focus was inside');
  await page.keyboard.press('Escape');await copied.waitFor({state:'detached'});
  if(!await copy.evaluate(e=>e===document.activeElement))throw Error('closing notification lost action focus');
  await page.evaluate(()=>{for(let i=0;i<10;i++)VulscanUI.notify('重复提示');});
  if(await page.locator('.notice-toast').filter({hasText:'重复提示'}).count()!==1)throw Error('repeated feedback was not deduplicated');
  await page.evaluate(()=>{for(let i=0;i<8;i++)VulscanUI.notify('提示 '+i);});
  if(await page.locator('.notice-toast').count()>3)throw Error('feedback DOM is unbounded');
  await page.evaluate(()=>VulscanUI.notify('<img src=x onerror=alert(1)>',{tone:'error'}));
  if(await page.locator('#notice-stack img,#notice-stack script').count()||!await page.locator('#notice-stack').innerText().then(t=>t.includes('<img')))throw Error('feedback treated message as HTML');
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.locator('[data-theme-toggle]').click();
  await page.locator('.delete-btn').first().click();
  if(screenshotDir)await page.screenshot({path:`${screenshotDir}/delete-dialog-light.png`});
  await page.mouse.click(3,3);await page.waitForSelector('#delete-dialog',{state:'hidden'});
  await page.locator('[data-theme-toggle]').click();
 });
 releaseFirst();await drain(page,'action components');await page.close();
}
// Restricted local storage must not break an offline report or its toggle.
{
 const page=await context.newPage();page.on('pageerror',e=>note('theme storage unavailable',e.message));
 await page.addInitScript(()=>Object.defineProperty(window,'localStorage',{get(){throw new DOMException('blocked','SecurityError');}}));
 await ready(page,'theme storage unavailable',async()=>{
  await page.goto(baseURL+'/summary/f0000007',{waitUntil:'domcontentloaded'});
  if(await page.locator('html').getAttribute('data-bs-theme')!=='light')throw Error('blocked storage changed default');
  await page.locator('[data-theme-toggle]').click();
  if(await page.locator('html').getAttribute('data-bs-theme')!=='dark')throw Error('toggle depends on storage permission');
 });
 await drain(page,'theme storage unavailable');await page.close();
}
if(screenshotDir){
 for(const name of ['offline-report.html','offline-overview.html']){
  const page=await context.newPage();page.on('pageerror',e=>note(name,e.message));
  await ready(page,name,async()=>{await page.goto(pathToFileURL(`${screenshotDir}/${name}`).href);await page.waitForFunction(()=>typeof Chart==='function'&&!!document.querySelector('.code-reader'));await page.fill('#finding-query','CWE-120');if(await page.locator('details[id^="finding-"]:visible').count()!==1)throw Error('offline search failed');await page.locator('#finding-expand').click();const code=page.locator('.code-reader').first();const original=await code.locator('code').textContent();await code.getByRole('button',{name:'复制代码原文',exact:true}).click();if(await page.evaluate(()=>navigator.clipboard.readText())!==original)throw Error('offline copy changed code');await waitCharts(page);await page.screenshot({path:`${screenshotDir}/${name}.png`,fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1))throw Error('offline report overflow');const before=await page.locator('html').getAttribute('data-bs-theme');await page.locator('[data-theme-toggle]').click();if(await page.locator('html').getAttribute('data-bs-theme')===before)throw Error('offline theme toggle did not work');await checkContrast(page,'offline theme',['.report-toc a','.hint','.status-pill','.code-toolbar button']);await page.screenshot({path:`${screenshotDir}/${name}-alternate-theme.png`,fullPage:true});});
  await drain(page,name);await page.close();
 }
}

// Real desktop page zoom: chrome.tabs.setZoom changes both the CSS viewport
// and DPR. CSS body zoom and mobile/pinch emulation do not test this contract.
{
 const root=mkdtempSync(join(tmpdir(),'vulscan-browser-zoom-')),extension=join(root,'extension');mkdirSync(extension);
 writeFileSync(join(extension,'manifest.json'),JSON.stringify({manifest_version:3,name:'Local UI zoom fixture',version:'1.0',permissions:['tabs'],background:{service_worker:'zoom.js'}}));
 writeFileSync(join(extension,'zoom.js'),'chrome.runtime.onInstalled.addListener(()=>{});');
 let zoomContext;
 try{
  zoomContext=await chromium.launchPersistentContext(join(root,'profile'),{...launchOpts,ignoreDefaultArgs:['--disable-extensions'],args:['--headless=new','--disable-extensions-except='+extension,'--load-extension='+extension],viewport:{width:1440,height:1000},reducedMotion:'reduce'});
  zoomContext.on('request',request=>{const u=new URL(request.url());if(['http:','https:'].includes(u.protocol)&&u.origin!==origin)note('zoom','unexpected external request '+u.href);});
  await zoomContext.addInitScript(()=>{Date.now=()=>new Date('2026-10-25T08:10:00Z').getTime();window.__violations=[];addEventListener('securitypolicyviolation',e=>window.__violations.push(`${e.violatedDirective} blocked=${e.blockedURI} at ${e.sourceFile||''}:${e.lineNumber}`));});
  const worker=zoomContext.serviceWorkers()[0]||await zoomContext.waitForEvent('serviceworker');
  for(const[name,path]of[['index','/'],['scan','/scan/f0000002'],['report','/report/f0000007'],['summary','/summary/f0000007'],['disclosure','/disclosure/f0000007/DISCLOSURE_01_FIXTURE.md']]){
   const page=await zoomContext.newPage();page.on('pageerror',e=>note('zoom-'+name,e.message));
   await ready(page,'zoom-'+name,async()=>{
    await page.goto(baseURL+path,{waitUntil:'domcontentloaded'});
    await worker.evaluate(async url=>{const tab=(await chrome.tabs.query({})).find(t=>t.url===url);await chrome.tabs.setZoom(tab.id,2);if(await chrome.tabs.getZoom(tab.id)!==2)throw Error('native zoom not applied');},page.url());
    await page.waitForFunction(()=>devicePixelRatio===2&&innerWidth===720&&getComputedStyle(document.body).zoom==='1');
    if(name==='scan')await page.waitForFunction(()=>document.getElementById('count-candidates').textContent==='6');
    if(['summary','disclosure'].includes(name))await page.waitForSelector('.code-reader');
    await page.evaluate(()=>document.fonts.ready);await settleLayout(page);if(name==='report')await waitCharts(page);
    if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1))throw Error('native 200% overflow '+JSON.stringify(await overflowDetails(page)));
    await checkContrast(page,'zoom '+name,['.meta','.hint','.status-pill','.badge','.summary-stat span']);
    if(screenshotDir)await page.screenshot({path:`${screenshotDir}/${name}-zoom-200.png`,fullPage:true});
    await page.keyboard.press('Tab');if(!await page.evaluate(()=>document.activeElement!==document.body&&document.activeElement.getBoundingClientRect().width>0))throw Error('keyboard focus unavailable at 200%');
    await page.locator('[data-theme-toggle]').click();await page.locator('.notice-close').click();
    if(await page.locator('html').getAttribute('data-bs-theme')!=='dark')throw Error('dark theme at 200%');
    await checkContrast(page,'dark zoom '+name,['.meta','.hint','.status-pill','.badge','.summary-stat span']);
    if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1))throw Error('dark native 200% overflow');
    if(screenshotDir)await page.screenshot({path:`${screenshotDir}/${name}-dark-zoom-200.png`,fullPage:true});
    await page.locator('[data-theme-toggle]').click();
   });
   await drain(page,'zoom-'+name);await page.close();
  }
 }catch(e){note('native zoom',e.message);}finally{if(zoomContext)await zoomContext.close();rmSync(root,{recursive:true,force:true});}
}

if(process.env.VULSCAN_REVIEW_SOURCE_DIR){
 const id=basename(process.env.VULSCAN_REVIEW_SOURCE_DIR);
 const {page}=await visit('current-scan','/scan/'+id);
 await ready(page,'current candidate 4',async()=>{
  await page.locator('#tab-findings').click();
  for(const width of [1440,1920,768,360]){
   await page.setViewportSize({width,height:1000});await settleLayout(page);
   if(screenshotDir)await page.screenshot({path:`${screenshotDir}/current-findings-${width}.png`,fullPage:true});
  }
  await page.locator('#finding-rows tr[data-finding-id="main.py:jwtmain"] .finding-title').click();
  for(const width of [1440,1920,768,360]){
   await page.setViewportSize({width,height:1000});await settleLayout(page);
   const size=await page.locator('#finding-dialog').evaluate(d=>({client:d.clientWidth,scroll:d.scrollWidth,left:d.scrollLeft}));
   if(size.scroll>size.client+1||size.left>1)throw Error('real candidate overflows '+JSON.stringify(size));
   if(screenshotDir)await page.screenshot({path:`${screenshotDir}/current-candidate-4-${width}.png`,fullPage:false});
  }
  if(await page.locator('#finding-title').innerText()!=='jwtmain')throw Error('real payload became the heading');
 });
 await drain(page,'current-scan');await page.close();
 const report=await visit('current-report','/report/'+id);await waitCharts(report.page);
 await report.page.locator('#pipeline > details > summary').click();
 await checkContrast(report.page,'current report',['.report-toc strong','.report-finding-title','.report-verification strong','.hint','#pipeline td']);
 if(screenshotDir){const html=await(await context.request.get(baseURL+'/report/'+id)).text();writeFileSync(join(screenshotDir,'current-report.html'),html);}
 await drain(report.page,'current-report');await report.page.close();
}

if (update && failures.length === 0) {
  writeFileSync(goldenPath, summaryHTML + '\n');
  console.log('GOLDEN UPDATED: ' + goldenPath);
} else if (update) {
  note('summary', 'update mode declined: the run had failures (the golden was NOT clobbered)');
} else {
  const expected = readFileSync(goldenPath, 'utf8');
  if (summaryHTML + '\n' !== expected && summaryHTML !== expected.trim()) {
    note('summary', 'golden mismatch — ACTUAL #content innerHTML follows:');
    console.log('--- ACTUAL #content innerHTML ---');
    console.log(summaryHTML);
    console.log('--- END ACTUAL ---');
  }
}

await browser.close();

// Late violations from any page (the listener ran in every page).
// Re-check: the pages are closed; violations were per-page. We aggregate
// them at close time by reading before close — done implicitly above via
// the per-page note path. Any __violations content was already collected.

if (failures.length > 0) {
  console.error('BROWSER-SMOKE FAILURES (' + failures.length + '):');
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log(`BROWSER-SMOKE OK: 5 page types, 9 job fixtures, light/dark, action feedback, motion, native 200% zoom, offline reports; ${violationsSeen} unexpected violations` +
  ` (+${dompurifyProbeBlocked} known-blocked DOMPurify self-test probes), canaries clean` +
  (update ? '' : ', golden matched'));
