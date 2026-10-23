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
import { readFileSync, writeFileSync } from 'node:fs';
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
const launchOpts = process.env.VULSCAN_BROWSER_CHANNEL
  ? { channel: process.env.VULSCAN_BROWSER_CHANNEL }
  : {};
const browser = await chromium.launch(launchOpts);
const context = await browser.newContext();
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
let violationsSeen = 0;
const note = (page, msg) => failures.push(`[${page}] ${msg}`);

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

const ready = async (page, name, fn) => { try { await fn(); } catch (e) { note(name, `readiness: ${e.message.split('\n')[0]}`); } };

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
  await ready(page, 'scan', () => page.waitForSelector('#btn-summary.ready'));
  await ready(page, 'scan', () => page.waitForFunction(
    () => document.querySelectorAll('#disclosure-links a').length >= 1));
  await ready(page, 'scan', () => page.waitForFunction(
    () => document.getElementById('status-text').dataset.state === 'done'));
  await ready(page, 'scan', async () => {
    if (!(await page.locator('#scan-timeout-budget').innerText()).includes('未记录（旧任务）')) throw new Error('legacy scan budget misrepresented');
    if (!(await page.locator('#overview-panel').isVisible())) throw new Error('overview is not the default');
    await page.getByRole('tab', {name:'详细日志'}).click();
    if (!(await page.locator('#terminal-panel').isVisible())) throw new Error('terminal tab did not open');
    await page.getByRole('tab', {name:'详细日志'}).press('ArrowLeft');
    if (!(await page.locator('#overview-panel').isVisible())) throw new Error('keyboard tab switch failed');
    if (!(await page.locator('#btn-cancel').isDisabled())) throw new Error('completed scan can still be cancelled');
    const result = await page.evaluate(() => {
      const line='11:22:33 [Enhance] 94/987 source.c::tc_error neutral 7.5s (elapsed 3m11s, ETA ~30m23s, $0.0064)';
      extractProgress(line);
      extractProgress('[Enhance] 95/987 <img src=x onerror=alert(1)> neutral (elapsed 3m12s, ETA ~30m0s, $0)');
      return {severity:classifyLine(line), warning:classifyLine('WARNING: failed'), count:document.getElementById('overview-count').textContent, injected:document.querySelector('#overview-task img')!==null};
    });
    if (result.severity!=='progress'||result.warning!=='warning'||result.count!=='95 / 987'||result.injected) throw new Error('progress/severity/XSS regression');
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
      constructor(){window.testStream=this;this.handlers={};setTimeout(()=>this.onopen?.(),0);}
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
      testStream.onmessage({lastEventId:'0',data:'[Enhance] 1/2 source.c::tc_error neutral (elapsed 1s, ETA ~1s, $0)'});
      testStream.onmessage({lastEventId:'0',data:'duplicate'});
      testStream.readyState=EventSource.CONNECTING;testStream.onerror();
    });
    if (await page.locator('.log-line').count()!==1) throw new Error('replay duplicated log');
    if (await page.locator('#status-text').getAttribute('data-state')!=='reconnecting') throw new Error('reconnect state missing');
    page.once('dialog', dialog=>dialog.dismiss()); await page.locator('#btn-cancel').click();
    if(requests!==0) throw new Error('dismissed confirmation submitted');
    page.once('dialog', dialog=>dialog.accept()); await page.locator('#btn-cancel').click();
    await page.waitForFunction(()=>document.getElementById('status-text').dataset.state==='cancelling');
    if (!(await page.locator('#btn-cancel').isDisabled())) throw new Error('repeat cancel enabled');
    await page.evaluate(()=>{testStream.onopen();testStream.onmessage({lastEventId:'1',data:'final log'});testStream.handlers.done({data:'cancelled'});});
    await page.waitForFunction(()=>document.getElementById('status-text').dataset.state==='cancelled');
    if(requests!==1 || await page.locator('.log-line').count()!==2) throw new Error('cancel request/log preservation regression');
  });
  await drain(page,'scan-cancel'); await page.close();
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
console.log(`BROWSER-SMOKE OK: 5 pages, ${violationsSeen} unexpected violations` +
  ` (+${dompurifyProbeBlocked} known-blocked DOMPurify self-test styles), canaries clean` +
  (update ? '' : ', golden matched'));
