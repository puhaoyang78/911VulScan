import {chromium} from 'playwright';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';

const [base, bootstrap] = process.argv.slice(2);
const launch = process.env.VULSCAN_BROWSER_EXECUTABLE ? {executablePath:process.env.VULSCAN_BROWSER_EXECUTABLE}
  : process.env.VULSCAN_BROWSER_CHANNEL ? {channel:process.env.VULSCAN_BROWSER_CHANNEL} : {};
const browser = await chromium.launch(launch);
const errors = [];
const contexts = [];
const password = 'Browser-test-password-2026';
async function context() {
  const ctx = await browser.newContext({reducedMotion:'reduce'});
  contexts.push(ctx);
  ctx.on('page', page => {
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (/Refused to|Content Security Policy/i.test(message.text())) errors.push(message.text()); });
  });
  ctx.on('request', req => {const u=new URL(req.url()); if (['http:','https:'].includes(u.protocol) && u.origin!==new URL(base).origin) errors.push('external network: '+u.href);});
  await ctx.addInitScript(() => {
    window.__violations=[];
    document.addEventListener('securitypolicyviolation', event => window.__violations.push(event.violatedDirective));
  });
  return ctx;
}
async function visit(page,path) {
  const response = await page.goto(base+path);
  if (!response.ok() || !response.headers()['content-security-policy']?.includes("script-src 'self' 'nonce-")) throw new Error('Page/CSP failure '+path);
}
async function register(page,name,mode='/register') {
  await visit(page,mode);
  if (mode==='/setup') await page.getByLabel('初始化口令',{exact:true}).fill(bootstrap);
  await page.getByLabel('账号',{exact:true}).fill(name);
  await page.getByLabel('密码',{exact:true}).fill(password);
  await page.getByLabel('确认密码',{exact:true}).fill(password);
  const invalid=await page.locator('form').evaluate(form=>[...form.elements].filter(el=>el.willValidate&&!el.checkValidity()).map(el=>({name:el.name,message:el.validationMessage})));
  if(invalid.length) throw new Error('Form validation: '+JSON.stringify(invalid));
  try { await Promise.all([page.waitForURL(base+'/'),page.getByRole('button',{name:mode==='/setup'?'创建管理员':'注册并登录',exact:true}).click()]); } catch(error) { console.error(page.url(),await page.locator('body').innerText()); throw error; }
  await page.locator('[data-account-nav] .account-name').filter({hasText:name}).waitFor();
}
async function noOverflow(page) {
  const widths=await page.evaluate(()=>({body:document.documentElement.scrollWidth,window:innerWidth,violations:window.__violations}));
  if (widths.body>widths.window+1 || widths.violations.length) throw new Error('Overflow/CSP: '+JSON.stringify(widths));
}
try {
  const admin=await context(); const p0=await admin.newPage();
  await register(p0,'browser-admin','/setup');
  if (!await p0.getByText('legacy-private-browser-project',{exact:true}).count()) throw new Error('Legacy task missing for admin');
  const alice=await context(); const a=await alice.newPage();
  const bob=await context(); const b=await bob.newPage();
  await Promise.all([register(a,'browser-alice'),register(b,'browser-bob')]);
  for (const page of [a,b]) {
    if (await page.getByText('legacy-private-browser-project',{exact:true}).count()) throw new Error('Legacy leak');
    await page.getByRole('navigation',{name:'账号',exact:true}).getByRole('link',{name:'用户设置',exact:true}).click();
    await page.getByRole('heading',{name:'用户设置',exact:true}).waitFor();
    await page.getByLabel('API 密钥',{exact:true}).fill(page===a?'browser-alice-key':'browser-bob-key');
    await Promise.all([page.waitForURL('**/settings?saved=1'),page.getByRole('button',{name:'保存模型配置',exact:true}).click()]);
    await page.getByText('已保存密钥',{exact:true}).waitFor();
    const html=await page.content();
    if (html.includes('browser-alice-key') || html.includes('browser-bob-key')) throw new Error('Secret rendered');
    await page.reload();
    if (await page.getByLabel('API 密钥',{exact:true}).inputValue()!=='') throw new Error('Key filled back into form');
  }
  // Both authenticated contexts remain usable; persisted cookies also work in
  // a fresh browser context without passing a password to the server again.
  const saved=await alice.storageState();
  const restored=await browser.newContext({storageState:saved});contexts.push(restored);
  const r=await restored.newPage();await r.goto(base+'/');
  await r.locator('[data-account-nav] .account-name').filter({hasText:'browser-alice'}).waitFor();
  if (await r.getByText('legacy-private-browser-project',{exact:true}).count()) throw new Error('Restore leak');
  const capture=process.env.VULSCAN_SCREENSHOTS;
  if (capture) mkdirSync(capture,{recursive:true});
  for (const width of [1920,1440,768,360]) {
    await a.setViewportSize({width,height:900});
    await a.goto(base+'/settings');await a.locator('[data-account-nav] .account-name').waitFor({state:width<=768?'attached':'visible'});
    await noOverflow(a);
    if (capture) await a.screenshot({path:join(capture,`accounts-settings-${width}.png`),fullPage:true});
    await a.getByRole('button',{name:'深色主题',exact:true}).click();await noOverflow(a);
    if (capture && width===1440) await a.screenshot({path:join(capture,'accounts-settings-dark.png'),fullPage:true});
    await a.getByRole('button',{name:'深色主题',exact:true}).click();
  }
  await a.setViewportSize({width:1440,height:900});
  await a.getByLabel('当前密码',{exact:true}).fill(password);
  await a.getByLabel('新密码',{exact:true}).fill('Updated-browser-password-2026');
  const confirm=a.getByLabel('确认新密码',{exact:true});await confirm.fill('Wrong-confirm-password');
  if (await confirm.evaluate(el=>el.checkValidity())) throw new Error('Confirmation mismatch accepted');
  await confirm.fill('Updated-browser-password-2026');
  await a.getByRole('button',{name:'更新密码',exact:true}).click();
  await a.getByRole('status').filter({hasText:'密码已更新'}).first().waitFor();
  await a.getByRole('button',{name:'退出',exact:true}).click();await a.waitForURL('**/login');
  await b.reload();await b.locator('[data-account-nav] .account-name').filter({hasText:'browser-bob'}).waitFor();
  await a.setViewportSize({width:360,height:900});await noOverflow(a);
  if (capture) await a.screenshot({path:join(capture,'accounts-login-360.png'),fullPage:true});
  // Keyboard form navigation and real sign-in after password change.
  await a.getByLabel('账号',{exact:true}).fill('browser-alice');
  await a.getByLabel('账号',{exact:true}).press('Tab');
  if (!await a.getByLabel('密码',{exact:true}).evaluate(el=>el===document.activeElement)) throw new Error('Keyboard focus order');
  await a.getByLabel('密码',{exact:true}).fill('Updated-browser-password-2026');
  await a.getByRole('button',{name:'登录',exact:true}).click();await a.waitForURL(base+'/');await noOverflow(a);
  if (errors.length) throw new Error(errors.join('\n'));
  console.log('ACCOUNTS-BROWSER OK: real setup/register/login/logout, two contexts, persistent cookies, isolated model settings, password confirmation/change, 4 viewport widths, light/dark, keyboard, 0 CSP/external-network errors');
} finally {for (const ctx of contexts) await ctx.close();await browser.close();}
