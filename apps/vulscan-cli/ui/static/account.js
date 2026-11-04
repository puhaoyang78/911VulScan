(() => {
  'use strict';
  // API credentials are not sign-in passwords. The input uses new-password,
  // and only presence/source information is reflected in the status component.
  document.querySelectorAll('[data-key-field]').forEach(field => {
    const input = field.querySelector('[data-secret]');
    const status = field.querySelector('[data-key-status]');
    const settings = field.dataset.keyContext === 'settings';
    const provider = settings ? document.getElementById('settings-provider') : document.getElementById('provider');
    const clear = field.querySelector('[data-clear-key]');
    const savedProvider = () => [...document.querySelectorAll('[data-provider]')].find(item => item.dataset.provider === provider.value);
    function update() {
      const saved = settings ? savedProvider()?.dataset.hasKey === 'true' : field.dataset.savedKey === 'true';
      const clearing = clear?.checked === true;
      const entered = input.value.trim() !== '';
      input.required = !saved && !clearing;
      if (settings) input.disabled = clearing;
      const state = clearing ? 'clearing' : entered ? 'entered' : saved ? 'saved' : 'missing';
      status.dataset.state = state;
      status.textContent = clearing ? '保存后清除' : entered ? (settings ? '已填写 · 待保存' : '已填写 · 本次扫描') : saved ? '已配置 · 个人设置' : '未配置';
      input.placeholder = saved ? '已保存密钥，留空使用' : '填写该服务商的 API 密钥';
    }
    input.addEventListener('input', update);
    input.addEventListener('change', update);
    provider?.addEventListener('change', () => {
      if (settings) {
        input.value = ''; clear.checked = false;
        document.getElementById('settings-url').value = savedProvider()?.dataset.baseUrl || '';
      }
      update();
    });
    clear?.addEventListener('change', () => { if (clear.checked) input.value = ''; update(); });
    window.addEventListener('pageshow', () => { input.value = ''; update(); });
    if (settings) document.getElementById('settings-url').value = savedProvider()?.dataset.baseUrl || '';
    update();
  });
  const nativeFetch = window.fetch.bind(window);
  const login = () => location.assign('/login?next=' + encodeURIComponent(location.pathname + location.search));
  document.querySelectorAll('[data-account-form]').forEach(form => {
    const confirmation = form.querySelector('[data-password-confirm]');
    if (confirmation) {
      const password = document.getElementById(confirmation.dataset.passwordConfirm);
      const validate = () => confirmation.setCustomValidity(confirmation.value === password.value ? '' : '两次输入的密码不一致。');
      confirmation.addEventListener('input', validate); password.addEventListener('input', validate);
    }
    form.addEventListener('submit', () => {
      const button = form.querySelector('[type=submit]');
      button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = '正在提交…';
    });
  });
  const nav = document.querySelector('[data-account-nav]');
  if (!nav) return;
  nav.classList.add('account-nav');
  // Fetches and long-lived SSE use the same server-side session. A 401 means
  // sign-in is required; a lost network connection never means a job failed.
  window.fetch = async (...args) => {
    const response = await nativeFetch(...args);
    if (response.status === 401) login();
    return response;
  };
  let csrf = '';
  async function account(initial = false) {
    try {
      const response = await nativeFetch('/account', {cache:'no-store'});
      if (response.status === 401) { login(); return; }
      if (!response.ok) return;
      const data = await response.json(); csrf = data.csrf;
      if (!initial) return;
      const name = document.createElement('span'); name.className = 'account-name'; name.textContent = data.username;
      const settings = document.createElement('a'); settings.className = 'btn'; settings.href = '/settings'; settings.textContent = '用户设置';
      const logout = document.createElement('button'); logout.className = 'btn'; logout.type = 'button'; logout.textContent = '退出';
      logout.addEventListener('click', async () => {
        logout.disabled = true; logout.setAttribute('aria-busy','true');
        try {
          const response = await nativeFetch('/logout', {method:'POST',headers:{'X-CSRF-Token':csrf}});
          if (response.ok || response.status === 401) { location.assign('/login'); return; }
          throw new Error('退出失败，请重试。');
        } catch (error) { VulscanUI.notify(error.message,{tone:'error',button:logout}); logout.disabled=false; logout.removeAttribute('aria-busy'); }
      });
      nav.replaceChildren(name,settings,logout);
    } catch (_) { /* Connection recovery is handled by each page. */ }
  }
  account(true);
  setInterval(() => { if (!document.hidden) account(); }, 30000);
  window.addEventListener('focus', () => account());
  const feedback = document.querySelector('[data-save-feedback]');
  if (feedback) VulscanUI.notify(feedback.textContent,{id:'settings-saved'});
})();
