(() => {
  'use strict';
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
