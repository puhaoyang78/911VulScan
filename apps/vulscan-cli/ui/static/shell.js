(() => {
  'use strict';
  const key = 'vulscan.theme';
  let theme = 'light';
  try {
    if (localStorage.getItem(key) === 'dark') theme = 'dark';
  } catch (_) { /* Storage may be unavailable when a report is opened locally. */ }

  function apply(value) {
    theme = value === 'dark' ? 'dark' : 'light';
    document.documentElement.dataset.bsTheme = theme;
    const next = theme === 'dark' ? '浅色' : '深色';
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.setAttribute('aria-pressed', String(theme === 'dark'));
      button.setAttribute('aria-label', '深色主题');
      button.title = '切换为' + next + '主题';
      button.querySelector('[data-theme-label]').textContent = '主题';
    });
    document.dispatchEvent(new CustomEvent('vulscan:themechange', {detail:{theme}}));
  }

  // Run before styles and body paint, including in a standalone file:// report.
  apply(theme);

  const buttonTimers = new WeakMap();
  const notices = new Map();
  function notify(message, {tone = 'success', button, id} = {}) {
    const kind = ['success','error','info'].includes(tone) ? tone : 'info';
    const key = id || kind + ':' + message;
    if (button) {
      clearTimeout(buttonTimers.get(button));
      button.dataset.feedback = kind;
      buttonTimers.set(button, setTimeout(() => delete button.dataset.feedback, 1800));
    }
    if (notices.has(key)) {
      const existing = notices.get(key);
      if (existing.message === String(message)) { existing.restart(); return; }
      existing.close(true);
    }
    let stack = document.getElementById('notice-stack');
    if (!stack) {
      stack = document.createElement('div'); stack.id = 'notice-stack';
      stack.className = 'notice-stack'; stack.setAttribute('role','region');
      stack.setAttribute('aria-label','操作提示'); document.body.append(stack);
    }
    const host = document.querySelector('dialog[open]') || document.body;
    if (stack.parentElement !== host) host.append(stack);
    if (notices.size >= 3) notices.values().next().value.close(true);
    const notice = document.createElement('div'); notice.className = 'notice-toast';
    notice.dataset.tone = kind; notice.setAttribute('role',kind === 'error' ? 'alert' : 'status');
    const icon = document.createElementNS('http://www.w3.org/2000/svg','svg');
    icon.setAttribute('viewBox','0 0 24 24'); icon.setAttribute('fill','none');
    icon.setAttribute('stroke','currentColor'); icon.setAttribute('stroke-width','1.8');
    icon.setAttribute('stroke-linecap','round'); icon.setAttribute('stroke-linejoin','round');
    icon.setAttribute('aria-hidden','true');
    const path = document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d',kind === 'success' ? 'M20 6 9 17l-5-5' : kind === 'error' ? 'M12 8v5m0 3h.01M12 3 2 21h20Z' : 'M12 11v6m0-10h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0');
    icon.append(path);
    const label = document.createElement('span'); label.className = 'notice-message';
    label.textContent = String(message);
    const dismiss = document.createElement('button'); dismiss.type = 'button';
    dismiss.className = 'notice-close'; dismiss.setAttribute('aria-label','关闭提示'); dismiss.textContent = '×';
    notice.append(icon,label,dismiss); stack.append(notice);
    let timer, closed = false;
    const pause = () => clearTimeout(timer);
    const close = (immediate = false) => {
      if (closed) return; closed = true; pause(); notices.delete(key);
      if (notice.contains(document.activeElement) && button?.isConnected && button.getClientRects().length) button.focus();
      notice.classList.add('is-leaving');
      if (immediate) notice.remove();
      else setTimeout(() => notice.remove(), matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 140);
    };
    const restart = () => {
      pause();
      if (!notice.matches(':hover') && !notice.contains(document.activeElement)) timer = setTimeout(close,kind === 'error' ? 6000 : 3000);
    };
    notices.set(key,{close,restart,message:String(message)}); restart();
    dismiss.addEventListener('click',() => close());
    notice.addEventListener('keydown', event => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
    });
    notice.addEventListener('mouseenter',pause); notice.addEventListener('mouseleave',restart);
    notice.addEventListener('focusin',pause); notice.addEventListener('focusout',() => requestAnimationFrame(restart));
  }
  globalThis.VulscanUI = {notify};
  document.addEventListener('DOMContentLoaded', () => {
    apply(theme);
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.addEventListener('click', () => {
        apply(theme === 'dark' ? 'light' : 'dark');
        try { localStorage.setItem(key, theme); } catch (_) { /* The toggle still works. */ }
        notify('已切换到' + (theme === 'dark' ? '深色' : '浅色') + '主题。',{tone:'info',button,id:'theme'});
      });
    });
    document.querySelectorAll('dialog.dialog').forEach(dialog => {
      dialog.addEventListener('close', () => {
        const stack = dialog.querySelector('#notice-stack');
        if (stack) document.body.append(stack);
      });
      dialog.addEventListener('click', event => {
        if (event.target !== dialog || dialog.getAttribute('aria-busy') === 'true') return;
        const box = dialog.getBoundingClientRect();
        if (event.clientX < box.left || event.clientX > box.right ||
            event.clientY < box.top || event.clientY > box.bottom) dialog.close();
      });
    });
    document.addEventListener('click', event => {
      const link = event.target.closest('a[download]');
      if (link && !event.defaultPrevented) notify('已开始下载' + (link.textContent.trim().includes('日志') ? '原始日志' : '文件') + '。',{tone:'info'});
    });
  });
  window.addEventListener('storage', event => {
    if (event.key === key || event.key === null) apply(event.newValue);
  });
})();
