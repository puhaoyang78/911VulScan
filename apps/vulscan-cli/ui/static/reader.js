/* Trusted code reader. Untrusted source enters the DOM only through textContent. */
(() => {
 'use strict';
 const originals=new WeakMap();
 const make=(tag,label,cls)=>{const n=document.createElement(tag);if(label!==undefined)n.textContent=label;if(cls)n.className=cls;return n;};
 const languages={c:'c',h:'c',cpp:'cpp',cc:'cpp',cxx:'cpp',hpp:'cpp',py:'python',python:'python',js:'javascript',javascript:'javascript',go:'go',sh:'bash',shell:'bash',bash:'bash',json:'json'};
 const MD_SANITIZE = {
  ALLOWED_TAGS: ['h1','h2','h3','h4','h5','h6','p','br','hr','blockquote',
    'ul','ol','li','pre','code','em','strong','del','a','span','div',
    'table','thead','tbody','tr','th','td','sup','sub','kbd'],
  ALLOWED_ATTR: ['href','title','class','align','colspan','rowspan'],
  FORBID_TAGS: ['style','form','input','button','textarea','select','option',
    'img','picture','source','svg','math','iframe','object','embed','link','base','meta','script'],
  FORBID_ATTR: ['style','src','srcset','action','formaction','background','poster','loading'],
  ALLOW_DATA_ATTR: false
};
 function markdown(root,source){
  root.innerHTML=DOMPurify.sanitize(marked.parse(String(source)),MD_SANITIZE);
  root.querySelectorAll('table').forEach(table=>{const wrap=make('div',undefined,'table-wrap');table.replaceWith(wrap);wrap.append(table);});
  enhance(root);
 }
 async function copy(text,button){try{await navigator.clipboard.writeText(text);button.textContent='已复制';VulscanUI.notify('代码原文已复制。',{button});setTimeout(()=>{button.textContent='复制';},1500);}catch(_){button.textContent='复制失败，请选择原文';VulscanUI.notify('复制失败，请选择代码原文后复制。',{tone:'error',button});}}
 function enhance(root){
  root.querySelectorAll('pre').forEach(pre=>{
   if(pre.closest('.code-reader'))return;
   let code=pre.querySelector('code');if(!code){code=make('code',pre.textContent);pre.replaceChildren(code);}
   const original=code.textContent;originals.set(code,original);
   const specified=code.className.match(/(?:^|\s)language-([^\s]+)/)?.[1]?.toLowerCase();
   const file=code.dataset.file||pre.dataset.file||'';
   const ext=file.split('.').pop()?.toLowerCase();const lang=languages[specified]||(!specified&&languages[ext])||'';
   code.textContent=original;code.className=lang?'language-'+lang:'language-plaintext';
   if(lang&&globalThis.hljs?.getLanguage(lang))globalThis.hljs.highlightElement(code);
   const box=make('div',undefined,'code-reader'),toolbar=make('div',undefined,'code-toolbar');
   const lineStart=Number(code.dataset.startLine||pre.dataset.startLine);const source=Number.isSafeInteger(lineStart)&&lineStart>0;
   const count=original.split('\n').length;const start=source?lineStart:1;
   toolbar.append(make('span',(lang||'纯文本')+(file?' · '+file:'')+' · '+(source?'源码行号':'片段行号'),'code-label'));
   const copyButton=make('button','复制');copyButton.type='button';copyButton.setAttribute('aria-label','复制代码原文');copyButton.addEventListener('click',()=>copy(originals.get(code),copyButton));
   const wrap=make('button','换行：关');wrap.type='button';wrap.setAttribute('aria-pressed','false');wrap.addEventListener('click',()=>{const on=box.classList.toggle('is-wrapped');wrap.textContent=on?'换行：开':'换行：关';wrap.setAttribute('aria-pressed',String(on));});
   toolbar.append(copyButton,wrap);
   if(count>20||original.length>3500){box.classList.add('is-collapsed');const expand=make('button','展开长代码');expand.type='button';expand.setAttribute('aria-expanded','false');expand.addEventListener('click',()=>{const collapsed=box.classList.toggle('is-collapsed');expand.textContent=collapsed?'展开长代码':'折叠长代码';expand.setAttribute('aria-expanded',String(!collapsed));});toolbar.append(expand);}
   const viewport=make('div',undefined,'code-viewport');viewport.tabIndex=0;viewport.setAttribute('aria-label',(lang||'纯文本')+'代码，可横向滚动');const numbers=make('div',Array.from({length:count},(_,i)=>start+i).join('\n'),'code-lines');numbers.setAttribute('aria-hidden','true');
   pre.replaceWith(box);box.append(toolbar,viewport);viewport.append(numbers,pre);
  });
 }
 function toc(root,target){
  target.replaceChildren();target.append(make('h2','本页目录'));
  root.querySelectorAll('h1,h2,h3').forEach((h,i)=>{h.id='section-'+i;const a=make('a',h.textContent);a.href='#'+h.id;a.dataset.level=h.tagName.slice(1);target.append(a);});
  if(target.children.length===1)target.append(make('p','本文未提供章节标题。','hint'));
 }
 globalThis.VulscanReader={enhance,markdown,toc,copy,original:code=>originals.get(code)};
})();
