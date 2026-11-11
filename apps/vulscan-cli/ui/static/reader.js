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
  readableReproduction(root);
  root.querySelectorAll('table').forEach(table=>{const wrap=make('div',undefined,'table-wrap');table.replaceWith(wrap);wrap.append(table);});
  enhance(root);
 }
 // Saved reports used to append command transcripts. Present their actual PoC
 // files with a short conclusion too; copying/downloading Markdown stays exact.
 function readableReproduction(root){
  const setup=/^(?:dockerfile|(?:docker-)?compose\.ya?ml|requirements\.txt|package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|go\.(?:mod|sum)|_vulscan_c_(?:runner\.py|spec\.json))$/i;
  for(const heading of [...root.querySelectorAll('h2,h3')]){
   if(!/^PoC\s*与测试记录$/.test(heading.textContent.trim()))continue;
   const level=Number(heading.tagName[1]),parts=[];let next=heading.nextElementSibling;
   while(next&&!(/^H[1-6]$/.test(next.tagName)&&Number(next.tagName[1])<=level)){parts.push(next);next=next.nextElementSibling;}
   const section=make('section',undefined,'reproduction-summary');section.append(make(heading.tagName,'PoC 与验证说明'));
   const status=parts.find(n=>n.tagName==='P'&&/^动态测试[：:]/.test(n.textContent.trim()));
   const description=root.closest('.report-finding')?.querySelector('.finding-section .markdown-prose');
   if(description?.textContent.trim())section.append(make('p',description.textContent.trim()));
   const design=root.dataset.pocDesign?.split(/\n\s*\n/)[0].trim();
   section.append(make('p',design?'PoC 构造思路（静态分析）：'+design:'旧记录未保存 PoC 构造说明。'));
   const label=parts.findIndex(n=>n.tagName==='P'&&/^结果说明[：:]$/.test(n.textContent.trim()));
   let detail=label>=0&&parts[label+1]?.tagName==='PRE'?parts[label+1].textContent.trim().split('\n')[0]:'';
   const cause=detail.match(/^(Docker 构建超时|Docker 构建失败|Docker 环境不可用|Docker 基础镜像不可用|容器执行失败|容器执行超时)/)?.[0];
   detail=cause||detail.split(/标准错误[：:]|标准输出[：:]/)[0].slice(0,500);
   section.append(make('p',[status?.textContent.trim()||'未记录动态测试结论。',detail].filter(Boolean).join('。')));
   let files=false,filename='',found=false;
   for(let i=0;i<parts.length;i++){
    const part=parts[i],text=part.textContent.trim();
    if(part.tagName==='H4'){files=text==='测试与构建文件';continue;}
    if(!files||part.tagName!=='P')continue;
    if(text==='文件名：'&&parts[i+1]?.tagName==='PRE')filename=parts[i+1].textContent.trim();
    const staged=text==='执行时的文件内容：',draft=/^原始生成的测试源码/.test(text);
    if(!(staged||draft)||parts[i+1]?.tagName!=='PRE'||staged&&(!filename||setup.test(filename.split('/').pop())))continue;
    if(!found){section.append(make('h4','完整 PoC'));found=true;}
    section.append(make('p',draft?'PoC 生成稿（未保存执行版本）':'文件：'+filename));
    const pre=parts[i+1].cloneNode(true);if(staged)pre.dataset.file=filename;section.append(pre);
   }
   if(!found)section.append(make('p','旧记录未保存可展示的 PoC 源码。'));
   heading.replaceWith(section);parts.forEach(n=>n.remove());
  }
 }
 async function copy(text,button){try{await navigator.clipboard.writeText(text);button.textContent='已复制';VulscanUI.notify('代码原文已复制。',{button});setTimeout(()=>{button.textContent='复制';},1500);}catch(_){button.textContent='复制';VulscanUI.notify('复制失败，请选择代码原文后复制。',{tone:'error',button});}}
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
   const box=make('div',undefined,'code-reader is-wrapped'),toolbar=make('div',undefined,'code-toolbar');
   const lineStart=Number(code.dataset.startLine||pre.dataset.startLine);const source=Number.isSafeInteger(lineStart)&&lineStart>0;
   const count=original.split('\n').length;const start=source?lineStart:1;
   toolbar.append(make('span',(lang||'纯文本')+(file?' · '+file:'')+' · '+(source?'源码行号':'片段行号'),'code-label'));
   const copyButton=make('button','复制');copyButton.type='button';copyButton.setAttribute('aria-label','复制代码原文');copyButton.addEventListener('click',()=>copy(originals.get(code),copyButton));
   const wrap=make('button','换行：开');wrap.type='button';wrap.setAttribute('aria-pressed','true');wrap.addEventListener('click',()=>{const on=box.classList.toggle('is-wrapped');wrap.textContent=on?'换行：开':'换行：关';wrap.setAttribute('aria-pressed',String(on));});
   toolbar.append(copyButton,wrap);
   const viewport=make('div',undefined,'code-viewport');viewport.tabIndex=0;viewport.setAttribute('aria-label',(lang||'纯文本')+'代码，默认完整显示并自动换行');const numbers=make('div',Array.from({length:count},(_,i)=>start+i).join('\n'),'code-lines');numbers.setAttribute('aria-hidden','true');
   pre.replaceWith(box);box.append(toolbar,viewport);viewport.append(numbers,pre);
  });
 }
 function toc(root,target){
  target.replaceChildren();target.append(make('h2','本页目录'));
  root.querySelectorAll('h1,h2,h3').forEach((h,i)=>{h.id='section-'+i;if(getComputedStyle(h).display==='none'||h.closest('.document-record,.document-record-body'))return;const a=make('a',h.textContent);a.href='#'+h.id;a.dataset.level=h.tagName.slice(1);target.append(a);});
  if(target.children.length===1)target.append(make('p','本文未提供章节标题。','hint'));
 }
 globalThis.VulscanReader={enhance,markdown,toc,copy,original:code=>originals.get(code)};
})();
