(() => {
 'use strict';
 const $=id=>document.getElementById(id),set=(id,value)=>{$(id).textContent=value;};
 const disclosure=documentContext.kind==='disclosure';
 const metadata={};
 if(disclosure){
  // Only the scanner's explicit leading Markdown fields associate this report
  // with a finding. Never guess from a filename, title, or positional number.
  for(const line of markdown.split(/\r?\n/)){
   if(/^#/.test(line))break;
   const match=line.match(/^>\s*\*\*(漏洞编号|所属发现|目标版本|复核状态|验证状态|动态测试|位置)[：:]\*\*\s*(.*)$/);
   if(match&&!metadata[match[1]])metadata[match[1]]=match[2].replace(/\s+$/,'');
  }
  set('document-finding',metadata['漏洞编号']||metadata['所属发现']||'未记录');
  set('document-version',metadata['目标版本']||'未记录');
  if(/^[a-f\d]{40,64}$/i.test(metadata['目标版本']||'')){set('document-version',metadata['目标版本'].slice(0,12));$('document-version').title=metadata['目标版本'];}
  set('document-review',metadata['复核状态']||metadata['验证状态']||'未记录');
  set('document-dynamic',metadata['动态测试']||'未记录');
  if(metadata['位置']){set('document-location',metadata['位置']);$('document-location').hidden=false;}
  const quote=$('content').querySelector(':scope > blockquote');
  if(quote&&[...quote.querySelectorAll('strong')].some(n=>/^(漏洞编号|所属发现|复核状态|验证状态)[：:]/.test(n.textContent))){
   const record=document.createElement('details'),summary=document.createElement('summary');record.className='document-record';summary.textContent='复核说明与版本记录';quote.replaceWith(record);record.append(summary,quote);
  }
  // Full reproduction transcripts stay available without overwhelming the
  // description, conditions, actual result and remediation in the main text.
  for(const heading of [...$('content').querySelectorAll(':scope > h2,:scope > h3')]){
   if(!/^(?:PoC\s*与测试记录|完整测试记录|完整复现记录)$/i.test(heading.textContent.trim()))continue;
   const record=document.createElement('details'),summary=document.createElement('summary'),body=document.createElement('div');record.className='document-test-record';body.className='document-record-body';
   const level=Number(heading.tagName[1]);let next=heading.nextElementSibling;heading.replaceWith(record);summary.append(heading);record.append(summary,body);
   while(next&&!(/^H[1-6]$/.test(next.tagName)&&Number(next.tagName[1])<=level)){const current=next;next=next.nextElementSibling;body.append(current);}
  }
  VulscanReader.toc($('content'),$('document-toc'));
 }
 $('document-copy').addEventListener('click',async()=>{set('document-feedback','');try{await navigator.clipboard.writeText(markdown);VulscanUI.notify('原始 Markdown 已复制。',{button:$('document-copy')});}catch(_){VulscanUI.notify('复制失败，可下载 Markdown 或打开原文后复制。',{tone:'error',button:$('document-copy')});}});
 $('document-download').addEventListener('click',()=>{const a=document.createElement('a');const url=URL.createObjectURL(new Blob([markdown],{type:'text/markdown;charset=utf-8'}));a.href=url;a.download=documentContext.filename||documentContext.kind+'-'+documentContext.jobID+'.md';a.click();VulscanUI.notify('已开始下载 Markdown。',{tone:'info',button:$('document-download')});setTimeout(()=>URL.revokeObjectURL(url),1000);});
 let rawCreated=false;
 $('document-source').addEventListener('click',()=>{const show=$('source-view').hidden;if(show&&!rawCreated){const pre=document.createElement('pre'),code=document.createElement('code');code.textContent=markdown;pre.append(code);$('source-view').append(pre);VulscanReader.enhance($('source-view'));rawCreated=true;}$('source-view').hidden=!show;$('content').hidden=show;$('document-source').setAttribute('aria-pressed',String(show));set('document-source',show?'返回预览':'查看原文');});
 function showPreview(){if($('content').hidden)$('document-source').click();}
 $('document-toc').addEventListener('click',event=>{const link=event.target.closest('a');if(!link)return;showPreview();const target=$(link.getAttribute('href').slice(1));const record=target?.closest('details');if(record)record.open=true;});
 document.querySelector('.skip-link')?.addEventListener('click',showPreview);
 window.addEventListener('hashchange',()=>{if(location.hash==='#content'||/^#section-\d+$/.test(location.hash))showPreview();});
 fetch('/scan/'+encodeURIComponent(documentContext.jobID)+'/snapshot').then(r=>{if(!r.ok)throw Error('snapshot');return r.json();}).then(s=>{
  const statuses={queued:'排队中',running:'运行中',cancelling:'取消中',cancelled:'已取消',timeout:'已超时',error:'失败',done:'完成'};
  set('document-conclusion',disclosure?'验证情况':'扫描'+(statuses[s.status]||'状态未知')+(s.partial?' · 部分结果':''));
  set('document-scope',[s.repo,s.branch,s.commit?.slice(0,10)].filter(Boolean).join(' · ')||'范围未记录');
  if(disclosure){
   const id=metadata['漏洞编号']||metadata['所属发现'];
   const matches=id?Object.values(s.findings||{}).filter(f=>f.report_id===id||f.finding_id===id):[];
   const f=matches.length===1?matches[0]:null;
   if(f){
    const reviews={pending:'待复核',retained:'复核保留',excluded:'复核排除',inconclusive:'无法确定',error:'复核错误',interrupted:'复核未完成',not_requested:'未请求复核',unreviewed:'未记录复核'},dynamic={pending:'待测试',running:'执行中',reproduced:'已复现',not_reproduced:'未复现',inconclusive:'无法确定',environment_error:'环境错误',error:'测试错误',skipped:'已跳过',blocked:'测试受阻',interrupted:'测试未完成'};
    set('document-review',reviews[f.model_review]||'未记录');$('document-review').dataset.state=f.model_review||'';set('document-dynamic',dynamic[f.dynamic]||'未记录');
    $('document-dynamic').dataset.state=f.dynamic||'';
    const loc=[f.file,f.function].filter(Boolean).join(' · ');if(loc){set('document-location',loc);$('document-location').hidden=false;}
   }
   if((!metadata['目标版本']||/^未记录(?:[；;]|$)/.test(metadata['目标版本']))&&(s.branch||s.commit)){set('document-version',[s.branch,s.commit?.slice(0,12)].filter(Boolean).join(' · '));$('document-version').title=s.commit||s.branch;}
  }else{
   const c=s.counts||{},fmt=n=>n===null||n===undefined?'—':n;
   set('document-counts',s.legacy?'历史任务 · 未记录结构化计数':'候选 '+fmt(c.candidates)+' · 复核保留 '+fmt(c.retained)+' · 复核排除 '+fmt(c.excluded)+' · 复核未完成 '+fmt(c.review_incomplete)+' · 动态已复现 '+fmt(c.reproduced));
  }
  if(s.partial){set('document-limits','有未完成步骤，详见扫描活动记录。');$('document-limits').hidden=false;}
 }).catch(()=>{if(disclosure){set('document-limits','任务状态暂时无法读取，以上为报告中保存的记录。');$('document-limits').hidden=false;}else{set('document-conclusion','任务状态暂时无法读取');set('document-counts','统计暂时无法读取，可返回扫描详情查看。');}});
})();
