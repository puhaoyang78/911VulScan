(() => {
 'use strict';
 const $=id=>document.getElementById(id),set=(id,value)=>{$(id).textContent=value;};
 $('document-copy').addEventListener('click',async()=>{set('document-feedback','');try{await navigator.clipboard.writeText(markdown);VulscanUI.notify('原始 Markdown 已复制。',{button:$('document-copy')});}catch(_){VulscanUI.notify('复制失败，可下载 Markdown 或打开原文后复制。',{tone:'error',button:$('document-copy')});}});
 $('document-download').addEventListener('click',()=>{const a=document.createElement('a');const url=URL.createObjectURL(new Blob([markdown],{type:'text/markdown;charset=utf-8'}));a.href=url;a.download=documentContext.kind+'-'+documentContext.jobID+'.md';a.click();VulscanUI.notify('已开始下载 Markdown。',{tone:'info',button:$('document-download')});setTimeout(()=>URL.revokeObjectURL(url),1000);});
 let rawCreated=false;
 $('document-source').addEventListener('click',()=>{const show=$('source-view').hidden;if(show&&!rawCreated){const pre=document.createElement('pre'),code=document.createElement('code');code.textContent=markdown;pre.append(code);$('source-view').append(pre);VulscanReader.enhance($('source-view'));rawCreated=true;}$('source-view').hidden=!show;$('content').hidden=show;$('document-source').setAttribute('aria-pressed',String(show));set('document-source',show?'返回预览':'查看原文');});
 fetch('/scan/'+encodeURIComponent(documentContext.jobID)+'/snapshot').then(r=>{if(!r.ok)throw Error('snapshot');return r.json();}).then(s=>{
  const statuses={queued:'排队中',running:'运行中',cancelling:'取消中',cancelled:'已取消',timeout:'已超时',error:'失败',done:'完成'};
  set('document-conclusion',documentContext.kind==='disclosure'?'披露材料草稿 · '+(statuses[s.status]||'任务状态未知'):'扫描'+(statuses[s.status]||'状态未知')+(s.partial?' · 部分结果':''));
  set('document-scope',[s.repo,s.branch,s.commit?.slice(0,10)].filter(Boolean).join(' · ')||'范围未记录');
  const c=s.counts||{},fmt=n=>n===null||n===undefined?'—':n;
  set('document-counts',s.legacy?'历史任务 · 未记录结构化计数':'累计候选 '+fmt(c.candidates)+' · 模型复核保留 '+fmt(c.retained)+' · 复核排除 '+fmt(c.excluded)+' · 动态已复现 '+fmt(c.reproduced));
  if(s.partial){set('document-limits','有未完成步骤，详见扫描活动记录。');$('document-limits').hidden=false;}
 }).catch(()=>{set('document-conclusion','任务状态暂时无法读取');set('document-counts','数量口径未能加载，请返回扫描详情核实；正文为已有材料。');});
})();
