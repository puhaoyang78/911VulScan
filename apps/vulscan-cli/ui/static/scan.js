/* UI projections only. All scan decisions remain in the scanner. */
(() => {
 'use strict';
 const stages={recovery:'历史恢复',queue:'等待执行',initialize:'初始化',clone:'获取仓库',parse:'代码解析','app-context':'应用上下文',enhance:'上下文增强',analyze:'漏洞分析',verify:'模型复核','build-output':'结果整理','dynamic-test':'动态测试',report:'生成报告',scan:'主扫描',cleanup:'停止与清理',task:'任务结束'};
 const statuses={queued:'排队中',running:'运行中',cancelling:'取消中',cancelled:'已取消',timeout:'已超时',error:'失败',done:'完成',success:'完成',completed:'完成',partial:'部分完成',interrupted:'中断',skipped:'跳过',pending:'待处理',reported:'已记录范围',incomplete:'覆盖不完整'};
 const reviews={pending:'待复核',retained:'复核保留',excluded:'复核排除',inconclusive:'无法确定',error:'复核错误',interrupted:'复核未完成',not_requested:'未请求复核',unreviewed:'未记录复核'};
 const dynamics={pending:'待测试',running:'执行中',reproduced:'已复现',not_reproduced:'未复现',inconclusive:'无法确定',environment_error:'环境错误',error:'测试错误',skipped:'已跳过',blocked:'测试受阻',unknown:'未知',interrupted:'未完成（任务已结束）'};
 const severities={critical:'严重',high:'高危',medium:'中危',low:'低危'};
 const phases={generation:'测试生成',build:'构建',run:'运行',analysis:'结果分析',environment:'执行环境',cleanup:'资源清理',compose_build:'构建',compose_run:'运行'};
 function findingTitle(f){
  const title=String(f.title||'').trim();
  if(title.length<=96&&title&&!/^(vulnerable|bypassable|safe|error|候选问题（未提供标题）)$/i.test(title))return title;
  return [f.cwe_name||'',f.function||f.file||'候选问题'].filter(Boolean).join(' · ');
 }
 const active=s=>['queued','running','cancelling'].includes(s);
 const stripTime=s=>s.replace(/^\d{2}:\d{2}:\d{2}\s+/, '').trim();
 function classifyLine(line){
  const s=stripTime(line).toLowerCase();
  if(/^(?:\[(?:error|fatal|错误)\]|(?:error|fatal|错误|失败)[:：]|traceback \(most recent call last\):)/.test(s))return 'error';
  if(/^(?:\[(?:warn(?:ing)?|警告)\]|(?:warn(?:ing)?|警告)[:：])/.test(s))return 'warning';
  if(/^\[[^\]]+\]\s+(?:---\s+|done:\s+)?\d[\d,]*\s*\/\s*\d[\d,]*/.test(s))return /^\[\d+\/\d+\]/.test(s)?'step-tag':'progress';
  if(/^\[(?:parse|enhance|analyze|detect|verify|report|dynamic[-_]test|代码解析|动态测试)\]/.test(s))return 'step-tag';
  return 'other';
 }
 function stageFromLog(line){
  const s=stripTime(line).toLowerCase();
  const tag=s.match(/^\[([^\]]+)\]/)?.[1];
  const aliases={detect:'analyze',dynamic:'dynamic-test',dynamic_test:'dynamic-test','动态测试':'dynamic-test','代码解析':'parse','上下文增强':'enhance','漏洞分析':'analyze','模拟验证':'verify'};
  if(tag&&(aliases[tag]||stages[tag]))return aliases[tag]||tag;
  return 'other';
 }
 function matchesFinding(f,q,review,dynamic){
  return (!review||f.model_review===review)&&(!dynamic||f.dynamic===dynamic)&&(!q||[f.finding_id,f.report_id,f.title,f.file,f.function,f.cwe,f.cwe?'CWE-'+String(f.cwe).replace(/^CWE-/i,''):'',f.cwe_name,f.verdict].join(' ').toLocaleLowerCase().includes(q));
 }
 function legacyRecord(line){
  const s=stripTime(line),low=s.toLowerCase();
  const aliases={detect:'analyze',analyze:'analyze',enhance:'enhance',verify:'verify',parse:'parse',report:'report'};
  const progress=s.match(/^\[([^\]]+)\]\s+(?:---\s+|Done:\s+)?(\d[\d,]*)\s*\/\s*(\d[\d,]*)\s+(.*)$/i);
  if(progress&&aliases[progress[1].toLowerCase()]){
   const timing=progress[4].match(/(?:\(|\|\s*)elapsed\s+([^,|]+)[,|]\s*ETA\s+([^,|]+)/i);
   return {stage:aliases[progress[1].toLowerCase()],processed:Number(progress[2].replaceAll(',','')),total:Number(progress[3].replaceAll(',','')),elapsed:timing?.[1]?.trim(),eta:timing?.[2]?.trim(),activity:progress[4]};
  }
  if(!/^\[\d+\/\d+\]|^-\s*skipping|^warning:/.test(low))return null;
  const stage=/dynamic test/.test(low)?'dynamic-test':/verif/.test(low)?'verify':/enhanc|application context/.test(low)?'enhance':/parsing repository/.test(low)?'parse':/vulnerability detection/.test(low)?'analyze':/generating reports/.test(low)?'report':'';
  if(!stage)return null;
  return {stage,status:/^warning:/.test(low)?'error':/^-\s*skipping/.test(low)?'skipped':'running',activity:/docker not found/.test(low)?'未找到 Docker':s};
 }
 globalThis.VulscanScan={classifyLine,stageFromLog,matchesFinding,legacyRecord,findingTitle};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id);
 const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const text=(id,value)=>{const n=$(id),v=String(value??'');if(n&&n.textContent!==v)n.textContent=v;};
 const fmt=n=>n===null||n===undefined?'—':Number(n).toLocaleString('zh-CN');
 const duration=n=>typeof n!=='number'||!Number.isFinite(n)?'—':n<60?Math.floor(n)+' 秒':n<3600?Math.floor(n/60)+' 分 '+Math.floor(n%60)+' 秒':Math.floor(n/3600)+' 小时 '+Math.floor(n%3600/60)+' 分';
 const date=s=>{if(!s)return '—';const d=new Date(s);return Number.isNaN(+d)?'—':new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(d)+' UTC+8';};
 const tone=s=>['error','environment_error','reproduced','critical','high'].includes(s)?'risk':['timeout','partial','inconclusive','blocked','cancelling'].includes(s)?'warn':['running','queued','pending'].includes(s)?'active':['done','success','completed'].includes(s)?'done':'neutral';
 const pill=(label,state)=>{const n=node('span',label||'尚未记录','status-pill');n.dataset.tone=tone(state);return n;};
 let snapshot=null,lastRevision=-1,currentView='overview',cancelPending=false,cancelPromptOpen=false,terminalStatus='',currentFinding='',artifactsChecked=false,artifactsLoading=false,lastArtifactState='';
 let observedActive=false,terminalNoticeShown=false;
 const rowMap=new Map(),rowValues=new WeakMap(),detailValues=new WeakMap(),recentRows=new Map(),activityRows=new Map(),activityGroups=new Map();let recentTable=null,detailValue="";
 const views=['overview','findings','activity','terminal','materials'];
 function showView(view){
  const previousPanel=document.activeElement?.closest('[role=tabpanel]');
  currentView=view;
  views.forEach(name=>{const selected=name===view;const tab=$('tab-'+name);tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;$(name+'-panel').hidden=!selected;});
  if(previousPanel?.hidden)$('tab-'+view).focus();
  if(view==='terminal'&&$('auto-scroll').checked)jumpLatest();
 }
 views.forEach((view,index)=>{
  $('tab-'+view).addEventListener('click',()=>showView(view));
  $('tab-'+view).addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const i=e.key==='Home'?0:e.key==='End'?views.length-1:(index+(e.key==='ArrowRight'?1:-1)+views.length)%views.length;showView(views[i]);$('tab-'+views[i]).focus();});
 });
 $('show-findings').addEventListener('click',()=>showView('findings'));$('show-activity').addEventListener('click',()=>showView('activity'));$('show-materials').addEventListener('click',()=>showView('materials'));
 document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{
  $('review-filter').value='';$('dynamic-filter').value='';$('finding-query').value='';
  const [axis,value]=button.dataset.filter.split(':');if(axis==='review')$('review-filter').value=value;if(axis==='dynamic')$('dynamic-filter').value=value;filterFindings();showView('findings');
 }));
 function updateElapsed(){if(!snapshot)return;const end=snapshot.finished_at?+new Date(snapshot.finished_at):active(snapshot.status)?Date.now():NaN;text('job-elapsed',Number.isFinite(end)&&snapshot.started_at?duration(Math.max(0,(end-new Date(snapshot.started_at))/1000)):'结束时间未记录');}
 setInterval(updateElapsed,1000);
 function setStatus(status){
  text('status-text',statuses[status]||status||'状态未记录');$('status-text').dataset.state=status;$('status-text').dataset.tone=tone(status);
  $('btn-cancel').disabled=!active(status)||status==='cancelling'||cancelPending;
  $('btn-cancel').setAttribute('aria-busy',String(status==='cancelling'||cancelPending));
  text('btn-cancel',status==='cancelling'?'正在取消…':active(status)?'取消扫描':status==='cancelled'?'已取消':'任务已结束');
 }
 function terminalPresentation(status){
  text('overview-eta','任务已结束');
  if(status==='timeout'){text('error-banner','任务超时。请查看活动和日志中的超时来源及对应时间设置；主扫描可在新建扫描中选择更长的时间上限，补充报告和摘要使用独立时限。已有中间结果保留。');$('error-banner').hidden=false;}
  if(status==='error'){text('error-banner','任务失败；已保留的分析结果和报告仍可查看。请从活动记录定位失败阶段，并核对原始日志。');$('error-banner').hidden=false;}
 }
 function applySnapshot(data){
  if(data.version!==1||data.job_id!==jobID||data.revision<lastRevision||(terminalStatus&&active(data.status)))return;
  lastRevision=data.revision;snapshot=data;
  if(active(data.status))observedActive=true;
  if(data.repo){text('project-name',data.repo.replace(/^https?:\/\/[^/]+\//,'').replace(/\.git$/,''));$('project-name').title=data.repo;}const artifactState=JSON.stringify(data.artifacts||{});if(artifactState!==lastArtifactState){artifactsChecked=false;lastArtifactState=artifactState;}setStatus(data.status);updateElapsed();text('last-updated',data.legacy?'未记录（旧任务）':date(data.updated_at));
  text('revision-label',[data.branch,data.commit?.slice(0,10)].filter(Boolean).join(' · ')||'—');
  ['candidates','retained','excluded','reproduced'].forEach(k=>text('count-'+k,fmt(data.counts?.[k])));
  const c=data.counts||{},states=Object.values(data.findings||{});text('secondary-counts',[[c.pending,'待复核'],...['not_reproduced','inconclusive','environment_error','error','skipped','interrupted'].map(status=>[states.filter(f=>f.dynamic===status).length,dynamics[status]])].filter(([n])=>n>0).map(([n,label])=>label+' '+fmt(n)).join(' · '));
  const notes=[];if(data.legacy)notes.push('历史任务 · 未记录结构化统计');
  if(data.partial)notes.push('部分结果 · 有未完成步骤');
  if(Object.keys(data.pending||{}).length)notes.push('正在同步缺失事件…');
  if(data.persistence_error)notes.push(data.persistence_error);
  $('coverage-note').hidden=notes.length===0&&!data.coverage_details;text('coverage-summary',notes.join(' · ')||'覆盖范围');text('coverage-detail',data.coverage_details||'详见活动记录。');
  const stage=data.stages?.[data.stage];text('overview-stage',stages[data.stage]||data.stage||'等待阶段信息');
  text('stage-status',stage?statuses[stage.status]||'处理中':'尚未产生');$('stage-status').dataset.tone=tone(stage?.status);
  text('overview-count',stage?.processed!==null&&stage?.processed!==undefined?fmt(stage.processed)+' / '+fmt(stage.total)+(stage.unit?' '+stage.unit:''):'—');
  text('overview-elapsed',duration(stage?.elapsed_seconds??stage?.duration_seconds));text('overview-eta',active(data.status)?duration(stage?.eta_seconds):'任务已结束');
  text('eta-label',(stages[data.stage]||'当前阶段')+'预计剩余');
  const known=Number.isInteger(stage?.total)&&stage.total>0&&Number.isInteger(stage.processed)&&stage.processed<=stage.total;
  $('stage-progress').hidden=!known;if(known){$('stage-progress').max=stage.total;$('stage-progress').value=stage.processed;}
  text('overview-progress-note',known?'阶段进度 '+Math.floor(stage.processed/stage.total*100)+'%':'');
  text('overview-task',stage?.activity||(!active(data.status)?'任务已结束':'等待扫描器状态…'));
  renderStages(data.stages||{});renderFindings(data.findings||{});renderActivity(data.activity||[]);
  if(data.legacy)logs.forEach(r=>applyLegacyRecord(r.raw));
  if(!active(data.status)){
   terminalPresentation(data.status);
   checkArtifacts();
  }
 }
 function renderStages(items){const list=$('stage-list');list.replaceChildren();Object.entries(items).forEach(([key,item])=>{const row=node('li');row.append(node('span',stages[key]||key),pill(statuses[item.status]||'处理中',item.status));list.append(row);});if(!list.children.length)list.append(node('li','历史任务未记录阶段状态。'));}
 function fillRow(row,f){
  const signature=JSON.stringify(f);if(rowValues.get(row)===signature)return;rowValues.set(row,signature);
  const cells=row.cells;cells[0].textContent=f.report_id||'候选 #'+row.dataset.ordinal;
  let button=cells[1].querySelector('button');if(!button){button=node('button','','finding-title');button.type='button';button.addEventListener('click',()=>openFinding(f.finding_id));cells[1].append(button,node('span','','finding-location'));}
  button.textContent=findingTitle(f);cells[1].querySelector('.finding-location').textContent=[f.file,f.function,f.cwe?'CWE-'+String(f.cwe).replace(/^CWE-/i,''):''].filter(Boolean).join(' · ');
  cells[2].replaceChildren(pill(severities[f.severity]||'未评级',f.severity));cells[3].replaceChildren(pill(reviews[f.model_review]||'尚未记录',f.model_review));cells[4].replaceChildren(pill(dynamics[f.dynamic]||'尚未记录',f.dynamic));
 }
 function renderFindings(findings){
  const ordered=Object.values(findings).sort((a,b)=>a.first_seq-b.first_seq);
  ordered.forEach(f=>{let row=rowMap.get(f.finding_id);if(!row){row=node('tr');for(let i=0;i<5;i++)row.append(node('td'));row.dataset.findingId=f.finding_id;row.dataset.ordinal=String(rowMap.size+1);rowMap.set(f.finding_id,row);$('finding-rows').append(row);}fillRow(row,f);});
  filterFindings();
  const recent=$('recent-findings');
  if(!ordered.length){recent.className='recent-findings empty-state';recent.textContent=snapshot.discovery_known?'尚未发现候选问题。':'尚未产生可列出的发现。';return;}
  if(!recentTable){recentTable=node('table',undefined,'findings-table');recentTable.append(node('tbody'));recent.replaceChildren(recentTable);recent.className='recent-findings';}
  const items=ordered.slice(-4),ids=new Set(items.map(f=>f.finding_id));
  recentRows.forEach((row,id)=>{if(!ids.has(id)&&!row.contains(document.activeElement)){row.remove();recentRows.delete(id);}});
  items.forEach(f=>{let row=recentRows.get(f.finding_id);if(!row){row=node('tr');const cell=node('td'),button=node('button','','finding-title');button.addEventListener('click',()=>openFinding(f.finding_id));cell.append(button,node('span','','finding-location'));row.append(cell,node('td'));recentRows.set(f.finding_id,row);recentTable.tBodies[0].append(row);}
   const signature=JSON.stringify(f);if(rowValues.get(row)===signature)return;rowValues.set(row,signature);row.cells[0].querySelector('button').textContent=findingTitle(f);const loc=row.cells[0].querySelector('.finding-location');loc.textContent=[f.report_id,f.file,f.function].filter(Boolean).join(' · ');loc.title=loc.textContent;row.cells[1].replaceChildren(pill(reviews[f.model_review]||'尚未复核',f.model_review),node('br'),pill(dynamics[f.dynamic]||'尚未测试',f.dynamic));});
  if(currentFinding&&$('finding-dialog').open)renderFindingDetail(currentFinding);
 }
 function filterFindings(){if(!snapshot)return;const q=$('finding-query').value.trim().toLocaleLowerCase(),review=$('review-filter').value,dynamic=$('dynamic-filter').value;let n=0;rowMap.forEach((row,id)=>{row.hidden=!matchesFinding(snapshot.findings[id],q,review,dynamic);if(!row.hidden)n++;});text('finding-count','显示 '+n+' / '+rowMap.size+' 个候选');$('findings-empty').hidden=n>0;text('findings-empty',rowMap.size?'没有匹配的发现，请调整或清除筛选。':snapshot.discovery_known?'尚未发现候选问题。':'尚未产生发现记录；旧任务请查看报告。');}
 ['finding-query','review-filter','dynamic-filter'].forEach(id=>$(id).addEventListener('input',filterFindings));
 $('clear-findings').addEventListener('click',()=>{['finding-query','review-filter','dynamic-filter'].forEach(id=>$(id).value='');filterFindings();});
 $('finding-sort').addEventListener('change',()=>{
  const key=$('finding-sort').value,rank={critical:0,high:1,medium:2,low:3};
  Object.values(snapshot?.findings||{}).sort((a,b)=>key==='severity'?(rank[a.severity]??4)-(rank[b.severity]??4)||a.first_seq-b.first_seq:key==='first'?a.first_seq-b.first_seq:key==='title'?findingTitle(a).localeCompare(findingTitle(b),'zh-CN'):String(a[key]||'').localeCompare(String(b[key]||''),'zh-CN')).forEach(f=>$('finding-rows').append(rowMap.get(f.finding_id)));
 });
 function renderFindingDetail(id){
  const f=snapshot.findings[id];if(!f)return;
  const signature=JSON.stringify(f);if(signature===detailValue)return;detailValue=signature;
  text('finding-title',findingTitle(f));const box=$('finding-detail');
  if(box.dataset.finding!==id){box.replaceChildren();box.dataset.finding=id;}
  const part=(tag,key,cls)=>{let el=box.querySelector('[data-detail="'+key+'"]');if(!el){el=node(tag,undefined,cls);el.dataset.detail=key;box.append(el);}return el;};
  const status=part('div','status','finding-statuses');
  status.replaceChildren(pill(severities[f.severity]||'未评级',f.severity),pill(reviews[f.model_review]||'未记录复核',f.model_review),pill(dynamics[f.dynamic]||'未记录测试',f.dynamic));
  part('p','location','detail-location mono').textContent=[f.file,f.function].filter(Boolean).join(' · ')||'位置未记录';
  const cwe=part('p','cwe','meta');cwe.hidden=!f.cwe&&!f.cwe_name;cwe.textContent=[f.cwe?'CWE-'+String(f.cwe).replace(/^CWE-/i,''):'',f.cwe_name].filter(Boolean).join(' · ');
  for(const [label,key] of [['问题描述','description'],['模型复核','review_details'],['动态测试','dynamic_details']]){
   const section=part('section',key,'finding-section');
   if(!section.firstElementChild)section.append(node('h3',label),node('div',undefined,'markdown-prose'));
   const prose=section.lastElementChild,value=f[key]||'';
   if(detailValues.get(prose)===value)continue;
   if(prose.contains(document.activeElement)){
    if(!prose.dataset.pending){prose.dataset.pending='true';prose.addEventListener('focusout',()=>requestAnimationFrame(()=>{delete prose.dataset.pending;if(currentFinding===id&&$('finding-dialog').open){detailValue='';renderFindingDetail(id);}}),{once:true});}
    continue;
   }
   if(value)VulscanReader.markdown(prose,value);else prose.replaceChildren(node('p','未提供','hint'));
   detailValues.set(prose,value);
  }
  const failure=part('p','failure','feedback');failure.hidden=!f.failure_phase;failure.textContent=f.failure_phase?'失败阶段：'+(phases[f.failure_phase]||f.failure_phase):'';
  const record=part('details','record','finding-record');
  if(!record.firstElementChild)record.append(node('summary','记录信息'),node('p',f.finding_id,'mono'),node('p'),node('p'),node('h3','原始标题'),node('p',undefined,'detail-prose'));
  record.children[2].hidden=!f.report_id;record.children[2].textContent='报告编号：'+(f.report_id||'');
  record.children[3].hidden=!f.attempt;record.children[3].textContent='测试尝试：'+(f.attempt||'');
  record.children[4].hidden=record.children[5].hidden=!f.title||findingTitle(f)===f.title;record.children[5].textContent=f.title||'';
 }
 function openFinding(id){currentFinding=id;renderFindingDetail(id);$('finding-dialog').showModal();}
 $('finding-close').addEventListener('click',()=>$('finding-dialog').close());$('finding-dialog').addEventListener('close',()=>{currentFinding='';detailValue='';});
 $('finding-activity').addEventListener('click',()=>{const id=currentFinding;$('finding-dialog').close();$('activity-finding').value=id;filterActivity();showView('activity');});
 function renderActivity(events){
  const live=new Set(events.map(e=>e.seq));activityRows.forEach((row,seq)=>{if(!live.has(seq)){row.remove();activityRows.delete(seq);}});
  events.forEach(e=>{
   if(activityRows.has(e.seq))return;const key=e.stage||'other';let group=activityGroups.get(key);
   if(!group){group=node('details');group.open=true;group.append(node('summary',stages[key]||key));activityGroups.set(key,group);$('activity-groups').append(group);const opt=node('option',stages[key]||key);opt.value=key;$('activity-stage').append(opt);}
   const row=node('div',undefined,'activity-row');row.dataset.stage=key;row.dataset.finding=e.finding_id||'';const desc=node('div');desc.append(node('span',[e.message||e.type,phases[e.phase]||e.phase].filter(Boolean).join(' · ')),node('br'),pill(e.type==='validation.updated'?dynamics[e.status]||e.status:e.type==='finding.upsert'?reviews[e.status]||'已记录':statuses[e.status]||e.status||'已记录',e.status));if(e.finding_id)desc.append(node('span',' · '+(snapshot.findings[e.finding_id]?.report_id||e.finding_id),'meta'));if(e.attempt)desc.append(node('span',' · 第 '+e.attempt+' 次尝试','meta'));
   row.append(node('time',date(e.time)),desc,node('small','耗时 '+duration(e.duration_seconds)));
   if(e.details){const full=node('details');full.open=['error','environment_error','partial'].includes(e.status);full.append(node('summary','完整输出'),node('pre',e.details));row.append(full);if(full.open)group.open=true;}
   activityRows.set(e.seq,row);group.append(row);
  });
  filterActivity();
 }
 function filterActivity(){const stage=$('activity-stage').value,q=$('activity-finding').value.trim().toLocaleLowerCase();let visible=0;activityRows.forEach(row=>{const f=snapshot?.findings[row.dataset.finding];row.hidden=!!((stage&&row.dataset.stage!==stage)||(q&&![row.dataset.finding,f?.report_id].join(' ').toLocaleLowerCase().includes(q)));if(!row.hidden)visible++;});activityGroups.forEach(g=>{g.hidden=![...g.querySelectorAll('.activity-row')].some(r=>!r.hidden);});text('activity-note',!activityRows.size?'尚无结构化活动记录。历史任务可从原始日志排障。':!visible?'没有匹配的活动，请调整或清除筛选。':snapshot?.activity_omitted?'仅展示最近 1000 条结构化活动，已省略 '+snapshot.activity_omitted+' 条；完整记录请查看原始日志。':'');}
 ['activity-stage','activity-finding'].forEach(id=>$(id).addEventListener('input',filterActivity));$('clear-activity').addEventListener('click',()=>{$('activity-stage').value='';$('activity-finding').value='';filterActivity();});
 const logs=[],filtered=[];const PAGE=250;let logOffset=0,lastEventID=-1,newLogs=0,paintPending=false;
 function logMatches(record){return (!$('log-query').value||record.raw.toLocaleLowerCase().includes($('log-query').value.toLocaleLowerCase()))&&(!$('log-level').value||record.level===$('log-level').value)&&(!$('log-stage').value||record.stage===$('log-stage').value);}
 function logLine(record,index){const line=node('div',undefined,'log-line log-level-'+record.level);line.dataset.logIndex=index;const match=record.raw.match(/^(\d{2}:\d{2}:\d{2})\s+(.*)/s);if(match)line.append(node('span',match[1]+' ','ts'));line.append(node('span',match?match[2]:record.raw,'body'));return line;}
 function paintLog(force=false){
  paintPending=false;const follow=$('auto-scroll').checked;if(follow)logOffset=Math.max(0,filtered.length-PAGE);
  const start=logOffset,indices=filtered.slice(start,start+PAGE),body=$('log-body');
  if(force||!body.firstElementChild?.dataset.logIndex||Number(body.lastElementChild?.dataset.logIndex)<indices[0]||Number(body.firstElementChild?.dataset.logIndex)>indices[indices.length-1]){body.replaceChildren(...indices.map(i=>logLine(logs[i],i)));}
  else {const keep=new Set(indices);[...body.children].forEach(n=>{if(!keep.has(Number(n.dataset.logIndex)))n.remove();});const shown=new Set([...body.children].map(n=>Number(n.dataset.logIndex)));indices.forEach(i=>{if(!shown.has(i))body.append(logLine(logs[i],i));});}
  if(!indices.length)body.replaceChildren(node('div',logs.length?'没有匹配的日志。':'本任务尚未保留日志记录。','log-empty'));
  text('log-count','匹配 '+filtered.length+' / '+logs.length+' 行 · 第 '+(filtered.length?start+1:0)+'–'+Math.min(start+PAGE,filtered.length)+' 行');$('log-prev').disabled=logOffset<=0;$('log-next').disabled=start+PAGE>=filtered.length;
  if(follow){body.scrollTop=body.scrollHeight;newLogs=0;}text('log-new',newLogs?'新增 '+newLogs+' 行':'' );
 }
 function queueLogPaint(){if(!paintPending){paintPending=true;requestAnimationFrame(()=>paintLog());}}
 function applyLegacyRecord(raw){
  if(!snapshot?.legacy)return;const p=legacyRecord(raw);if(!p)return;
  text('overview-stage',stages[p.stage]||p.stage);text('stage-status','旧版日志记录');text('overview-task',p.activity);
  text('overview-count',p.processed===undefined?'—':fmt(p.processed)+' / '+fmt(p.total));text('overview-elapsed',p.elapsed||'—');text('overview-eta',active(snapshot.status)?p.eta||'—':'任务已结束');
  const known=p.total>0&&p.processed<=p.total;$('stage-progress').hidden=!known;if(known){$('stage-progress').max=p.total;$('stage-progress').value=p.processed;}
  text('overview-progress-note','降级显示旧版日志中的阶段处理量；发现及验证数量仍未记录，不计算整体完成率。');
 }
 function appendLine(raw){const record={raw,level:classifyLine(raw),stage:stageFromLog(raw)};logs.push(record);applyLegacyRecord(raw);const matched=logMatches(record);if(matched)filtered.push(logs.length-1);if(matched&&!$('auto-scroll').checked)newLogs++;queueLogPaint();}
 function refilterLogs(){filtered.length=0;logs.forEach((r,i)=>{if(logMatches(r))filtered.push(i);});logOffset=0;newLogs=0;$('auto-scroll').checked=false;paintLog(true);}
 ['log-query','log-level','log-stage'].forEach(id=>$(id).addEventListener('input',refilterLogs));$('log-clear').addEventListener('click',()=>{['log-query','log-level','log-stage'].forEach(id=>$(id).value='');refilterLogs();});
 $('log-prev').addEventListener('click',()=>{$('auto-scroll').checked=false;logOffset=Math.max(0,logOffset-PAGE);paintLog(true);});$('log-next').addEventListener('click',()=>{$('auto-scroll').checked=false;logOffset=Math.min(Math.max(0,filtered.length-PAGE),logOffset+PAGE);paintLog(true);});
 function jumpLatest(){$('auto-scroll').checked=true;newLogs=0;paintLog(true);}
 $('log-latest').addEventListener('click',jumpLatest);$('auto-scroll').addEventListener('change',()=>{if($('auto-scroll').checked)jumpLatest();});
 $('log-body').addEventListener('scroll',()=>{const b=$('log-body');if(b.scrollHeight-b.scrollTop-b.clientHeight>30)$('auto-scroll').checked=false;},{passive:true});
 $('log-body').addEventListener('wheel',e=>{if(e.deltaY<0)$('auto-scroll').checked=false;},{passive:true});
 $('log-copy').addEventListener('click',async()=>{text('log-feedback','');try{await navigator.clipboard.writeText(filtered.map(i=>logs[i].raw).join('\n'));VulscanUI.notify('已复制全部 '+filtered.length+' 条匹配日志。',{button:$('log-copy')});}catch(_){VulscanUI.notify('复制失败，可下载原始日志后复制。',{tone:'error',button:$('log-copy')});}});
 function confirmCancellation(){const dialog=$('cancel-dialog');return new Promise(resolve=>{const cleanup=()=>{$('cancel-confirm').removeEventListener('click',yes);$('cancel-dismiss').removeEventListener('click',no);dialog.removeEventListener('close',closed);};const yes=()=>{cleanup();dialog.close();resolve(true);};const no=()=>{cleanup();dialog.close();resolve(false);};const closed=()=>{cleanup();resolve(false);};$('cancel-confirm').addEventListener('click',yes);$('cancel-dismiss').addEventListener('click',no);dialog.addEventListener('close',closed);dialog.showModal();});}
 function showCancelling(){cancelPending=true;setStatus('cancelling');text('cancel-feedback','正在停止扫描并清理本任务资源，请稍候。');VulscanUI.notify('正在停止扫描并清理资源…',{tone:'info',id:'job-status'});}
 $('btn-cancel').addEventListener('click',async()=>{
  if(cancelPending||cancelPromptOpen||terminalStatus||snapshot&&!active(snapshot.status))return;
  cancelPromptOpen=true;let confirmed;try{confirmed=await confirmCancellation();}finally{cancelPromptOpen=false;}if(!confirmed)return;if(terminalStatus){VulscanUI.notify('任务已结束，可查看已保存的结果。',{tone:'info',id:'job-status'});return;}
  cancelPending=true;$('btn-cancel').disabled=true;$('btn-cancel').setAttribute('aria-busy','true');text('btn-cancel','正在请求取消…');text('cancel-feedback','');
  try{const r=await fetch('/scan/'+encodeURIComponent(jobID)+'/cancel',{method:'POST',headers:{'X-CSRF-Token':document.querySelector('meta[name=csrf]').content}});if(!r.ok)throw Error('cancel');const result=await r.json();if(terminalStatus)return;if(active(result.status))showCancelling();else text('cancel-feedback','任务已结束，正在同步最后日志；等待服务端终态。');}
  catch(_){if(terminalStatus)return;cancelPending=false;$('btn-cancel').disabled=false;$('btn-cancel').setAttribute('aria-busy','false');text('btn-cancel','重试取消');text('cancel-feedback','取消请求未确认，扫描可能仍在运行。可重试取消或刷新核实。');VulscanUI.notify('未确认取消结果，可重试取消。',{tone:'error',button:$('btn-cancel'),id:'job-status'});}
 });
 async function checkArtifacts(manual=false){
  if(artifactsChecked||artifactsLoading)return;artifactsChecked=true;artifactsLoading=true;
  const button=$('refresh-artifacts'),errors=[];let found=0;
  button.disabled=true;button.setAttribute('aria-busy','true');button.textContent='正在刷新…';
  try{
   for(const [path,label,ids]of[['summary','扫描摘要',['btn-summary']],['report','扫描报告',['btn-report','download-report']]]){
    for(const id of ids){$(id).classList.remove('ready');$(id).setAttribute('aria-disabled','true');$(id).tabIndex=-1;$(id).removeAttribute('href');}
    if(snapshot?.artifacts?.[path]===false)continue;
    try{
     const r=await fetch('/'+path+'/'+encodeURIComponent(jobID),{method:'HEAD'});
     if(r.ok){for(const id of ids){$(id).href=$(id).dataset.href;$(id).classList.add('ready');$(id).removeAttribute('aria-disabled');$(id).removeAttribute('tabindex');}found++;}
     else if(r.status!==404)errors.push(label);
    }catch(_){errors.push(label);}
   }
   try{
    const r=await fetch('/disclosures/'+encodeURIComponent(jobID));if(!r.ok)throw Error('list');
    const items=await r.json();if(!Array.isArray(items))throw Error('list');
    const links=items.map(d=>{const a=node('a',d.label||d.name,'btn-disclosure');a.href=d.url;a.target='_blank';a.rel='noopener';return a;});
    $('disclosure-links').replaceChildren(...links);$('disclosures').hidden=!items.length;if(items.length)found++;
   }catch(_){errors.push('漏洞报告列表');}
   text('artifact-note',errors.length?errors.join('、')+'暂时无法读取，请刷新重试。':found?(snapshot?.partial?'已有报告可查看；本次扫描包含未完成步骤。':active(snapshot?.status)?'已有报告可查看，扫描仍在进行。':'已生成的报告可阅读和下载。'):'尚未生成可阅读的报告，已保存的结果和日志仍可查看。');
   if(manual)VulscanUI.notify(errors.length?'部分报告暂时无法读取，请重试。':'报告列表已更新。',{tone:errors.length?'error':'info',button,id:'artifacts'});
  }finally{
   artifactsLoading=false;button.disabled=false;button.setAttribute('aria-busy','false');button.textContent='刷新报告';
   if(!artifactsChecked)checkArtifacts();
  }
 }
 $('refresh-artifacts').addEventListener('click',()=>{artifactsChecked=false;checkArtifacts(true);});
 const channels={snapshot:false,logs:false};
 function connection(){const good=channels.snapshot&&channels.logs;const n=$('connection-status');n.dataset.state=good?'connected':'reconnecting';n.textContent=good?'实时更新已连接':'连接中断，正在重连…';}
 function connect(){
  const stateStream=new EventSource('/scan/'+encodeURIComponent(jobID)+'/events');
  stateStream.onopen=()=>{channels.snapshot=true;connection();};stateStream.addEventListener('snapshot',e=>{try{applySnapshot(JSON.parse(e.data));}catch(_){text('connection-status','状态事件无法读取，请刷新核实。');}});
  stateStream.addEventListener('done',()=>{stateStream.close();});stateStream.onerror=()=>{channels.snapshot=false;connection();if(stateStream.readyState===EventSource.CLOSED){$('connection-status').dataset.state='disconnected';text('connection-status','状态连接已断开，请刷新页面重新连接。');}};
  const rawStream=new EventSource('/scan/'+encodeURIComponent(jobID)+'/logs');
  rawStream.onopen=()=>{channels.logs=true;connection();};rawStream.onmessage=e=>{const id=Number(e.lastEventId);if(e.lastEventId!==''&&Number.isSafeInteger(id)&&id>=0){if(id<=lastEventID)return;lastEventID=id;}appendLine(e.data);};
  rawStream.addEventListener('done',e=>{const notifyEnd=observedActive||cancelPending;terminalStatus=e.data;rawStream.close();cancelPending=false;setStatus(e.data);terminalPresentation(e.data);text('cancel-feedback','');text('connection-status',channels.snapshot?'任务日志已同步':'日志已同步；状态连接中断，正在重连…');$('connection-status').dataset.state=channels.snapshot?'complete':'reconnecting';if(notifyEnd&&!terminalNoticeShown){terminalNoticeShown=true;VulscanUI.notify(e.data==='cancelled'?'扫描已停止，已保存的结果可继续查看。':'扫描'+(statuses[e.data]||'已结束')+'。',{tone:['error','timeout'].includes(e.data)?'error':'success',id:'job-status'});}if(snapshot)checkArtifacts();});
  rawStream.onerror=()=>{channels.logs=false;connection();if(rawStream.readyState===EventSource.CLOSED){$('connection-status').dataset.state='disconnected';text('connection-status','日志连接已断开，请刷新页面重新连接。');}};
  window.addEventListener('pagehide',()=>{stateStream.close();rawStream.close();},{once:true});
 }
 window.addEventListener('pageshow',e=>{if(e.persisted)location.reload();});
 globalThis.VulscanScan={...globalThis.VulscanScan,applySnapshot,appendLine,showView};
 connect();
})();
