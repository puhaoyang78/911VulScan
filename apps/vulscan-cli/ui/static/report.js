(() => {
 'use strict';
 globalThis.VulscanChartLabelColor=ctx=>{
  const color=ctx.dataset.backgroundColor[ctx.dataIndex];const match=String(color).match(/^#([0-9a-f]{6})$/i);
  if(!match)return '#000';
  const rgb=[0,2,4].map(i=>parseInt(match[1].slice(i,i+2),16)/255).map(v=>v<=0.04045?v/12.92:((v+0.055)/1.055)**2.4);
  return .2126*rgb[0]+.7152*rgb[1]+.0722*rgb[2]>.179?'#000':'#fff';
 };
 document.querySelectorAll('[data-markdown]').forEach(element=>VulscanReader.markdown(element,element.textContent));
 VulscanReader.enhance(document);
 const section=document.getElementById('findings');if(!section)return;
 const query=document.getElementById('finding-query'),status=document.getElementById('finding-count');
 const rows=[...section.querySelectorAll('details[id^="finding-"]')];
 const groups=[...section.querySelectorAll('.report-group')];
 const links=[...document.querySelectorAll('.report-toc a[data-finding]')];
 rows.filter(row=>row.open).slice(1).forEach(row=>{row.open=false;});
 function reveal(row){if(!row)return;row.open=true;let parent=row.parentElement;while(parent&&parent!==section){if(parent.tagName==='DETAILS')parent.open=true;parent=parent.parentElement;}}
 links.forEach(link=>link.addEventListener('click',()=>{const row=document.getElementById(link.dataset.finding);rows.forEach(other=>{if(other!==row)other.open=false;});reveal(row);links.forEach(a=>a.setAttribute('aria-current',String(a===link)));}));
 function filter(){const term=query.value.trim().toLocaleLowerCase();let count=0;rows.forEach(row=>{const matched=!term||(row.dataset.search||'').toLocaleLowerCase().includes(term);row.hidden=!matched;if(matched){count++;if(term)reveal(row);}});groups.forEach(group=>{group.hidden=![...group.querySelectorAll('.report-finding')].some(row=>!row.hidden);});links.forEach(link=>{link.hidden=!!document.getElementById(link.dataset.finding)?.hidden;});status.textContent=count+' / '+rows.length+' 条记录';}
 query.addEventListener('input',filter);
 document.getElementById('finding-expand').addEventListener('click',()=>section.querySelectorAll('details:not([hidden])').forEach(d=>{d.open=true;}));
 document.getElementById('finding-collapse').addEventListener('click',()=>section.querySelectorAll('details').forEach(d=>{d.open=false;}));
 filter();
 if(location.hash.startsWith('#finding-'))reveal(document.getElementById(location.hash.slice(1)));
})();
