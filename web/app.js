'use strict';
const one = id => document.getElementById(id);
const svgNS = 'http://www.w3.org/2000/svg';
const make = (tag,cls,text) => {
  const el=document.createElement(tag);
  if(cls)el.className=cls;
  if(text!==undefined)el.textContent=String(text);
  return el;
};
const dateLabel = s => { if(!s)return 'Awaiting first check'; const d=new Date(s); return Number.isNaN(d.getTime())?String(s):d.toLocaleString(); };
function renderTrend(trend,isDemo){
  const root=one('trendChart');
  root.replaceChildren();
  if(!Array.isArray(trend)||!trend.length){
    root.append(make('div','trend-empty','Collecting response time measurements. The chart will update each hour.'));
    one('sampleInfo').textContent='NO SAMPLES';
    return;
  }
  one('sampleInfo').textContent=isDemo?'SIMULATED TREND':trend.reduce((s,r)=>s+(r.samples||0),0)+' SAMPLES';
  const W=850,H=155, PAD=22;
  const nums=trend.map(t=>Number(t.ms)).filter(Number.isFinite);
  if(!nums.length){root.append(make('div','trend-empty','No valid response times yet.'));return;}
  const lo=Math.max(0,Math.min(...nums)-40), hi=Math.max(...nums)+40;
  const x=i=>PAD+(trend.length===1?0.5:i/(trend.length-1))*(W-2*PAD);
  const y=v=>H-PAD-((v-lo)/(hi-lo||1))*(H-2*PAD);
  const svg=document.createElementNS(svgNS,'svg');
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
  svg.setAttribute('role','img');
  svg.setAttribute('aria-label',isDemo?'Illustrative latency trend':'Measured average response time trend');
  svg.setAttribute('preserveAspectRatio','none');
  for(let i=0;i<4;i++){
    const yy=PAD+i*(H-2*PAD)/3;
    const line=document.createElementNS(svgNS,'line');
    line.setAttribute('x1','0');line.setAttribute('x2',String(W));
    line.setAttribute('y1',String(yy));line.setAttribute('y2',String(yy));
    line.setAttribute('class','gridline');svg.append(line);
  }
  const pts=trend.map((t,i)=>[x(i),y(Number(t.ms))]);
  const line=document.createElementNS(svgNS,'polyline');
  line.setAttribute('points',pts.map(p=>p.join(',')).join(' '));
  line.setAttribute('class','trend-line');
  svg.append(line);
  for(const p of pts){
    const dot=document.createElementNS(svgNS,'circle');
    dot.setAttribute('cx',String(p[0]));dot.setAttribute('cy',String(p[1]));
    dot.setAttribute('r','4');dot.setAttribute('class','trend-dot');
    svg.append(dot);
  }
  root.append(svg);
  const axis=make('div','trend-axis');
  axis.append(make('span','',trend[0].hour+' UTC'),make('span','',trend.at(-1).hour+' UTC'));
  root.append(axis);
}
function render(data){
  const isDemo=data.mode==='demo';
  one('demoNotice').hidden=!isDemo;
  one('modeTag').className='tag '+(isDemo?'demo':'live');
  one('modeTag').textContent=isDemo?'● DEMO MODE':'● LIVE READ-ONLY';
  one('checked').textContent=isDemo?'Simulated data (not measured)':'Last check: '+dateLabel(data.last_check);
  const services=Array.isArray(data.services)?data.services:[];
  const healthy=services.filter(x=>x.status==='up').length;
  const issues=services.filter(x=>x.status==='down'||x.status==='warning').length;
  const values=services.map(x=>x.ms).filter(x=>typeof x==='number'&&Number.isFinite(x)).sort((a,b)=>a-b);
  const mid=Math.floor(values.length/2);
  const median=values.length?(values.length%2?values[mid]:Math.round((values[mid-1]+values[mid])/2)):null;
  one('metricTotal').textContent=String(services.length);
  one('metricHealthy').textContent=String(healthy);
  one('metricIssues').textContent=String(issues);
  one('metricLatency').textContent=median===null?'—':median+' ms';
  const wrap=one('serviceRows');
  wrap.replaceChildren();
  const uptime=data.uptime24h||{};
  for(const s of services){
    const line=make('div','service-row');
    const name=make('div','service-name',s.name);
    let host;
    try{host=new URL(s.url).hostname;}catch{host='Unknown host';}
    name.append(make('small','',host));
    const sample=uptime[s.name];
    if(sample && sample.observed>=3 && sample.percent!==null){
      name.append(make('small','uptime-note',sample.percent+'% measured samples · 24h'));
    }
    const status=make('span','service-pill '+s.status,
      ({up:'Healthy',warning:'Review',down:'Down',pending:'Pending'})[s.status]||'Unknown');
    status.title=s.message||'';
    const ms=make('span','latency',typeof s.ms==='number'?s.ms+' ms':'—');
    const days=typeof s.cert_days==='number'?s.cert_days:null;
    const cert=make('span','cert-days'+(days!==null&&days<14?' cert-warning':''),
      days===null?'—':days+' days');
    cert.title=days===null?'Certificate not measured':days+' days before TLS certificate expiry';
    line.append(name,status,ms,cert);
    wrap.append(line);
  }
  if(!services.length)wrap.append(make('div','event-empty','No services configured.'));
  const down=services.filter(s=>s.status==='down');
  const warning=services.filter(s=>s.status==='warning');
  const pending=services.filter(s=>s.status==='pending');
  const certDays=services.map(s=>s.cert_days).filter(v=>typeof v==='number');
  one('tlsSummary').textContent=certDays.length?
    'Nearest TLS expiry: '+Math.min(...certDays)+' days':
    'Waiting for TLS certificate checks';
  const uptimeVals=Object.values(uptime).filter(v=>v && v.observed>=3 && v.percent!==null);
  one('uptimeSummary').textContent=uptimeVals.length?
    '24h observed checks: '+(uptimeVals.reduce((a,r)=>a+r.percent,0)/uptimeVals.length).toFixed(1)+'% healthy':
    'Collecting 24h sampled uptime baseline';
  let recommendation;
  if(isDemo) recommendation='This is a design preview. All health, latency, certificate and uptime readings are simulated. Select live monitoring when deploying to begin actual measurements.';
  else if(data.error) recommendation=data.error+'. Existing observations may be stale.';
  else if(pending.length) recommendation='HTTPS checks are running. Initial data will appear once the first monitoring cycle finishes.';
  else if(down.length) recommendation=down.length+' service(s) returned a failed read-only HTTPS check: '+down.map(s=>s.name).join(', ')+'. Review the recorded status; no corrective actions are automatic.';
  else if(warning.length) recommendation=warning.length+' service(s) need review: '+warning.map(s=>s.name).join(', ')+'. An HTTP 401, 403 or 405 may represent an expected access restriction rather than an outage.';
  else recommendation='All '+healthy+' configured HTTPS endpoints responded successfully and passed certificate verification. This confirms basic availability, not logins, internal workflows, security posture or customer experience.';
  one('insight').textContent=recommendation;
  const events=one('events');
  events.replaceChildren();
  for(const item of (data.history||[]).slice(0,5)){
    const line=make('div','event-item '+item.status);
    const content=make('div','',item.message||'Event');
    content.append(make('small','',item.when?dateLabel(item.when):''));
    line.append(content);events.append(line);
  }
  if(!(data.history||[]).length) events.append(make('div','event-empty','No status transitions recorded yet.'));
  const lab=data.lab||{};
  one('labState').textContent=(lab.status||'pending').toUpperCase();
  one('labReach').textContent=({online:'Online',offline:'Offline',unverified:'Identity unverified',pending:'Pending',unknown:'Unavailable',demo:'Simulated'})[lab.status]||'Unknown';
  one('labSSH').textContent=({open:'Available',closed:'Port closed',unreachable:'Not reachable','not tested':'Not tested',simulated:'Simulated'})[lab.ssh]||'Not tested';
  one('labPing').textContent=typeof lab.rtt_ms==='number'?lab.rtt_ms+' ms':'—';
  one('labMessage').textContent=lab.message||'No confirmed Dell measurement yet.';
  renderTrend(data.trend||[],isDemo);
}
async function refresh(){
  const button=one('refresh');
  button.disabled=true;
  try{
    const response=await fetch('/api/status',{cache:'no-store'});
    if(!response.ok)throw Error('HTTP '+response.status);
    render(await response.json());
  }catch(error){
    one('insight').textContent='Unable to load monitoring data: '+error.message;
  }finally{button.disabled=false;}
}
one('refresh').addEventListener('click',refresh);
refresh();
setInterval(refresh,60000);

async function refreshQa() {
  try {
    const response=await fetch('/api/qa/latest',{cache:'no-store'});
    if(!response.ok)throw new Error('HTTP '+response.status);
    const data=await response.json();
    const tag=one('qaRunTag');
    const summary=one('qaSummary');
    const root=one('qaRows');
    root.replaceChildren();
    if(data.state!=='complete'){
      tag.textContent='NOT VERIFIED';
      summary.textContent=data.message||'No completed full-ecosystem QA run found.';
      one('qaFoot').textContent='Use the local QA runner to perform a public-site check. No forms or logins are submitted.';
      return;
    }
    const results=Array.isArray(data.results)?data.results:[];
    const counts={pass:0,'auth-gated':0,review:0,fail:0};
    for(const r of results)if(Object.hasOwn(counts,r.status))counts[r.status]++;
    tag.textContent='QA VERIFIED';
    summary.textContent='Last completed: '+dateLabel(data.at)+' · '+results.length+' checks · '+
      counts.pass+' passed · '+counts['auth-gated']+' auth required · '+counts.review+' review · '+counts.fail+' failed';
    const names=Array.isArray(data.services)?data.services:[];
    for(const name of names){
      const entries=results.filter(r=>r.name===name);
      const row=make('div','qa-row');
      const label=make('div','qa-name',name);
      const messages=[...new Set(entries.flatMap(r=>Array.isArray(r.warnings)?r.warnings:[]))];
      const failures=entries.filter(r=>r.navigationError).map(r=>r.navigationError);
      const issue=messages.concat(failures).slice(0,2).join(' · ');
      label.append(make('small','',issue||'No warnings in public page checks'));
      row.append(label);
      for(const vp of ['desktop','mobile']){
        const r=entries.find(x=>x.viewport===vp);
        const status=(r?.status||'pending');
        const cell=make('div','qa-result '+status);
        cell.append(make('strong','',status==='auth-gated'?'AUTH REQ.':status.toUpperCase()));
        cell.append(make('small','',r?.http?'HTTP '+r.http:'No result'));
        row.append(cell);
      }
      const links=make('div','qa-links');
      for(const vp of ['desktop','mobile']){
        const r=entries.find(x=>x.viewport===vp);
        if(!r?.screenshot)continue;
        const link=make('a','qa-screenshot',vp==='desktop'?'Desktop ↗':'Mobile ↗');
        link.href='/api/qa/screenshot/'+encodeURIComponent(data.runId)+'/'+encodeURIComponent(r.screenshot);
        link.target='_blank';
        link.rel='noopener noreferrer';
        links.append(link);
      }
      if(!links.childNodes.length)links.append(make('span','qa-none','No screenshot'));
      row.append(links);
      root.append(row);
    }
    one('qaFoot').textContent='AUTH REQUIRED means an observed login/session check or expected V79 Hub redirect, not a completed authenticated test. REVIEW indicates a remaining browser error; neither status proves a service outage. No logins, forms, or purchases were attempted.';
  } catch(err) {
    one('qaRunTag').textContent='UNAVAILABLE';
    one('qaSummary').textContent='QA report could not be retrieved: '+err.message;
  }
}
one('refresh').addEventListener('click',refreshQa);
refreshQa();
setInterval(refreshQa,300000);

// Protected-app QA remains gated until an isolated synthetic-account tenant exists.
async function refreshProtectedQa(){
 try{
  const response=await fetch('/api/qa/auth-readiness',{cache:'no-store'});
  if(!response.ok)throw Error('HTTP '+response.status);
  const v=await response.json();
  one('qaAuthTag').textContent=v.state==='blocked'?'NOT CONFIGURED':'REVIEW REQUIRED';
  one('qaAuthSummary').textContent='Dedicated test accounts: '+v.complete+'/'+v.total+
    ' safeguards verified. '+v.message;
 }catch(error){
  one('qaAuthTag').textContent='UNAVAILABLE';
  one('qaAuthSummary').textContent='Readiness cannot be verified; protected tests remain disabled.';
 }
}
refreshProtectedQa();
