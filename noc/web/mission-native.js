"use strict";
/* Native V79 Sentinel Command Center. No iframe or remote script imports.
 * NetPulse investigation metadata stays in this browser; never POST or store it.
 * All untrusted monitoring fields use textContent, not HTML.
 */
(()=>{
const q=id=>document.getElementById(id);
const el=(tag,cls,txt)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(txt!==undefined)x.textContent=String(txt);return x;};
const fmt=n=>Number.isFinite(Number(n))?Number(n).toLocaleString():"—";
const when=x=>{try{return x?new Date(x).toLocaleString():"Not sampled";}catch{return "Not sampled";}};
const bytes=n=>{if(!Number.isFinite(Number(n)))return "—";let v=Number(n);return v>=1e9?(v/1e9).toFixed(2)+" GB":v>=1e6?(v/1e6).toFixed(1)+" MB":v>=1e3?(v/1e3).toFixed(1)+" KB":v+" B";};
const clean=(str,max=90)=>String(str??"—").slice(0,max);
const put=(id,value)=>{const x=q(id);if(x)x.textContent=String(value);};
const clear=id=>{const x=q(id);if(x)x.replaceChildren();return x;};
let active=false,inflight=false,refreshId=null,investigation=null,packetFilter="All",generation=0;
const request=async url=>{const r=await fetch(url,{credentials:"same-origin",cache:"no-store"});if(!r.ok){const err=Error("Endpoint unavailable ("+r.status+")");err.status=r.status;throw err;}return r.json();};
const stateName=value=>String(value||"unknown").toLowerCase();
const tag=(status)=>{const v=stateName(status);const s=el("span","v79-state "+(["healthy","up","pass","ok","connected"].includes(v)?"good":v==="down"||v==="fail"?"bad":"warn"),v.toUpperCase());return s;};
function panelRow(name,detail,status){
 const row=el("div","v79-row");const info=el("div","v79-row-info");info.append(el("strong","",clean(name,120)),el("small","",clean(detail,200)));row.append(info,tag(status));return row;
}
function lineChart(root,values,{key="ms",stroke="#44d9c6",label="Measured response time"}={}){
 root.replaceChildren();
 const usable=values.map(v=>Number(v?.[key])).filter(n=>Number.isFinite(n)&&n>=0);
 if(!usable.length){root.append(el("p","muted","No measurements recorded yet."));return;}
 const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
 svg.setAttribute("viewBox","0 0 760 225");svg.setAttribute("role","img");svg.setAttribute("aria-label",label);
 svg.setAttribute("preserveAspectRatio","none");svg.classList.add("v79-svg");
 const max=Math.max(20,...usable),min=0,usableWidth=722;
 for(let i=0;i<=4;i++){
  const y=22+i*42;const line=document.createElementNS(svg.namespaceURI,"line");
  for(const [k,v] of Object.entries({x1:"20",y1:y,x2:"742",y2:y,stroke:"#244357","stroke-dasharray":"4 8"}))line.setAttribute(k,String(v));
  svg.append(line);
 }
 const points=usable.map((v,i)=>[20+usableWidth*i/Math.max(usable.length-1,1),190-(v-min)/Math.max(max-min,1)*162]);
 const poly=document.createElementNS(svg.namespaceURI,"polyline");
 poly.setAttribute("points",points.map(([x,y])=>x.toFixed(1)+","+y.toFixed(1)).join(" "));
 poly.setAttribute("fill","none");poly.setAttribute("stroke",stroke);poly.setAttribute("stroke-width","3.8");
 poly.setAttribute("stroke-linejoin","round");poly.setAttribute("stroke-linecap","round");svg.append(poly);
 for(const [x,y] of [points[0],points[points.length-1]]){
  const dot=document.createElementNS(svg.namespaceURI,"circle");
  dot.setAttribute("cx",String(x));dot.setAttribute("cy",String(y));dot.setAttribute("r","4");
  dot.setAttribute("fill",stroke);svg.append(dot);
 }
 root.append(svg);
}
function bars(root,counts){
 root.replaceChildren();const items=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8);
 if(!items.length){root.append(el("p","muted","No packet metadata imported."));return;}
 const maximum=Math.max(...items.map(x=>x[1]),1);
 for(const [name,count] of items){
  const line=el("div","v79-bar");const label=el("span","",clean(name,32));const track=el("div","v79-bar-track");
  const filled=el("span","v79-bar-fill");filled.style.width=Math.max(2,count/maximum*100)+"%";track.append(filled);
  line.append(label,track,el("b","",fmt(count)));root.append(line);
 }
}
function renderStatus(s,qa){
 const services=Array.isArray(s.services)?s.services:[],tr=s.trend||[],history=Array.isArray(s.history)?s.history:[];
 const healthy=services.filter(x=>stateName(x.status)==="healthy"||stateName(x.status)==="up").length;
 const unhealthy=services.length-healthy;
 const avg=services.reduce((sum,x)=>sum+(Number(x.ms)||0),0)/Math.max(services.filter(x=>Number.isFinite(Number(x.ms))).length,1);
 put("nativeServices",services.length);put("nativeHealthy",healthy);put("nativeDegraded",unhealthy);
 put("nativeLatency",Math.round(avg)+" ms");
 put("nativeFreshness",s.last_check?"Latest check: "+when(s.last_check):"No successful monitoring cycle yet");
 const badge=q("nativeLiveBadge");
 const observed=s.mode==="live"&&services.length>0&&Boolean(s.last_check);
 badge.textContent=observed?"LIVE MEASUREMENTS":"MONITORING STATUS UNVERIFIED";
 badge.className="v79-chip "+(observed?"v79-chip-ok":"v79-chip-warn");
 const table=clear("nativeServiceRows");
 for(const service of services){
  const d=[service.http?"HTTP "+service.http:"No HTTP sample",service.ms!=null?service.ms+" ms":"Latency unavailable",
          service.cert_days!=null?"TLS "+service.cert_days+" days":"TLS not recorded"].join(" · ");
  table.append(panelRow(service.name,d,service.status));
 }
 lineChart(q("nativeTrend"),Array.isArray(tr)?tr:[],{label:"Measured public application response time over the last 24 hours"});
 const events=clear("nativeActivity");
 for(const item of history.slice(0,9).reverse()){
  events.append(panelRow(item.name,when(item.when)+" · "+clean(item.message,90),item.status));
 }
 if(!history.length)events.append(el("p","muted","No monitoring events recorded."));
 const lab=s.lab||{};
 put("nativeDell",lab.status?String(lab.status).toUpperCase():"NOT VERIFIED");
 put("nativeDellDetail",[lab.ip||"No lab IP",lab.rtt_ms!=null?lab.rtt_ms+" ms":"No RTT",lab.ssh||"SSH not assessed"].join(" · "));
 put("nativeInsight",!services.length?
  "No public-service measurements available. Do not assume services are healthy.":
  unhealthy?
    unhealthy+" applications require review. Verify current measurements and error messages before declaring an incident.":
    "All "+healthy+" checked public services responded normally in the latest monitoring cycle. This does not certify authenticated application workflows.");
 renderQA(qa);
}
function renderQA(qa){
 const rows=Array.isArray(qa.results)?qa.results:[],counts={pass:0,review:0,"auth-gated":0,fail:0};
 for(const r of rows)if(Object.hasOwn(counts,r.status))counts[r.status]++;
 put("nativeQaRun",qa.runId?"Run "+clean(qa.runId,60)+" · "+when(qa.at):"No automated browser QA run");
 put("nativeQaSummary",counts.pass+" passed · "+counts.review+" review · "+counts["auth-gated"]+" auth-gated · "+counts.fail+" failed");
 const target=clear("nativeQA");
 for(const row of rows){
  const tr=el("tr","");
  for(const val of [clean(row.name,50),clean(row.viewport,28),row.http??"—",row.navigateMs!=null?row.navigateMs+" ms":"—"]){
   tr.append(el("td","",String(val)));
  }
  const statusCol=el("td");statusCol.append(tag(row.status));tr.append(statusCol);
  const screenshot=el("td");
  if(typeof row.screenshot==="string"&&row.screenshot.length<240){
   const runId=String(qa.runId||"");
   const safeRun=/^[A-Za-z0-9_-]{6,80}$/.test(runId);
   const safeName=/^[A-Za-z0-9_-]{1,80}-(?:desktop|mobile)\.png$/.test(row.screenshot);
   if(safeRun&&safeName){
     const link=el("a","v79-text-link","View image ↗");
     link.href="/mission-control/api/qa/screenshot/"+encodeURIComponent(runId)+"/"+encodeURIComponent(row.screenshot);
     link.target="_blank";link.rel="noopener noreferrer";screenshot.append(link);
   }else screenshot.textContent="—";
  }else screenshot.textContent="—";
  tr.append(screenshot);target.append(tr);
 }
 if(!rows.length){const tr=el("tr");const td=el("td","", "No browser QA observations");td.colSpan=6;tr.append(td);target.append(tr);}
}
function renderNics(data){
 const target=clear("netpulseNicRows");
 const rows=Array.isArray(data.interfaces)?data.interfaces:[];
 for(const item of rows.filter(x=>x.name!=="lo").slice(0,16)){
  const detail="RX "+bytes(item.totalReceivedBytes)+" · TX "+bytes(item.totalTransmittedBytes)+
  (item.receivedBytes!=null?" · interval RX "+bytes(item.receivedBytes):"");
  target.append(panelRow(item.name,detail,"measured"));
 }
 if(!target.childElementCount)target.append(el("p","muted","No host network interfaces reported."));
 put("netpulseNicSource","Measured on Acer · "+rows.length+" interfaces · "+(rows[0]?.sampleIntervalSeconds||"initial")+" s interval");
}
function renderInvestigation(){
 const a=investigation?.analysis||{};const raw=Array.isArray(a.packets)?a.packets:[];
 const packets=raw.slice(0,3000);
 const protocolCounts=Object.create(null);const flows=new Map();let total=0;
 for(const p of packets){
  const proto=clean(p.protocol||"Unknown",40),src=clean(p.source||"?",65),dst=clean(p.destination||"?",65);
  protocolCounts[proto]=(protocolCounts[proto]||0)+1;
  const key=src+" → "+dst;flows.set(key,(flows.get(key)||0)+1);
  total+=Number(p.lengthBytes)||0;
 }
 put("netpulseImportStatus",packets.length+" captured frames · "+bytes(total)+" frame bytes · "+flows.size+" observed endpoint pairs · "+clean(a.provenance||"saved investigation",100));
 bars(q("netpulseProtocolBars"),protocolCounts);
 const flowTarget=clear("netpulseFlowRows");
 for(const [pair,count] of [...flows.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8))
  flowTarget.append(panelRow(pair,fmt(count)+" observed frames","observed"));
 const packetTarget=clear("netpulsePacketRows");
 for(const p of packets.filter(p=>packetFilter==="All"||p.protocol===packetFilter).slice(0,80)){
  const tr=el("tr");
  for(const val of [p.number,p.protocol,p.source,p.destination,p.lengthBytes,p.dnsQuery||"—"])tr.append(el("td","",clean(val,82)));
  packetTarget.append(tr);
 }
 const select=q("netpulseProtocolFilter"),selected=select.value;select.replaceChildren();
 select.append(new Option("All protocols","All"));
 for(const key of Object.keys(protocolCounts).sort())select.append(new Option(key,key));
 if([...select.options].some(o=>o.value===selected))select.value=selected;else select.value="All";
 put("netpulsePacketNote","Showing first 80 matching frames of "+fmt(packets.length)+". Evidence from the imported file, not a live capture.");
}
async function importFile(event){
 const file=event.target.files?.[0];if(!file)return;const importGeneration=generation;
 try{
  if(file.size>2_000_000||!file.name.toLowerCase().endsWith(".json"))throw Error("Choose a NetPulse JSON investigation under 2 MB.");
  const data=JSON.parse(await file.text());
  if(data?.format!=="v79-netpulse-investigation-v1"||!data.analysis||!Array.isArray(data.analysis.packets)||
    data.analysis.packets.length>3000)throw Error("Not a supported NetPulse investigation export (up to 3,000 frames).");
  for(const packet of data.analysis.packets){
   if(!packet||typeof packet!=="object"||typeof packet.protocol!=="string"||
      !Number.isFinite(Number(packet.lengthBytes)))throw Error("The investigation contains an invalid packet record.");
  }
  if(!active||importGeneration!==generation)return;
  investigation=window.NetPulseModel.normalize(data);packetFilter="All";renderInvestigation();
  document.dispatchEvent(new CustomEvent("sentinel:investigation",{detail:investigation}));
  put("netpulsePrivacy","Loaded only in this browser. No packet data was uploaded.");
 }catch(error){put("netpulseImportStatus","Import rejected: "+error.message);}
 finally{event.target.value="";}
}
function markLiveEvidenceUnavailable(){
 for(const id of ["nativeServices","nativeHealthy","nativeDegraded","nativeLatency","nativeDell"])put(id,"—");
 for(const id of ["nativeServiceRows","nativeTrend","nativeActivity","nativeQA","netpulseNicRows"])clear(id);
 for(const id of ["nativeFreshness","nativeQaRun","nativeQaSummary","nativeDellDetail","netpulseNicSource"])put(id,"Current evidence unavailable");
 put("nativeInsight","The latest measurements could not be verified. Do not infer that services are healthy.");
 const badge=q("nativeLiveBadge");badge.textContent="MONITORING STATUS UNVERIFIED";badge.className="v79-chip v79-chip-warn";
}
// The independent monitor polls every 5 minutes. Two missed cycles plus a
// small grace period must never be presented as current healthy evidence.
const MAX_MONITOR_AGE_MS=11*60*1000;
function currentMonitoringEvidence(s){
 if(s?.mode!=="live"||s.error||!Array.isArray(s.services)||!s.services.length)return false;
 const checkedAt=Date.parse(s.last_check);
 if(!Number.isFinite(checkedAt))return false;
 const age=Date.now()-checkedAt;
 return age>=-120_000&&age<=MAX_MONITOR_AGE_MS;
}
async function refresh(){
 if(!active||inflight)return;inflight=true;const refreshGeneration=generation;
 try{
  const [status,qa,nics]=await Promise.all([
   request("/mission-control/api/status"),
   request("/mission-control/api/qa/latest"),
   request("/api/v1/netpulse/interfaces")
  ]);
  if(!active||refreshGeneration!==generation)return;
  if(!currentMonitoringEvidence(status)){
   markLiveEvidenceUnavailable();
   put("nativeDataError","Monitoring evidence is missing, stale or degraded. Awaiting a fresh successful monitoring cycle.");
   return;
  }
  renderStatus(status,qa);renderNics(nics);
  put("nativeDataError","");
 }catch(e){
  if(!active||refreshGeneration!==generation)return;
  markLiveEvidenceUnavailable();
  put("nativeDataError","Latest measurements unavailable. Existing values have been cleared; no simulated values substituted.");
  if(e.status===401)stop();
 }finally{inflight=false;}
}
function start(){
 if(active)return;active=true;generation++;void refresh();
 refreshId=window.setInterval(()=>{if(!q("appSection")?.hidden)void refresh();},30000);
}
function stop(){
 active=false;generation++;if(refreshId!==null)window.clearInterval(refreshId);refreshId=null;
 markLiveEvidenceUnavailable();
 put("nativeDataError","");
 clear("netpulseProtocolBars");q("netpulseProtocolFilter").replaceChildren(new Option("All protocols","All"));
 put("netpulsePrivacy","Signed out; imported evidence cleared.");
 clear("netpulseFlowRows");clear("netpulsePacketRows");
 investigation=null;
 put("netpulseImportStatus","No investigation imported.");
}
document.addEventListener("sentinel:clear-investigation",()=>{investigation=null;packetFilter="All";renderInvestigation();put("netpulsePrivacy","Evidence cleared from browser memory.");});
document.addEventListener("sentinel:authenticated",start);
document.addEventListener("sentinel:signed-out",stop);
document.addEventListener("DOMContentLoaded",()=>{
 const input=q("netpulseImport");if(input)input.addEventListener("change",importFile);
 const filter=q("netpulseProtocolFilter");if(filter)filter.addEventListener("change",()=>{
   packetFilter=filter.value;
   if(investigation)renderInvestigation();
 });
 const refreshBtn=q("nativeRefresh");if(refreshBtn)refreshBtn.addEventListener("click",()=>void refresh());
 const sectionLinks=[...document.querySelectorAll('.nav-item[href^="#"]')];
 for(const link of sectionLinks)link.addEventListener("click",()=>{
  for(const item of sectionLinks)item.classList.toggle("active",item===link);
 });
 if(!q("appSection")?.hidden)start();
});
})();
