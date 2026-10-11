"use strict";
// Untrusted site/device/incident names are always rendered with textContent.
let csrf="";
let role="";
let signedInUsername="";
const byId=id=>document.getElementById(id);
const loginSection=byId("loginSection"),appSection=byId("appSection");
function node(tag,cls,text){
 const e=document.createElement(tag);
 if(cls)e.className=cls;
 if(text!==undefined&&text!==null)e.textContent=String(text);
 return e;
}
function clear(id){byId(id).replaceChildren();}
function showLogin(){
 document.dispatchEvent(new Event("sentinel:signed-out"));
 loginSection.hidden=false;appSection.hidden=true;byId("logout").hidden=true;csrf="";
 role="";signedInUsername="";
 byId("agentCredential").textContent="";byId("oneTimeSecret").hidden=true;
 byId("mfaSecret").textContent="";byId("mfaUri").textContent="";
 byId("mfaSetup").hidden=true;byId("disableOperatorPassword").value="";
 byId("recoveryCodes").textContent="";byId("recoveryCodesPanel").hidden=true;
}
function showApp(){
 document.dispatchEvent(new Event("sentinel:authenticated"));
 loginSection.hidden=true;appSection.hidden=false;byId("logout").hidden=false;
}
async function api(url,{method="GET",data,withCsrf=false}={}){
 const headers={};
 if(data!==undefined)headers["Content-Type"]="application/json";
 if(withCsrf)headers["X-Sentinel-CSRF"]=csrf;
 const response=await fetch(url,{method,headers,credentials:"same-origin",
   body:data===undefined?undefined:JSON.stringify(data),cache:"no-store"});
 const payload=await response.json().catch(()=>null);
 if(!response.ok)throw Object.assign(Error(payload?.error||"Request failed"),{status:response.status});
 return payload;
}
const status=(value)=>{
 const label=node("span","state "+value,value.replaceAll("_"," "));
 return label;
};
function entry(container,title,subtitle,kind,action){
 const wrapper=node("article","incident");
 const top=node("div","entry-top");
 top.append(node("strong","",title),status(kind));
 wrapper.append(top,node("div","entry-sub",subtitle));
 if(action)wrapper.append(action);
 container.append(wrapper);
}
function dateLabel(epoch){
 if(!epoch)return"Never";
 return new Date(epoch*1000).toLocaleString();
}
function render(snapshot){
 const data=snapshot||{};
 const active=(data.incidents||[]).filter(i=>i.state!=="resolved");
 byId("customerCount").textContent=(data.customers||[]).length;
 byId("siteCount").textContent=(data.sites||[]).length;
 byId("incidentCount").textContent=active.length;
 byId("agentCount").textContent=(data.agents||[]).filter(a=>a.connection==="online").length+"/"+(data.agents||[]).length;
 byId("incidentTag").textContent=active.length+" active";
 clear("incidents");
 const box=byId("incidents");
 if(!active.length)box.append(node("p","empty","No active incidents. Resolved incident history is retained."));
 for(const i of active){
  const action=i.state==="open"&&role!=="viewer"?node("button","small-action","Acknowledge"):null;
  if(action){
   action.type="button";
   action.addEventListener("click",async()=>{
    action.disabled=true;
    try{await api("/api/v1/incidents/ack",{method:"POST",withCsrf:true,data:{incident_id:i.id}});await refresh();}
    catch(e){alert(e.message);}finally{action.disabled=false;}
   });
  }
  entry(box,i.title,i.customer_name+" · "+i.site_name+
       " · "+i.affected_checks+" affected check(s) · "+dateLabel(i.opened),
       i.state,action);
 }
 clear("agents");
 const agents=byId("agents");
 if(!(data.agents||[]).length)agents.append(node("p","empty","No Edge Agents enrolled."));
 for(const a of data.agents||[]){
  const site=(data.sites||[]).find(x=>x.id===a.site_id);
  const details=(site?.customer_name||"Customer")+" · "+(site?.name||"Site")+
        " · Last heard "+dateLabel(a.last_seen);
  const row=node("article","agent");
  const top=node("div","entry-top");
  top.append(node("strong","",a.name),status(a.connection));
  row.append(top,node("div","entry-sub",details));
  if(!a.revoked&&role==="admin"){
    const revoke=node("button","small-action","Revoke agent");
    revoke.type="button";
    revoke.addEventListener("click",async()=>{
      if(!confirm("Revoke this simulated Edge Agent? Its credential will stop working."))return;
      revoke.disabled=true;
      try{
        await api("/api/v1/agents/revoke",{method:"POST",withCsrf:true,
          data:{agent_id:a.id}});
        await refresh();
      }catch(e){showOperation(e.message,true);}
      finally{revoke.disabled=false;}
    });
    row.append(revoke);
  }
  agents.append(row);
 }
 clear("sites");
 const sites=byId("sites");
 if(!(data.sites||[]).length)sites.append(node("p","empty","No managed sites configured."));
 for(const site of data.sites||[]){
  const card=node("div","site");
  card.append(node("strong","",site.name),node("small","",site.customer_name));
  const n=(data.assets||[]).filter(a=>a.site_id===site.id).length;
  card.append(node("small","",n+" configured asset(s)"));
  sites.append(card);
 }
 clear("assets");
 const table=node("table");
 const head=node("thead");
 const hr=node("tr");
 for(const column of ["DEVICE","CUSTOMER","SITE","ADDRESS","TYPE","CHECK STATE"])
  hr.append(node("th","",column));
 head.append(hr);table.append(head);
 const body=node("tbody");
 for(const a of data.assets||[]){
  const tr=node("tr");
  const site=(data.sites||[]).find(s=>s.id===a.site_id);
  const check=(data.checks||[]).filter(c=>c.asset_id===a.id);
  for(const value of [a.name,site?.customer_name,site?.name,a.address,a.type,
                         check.map(c=>c.state).join(", ")||"Not configured"])
    tr.append(node("td","",value||"—"));
  body.append(tr);
 }
 table.append(body);byId("assets").append(table);
 if(!(data.assets||[]).length)byId("assets").append(node("p","empty","No assets have been added."));
 const metrics=data.metrics||{};
 byId("resolvedCount").textContent=String(metrics.resolved_incidents??0);
 byId("recoveryTime").textContent=metrics.mean_recovery_seconds===null||
   metrics.mean_recovery_seconds===undefined?"—":metrics.mean_recovery_seconds+"s";
 byId("mockEventCount").textContent=String(data.pending_mock_events??0);
 clear("maintenanceList");
 const maintenanceList=byId("maintenanceList");
 for(const m of data.maintenance||[]){
   if(m.ends*1000<=Date.now())continue;
   entry(maintenanceList,"Maintenance · "+m.site_name,
     m.customer_name+" · "+m.reason+" · ends "+dateLabel(m.ends),"acknowledged");
 }
 clear("history");
 const historyBox=byId("history");
 if(!(data.history||[]).length)historyBox.append(node("p","empty","No incident events recorded."));
 for(const event of data.history||[]){
   const kind=event.action==="incident.opened"?"open":
      event.action==="incident.resolved"?"resolved":"acknowledged";
   entry(historyBox,event.action.replaceAll("."," · "),
      event.customer_name+" · "+event.site_name+" · "+event.title+
      " · "+dateLabel(event.seen),kind);
 }
 byId("refreshTime").textContent="Last local update: "+dateLabel(data.generated_at);
 updateInventorySelectors(data);
}
async function refreshOwnerPilot(){
 const panel=byId("ownerPilotPanel");
 if(role!=="admin"){panel.hidden=true;return;}
 panel.hidden=false;
 try{
  const p=await api("/api/v1/owner-pilot");
  const current=p.data_current===true;
  byId("ownerPilotBadge").textContent=current?"LIVE EVIDENCE":"STALE / UNVERIFIED";
  byId("ownerPilotStatus").textContent=(current?p.connectivity_status.replaceAll("_"," "):
    "Pilot observation missing or stale; do not assume equipment is online.")+
    (p.data_age_seconds!==null?" · last reading "+p.data_age_seconds+"s ago":"");
  byId("ownerPilotChecks").replaceChildren();
  for(const c of p.approved_checks||[]){
   entry(byId("ownerPilotChecks"),c.ip+" · TCP "+c.port,
     "Connectivity only · "+(c.latency_ms??"—")+" ms",
     !current?"unverified":c.connected?"online":"open");
  }
  byId("ownerPilotApps").replaceChildren();
  const deepFresh=p.service_readiness_current===true;
  for(const a of p.applications||[]){
   const semantics=deepFresh?a.service_readiness:"unverified";
   const note=deepFresh?"GET "+(a.service_path||"—")+" · HTTPS "+
     (a.service_http_status??"—")+" · "+semantics:
     "Health endpoint evidence missing or stale · homepage HTTP "+(a.http_status??"—");
   entry(byId("ownerPilotApps"),a.app,note,
     semantics==="ready"?"online":semantics==="failed"?"open":"unverified");
  }
  const service=p.service_readiness_summary||{};
  const info="Verified app readiness: "+(deepFresh?(service.ready??0)+"/8 ready · "+
     (service.protected??0)+" protected · "+(service.failed??0)+" failed":
     "stale / unverified")+". TLS: "+p.cert_status+
    (p.client_hours_remaining!==null?" · Agent "+p.client_hours_remaining+"h":"")+
    (p.server_hours_remaining!==null?" · Receiver "+p.server_hours_remaining+"h":"")+
    (p.ca_days_remaining!==null?" · CA "+p.ca_days_remaining+" days":"")+
    " · queued "+(p.queue_pending??"unknown")+
    ". Limited TCP/HEAD checks; not full application or SLA health.";
  byId("ownerPilotSecurity").textContent=info;
  const mockCurrent=p.mock_incidents_current===true && p.mock_integrations==="disabled";
  byId("ownerMockBadge").textContent=mockCurrent?"MOCK ONLY":"STALE / UNAVAILABLE";
  byId("ownerMockIncidents").replaceChildren();
  if(mockCurrent){
   const events=p.mock_events_pending??"unknown";
   byId("ownerMockStatus").textContent=(p.mock_incidents_open??"unknown")+
     " open qualified mock incidents · "+events+
     " undelivered mock events · no Tiquet ticket created";
   for(const i of p.mock_incidents||[]){
    entry(byId("ownerMockIncidents"),i.app+" · "+i.state.toUpperCase(),
      "SIMULATION ONLY · detected "+dateLabel(i.opened_at)+
        (i.resolved_at?" · recovered "+dateLabel(i.resolved_at):""),
      i.state==="open"?"open":"unverified");
   }
  }else{
   byId("ownerMockStatus").textContent="Mock incident evidence missing or stale; incident count unknown. No external tickets are enabled.";
  }
 }catch(error){
  byId("ownerMockBadge").textContent="UNAVAILABLE";
  byId("ownerMockStatus").textContent="Qualified mock incident evidence could not be verified.";
  byId("ownerMockIncidents").replaceChildren();
  byId("ownerPilotBadge").textContent="UNAVAILABLE";
  byId("ownerPilotStatus").textContent="Real pilot telemetry temporarily unavailable ("+error.status+"). Synthetic data below remains separate.";
  byId("ownerPilotChecks").replaceChildren();
  byId("ownerPilotApps").replaceChildren();
 }
}
async function refreshTicketReviews(){
 const panel=byId("sentinelReviewPanel");
 if(role!=="admin"){panel.hidden=true;return;}
 panel.hidden=false;
 const list=byId("sentinelReviewList"),form=byId("sentinelReviewForm");
 const select=byId("sentinelReviewIncident");
 list.replaceChildren();select.replaceChildren();form.hidden=true;
 try{
  const data=await api("/api/v1/sentinel/reviews");
  const proposals=data.proposals||[];
  byId("sentinelReviewBadge").textContent=data.enabled?"OFFLINE REVIEW ONLY":"NOT CONFIGURED";
  if(!data.enabled){
   list.append(node("p","empty","Review is disabled until authorized source and signing keys are installed."));
   return;
  }
  if(!proposals.length){
   list.append(node("p","empty","No owner incidents have independently verified signed evidence."));
   return;
  }
  for(const item of proposals){
   entry(list,item.title,item.site+" · "+item.severity+" · "+item.detected_at,
     "acknowledged");
   const opt=node("option","",item.title+" · "+item.site);
   opt.value=item.incident_id;select.append(opt);
  }
  form.hidden=false;
 }catch(_err){
  byId("sentinelReviewBadge").textContent="UNAVAILABLE";
  list.append(node("p","empty","Unable to verify eligible owner incidents."));
 }
}
byId("sentinelReviewForm").addEventListener("submit",async event=>{
 event.preventDefault();
 const form=event.currentTarget;
 const confirmField=form.elements.namedItem("confirmed");
 if(role!=="admin" || !confirmField.checked)return;
 const button=form.querySelector('button[type="submit"]');
 button.disabled=true;
 const otp=form.elements.namedItem("otp");
 const msg=byId("sentinelReviewMessage");
 try{
  const result=await api("/api/v1/sentinel/approve",{method:"POST",withCsrf:true,
   data:{incident_id:byId("sentinelReviewIncident").value,
         otp:otp.value,confirmed:true}});
  msg.textContent=result.queued?
   "Approved and stored in the OFFLINE queue. No live ticket has been sent.":
   "Existing approved proposal retained. No live ticket has been sent.";
  await refreshTicketReviews();
 }catch(_err){
  msg.textContent="Approval was not accepted. Recheck signed evidence and fresh MFA.";
 }finally{
  otp.value="";confirmField.checked=false;button.disabled=false;
 }
});
async function refresh(){
 try{render(await api("/api/v1/dashboard"));}
 catch(err){if(err.status===401)showLogin();else byId("refreshTime").textContent="Refresh failed: "+err.message;}
}
async function checkSession(){
 try{
  const session=await api("/api/v1/session");
  csrf=session.csrf;
  role=session.role;signedInUsername=session.username;
  byId("roleLabel").textContent=role.toUpperCase();
  byId("operatorTools").hidden=role!=="admin";
  byId("operatorAdminPanel").hidden=role!=="admin";
  showApp();
  await refresh();
  await refreshOwnerPilot();
  await refreshTicketReviews();
  try{await refreshSecurity();}
  catch(err){
    securityMessage("Security settings temporarily unavailable. Your signed-in dashboard remains usable.",true);
  }
 }catch(err){
   if(err.status===401){showLogin();}
   else{
     byId("loginError").textContent="Unable to verify session. Please retry.";
     if(!csrf)showLogin();
   }
 }
}
byId("loginForm").addEventListener("submit",async event=>{
 event.preventDefault();
 const loginError=byId("loginError");
 loginError.textContent="";
 const button=event.currentTarget.querySelector("button");
 button.disabled=true;
 try{
  await api("/api/v1/login",{method:"POST",data:{
   username:byId("username").value,
   password:byId("password").value,
   otp:byId("loginOtp").value,
   recovery_code:byId("loginRecovery").value
  }});
  byId("password").value="";byId("loginOtp").value="";byId("loginRecovery").value="";
  await checkSession();
 }catch(err){loginError.textContent=err.message;}
 finally{button.disabled=false;}
});
byId("logout").addEventListener("click",async()=>{
 try{await api("/api/v1/logout",{method:"POST",withCsrf:true});}finally{showLogin();}
});
function showOperation(message,isError=false){
 const el=byId("operationStatus");
 el.textContent=message;el.classList.toggle("fail",isError);
}
function replaceOptions(id,items,format){
 const select=byId(id),selected=select.value;
 const fragment=document.createDocumentFragment();
 for(const item of items){
   const option=document.createElement("option");
   option.value=item.id;
   option.textContent=format(item);
   fragment.append(option);
 }
 select.replaceChildren(fragment);
 select.disabled=items.length===0;
 if(items.some(x=>x.id===selected))select.value=selected;
}
function updateInventorySelectors(data){
 const sites=data.sites||[],assets=data.assets||[],customers=data.customers||[];
 replaceOptions("siteCustomer",customers,c=>c.name);
 replaceOptions("assetSite",sites,s=>s.customer_name+" · "+s.name);
 replaceOptions("agentSite",sites,s=>s.customer_name+" · "+s.name);
 replaceOptions("maintenanceSite",sites,s=>s.customer_name+" · "+s.name);
 replaceOptions("checkAsset",assets,a=>{
   const site=sites.find(s=>s.id===a.site_id);
   return (site?.customer_name||"Customer")+" · "+(site?.name||"Site")+" · "+a.name;
 });
}
const routes=[
 ["customerForm","/api/v1/customers","Customer added"],
 ["siteForm","/api/v1/sites","Site added"],
 ["assetForm","/api/v1/assets","Asset added"],
 ["checkForm","/api/v1/checks","Simulated check added"],
 ["agentForm","/api/v1/agents/enroll","Simulated Edge Agent enrolled"],
 ["maintenanceForm","/api/v1/maintenance","Site maintenance scheduled"],
];
for(const [formId,route,description] of routes){
 const form=byId(formId);
 form.addEventListener("submit",async event=>{
   event.preventDefault();
   const button=form.querySelector('button[type="submit"]');
   button.disabled=true;
   showOperation("Saving lab-only configuration…");
   try{
     const fields=Object.fromEntries(new FormData(form).entries());
     if(formId==="maintenanceForm")fields.hours=Number(fields.hours);
     const result=await api(route,{method:"POST",withCsrf:true,data:fields});
     if(result.credential){
       byId("agentCredential").textContent=result.credential;
       byId("oneTimeSecret").hidden=false;
     }
     showOperation(description+". Stored on Acer staging only.");
     form.reset();
     await refresh();
   }catch(err){showOperation(err.message,true);}
   finally{button.disabled=false;}
 });
}
byId("hideCredential").addEventListener("click",()=>{
 byId("agentCredential").textContent="";
 byId("oneTimeSecret").hidden=true;
});
function securityMessage(message,isError=false){
 byId("mfaState").textContent=message;
 byId("mfaState").classList.toggle("error",isError);
}
async function refreshSecurity(){
 const state=await api("/api/v1/mfa/status");
 byId("mfaBeginForm").hidden=state.enabled;
 securityMessage(state.enabled
   ?"Authenticator MFA enabled for this operator. A fresh code is required at every sign-in."
   :"MFA is not enabled for this operator. Enroll only when your authenticator is available.");
 if(role==="admin")await refreshOperators();
}
async function refreshOperators(){
 if(role!=="admin")return;
 const result=await api("/api/v1/operators");
 const list=byId("operatorList");
 list.replaceChildren();
 for(const op of result.operators){
   const panel=node("div","agent");
   const head=node("div","entry-top");
   head.append(node("strong","",op.username),status(op.disabled?"revoked":"online"));
   panel.append(head,node("div","entry-sub",
      op.role+" · MFA "+(op.mfa_enabled?"enabled":"not enrolled")));
   if(!op.disabled && op.username!==signedInUsername){
      const button=node("button","small-action","Disable account");
      button.type="button";
      button.addEventListener("click",async()=>{
         const pw=byId("disableOperatorPassword").value;
         if(!pw){securityMessage("Enter your admin password to disable an operator.",true);return;}
         if(!confirm("Disable this staging operator and revoke all sessions?"))return;
         button.disabled=true;
         try{
          await api("/api/v1/operators/disable",{method:"POST",withCsrf:true,
             data:{operator_id:op.id,current_password:pw}});
          byId("disableOperatorPassword").value="";
          await refreshOperators();
          securityMessage("Staging operator disabled and sessions revoked.");
         }catch(e){securityMessage(e.message,true);}
         finally{button.disabled=false;}
      });
      panel.append(button);
   }
   list.append(panel);
 }
}
byId("createOperatorForm").addEventListener("submit",async event=>{
 event.preventDefault();
 const form=event.currentTarget;
 const button=form.querySelector('button[type="submit"]');
 button.disabled=true;
 try{
  const data=Object.fromEntries(new FormData(form).entries());
  const added=await api("/api/v1/operators",{method:"POST",withCsrf:true,data});
  form.reset();
  securityMessage("Created staging operator: "+added.username+". Set up MFA before real use.");
  await refreshOperators();
 }catch(e){securityMessage(e.message,true);}
 finally{button.disabled=false;}
});
byId("mfaBeginForm").addEventListener("submit",async event=>{
 event.preventDefault();
 const form=event.currentTarget;
 const button=form.querySelector('button[type="submit"]');
 button.disabled=true;
 try{
  const data=Object.fromEntries(new FormData(form).entries());
  const result=await api("/api/v1/mfa/start",{method:"POST",withCsrf:true,data});
  form.reset();
  byId("mfaSecret").textContent="Setup key: "+result.secret;
  byId("mfaUri").textContent=result.uri;
  byId("mfaSetup").hidden=false;
  securityMessage("MFA setup started. Enter the next code from your authenticator.");
 }catch(e){securityMessage(e.message,true);}
 finally{button.disabled=false;}
});
byId("mfaConfirmForm").addEventListener("submit",async event=>{
 event.preventDefault();
 const form=event.currentTarget;
 const button=form.querySelector('button[type="submit"]');
 button.disabled=true;
 try{
  const data=Object.fromEntries(new FormData(form).entries());
  const result=await api("/api/v1/mfa/confirm",{method:"POST",withCsrf:true,data});
  form.reset();
  byId("mfaSecret").textContent="";byId("mfaUri").textContent="";
  byId("mfaSetup").hidden=true;
  const codes=Array.isArray(result.recovery_codes)?result.recovery_codes:[];
  if(codes.length!==8)throw Error("MFA enabled, but recovery confirmation was incomplete; seek supervised recovery.");
  byId("recoveryCodes").textContent=codes.join("\n");
  byId("recoveryCodesPanel").hidden=false;
  byId("mfaBeginForm").hidden=true;
  securityMessage("MFA enabled. Save the recovery codes before leaving this screen.");
 }catch(e){securityMessage(e.message,true);}
 finally{button.disabled=false;}
});
byId("hideMfaSetup").addEventListener("click",()=>{
 byId("mfaSecret").textContent="";byId("mfaUri").textContent="";
 byId("mfaSetup").hidden=true;
});
byId("savedRecoveryCodes").addEventListener("click",()=>{
 showLogin();
 byId("loginError").textContent="MFA enabled. Sign in using a fresh authenticator code or an unused recovery code.";
});
checkSession();
setInterval(()=>{if(!appSection.hidden && byId("recoveryCodesPanel").hidden)refresh();},15000);
// Real owner-pilot evidence is separately refreshed; never mix it with the
// synthetic dashboard counters or hide login errors behind telemetry failures.
setInterval(()=>{if(!appSection.hidden && byId("recoveryCodesPanel").hidden)
 refreshOwnerPilot();},60000);
