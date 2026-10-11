#!/usr/bin/env node
/**
 * Sentinel Browser QA v0.3.
 * Authorized public V79 sites only, no credentials, no clicks, no POST or form input.
 * Uses the machine's installed Google Chrome; downloads no browser binary.
 */
'use strict';
const fs=require('node:fs');
const path=require('node:path');
const { chromium }=require('playwright-core');
const {classify}=require('./classify');
const ROOT=path.resolve(__dirname,'..');
const OUT=path.join(ROOT,'data','qa-runs');
const LATEST=path.join(ROOT,'data','qa-latest.json');
const CONFIG=path.join(ROOT,'config.json');
const args=process.argv.slice(2);
const sampleArg=args.indexOf('--service');
const selected=sampleArg>=0?args[sampleArg+1]:null;
const dryRun=args.includes('--dry-run');
const targets=JSON.parse(fs.readFileSync(CONFIG,'utf8')).services;
const VIEWPORTS=[
 {name:'desktop', width:1366,height:820,isMobile:false,hasTouch:false},
 {name:'mobile',width:390,height:844,isMobile:true,hasTouch:true}
];
const DATE_TAG=()=>new Date().toISOString().replace(/[-:]/g,'').replace(/\..+$/,'Z');
function validate(t){
 if(!Array.isArray(t)||!t.length||t.length>20)throw Error('Invalid configuration');
 const names=new Set();
 for(const s of t){
  if(typeof s.name!=='string'||!s.name.trim()||typeof s.url!=='string')throw Error('Bad entry');
  const u=new URL(s.url);
  if(u.protocol!=='https:'||(u.hostname!=='v79sl.com'&&!u.hostname.endsWith('.v79sl.com'))||
     (u.port&&u.port!=='443')||u.username||u.password||u.hash)
     throw Error('Unsafe QA target '+s.url);
  if(names.has(s.name))throw Error('Duplicate service name');names.add(s.name);
 }
}
validate(targets);
const planned=selected?targets.filter(x=>x.name.toLowerCase()===selected.toLowerCase()):targets;
if(!planned.length)throw Error('No matching service: '+selected);
const safeName=s=>s.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,48);
function scrub(message){
 return String(message).replace(/https?:\/\/[^\s"'<>]+/g,raw=>{
  try{const u=new URL(raw);return u.origin+u.pathname;}catch{return '[redacted URL]';}
 }).slice(0,240);
}
function sanitizeUrl(value){
 try{const u=new URL(value); const validReturn=['ffpro','tiquet','marketing'];
  const r=u.hostname==='hub.v79sl.com'?u.searchParams.get('return'):null;
  return u.origin+u.pathname+(validReturn.includes(r)?'?return='+r:'');
 }catch{return '[unavailable]';}
}
if(dryRun){
 console.log(JSON.stringify({mode:'dry-run',planned:planned.map(s=>s.name),viewports:VIEWPORTS.map(v=>v.name),
  permissions:'No clicks, no forms, no non-GET requests, public HTTPS only'},null,2));
 process.exit(0);
}
async function inspect(browser,target,viewport,dir){
 const errors=[], warnings=[], responseEvents=[];
 const slug=safeName(target.name);
 const screenshot=slug+'-'+viewport.name+'.png';
 const context=await browser.newContext({
  viewport:{width:viewport.width,height:viewport.height},
  deviceScaleFactor:1,isMobile:viewport.isMobile,hasTouch:viewport.hasTouch,
  reducedMotion:'reduce',permissions:[],
  serviceWorkers:'block',javaScriptEnabled:true,
  ignoreHTTPSErrors:false,acceptDownloads:false,
 });
 const page=await context.newPage();
 page.setDefaultTimeout(7000);
 page.on('pageerror', e=>{if(errors.length<12)errors.push(scrub(e.message||e));});
 page.on('console',m=>{if(m.type()==='error'&&errors.length<12)errors.push(scrub('console: '+m.text()));});
 page.on('response',r=>{
  const status=r.status();
  if(status<400 || responseEvents.length>=30)return;
  try{
   const u=new URL(r.url());
   responseEvents.push({status,host:u.hostname.toLowerCase(),path:u.pathname.slice(0,130),
      resource:r.request().resourceType(),method:r.request().method()});
  }catch{}
 });
 page.on('dialog',async dialog=>{warnings.push('Browser dialog blocked: '+dialog.type());await dialog.dismiss().catch(()=>{});});
 // Site resources may issue telemetry, authenticate visitors or write state. Block every non-idempotent HTTP method.
 let blockedRequests=0;
 await page.route('**/*', async route=>{
  const req=route.request();
  if(!['GET','HEAD'].includes(req.method())) {
   blockedRequests++;
   return route.abort('blockedbyclient');
  }
  return route.continue();
 });
 const started=Date.now();
 let http=null,navigated=false,navigateError=null;
 try{
  const response=await page.goto(target.url,{waitUntil:'domcontentloaded',timeout:25000});
  http=response?response.status():null;
  navigated=true;
  await page.waitForTimeout(1800);
 }catch(e){navigateError=String(e.message||e).slice(0,240);}
 let meta={title:'',finalUrl:'',bodyChars:0,heading:'',
  scrollWidth:0,viewportWidth:viewport.width,readyState:null};
 try{
  meta=await page.evaluate(()=>{
   const text=document.body?.innerText||'';
   return {
    title:document.title||'',finalUrl:location.href,bodyChars:text.trim().length,
    heading:(document.querySelector('h1')?.innerText||'').trim().slice(0,100),
    scrollWidth:document.documentElement.scrollWidth,
    viewportWidth:window.innerWidth,readyState:document.readyState
   };
  });
 }catch(e){warnings.push('DOM inspection unavailable');}
 const actualUrl=meta.finalUrl||target.url;
 let redirectSafe=true;
 try{
  const u=new URL(actualUrl);
  redirectSafe=u.protocol==='https:'&&(u.hostname==='v79sl.com'||u.hostname.endsWith('.v79sl.com'));
 }catch{redirectSafe=false;}
 if(!redirectSafe)warnings.push('Navigation ended outside the configured V79 domain allowlist');
 if(meta.scrollWidth>meta.viewportWidth+24)warnings.push('Horizontal overflow: '+(meta.scrollWidth-meta.viewportWidth)+' px');
 if(meta.bodyChars<35)warnings.push('Little visible page text; inspect screenshot for blank shell');
 if(!meta.title)warnings.push('Missing document title');
 if(blockedRequests)warnings.push(blockedRequests+' non-GET requests blocked to prevent writes or login');
 // Console errors are correlated with observed HTTP auth checks by classify().
 try{
  await page.screenshot({path:path.join(dir,screenshot),fullPage:false,animations:'disabled',timeout:10000});
 }catch(e){warnings.push('Screenshot failed: '+String(e.message).slice(0,100));}
 const result={
  name:target.name, source:target.url,viewport:viewport.name,
  navigated,http,navigateMs:Date.now()-started,
  finalUrl:sanitizeUrl(actualUrl), title:meta.title,heading:meta.heading,
  bodyChars:meta.bodyChars, horizontalOverflowPx:Math.max(0,meta.scrollWidth-meta.viewportWidth),
  blockedRequests, errors, warnings, responseEvents, navigationError:navigateError,
  screenshot:fs.existsSync(path.join(dir,screenshot))?screenshot:null
 };
 const interpretation=classify({...result,finalUrl:actualUrl});
 Object.assign(result,interpretation);
 delete result.navigated;
 await Promise.race([context.close(),new Promise(resolve=>setTimeout(resolve,4000))]);
 return result;
}
async function main(){
 fs.mkdirSync(OUT,{recursive:true,mode:0o700});
 const id=DATE_TAG();
 const runDir=path.join(OUT,id);
 fs.mkdirSync(runDir,{recursive:true,mode:0o700});
 const report={version:1,mode:'public-browser-qa',runId:id,at:new Date().toISOString(),
  policy:'Public pages only. No account logins, no clicks, blocked POST/PUT/PATCH/DELETE.',
  browsers:'Installed Google Chrome (headless)',
  viewports:VIEWPORTS.map(v=>({name:v.name,width:v.width,height:v.height})),
  services:planned.map(s=>s.name),results:[],complete:false};
 console.log('V79 Sentinel Browser QA - '+planned.length+' approved services, 2 viewports');
 const saveProgress=()=>{
  const tmp=path.join(runDir,'report.json.tmp');
  fs.writeFileSync(tmp,JSON.stringify(report,null,2)+'\n',{mode:0o600});
  fs.renameSync(tmp,path.join(runDir,'report.json'));
 };
 saveProgress();
 const browser=await chromium.launch({
  headless:true,executablePath:'/usr/bin/google-chrome',
  args:['--disable-dev-shm-usage']
 });
 try{
  for(const service of planned){
   for(const viewport of VIEWPORTS){
    console.log('Checking '+service.name+' ('+viewport.name+')');
    let result;
    try {result=await inspect(browser,service,viewport,runDir);}
    catch(e){
     result={name:service.name,source:service.url,viewport:viewport.name,status:'fail',
      http:null,errors:[],warnings:[],navigationError:String(e.message||e).slice(0,250),
      screenshot:null};
    }
    report.results.push(result);
    saveProgress();
    console.log('  '+result.status.toUpperCase()+' HTTP '+result.http+
      ' visible chars '+(result.bodyChars||0)+' issues '+(result.warnings||[]).length);
    await new Promise(r=>setTimeout(r,600)); // avoid burst load
   }
  }
  report.complete=true;
  saveProgress();
 }finally{await Promise.race([browser.close(),new Promise(resolve=>setTimeout(resolve,5000))]);}
 const json=JSON.stringify(report,null,2)+'\n';
 fs.writeFileSync(path.join(runDir,'report.json'),json,{mode:0o600});
 // A single-service test should not replace the complete multi-service dashboard report.
 if(!selected){
  const tmp=LATEST+'.tmp-'+process.pid;
  fs.writeFileSync(tmp,json,{mode:0o600});
  fs.renameSync(tmp,LATEST);
 }
 const counts=report.results.reduce((o,r)=>(o[r.status]=(o[r.status]||0)+1,o),{});
 console.log('Completed '+report.results.length+' checks:',JSON.stringify(counts));
 console.log('Saved '+path.join(runDir,'report.json'));
 if(!report.complete)process.exitCode=1;
}
main().catch(e=>{console.error('QA runner fatal error:',e.message);process.exitCode=1;});
