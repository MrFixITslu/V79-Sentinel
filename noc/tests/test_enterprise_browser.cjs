"use strict";
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawn}=require('node:child_process');
const {chromium}=require('../../qa/node_modules/playwright-core');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-enterprise-test-'));
const py=spawn('/usr/bin/python3',['-u','-c','from pathlib import Path; import sys; from noc.server import NocAPI,bootstrap; from noc.store import NocStore; db=Path(sys.argv[1]); bootstrap(NocStore(db),"mission-admin","synthetic-long-private-operator-password"); server=NocAPI("127.0.0.1",0,db); print(server.server_port,flush=True); server.serve_forever()',path.join(tmp,'isolated.sqlite3')],{cwd:path.resolve(__dirname,'../..')});
const packet={number:1,timestamp:1234567890,lengthBytes:64,protocol:'DNS',source:'192.168.100.20',destination:'192.168.100.1',sourcePort:51111,destinationPort:53,dnsQuery:'example.org'};
const investigation={format:'v79-netpulse-investigation-v1',analysis:{source:'isolated QA fixture',packets:[packet,{...packet,number:2,protocol:'TLS',dnsQuery:null,tlsServerName:'<img src=x onerror=alert(1)>'}]}};
async function main(){
 const port=await new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(Error('Isolated server startup timeout')),15000);py.stdout.once('data',d=>{clearTimeout(t);resolve(Number(d.toString().trim()));});py.once('exit',code=>reject(Error('Server exited '+code)));});
 const browser=await chromium.launch({executablePath:process.env.SENTINEL_CHROME_PATH||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/mission-control/api/status',r=>r.fulfill({json:{mode:'live',last_check:new Date().toISOString(),services:[{name:'Fixture website',status:'up',http:200,ms:123},{name:'Fixture hub',status:'up',http:200,ms:145},{name:'Fixture tickets',status:'up',http:200,ms:118},{name:'Fixture academy',status:'up',http:200,ms:121},{name:'Fixture finance',status:'up',http:200,ms:155},{name:'Fixture marketing',status:'up',http:200,ms:139},{name:'Fixture POS',status:'up',http:200,ms:133}],trend:[{ms:123},{ms:145},{ms:118},{ms:121},{ms:155},{ms:139},{ms:133}],history:[{name:'Fixture website',when:new Date(Date.now()-40*60*1000).toISOString(),status:'up',message:'Synthetic recovery event'}],lab:{status:'offline',ip:'192.0.2.50',rtt_ms:null,ssh:'not tested'}}}));
  await page.route('**/mission-control/api/qa/latest',r=>r.fulfill({json:{runId:'synthetic_qa_older',at:new Date(Date.now()-48*60*60*1000).toISOString(),results:[{name:'Fixture website',viewport:'desktop',http:200,navigateMs:185,status:'pass'}]}}));
  await page.route('**/api/v1/network/capabilities',r=>r.fulfill({json:{captureReason:'Synthetic operator QA: no live capture',targets:[{name:'Hub',host:'example.org',port:443}],traceroute:false}}));
  await page.route('**/api/v1/network/diagnostic',r=>r.fulfill({json:{target:'Synthetic fixture',at:'Test time',note:'No network probe performed',resolutionMs:0,results:[]}}));
  await page.goto('http://127.0.0.1:'+port,{waitUntil:'domcontentloaded'});
  assert(await page.locator('#loginSection').isVisible());
  await page.locator('#username').fill('mission-admin');await page.locator('#password').fill('synthetic-long-private-operator-password');await page.locator('#loginForm button').click();await page.locator('#appSection').waitFor({state:'visible'});
  await page.locator('#nativeServices').getByText('7',{exact:true}).waitFor();assert(await page.locator('#nativeTrend svg').isVisible());assert.equal(await page.locator('iframe').count(),0);
  await page.getByText('HISTORICAL QA · NOT CURRENT HEALTH',{exact:false}).waitFor();
  assert.equal(await page.locator('#nativeQaRun').getAttribute('data-qa-freshness'),'historical','Two-day-old QA must not be presented as current');
  assert.equal(await page.locator('#nativeDell').textContent(),'MONITOR REPORT: OFFLINE','Ambiguous pilot status must be qualified as monitor report');
  assert((await page.locator('.v79-source-disclaimer').textContent()).includes('does not confirm an outage'),'Untested pilot link needs evidence caveat');
  const failingStatus=r=>r.fulfill({status:503,json:{error:'synthetic unavailable'}});
  await page.route('**/mission-control/api/status',failingStatus);
  await page.locator('#nativeRefresh').click();
  await page.getByText('MONITORING STATUS UNVERIFIED',{exact:true}).waitFor();
  assert.equal(await page.locator('#nativeServices').textContent(),'—','Old healthy count must not survive refresh failure');
  assert.equal(await page.locator('#nativeServiceRows').locator('.v79-row').count(),0,'Old healthy service rows must be cleared');
  assert.equal(await page.locator('#nativeTrend svg').count(),0,'Old trend must be cleared');
  await page.unroute('**/mission-control/api/status',failingStatus);
  await page.locator('#nativeRefresh').click();
  await page.locator('#nativeServices').getByText('7',{exact:true}).waitFor();
  const staleStatus=r=>r.fulfill({json:{mode:'live',last_check:new Date(Date.now()-60*60*1000).toISOString(),services:[{name:'Stale website',status:'up',http:200,ms:12}],trend:[{ms:12}],history:[]}});
  await page.route('**/mission-control/api/status',staleStatus);
  await page.locator('#nativeRefresh').click();
  await page.getByText('Monitoring evidence is missing, stale or degraded.',{exact:false}).waitFor();
  assert.equal(await page.locator('#nativeServices').textContent(),'—','Stale monitoring counts must not be displayed');
  assert.equal(await page.locator('#nativeLiveBadge').textContent(),'MONITORING STATUS UNVERIFIED');
  assert.equal(await page.locator('#nativeTrend svg').count(),0,'Stale chart must be cleared');
  await page.unroute('**/mission-control/api/status',staleStatus);
  await page.locator('#nativeRefresh').click();
  await page.locator('#nativeServices').getByText('7',{exact:true}).waitFor();
  const degradedStatus=r=>r.fulfill({json:{mode:'live',error:'Synthetic collector exception',last_check:new Date().toISOString(),services:[{name:'Fixture website',status:'up',http:200,ms:123}],trend:[],history:[]}});
  await page.route('**/mission-control/api/status',degradedStatus);
  await page.locator('#nativeRefresh').click();
  await page.getByText('MONITORING STATUS UNVERIFIED',{exact:true}).waitFor();
  assert.equal(await page.locator('#nativeServices').textContent(),'—','Monitoring failure cannot retain a healthy count');
  await page.unroute('**/mission-control/api/status',degradedStatus);
  await page.locator('#nativeRefresh').click();
  await page.locator('#nativeServices').getByText('7',{exact:true}).waitFor();
  for(const route of ['devices','map','activity','alerts','diagnostics','design','customers','reports','settings','packets','overview']){await page.locator('.nav-item[data-page="'+route+'"]').click();await page.waitForFunction(key=>document.querySelector('.nav-item[aria-current="page"]')?.dataset.page===key,route);assert.equal(await page.locator('#enterprisePageTitle').textContent(),Object.entries({devices:'Devices',map:'Network Map',activity:'Web & App Activity',alerts:'Alerts & approvals',diagnostics:'Diagnostics',design:'Network Design',customers:'Managed customers',reports:'Reports & history',settings:'Sensors & security',packets:'Packet Explorer',overview:'Overview'}).find(x=>x[0]===route)[1]);}
  await page.locator('.nav-item[data-page="diagnostics"]').click();
  await page.locator('#enterpriseTCP').click();
  await page.locator('#enterpriseDiagResult').getByText(/Synthetic fixture/).waitFor();
  assert(await page.locator('#enterpriseTrace').isDisabled(),'Unsupported traceroute must stay disabled after TCP diagnostic');
  await page.locator('.nav-item[data-page="packets"]').click();await page.locator('#netpulseImport').setInputFiles({name:'fixture.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(investigation))});await page.locator('#enterprisePacketStatus').getByText(/2 frames/).waitFor();await page.locator('#enterprisePackets button').first().click();assert((await page.locator('#enterprisePacketDetail').textContent()).includes('does not prove'));assert((await page.locator('#enterpriseFlows').textContent()).includes('2'));
  await page.locator('#enterprisePacketSearch').fill('TLS');assert.equal(await page.locator('#enterprisePackets button').count(),1);await page.locator('#enterpriseMode').selectOption('analyst');assert(await page.locator('body').evaluate(n=>n.classList.contains('enterprise-analyst')));
  await page.locator('.nav-item[data-page="activity"]').click();assert((await page.locator('#enterpriseDomains').textContent()).includes('example.org'));assert.equal(await page.locator('#enterpriseDomains img').count(),0);
  await page.locator('.nav-item[data-page="design"]').click();await page.locator('#enterpriseDesignName').fill('Core Router');await page.locator('#enterpriseDesignKind').fill('Router');await page.getByRole('button',{name:'Add device',exact:true}).click();assert((await page.locator('#enterpriseDesignList').textContent()).includes('Core Router'));
  await page.locator('.nav-item[data-page="packets"]').click();await page.getByRole('button',{name:'Clear sensitive evidence',exact:true}).click();assert.equal(await page.locator('#enterpriseFlows').textContent(),'');assert(!(await page.locator('#enterpriseDomains').textContent()).includes('example.org'));assert.equal(await page.locator('#enterpriseExport').isDisabled(),true);await page.locator('#netpulseImport').setInputFiles({name:'fixture.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(investigation))});await page.locator('#enterprisePacketStatus').getByText(/2 frames/).waitFor();
  await page.locator('.nav-item[data-page="settings"]').click();await page.locator('#securityPanel').waitFor({state:'visible'});assert(await page.locator('#securityPanel').isVisible());assert(await page.locator('#operatorTools').isVisible());
  const screenshots=process.env.SENTINEL_QA_SCREENSHOTS_DIR||tmp;
  fs.mkdirSync(screenshots,{recursive:true});
  const captureRoute=async(route,filename)=>{
   await page.locator('.nav-item[data-page="'+route+'"]').click();
   await page.waitForFunction(key=>document.querySelector('.nav-item[aria-current="page"]')?.dataset.page===key,route);
   await page.evaluate(()=>window.scrollTo({top:0,left:0,behavior:'instant'}));
   await page.waitForFunction(()=>window.scrollY===0);
   assert(await page.evaluate(()=>document.querySelector('#appSection')?.lastElementChild?.tagName==='FOOTER'),'Shared application footer must follow every dynamic page');
   assert(await page.locator('.sidebar .nav').isVisible(),'Primary navigation missing on '+route);
   assert.equal(await page.locator('.nav-item[aria-current="page"]').count(),1,'One active navigation item expected');
   await page.screenshot({path:path.join(screenshots,filename)});
  };
  await captureRoute('map','enterprise-network-map-desktop.png');
  await captureRoute('packets','enterprise-packet-explorer-desktop.png');
  await captureRoute('diagnostics','enterprise-diagnostics-desktop.png');
  assert(await page.locator('#enterpriseTrace').isDisabled(),'Traceroute unavailable by capability must stay disabled');
  const disabledOpacity=await page.locator('#enterpriseTrace').evaluate(e=>Number(getComputedStyle(e).opacity));
  assert(disabledOpacity<0.8,'Disabled traceroute must appear visually unavailable');
  await captureRoute('overview','enterprise-desktop-viewport.png');
  const desktopFold=await page.evaluate(()=>{
   const rect=s=>document.querySelector(s)?.getBoundingClientRect();
   const hero=rect('#missionControlPanel .v79-hero'),stats=rect('#missionControlPanel .v79-stats'),services=rect('#nativeServiceRows'),chart=rect('#nativeTrend');
   const badge=rect('#nativeLiveBadge'),refresh=rect('#nativeRefresh');
   return {heroHeight:hero?.height||0,statsBottom:stats?.bottom||9999,servicesTop:services?.top||9999,chartTop:chart?.top||9999,badgeHeight:badge?.height||0,refreshHeight:refresh?.height||0};
  });
  assert(desktopFold.heroHeight>110&&desktopFold.heroHeight<=220,'Operations-first desktop hero must be compact but retain its content');
  assert(desktopFold.statsBottom<790,'All four KPI cards should appear in the first desktop viewport');
  assert(desktopFold.servicesTop<900&&desktopFold.chartTop<900,'Service health and response chart should start in the first desktop viewport');
  assert(desktopFold.badgeHeight>22&&desktopFold.refreshHeight>20,'Live evidence provenance and refresh control must stay present');
  const opsLayout=await page.evaluate(()=>({
    heroVisualHidden:getComputedStyle(document.querySelector('.v79-ops-header .v79-hero-visual')).display==='none',
    serviceColumns:getComputedStyle(document.querySelector('#nativeServiceRows')).gridTemplateColumns.split(' ').length,
    serviceCards:document.querySelectorAll('#nativeServiceRows .v79-row').length,
    timelineNodes:document.querySelectorAll('#nativeActivity .v79-row').length,
    gridTag:document.querySelector('.v79-service-evidence-grid')!==null
  }));
  assert(opsLayout.heroVisualHidden,'Decorative shield should not occupy the new operations status header');
  assert(opsLayout.gridTag&&opsLayout.serviceColumns===2&&opsLayout.serviceCards===7,'Desktop service-health matrix must render seven source-labelled synthetic fixture tiles');
  assert(opsLayout.timelineNodes===1,'Synthetic historical event must stay visible');

  const desktopSidebar=await page.locator('.sidebar').evaluate(e=>({top:e.getBoundingClientRect().top,position:getComputedStyle(e).position,height:e.getBoundingClientRect().height}));
  assert(Math.abs(desktopSidebar.top)<=1,'Desktop primary sidebar should appear at top of first viewport');
  assert.equal(desktopSidebar.position,'sticky','Desktop primary sidebar must remain sticky');
  assert(desktopSidebar.height>=800,'Desktop sidebar should occupy its visible viewport');
  await page.screenshot({path:path.join(screenshots,'enterprise-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await captureRoute('overview','enterprise-mobile-viewport.png');
  const mobileControls=await page.evaluate(()=>{
   const hero=document.querySelector('#missionControlPanel .v79-hero')?.getBoundingClientRect();
   const badge=document.querySelector('#nativeLiveBadge')?.getBoundingClientRect();
   const refresh=document.querySelector('#nativeRefresh')?.getBoundingClientRect();
   const metrics=document.querySelector('#missionControlPanel .v79-stats')?.getBoundingClientRect();
   return {heroHeight:hero?.height||0,badgeHeight:badge?.height||0,refreshHeight:refresh?.height||0,metricTop:metrics?.top||9999};
  });
  assert(mobileControls.heroHeight>150&&mobileControls.heroHeight<400,'Mobile Overview must stay compact and readable');
  assert(mobileControls.badgeHeight>22&&mobileControls.refreshHeight>20,'Mobile refresh and monitoring provenance must remain visible');
  assert(mobileControls.metricTop<790,'First mobile monitoring cards should appear without scrolling far past the first viewport');
  assert.equal(await page.locator('#nativeServiceRows').evaluate(e=>getComputedStyle(e).gridTemplateColumns.split(' ').length),1,'Mobile service matrix must fit one column');
  assert.equal(await page.locator('#nativeQaRun').getAttribute('data-qa-freshness'),'historical','Historical QA provenance must remain visible on mobile');
  await page.screenshot({path:path.join(screenshots,'enterprise-mobile.png'),fullPage:true});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'Mobile document must not overflow');
  await captureRoute('map','enterprise-network-map-mobile.png');
  await captureRoute('packets','enterprise-packet-explorer-mobile.png');
  await captureRoute('overview','enterprise-mobile-viewport.png');
  const mobilePresentation=await page.evaluate(()=>{const nav=document.querySelector('.sidebar .nav'),tile=document.querySelector('.v79-stat'),metrics=document.querySelector('.v79-stats');return {navVisible:!!nav&&nav.getBoundingClientRect().height>0,navScroll:getComputedStyle(nav).overflowX,metricColumns:getComputedStyle(metrics).gridTemplateColumns.split(' ').length,tileVisible:!!tile&&tile.getBoundingClientRect().height>50,navTouchHeight:document.querySelector('.nav-item')?.getBoundingClientRect().height||0};});
  assert(mobilePresentation.navVisible,'Mobile primary navigation must remain visible');
  assert.equal(mobilePresentation.navScroll,'auto','Mobile navigation should scroll within its own row');
  assert.equal(mobilePresentation.metricColumns,2,'Mobile KPI layout should use two accessible columns');
  assert(mobilePresentation.tileVisible,'Overview KPI tiles must remain readable');
  assert(mobilePresentation.navTouchHeight>=40,'Mobile navigation touch target too small');
  await page.locator('#logout').click();await page.locator('#loginSection').waitFor({state:'visible'});assert.equal(await page.locator('#nativeTrend svg').count(),0,'Logout must remove monitored trend');assert.equal(await page.locator('#nativeHealthy').textContent(),'—','Logout must clear previous healthy counts');assert.equal(await page.locator('#enterpriseDomains img').count(),0);assert.equal(await page.locator('#enterpriseDesignList').textContent(),'');assert((await page.locator('#enterprisePacketStatus').textContent()).includes('No packet'));assert.equal(errors.length,0,errors.join('|'));
  console.log('PASS: all 11 routes, stale/503/collector-error fail-closed, protected diagnostics, safe NetPulse import, top-anchored desktop navigation, routed-page footer order, operations status header, seven-card service matrix, historical QA and Dell provenance, mobile-safe view, disabled-control contrast and 9 synthetic desktop/mobile screenshots, logout and zero JS errors');console.log('SYNTHETIC SCREENSHOTS '+screenshots);
 }finally{await browser.close();}
}
main().catch(e=>{console.error(e.stack);process.exitCode=1;}).finally(()=>py.kill('SIGTERM'));
