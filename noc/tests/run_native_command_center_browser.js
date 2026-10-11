"use strict";
const assert=require("node:assert/strict");
const puppeteer=require("/home/firelion/.npm/_npx/4b4c857f6efdfb61/node_modules/puppeteer");
(async()=>{
 const browser=await puppeteer.launch({executablePath:"/usr/bin/google-chrome",headless:true,
 args:["--no-sandbox","--disable-dev-shm-usage","--disable-gpu"]});
 try{
  const page=await browser.newPage();await page.setViewport({width:1480,height:930,deviceScaleFactor:1});
  const failures=[];page.on("pageerror",e=>failures.push(e.message));
  await page.goto(process.env.SYNTHETIC_NOC_ORIGIN,{waitUntil:"domcontentloaded",timeout:15000});
  await page.type("#username","native-command-browser-test");
  await page.type("#password",process.env.SYNTHETIC_NOC_BROWSER_PASSWORD);
  await page.click('#loginForm button[type=submit]');
  await page.waitForFunction(()=>{
    const count=document.querySelector("#nativeServices")?.textContent;
    return !document.querySelector("#appSection")?.hidden && count!== "—" && Number(count)>=5;
  },{timeout:22000});
  await page.waitForFunction(()=>document.querySelectorAll("#nativeQA tr").length>=12,{timeout:18000});
  const data=await page.evaluate(()=>({
   nested:document.querySelectorAll("iframe").length,
   services:Number(document.querySelector("#nativeServices")?.textContent),
   serviceRows:document.querySelectorAll("#nativeServiceRows .v79-row").length,
   trendPolylines:document.querySelectorAll("#nativeTrend svg polyline").length,
   qaRows:document.querySelectorAll("#nativeQA tr").length,
   screenshots:document.querySelectorAll("#nativeQA a[href*='/mission-control/api/qa/screenshot/']").length,
   activity:document.querySelectorAll("#nativeActivity .v79-row").length,
   localNicRows:document.querySelectorAll("#netpulseNicRows .v79-row").length,
   labVisible:!!document.querySelector("#netpulseLab"),
   nativeError:document.querySelector("#nativeDataError")?.textContent,
   csv:document.querySelector('a[href="/mission-control/api/report.csv"]')?.href,
  }));
  assert.equal(data.nested,0);assert.equal(data.services,data.serviceRows);
  assert.ok(data.services>=5);assert.ok(data.trendPolylines>=1);
  assert.ok(data.qaRows>=12);assert.ok(data.screenshots>=10);
  assert.ok(data.activity>=3);assert.ok(data.localNicRows>=1);
  assert.ok(data.labVisible);
  assert.equal(data.nativeError,"");
  const imageHref=await page.$eval("#nativeQA a[href*='/mission-control/api/qa/screenshot/']",e=>e.getAttribute("href"));
  const proof=await page.evaluate(async uri=>{
   const r=await fetch(uri,{credentials:"same-origin"});return {status:r.status,mime:r.headers.get("content-type"),length:(await r.arrayBuffer()).byteLength};
  },imageHref);
  assert.equal(proof.status,200);assert.match(proof.mime||"",/image\/png/);assert.ok(proof.length>100);
  const input=await page.$("#netpulseImport");
  assert.ok(input);
  await input.uploadFile(process.env.SYNTHETIC_NETPULSE_JSON_FILE);
  await page.waitForFunction(()=>document.querySelector("#netpulseImportStatus")?.textContent.includes("3 captured frames"),{timeout:5000});
  const imported=await page.evaluate(()=>({
    barRows:document.querySelectorAll("#netpulseProtocolBars .v79-bar").length,
    flowRows:document.querySelectorAll("#netpulseFlowRows .v79-row").length,
    packetRows:document.querySelectorAll("#netpulsePacketRows tr").length,
    privacy:document.querySelector("#netpulsePrivacy")?.textContent,
  }));
  assert.equal(imported.packetRows,3);assert.ok(imported.barRows>=2);
  assert.ok(imported.flowRows>=2);assert.match(imported.privacy,/No packet data was uploaded/);
  const screenshotPath=process.env.SYNTHETIC_SCREENSHOT_PATH;
  await page.screenshot({path:screenshotPath,fullPage:false});
  assert.deepEqual(failures,[]);
  console.log("NATIVE_MISSION_BROWSER=PASS "+JSON.stringify({...data,proof,imported}));
  await page.click("#logout");
  await page.waitForFunction(()=>document.querySelector("#appSection").hidden,{timeout:7000});
  const loggedOut=await page.evaluate(async()=>{
    const a=await fetch("/api/v1/netpulse/interfaces");
    const b=await fetch("/mission-control/api/status");
    return [a.status,b.status];
  });
  assert.deepEqual(loggedOut,[401,401]);
  console.log("NATIVE_MISSION_LOGOUT_PRIVACY=PASS");
 }finally{await browser.close();}
})().catch(e=>{console.error("NATIVE_BROWSER_ERROR",e.stack||e.message);process.exitCode=1;});
