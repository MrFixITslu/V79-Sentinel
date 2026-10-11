"use strict";
const assert=require("node:assert/strict");
const puppeteer=require("/home/firelion/.npm/_npx/4b4c857f6efdfb61/node_modules/puppeteer");
(async()=>{
 const browser=await puppeteer.launch({
   executablePath:"/usr/bin/google-chrome",headless:true,
   args:["--no-sandbox","--disable-dev-shm-usage","--disable-gpu"],
 });
 try{
   const page=await browser.newPage();
   await page.setViewport({width:1500,height:900,deviceScaleFactor:1});
   const origin=process.env.SYNTHETIC_NOC_ORIGIN;
   await page.goto(origin,{waitUntil:"domcontentloaded",timeout:15000});
   await page.waitForSelector("#loginForm",{timeout:9000});
   await page.type("#username","full-mission-browser-test");
   await page.type("#password",process.env.SYNTHETIC_NOC_BROWSER_PASSWORD);
   await Promise.all([
     page.click("#loginForm button[type=submit]"),
     page.waitForFunction(()=>document.querySelector("#appSection")?.hidden===false,{timeout:20000}),
   ]);
   await page.waitForFunction(()=>document.querySelector("#missionFullFrame")?.getAttribute("src")==="/mission-control/",{timeout:12000});
   let frame=null;
   for(let i=0;i<35;i++){
     frame=page.frames().find(f=>f.url().includes("/mission-control/")&&!f.url().includes("about:"));
     if(frame)break;
     await new Promise(r=>setTimeout(r,300));
   }
   assert.ok(frame,"Full Mission Control frame did not load");
   await frame.waitForSelector("#serviceRows .service-row",{timeout:13000});
   await frame.waitForSelector("#trendChart svg",{timeout:13000});
   await frame.waitForSelector("#qaRows .qa-row",{timeout:18000});
   const result=await frame.evaluate(()=>({
     total:Number(document.querySelector("#metricTotal")?.textContent||0),
     health:Number(document.querySelector("#metricHealthy")?.textContent||0),
     rows:document.querySelectorAll("#serviceRows .service-row").length,
     events:document.querySelectorAll("#events .event-item").length,
     trendSvg:document.querySelectorAll("#trendChart svg polyline").length,
     qaRows:document.querySelectorAll("#qaRows .qa-row").length,
     qaLinks:document.querySelectorAll("#qaRows a.qa-screenshot").length,
     insight:document.querySelector("#insight")?.textContent?.length||0,
     readiness:document.querySelector("#qaAuthSummary")?.textContent?.length||0,
     lab:document.querySelector("#labState")?.textContent?.length||0,
     csv:document.querySelector('a[download="sentinel-report.csv"]')?.getAttribute("href"),
     title:document.title,
   }));
   assert.ok(result.total>=5,result);
   assert.equal(result.rows,result.total);
   assert.ok(result.trendSvg>=1,result);
   assert.ok(result.qaRows>=5,result);
   assert.ok(result.insight>20,result);
   assert.ok(result.readiness>8,result);
   assert.ok(result.lab>0,result);
   assert.equal(result.csv,"/mission-control/api/report.csv");
   let screenshotFetch="not_available";
   if(result.qaLinks){
     const href=await frame.$eval("#qaRows a.qa-screenshot",x=>x.getAttribute("href"));
     assert.ok(href.startsWith("/mission-control/api/qa/screenshot/"),href);
     screenshotFetch=await frame.evaluate(async href=>{
       const r=await fetch(href,{credentials:"same-origin",cache:"no-store"});
       return {status:r.status,mime:r.headers.get("content-type"),bytes:(await r.arrayBuffer()).byteLength};
     },href);
     assert.equal(screenshotFetch.status,200);
     assert.match(screenshotFetch.mime||"",/image\/png/);
   }
   console.log("SYNTHETIC_BROWSER_FULL_TRANSFER=PASS");
   console.log(JSON.stringify({...result,screenshotFetch}));
   const forbidden=await page.evaluate(async()=>{
     const result=await fetch("/mission-control/api/nonallowlisted",{credentials:"same-origin"});
     return result.status;
   });
   assert.equal(forbidden,404);
   await page.click("#logout");
   await page.waitForFunction(()=>document.querySelector("#loginSection")?.hidden===false,{timeout:10000});
   const signedOut=await page.evaluate(async()=>{
     const r=await fetch("/mission-control/api/status");
     return r.status;
   });
   assert.equal(signedOut,401);
   console.log("BROWSER_LOGOUT_PROTECTS_MONITOR_API=PASS");
 }finally{await browser.close();}
})().catch(error=>{console.error("SYNTHETIC_BROWSER_FAILURE",error.message);process.exitCode=1;});
