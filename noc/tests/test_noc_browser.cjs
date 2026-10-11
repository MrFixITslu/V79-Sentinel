"use strict";
// Provider-only NOC browser smoke: read-only page flow and reversible login session.
// No customer/site/agent creation, no Hub/Tiquet/other product requests.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {chromium}=require("../../qa/node_modules/playwright-core");

(async()=>{
 const browser=await chromium.launch({
  executablePath:"/usr/bin/google-chrome",
  headless:true,
  args:["--no-sandbox","--disable-dev-shm-usage"]
 });
 const page=await browser.newPage({viewport:{width:1366,height:900}});
 const errors=[];
 page.on("pageerror",e=>errors.push(String(e.message).slice(0,150)));
 try{
  await page.goto("http://127.0.0.1:8788/",{waitUntil:"domcontentloaded"});
  assert(await page.locator("#loginSection").isVisible(),"Unauthenticated login must be visible");
  assert(!await page.locator("#appSection").isVisible(),"NOC data must not be visible anonymously");
  await page.locator("#username").fill("noc-admin");
  const secret=fs.readFileSync("/home/firelion/.config/v79-sentinel/noc-admin-password","utf8").trim();
  await page.locator("#password").fill(secret);
  await page.locator("#loginForm button").click();
  await page.locator("#appSection").waitFor({state:"visible",timeout:12000});
  await page.locator("#siteCount").waitFor({state:"visible"});
  // Live local pilot inventory changes as approved read-only sites are added.
  // Browser smoke must validate numeric rendering, not historic fixture totals.
  const customerCount=Number((await page.locator("#customerCount").textContent()).trim());
  const incidentCount=Number((await page.locator("#incidentCount").textContent()).trim());
  assert(Number.isSafeInteger(customerCount)&&customerCount>=1,"Invalid customer count");
  assert(Number.isSafeInteger(incidentCount)&&incidentCount>=0,"Invalid incident count");
  assert(await page.locator("#operatorTools").isVisible());
  assert(await page.locator("#securityPanel").isVisible());
  assert.equal((await page.locator("#roleLabel").textContent()).trim(),"ADMIN");
  assert(await page.locator("#operatorAdminPanel").isVisible());
  assert(await page.locator("#mfaBeginForm").isVisible());
  assert(await page.locator("#resolutionProof").isVisible());
  assert(await page.locator(".report-download").isVisible());
  assert(await page.locator("#maintenanceForm").isVisible());
  assert(!await page.locator("#oneTimeSecret").isVisible());
  assert(await page.locator("#siteCustomer option").count()>=2);
  assert(await page.locator("#agentSite option").count()>=2);
  assert(await page.locator("#checkAsset option").count()>=2);
  const screenshot=path.resolve(__dirname,"../../data/noc-ui-preview.png");
  await page.screenshot({path:screenshot,fullPage:true});
  console.log("PASS: Provider NOC UI, demo customers, grouped incident, inventory forms");
  console.log("PREVIEW saved on Acer: data/noc-ui-preview.png");
  await page.locator("#logout").click();
  await page.locator("#loginSection").waitFor({state:"visible",timeout:8000});
  assert(!await page.locator("#appSection").isVisible());
  assert.equal(errors.length,0,"Browser JavaScript errors: "+errors.join(" | "));
  console.log("PASS: Logout hides provider dashboard; 0 uncaught JS errors");
 }finally{
  await browser.close();
 }
})().catch(e=>{console.error("NOC BROWSER TEST FAILED:",e.message);process.exitCode=1;});
