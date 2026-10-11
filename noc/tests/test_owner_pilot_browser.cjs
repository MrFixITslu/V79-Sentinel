"use strict";
// Completely isolated browser QA for the read-only first-party pilot panel.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const {chromium}=require("/home/firelion/V79-Sentinel/sentinel/qa/node_modules/playwright-core");
const base=process.env.SENTINEL_PILOT_TEST_URL;
const passwordFile=process.env.SENTINEL_PILOT_TEST_PASSWORD_FILE;
if(!base || !passwordFile)throw Error("Isolated test URL and password file required");
async function main(){
 const browser=await chromium.launch({executablePath:"/usr/bin/google-chrome",
   headless:true,args:["--no-sandbox","--disable-dev-shm-usage"]});
 const page=await browser.newPage({viewport:{width:1366,height:900}});
 const jsErrors=[];
 page.on("pageerror",e=>jsErrors.push(e.message));
 try{
  await page.goto(base,{waitUntil:"domcontentloaded"});
  assert(await page.locator("#loginSection").isVisible());
  assert(!await page.locator("#appSection").isVisible());
  await page.locator("#username").fill("noc-admin");
  await page.locator("#password").fill(fs.readFileSync(passwordFile,"utf8").trim());
  await page.locator("#loginForm button").click();
  await page.locator("#appSection").waitFor({state:"visible",timeout:15000});
  await page.locator("#ownerPilotBadge").getByText(/LIVE EVIDENCE/).waitFor({timeout:10000});
  assert(await page.locator("#ownerPilotPanel").isVisible());
  assert.equal(await page.locator("#ownerPilotChecks article.incident").count(),5);
  assert.equal(await page.locator("#ownerPilotApps article.incident").count(),8);
  assert((await page.locator("#ownerPilotSecurity").textContent()).includes("7/8 ready"));
  const pos=page.locator("#ownerPilotApps article.incident").filter({hasText:"POS"});
  assert((await pos.textContent()).includes("protected"),"POS must remain labeled as protected");
  assert.equal(await pos.locator(".state.online").count(),0,"Protected POS cannot appear ready");
  assert(await page.locator("#ownerPilotStatus").textContent());
  assert.equal((await page.locator("#ownerMockBadge").textContent()).trim(),"MOCK ONLY");
  const mockStatus=await page.locator("#ownerMockStatus").textContent();
  assert(mockStatus.includes("qualified mock incidents"));
  assert(mockStatus.includes("no Tiquet ticket created"));
  if(process.env.SENTINEL_EXPECT_SYNTHETIC_MOCK_OPEN==="1"){
   assert(mockStatus.includes("1 open qualified mock incidents"));
   assert.equal(await page.locator("#ownerMockIncidents article.incident").count(),1);
   assert((await page.locator("#ownerMockIncidents").textContent()).includes("SIMULATION ONLY"));
  }
  await page.waitForTimeout(1400);
  assert(await page.locator("#appSection").isVisible(),"Previous login flash must not recur");
  console.log("PASS: authenticated NOC admin views five real-scope synthetic fixture checks");
  await page.route("**/api/v1/owner-pilot",route=>route.fulfill({
     status:503,contentType:"application/json",body:'{"error":"Pilot evidence unavailable"}'}));
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator("#appSection").waitFor({state:"visible",timeout:10000});
  await page.waitForTimeout(800);
  assert(await page.locator("#appSection").isVisible(),"Owner pilot API failure cannot log user out");
  assert.equal((await page.locator("#ownerPilotBadge").textContent()).trim(),"UNAVAILABLE");
  await page.unroute("**/api/v1/owner-pilot");
  console.log("PASS: pilot outage does not log out admin or misrepresent unavailable telemetry");
  assert.equal(jsErrors.length,0,"Browser JavaScript exceptions: "+jsErrors.join("|"));
  await page.locator("#logout").click();
  await page.locator("#loginSection").waitFor({state:"visible",timeout:8000});
  assert(!await page.locator("#appSection").isVisible());
  console.log("PASS: logout and 0 uncaught JavaScript errors");
 }finally{await browser.close();}
}
main().catch(e=>{console.error(e.stack);process.exitCode=1;});
