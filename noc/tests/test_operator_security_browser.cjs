"use strict";
// Local, synthetic, isolated browser flow. Never points at the running user NOC.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const crypto=require("node:crypto");
const {chromium}=require("/home/firelion/V79-Sentinel/sentinel/qa/node_modules/playwright-core");
const base=process.env.SENTINEL_SECURITY_TEST_URL || "http://127.0.0.1:8790";
const passwordFile=process.env.SENTINEL_SECURITY_TEST_PASSWORD_FILE;
if(!passwordFile)throw Error("Private synthetic password-file path missing");
const password=fs.readFileSync(passwordFile,"utf8").trim();
function fromBase32(encoded){
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
 let buffer=0,bits=0,bytes=[];
 for(const ch of encoded.replace(/=+$/,"").toUpperCase()){
  const n=alphabet.indexOf(ch);if(n<0)throw Error("Invalid base32 test secret");
  buffer=(buffer<<5)|n;bits+=5;
  if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}
 }
 return Buffer.from(bytes);
}
function totp(secret){
 const counter=BigInt(Math.floor(Date.now()/30000));
 const data=Buffer.alloc(8);
 data.writeBigUInt64BE(counter);
 const digest=crypto.createHmac("sha1",fromBase32(secret)).update(data).digest();
 const offset=digest[digest.length-1]&15;
 return String((digest.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,"0");
}
async function main(){
 const browser=await chromium.launch({executablePath:"/usr/bin/google-chrome",
   headless:true,args:["--no-sandbox","--disable-dev-shm-usage"]});
 const page=await browser.newPage({viewport:{width:1280,height:800}});
 const pageErrors=[];
 page.on("pageerror",e=>pageErrors.push(e.message));
 async function login(recoveryCode){
  await page.locator("#username").fill("noc-admin");
  await page.locator("#password").fill(password);
  if(recoveryCode)await page.locator("#loginRecovery").fill(recoveryCode);
  await page.locator("#loginForm button").click();
  await page.locator("#appSection").waitFor({state:"visible",timeout:15000});
  await page.waitForTimeout(900);
  assert(await page.locator("#appSection").isVisible(),"Dashboard must remain visible");
  assert(!await page.locator("#loginSection").isVisible(),"No flash back to login");
 }
 try{
  await page.goto(base+"/",{waitUntil:"domcontentloaded"});
  assert(await page.locator("#loginSection").isVisible());
  assert(!await page.locator("#appSection").isVisible());
  await login(null);
  assert(await page.locator("#operatorAdminPanel").isVisible());
  assert(await page.locator("#operatorTools").isVisible());
  assert((await page.locator("#roleLabel").textContent()).trim()==="ADMIN");
  console.log("PASS: Isolated operator login, admin panel and inventory");
  // Regression for the previous flash-to-login incident: a temporary
  // non-auth security-settings failure must never discard a valid session.
  const failureRoute="**/api/v1/mfa/status";
  await page.route(failureRoute,async route=>route.fulfill({
    status:503,contentType:"application/json",body:'{"error":"Temporary staging outage"}'
  }));
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator("#appSection").waitFor({state:"visible",timeout:10000});
  await page.waitForTimeout(1000);
  assert(!await page.locator("#loginSection").isVisible(),
    "Security-settings HTTP 503 must not flash back to login");
  await page.unroute(failureRoute);
  // Regression for the exact previous failure: a 404 from mismatched
  // ancillary security settings must not discard a valid login session.
  await page.route(failureRoute,async route=>route.fulfill({
    status:404,contentType:"application/json",body:'{"error":"Not found"}'
  }));
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator("#appSection").waitFor({state:"visible",timeout:10000});
  await page.waitForTimeout(1100);
  assert(!await page.locator("#loginSection").isVisible(),
    "Security-settings HTTP 404 must not flash back to login");
  await page.unroute(failureRoute);
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator("#mfaBeginForm").waitFor({state:"visible",timeout:10000});
  console.log("PASS: Valid session retained when security-settings API returns 503 or 404");
  await page.locator('#mfaBeginForm input[name="password"]').fill(password);
  await page.locator('#mfaBeginForm button').click();
  await page.locator("#mfaSetup").waitFor({state:"visible",timeout:12000});
  const secretLine=(await page.locator("#mfaSecret").textContent()).trim();
  assert(secretLine.startsWith("Setup key: "));
  const secret=secretLine.slice("Setup key: ".length);
  const otp=totp(secret);
  await page.locator('#mfaConfirmForm input[name="code"]').fill(otp);
  await page.locator('#mfaConfirmForm button').click();
  await page.locator("#recoveryCodesPanel").waitFor({state:"visible",timeout:12000});
  const codes=(await page.locator("#recoveryCodes").textContent()).trim().split(/\n/);
  assert.equal(codes.length,8);
  assert(codes.every(x=>/^sc_[a-f0-9]{24}$/.test(x)));
  await page.waitForTimeout(1000);
  assert(await page.locator("#recoveryCodesPanel").isVisible(),
    "Recovery codes stay visible until user acknowledges saving");
  console.log("PASS: MFA enrollment, verification, and eight one-time recovery codes");
  await page.locator("#savedRecoveryCodes").click();
  await page.locator("#loginSection").waitFor({state:"visible",timeout:5000});
  await login(codes[0]);
  console.log("PASS: One-time recovery code login and stable dashboard");
  await page.locator("#logout").click();
  await page.locator("#loginSection").waitFor({state:"visible",timeout:8000});
  await page.locator("#username").fill("noc-admin");
  await page.locator("#password").fill(password);
  await page.locator("#loginRecovery").fill(codes[0]);
  await page.locator("#loginForm button").click();
  await page.waitForFunction(()=>document.getElementById("loginError").textContent.length>0,
    {timeout:10000});
  assert(await page.locator("#loginSection").isVisible());
  console.log("PASS: Reusing recovery code rejected");
  await login(codes[1]);
  assert.equal(pageErrors.length,0,"JavaScript errors: "+pageErrors.join("; "));
  console.log("PASS: Second recovery code works; zero browser JavaScript errors");
 }finally{
  await browser.close();
 }
}
main().catch(e=>{console.error("FAIL: Isolated MFA browser scenario:",e.message);process.exitCode=1;});
