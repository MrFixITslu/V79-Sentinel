#!/usr/bin/env node
'use strict';
const path=require('node:path');
const assert=require('node:assert/strict');
const {chromium}=require('../qa/node_modules/playwright-core');
(async()=>{
 const port=process.argv[2]||18791;
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',
   args:['--disable-dev-shm-usage']});
 try{
  const page=await browser.newPage({viewport:{width:1350,height:900},deviceScaleFactor:1});
  await page.goto('http://127.0.0.1:'+port,{waitUntil:'domcontentloaded',timeout:18000});
  await page.waitForFunction(()=>document.getElementById('qaRunTag')?.textContent==='QA VERIFIED',
                             {timeout:12000});
  const data=await page.evaluate(()=>({
   label:document.querySelector('#qaRunTag')?.textContent,
   summary:document.querySelector('#qaSummary')?.textContent,
   protected:document.querySelector('#qaAuthTag')?.textContent,
   rows:document.querySelectorAll('#qaRows .qa-row').length,
   shots:document.querySelectorAll('#qaRows a.qa-screenshot').length,
   empty:document.querySelector('#qaRows')?.innerText,
   warnings:document.querySelector('#insight')?.textContent
  }));
  console.log(JSON.stringify(data,null,2));
  assert.equal(data.label,'QA VERIFIED');
  assert.equal(data.rows,7);
  assert.equal(data.shots,14);
  assert.match(data.summary,/14 checks/);
  assert.match(data.summary,/8 auth required/);
  assert.match(data.summary,/2 review/);
  await page.waitForFunction(()=>document.querySelector('#qaAuthTag')?.textContent==='NOT CONFIGURED');
  await page.screenshot({path:path.resolve(__dirname,'../data/qa-dashboard-desktop.png'),
    fullPage:true,timeout:12000});
  console.log('DASHBOARD_QA_RENDER_PASS');
 } finally {
  await Promise.race([browser.close(),new Promise(resolve=>setTimeout(resolve,4000))]);
 }
})().catch(e=>{console.error('DASHBOARD_QA_RENDER_FAIL',e.message);process.exitCode=1;});
