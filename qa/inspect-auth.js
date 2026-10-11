'use strict';
const {chromium}=require('playwright-core');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--disable-dev-shm-usage']});
 try{
  for(const [name,url] of [['Hub','https://hub.v79sl.com/'],['POS','https://pos.v79sl.com/']]){
   const ctx=await browser.newContext({serviceWorkers:'block',acceptDownloads:false,ignoreHTTPSErrors:false});
   const p=await ctx.newPage();
   const events=[];
   p.on('response',r=>{
     if([401,403,405].includes(r.status())&&events.length<15){
       let path='unknown';let host='unknown';
       try{const u=new URL(r.url()); path=u.pathname.slice(0,120);host=u.hostname;}catch{}
       events.push({status:r.status(),host,path,resource:r.request().resourceType(),method:r.request().method()});
     }
   });
   await p.route('**/*',async rt=>{
     if(!['GET','HEAD'].includes(rt.request().method())) return rt.abort('blockedbyclient');
     return rt.continue();
   });
   try{await p.goto(url,{waitUntil:'domcontentloaded',timeout:18000});await p.waitForTimeout(1200);}catch(e){}
   console.log(JSON.stringify({name,url: p.url().split('?')[0],status401:events},null,2));
   await Promise.race([ctx.close(),new Promise(r=>setTimeout(r,3000))]);
  }
 }finally{await Promise.race([browser.close(),new Promise(r=>setTimeout(r,3000))]);}
})().catch(e=>{console.error(e.message);process.exitCode=1});
