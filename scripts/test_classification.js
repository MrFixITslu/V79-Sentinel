'use strict';
const assert=require('node:assert/strict');
const {classify,authEvent,expectedHubRedirect}=require('../qa/classify');
const ok={name:'Website',source:'https://v79sl.com/',finalUrl:'https://v79sl.com/',
  navigated:true,http:200,screenshot:'website-desktop.png',errors:[],warnings:[],responseEvents:[]};
function check(name,input,expected){
 const r=classify({...ok,...input});
 assert.equal(r.status,expected,`${name}: expected ${expected} got ${r.status}`);
 console.log('PASS',name,'=>',r.status);
}
check('Healthy homepage',{},'pass');
check('Hub unauthenticated me endpoint',{
 name:'V79 Hub',source:'https://hub.v79sl.com/',finalUrl:'https://hub.v79sl.com/',
 errors:['console: Failed to load resource: the server responded with a status of 401 ()'],
 responseEvents:[{host:'hub.v79sl.com',path:'/api/auth/me',method:'GET',status:401,resource:'fetch'}]
},'auth-gated');
check('POS unauthenticated me endpoint',{
 name:'V79 POS',source:'https://pos.v79sl.com/',finalUrl:'https://pos.v79sl.com/',
 errors:['console: Failed to load resource: the server responded with a status of 401 ()'],
 responseEvents:[{host:'pos.v79sl.com',path:'/v1/me',method:'GET',status:401,resource:'fetch'}]
},'auth-gated');
check('Protected FFPRO redirected to Hub',{
 name:'FFPRO',source:'https://ffpro.v79sl.com/',finalUrl:'https://hub.v79sl.com/?return=ffpro',
 errors:['console: Failed to load resource: the server responded with a status of 401 ()'],
 responseEvents:[{host:'hub.v79sl.com',path:'/api/auth/me',method:'GET',status:401,resource:'fetch'}]
},'auth-gated');
check('FFPRO expected private GETs before Hub redirect',{
 name:'FFPRO',source:'https://ffpro.v79sl.com/',finalUrl:'https://hub.v79sl.com/?return=ffpro',
 errors:Array(3).fill('console: Failed to load resource: the server responded with a status of 401 ()'),
 responseEvents:[
 {host:'ffpro.v79sl.com',path:'/api/gmail/dismissed',method:'GET',status:401},
 {host:'ffpro.v79sl.com',path:'/api/gmail/notifications',method:'GET',status:401},
 {host:'ffpro.v79sl.com',path:'/api/calendar/status',method:'GET',status:401}]
},'auth-gated');
check('Tiquet and Marketing sessions are known guest checks',{
 name:'V79 Tiquet',source:'https://tiquet.v79sl.com/',finalUrl:'https://hub.v79sl.com/?return=tiquet',
 responseEvents:[{host:'tiquet.v79sl.com',path:'/api/auth/me',method:'GET',status:401}]
},'auth-gated');
check('FFPRO beforeunload still actionable',{
 name:'FFPRO',source:'https://ffpro.v79sl.com/',finalUrl:'https://hub.v79sl.com/?return=ffpro',
 errors:["console: Blocked attempt to show a 'beforeunload' confirmation panel"],
 responseEvents:[]},'review');
check('Unknown 401 must stay review',{
 name:'V79 Hub',source:'https://hub.v79sl.com/',finalUrl:'https://hub.v79sl.com/',
 errors:['console: Failed to load resource: the server responded with a status of 401 ()'],
 responseEvents:[{host:'hub.v79sl.com',path:'/api/private-data',method:'GET',status:401,resource:'fetch'}]
},'review');
check('Five hundred server error',{
 responseEvents:[{host:'v79sl.com',path:'/api/something',method:'GET',status:500,resource:'fetch'}]
},'review');
check('HTTP 200 with navigation exception',{navigationError:'Navigation timeout'},'fail');
check('Unknown hub redirect not expected',{name:'FFPRO',source:'https://ffpro.v79sl.com/',finalUrl:'https://hub.v79sl.com/?return=other'},'pass');
check('Blocked mutations remain review',{warnings:['1 non-GET requests blocked']},'review');
assert.equal(authEvent({host:'hub.v79sl.com',path:'/api/auth/me',status:401,method:'POST'}),false);
assert.equal(expectedHubRedirect('FFPRO','https://ffpro.v79sl.com/','https://evil.com/?return=ffpro'),false);
console.log('CLASSIFICATION TESTS PASS');
