import assert from 'node:assert/strict';
import {previewSentinelDeletion} from '../qa/tenant-cleanup.mjs';

const manifest={system:'V79_SENTINEL_QA',cleanupApproved:true,
  organizationId:'test-uuid-8492',organizationName:'Sentinel-QA-isolated-20261009',
  syntheticUserIds:['owner-test','user-test']};
function fixture(){
 return {
  organizations:[
    {id:'production-owner',name:'V79 Digital'},
    {id:manifest.organizationId,name:manifest.organizationName}],
  memberships:[
    {organizationId:'production-owner',userId:'platform-owner',role:'owner'},
    {organizationId:manifest.organizationId,userId:'owner-test',role:'owner'},
    {organizationId:manifest.organizationId,userId:'user-test',role:'staff'}],
  appTenantMappings:[],billingOrders:[],billingPaymentEvents:[],
  organizationPlans:[],appEntitlements:[],ownerInvitations:[],teamInvitations:[],
  trialReminderEvents:[],users:[{id:'platform-owner'},{id:'owner-test'},{id:'user-test'}]
 };
}
const before=fixture();
const immutable=JSON.stringify(before);
const result=previewSentinelDeletion(before,manifest);
assert.equal(result.state,'dry-run-only');
assert.equal(result.readyForLiveDeletion,false);
assert.equal(result.memberCount,2);
assert.equal(JSON.stringify(before),immutable);
console.log('PASS staging-only dry-run, no mutation, unrelated owner preserved');

const fails=(label,fn)=>{
 assert.throws(fn);
 console.log('PASS rejects '+label);
};
fails('production owner',()=>previewSentinelDeletion(fixture(),{...manifest,organizationId:'production-owner'}));
fails('forged label',()=>previewSentinelDeletion(fixture(),{...manifest,organizationName:'V79 Digital'}));
fails('unapproved cleanup',()=>previewSentinelDeletion(fixture(),{...manifest,cleanupApproved:false}));
fails('wrong ID',()=>previewSentinelDeletion(fixture(),{...manifest,organizationId:'unknown'}));
fails('unexpected synthetic membership',()=>{
 const v=fixture(); v.memberships.push({organizationId:manifest.organizationId,userId:'real-user'});
 previewSentinelDeletion(v,manifest);
});
fails('shared user in other tenant',()=>{
 const v=fixture();v.memberships.push({organizationId:'production-owner',userId:'user-test'});
 previewSentinelDeletion(v,manifest);
});
fails('external mapping',()=>{
 const v=fixture();v.appTenantMappings.push({organizationId:manifest.organizationId,appId:'app-v79pos'});
 previewSentinelDeletion(v,manifest);
});
fails('billing orders',()=>{
 const v=fixture();v.billingOrders.push({organizationId:manifest.organizationId});
 previewSentinelDeletion(v,manifest);
});
fails('billing plan',()=>{
 const v=fixture();v.organizationPlans.push({organizationId:manifest.organizationId});
 previewSentinelDeletion(v,manifest);
});
fails('app entitlement',()=>{
 const v=fixture();v.appEntitlements.push({organizationId:manifest.organizationId,appId:'app-ffpro'});
 previewSentinelDeletion(v,manifest);
});
fails('pending invite',()=>{
 const v=fixture();v.teamInvitations.push({organizationId:manifest.organizationId,status:'pending'});
 previewSentinelDeletion(v,manifest);
});
console.log('ALL TEST TENANT SAFETY CHECKS PASSED');
