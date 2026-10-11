// Experimental PURE staging helper. Does not connect to V79 Hub or mutate a live database.
// Requires exact identifiers of an exclusively Sentinel-owned organization.
export function previewSentinelDeletion(store, manifest) {
  if (!manifest || manifest.system !== 'V79_SENTINEL_QA' ||
      manifest.cleanupApproved !== true ||
      typeof manifest.organizationId !== 'string' ||
      !/^sentinel-qa-[a-z0-9-]+$/i.test(manifest.organizationName || '')) {
    throw Error('Not an approved, explicitly labeled Sentinel test organization');
  }
  const orgMatches = store.organizations.filter(o => o.id === manifest.organizationId);
  if (orgMatches.length !== 1 || orgMatches[0].name !== manifest.organizationName) {
    throw Error('Organization identity mismatch: refuse cleanup');
  }
  const id = manifest.organizationId;
  const members = store.memberships.filter(m => m.organizationId === id);
  const permittedUsers = new Set(manifest.syntheticUserIds || []);
  if (!Array.isArray(manifest.syntheticUserIds) || !members.length ||
      members.some(m => !permittedUsers.has(m.userId)) ||
      permittedUsers.size !== members.length) {
    throw Error('Unexpected member / missing synthetic ownership evidence');
  }
  for(const uid of permittedUsers){
    if (store.memberships.some(m => m.organizationId !== id && m.userId===uid))
      throw Error('Shared user account: cleanup not isolated');
  }
  if (store.appTenantMappings.some(m => m.organizationId===id))
    throw Error('External application tenant mapping requires separately verified deprovision');
  if (store.billingOrders.some(v => v.organizationId===id) ||
      store.organizationPlans.some(v => v.organizationId===id) ||
      store.billingPaymentEvents.some(v => v.organizationId===id || v.ownerOrganizationId===id))
    throw Error('Billing or subscription state requires separate reconciliation');
  if (store.appEntitlements.some(v => v.organizationId===id))
    throw Error('App entitlements must be removed by approved tenant-lifecycle workflow');
  const links=['teamInvitations','ownerInvitations','trialReminderEvents'];
  for(const key of links){
    if((store[key]||[]).some(v=>v.organizationId===id && v.status==='pending'))
      throw Error('Pending invitations must be revoked via supported admin API before cleanup');
  }
  const membersDeleted=members.map(m=>m.userId);
  return Object.freeze({
    organizationId:id, organizationName:orgMatches[0].name,
    memberCount:members.length, userIds:membersDeleted,
    externalTenantMappings:0, billingOrders:0, activeInvitations:0,
    state:'dry-run-only', readyForLiveDeletion:false,
    reason:'Hub lacks a reviewed operator-only organization deletion route; no live changes made',
  });
}
