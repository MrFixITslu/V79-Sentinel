'use strict';

/* Sentinel public browser QA classification:
 * 401 from a known "who am I" endpoint can be expected for a logged-out visitor.
 * Anything else remains actionable until independently reviewed.
 * No URLs with query parameters, cookies, tokens or page content are saved in auth evidence.
 */
const KNOWN_ANONYMOUS_ENDPOINTS = Object.freeze({
  'hub.v79sl.com': new Set(['/api/auth/me']),
  'pos.v79sl.com': new Set(['/v1/me']),
  'tiquet.v79sl.com': new Set(['/api/auth/me']),
  'marketing.v79sl.com': new Set(['/api/auth/me']),
  // These three FFPRO endpoints explicitly refused unauthenticated GET checks before Hub redirect.
  'ffpro.v79sl.com': new Set(['/api/gmail/dismissed','/api/gmail/notifications','/api/calendar/status']),
});
const EXPECTED_HUB_RETURN = Object.freeze({
  'FFPRO':'ffpro',
  'V79 Tiquet':'tiquet',
  'Marketing':'marketing',
});

function authEvent(event) {
  if (!event || event.status !== 401 || event.method !== 'GET') return false;
  const host = typeof event.host === 'string' ? event.host.toLowerCase() : '';
  return !!KNOWN_ANONYMOUS_ENDPOINTS[host]?.has(event.path);
}

function expectedHubRedirect(name, source, finalUrl) {
  const slug=EXPECTED_HUB_RETURN[name];
  if (!slug) return false;
  try {
    const s=new URL(source);
    const f=new URL(finalUrl);
    return s.protocol==='https:' && f.protocol==='https:' &&
      s.hostname!=='hub.v79sl.com' &&
      f.hostname==='hub.v79sl.com' &&
      f.pathname==='/' &&
      f.searchParams.get('return')===slug;
  } catch {return false;}
}

function classify(result) {
  const responseEvents=(result.responseEvents||[]).filter(e=>e && Number.isInteger(e.status));
  const knownAuth=responseEvents.filter(authEvent);
  const unexpectedHttp=responseEvents.filter(e=>
    e.status>=400 && e.status!==404 && !authEvent(e));
  const rawErrors=result.errors||[];
  const generic401=/^console: Failed to load resource: the server responded with a status of 401 \(\)$/;
  let unmatchedAuthGeneric=knownAuth.length;
  const actionableErrors=[];
  for(const entry of rawErrors) {
    if (generic401.test(entry) && unmatchedAuthGeneric>0) {
      unmatchedAuthGeneric--; // explicitly correlate by counts to captured 401 events
    } else {
      actionableErrors.push(entry);
    }
  }
  const warnings=[...(result.warnings||[])];
  const protectedRedirect=expectedHubRedirect(result.name,result.source,result.finalUrl);
  if(protectedRedirect) warnings.push('Unauthenticated visitor redirected to V79 Hub (protected access)');
  const authEvidence={
    recognized:knownAuth.map(({host,path,status})=>({host,path,status})),
    redirectedToHub:protectedRedirect
  };
  if(unexpectedHttp.length) {
    warnings.push(unexpectedHttp.length+' unexpected HTTP resource error(s)');
  }
  if(actionableErrors.length) {
    warnings.push(actionableErrors.length+' browser console or JavaScript error(s) requiring review');
  }
  const failed=!!result.navigationError ||
    (Number.isInteger(result.http)&&result.http>=400) ||
    result.navigated===false || !result.screenshot;
  const isAuthenticatedCheck=knownAuth.length>0 || protectedRedirect;
  const status=failed?'fail':warnings.some(w=>!w.includes('Unauthenticated visitor redirected to V79 Hub'))?'review':
    isAuthenticatedCheck?'auth-gated':'pass';
  return {status,warnings,errors:actionableErrors,authEvidence,
    unexpectedHttp:unexpectedHttp.map(({host,path,status})=>({host,path,status}))};
}

module.exports={authEvent,expectedHubRedirect,classify};
