# V79 Sentinel signed incident approval - staging

Date: 2026-10-10 AST. NO PRODUCTION RELEASE OR LIVE TICKET DISPATCH.
Scope: V79 Digital owner-network internal pilot only.

## Complete isolated sequence

1. sentinel_agent_sampler.py signs fixed owner-approved TCP checks with an
   agent-specific Ed25519 signing key. No arbitrary hosts, scanning schedule,
   external HTTP endpoint or private production key is configured. The local
   journal replays the same signed envelope after an interrupted delivery.
2. sentinel_real_edge.py validates signature, agent enrollment, exact
   customer/site/check/IP/port, nonce/sequence, freshness, maintenance and
   revocation. It correlates the signed readings SERVER-SIDE; the agent cannot
   choose an incident UUID. Two independent failed samples separated by 20
   seconds open a real-only incident. Two successes resolve it internally.
3. sentinel_real_ticket_review.py generates a deterministic event for the
   actual owner incident, verifies current signed evidence, requires explicit
   human owner approval plus fresh TOTP and signs an event-bound approval.
4. sentinel_ticket_outbox.py durably records the event exactly once per
   incident, retains a tamper-evident event hash, expires approvals, supports
   cancel/retry bookkeeping, and never automatically closes a technician job.
5. sentinel_ticket_transport.py separately checks current signed source,
   human approval, live reviewer authorization and machine-service entitlement
   before an EXPLICIT dispatch attempt. The transport defaults disabled and
   accepts responses only from the exact pinned HTTPS Tiquet endpoint.
6. The staged NOC browser review panel and authenticated API are OFF by
   default. A 0600 owner configuration with exact trusted public observation
   keys, target mapping and NOC private signer is mandatory.

The obsolete incident-ID-in-agent-protocol prototype was removed. It is
retained only in earlier version-control history, never imported in the
current NOC server or delivery tests.

## Unimplemented live release gates

- No long-term owner Edge Agent signing or NOC approval private keys issued.
- No approved persistent owner service grant enabled on the running Hub.
- No trusted live NOC reviewer-status client wired in Tiquet.
- No scheduled production transport worker or unattended dispatch enabled.
- No mTLS/external Edge Agent ingress or external network exposure.
- No independent exact-commit security assessment and final owner cutover.
- The running NOC on the Acer stays loopback-only with current data preserved.

All signed source evidence and ticket delivery tests use disposable synthetic
identities, ephemeral keys, loopback transport and isolated databases.
