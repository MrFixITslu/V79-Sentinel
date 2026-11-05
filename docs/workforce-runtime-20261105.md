# Sentinel workforce connection — 5 November 2026

The existing in-process HTTPS sampler emits only fixed aggregate counts after its strict scope projection. A dedicated Ed25519 publisher key is readable only by the monitor identity. The separate Evidence Gateway verifies the pinned publisher, scope, expiry and durable monotonic sequence before storing a report. No browser status JSON is signed.

A separate owner relay reads the authenticated private receiver endpoint, independently verifies the publisher signature and makes only a pending create_work_item proposal for Sentinel. It cannot approve or execute a repair. A persistent episode key deduplicates retries; changing FAIL to UNKNOWN does not create a second proposal, and renewed alerts are limited to one per 30 minutes. Recovery clears the local episode without claiming that an existing task is complete.

The source counter/outbox and receiver cursor survive process restarts. A lost acknowledgement can be superseded by a later valid report. Expired records remain STALE; missing or invalid reports remain UNKNOWN. No public ports, customer writes or emails are added.

Limits: source authentication is not independent attestation of physical network probes or security certification. The Gateway's off-host rollback witness remains UNKNOWN. Existing external Hetrix monitoring is still needed for complete host/network outage visibility. Historical GitGuardian incident disposition is not changed by this release.

Validation: 13 new integrated signer/receiver/relay tests; 23 affected Gateway regression tests; one additional private HTTP ingestion/replay/browser-boundary test. Runtime and owner-queue acceptance evidence are recorded separately after activation. Existing passed tests are not repeated without affected changes.
