# Sentinel runtime acceptance — 5 November 2026

The source-bound monitor, separate Gateway verifier, owner proposal relay and independent Acer source-sequence witness are deployed. Seven authorised service observations reached the Gateway with valid signatures. A labelled synthetic alert was observed in the real owner action queue, then cancelled. No outage was induced and no repair was approved.

The monitor restart produced a new accepted sequence without resetting its durable sender. The encrypted checkpoint was decrypted and restored on Acer and its signer public pin and Gateway SQLite integrity matched. Runtime source hashes match the committed candidates; original containers remain stopped for rollback.

Acer retains its own witness private key and durable source anchor. Witness reports expire after 180 seconds; missing, stale or invalid witness data raises an owner-review proposal. A deleted independent checkpoint requires owner reenrolment rather than silently resetting it. The witness attests Sentinel sequence continuity only; it does not certify physical probes or the general Gateway audit chain.

No emails, automatic repairs, new public ports or customer actions were introduced. Source and witness freshness are exposed separately through the existing authenticated Gateway tools. Existing external uptime monitoring remains necessary for complete host/network outages.
