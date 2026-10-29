# Sentinel P1: complete isolated signed-to-founder rehearsal — 29 October 2026

**Source-only; no live collector, no production key, no Resend call, no trusted security incident, no Dell change.**

Three options considered and REDTEAM: (1) turn on existing raw signer in live monitor: rejected, because its source identity and private key custody are not attested; (2) deploy separate simulated sender/receiver and call that production: rejected, would create misleading security status and new network/secrets boundary; (3) selected: prove every existing gate together end-to-end using temporary isolated files, synthetic HTTPS samples and ephemeral Ed25519 keys.

Rehearsal runs project_probe_cycle → sign_with_atomic_sender_counter → evaluate_and_enqueue_isolated_advisory → stage_next_founder_advisory → claim_founder_delivery → reserve_isolated_resend_request → record_resend_submission_response → synthetic signed founder ACK. Tests first all-UP baseline, DOWN report, duplicate DOWN suppression, recovery, stable retry idempotency, provider acceptance NOT founder delivery, wrong endpoint public key and replay refusal. Fault injection must rollback receiver replay+queue together. Every advisory remains UNVERIFIED_OWNER_ADVISORY and is never pushed to a real HTTP/Resend endpoint.

Critically, the fixture is fabricated inside the test. Even if every test passes, there is no proof the sender process conducted an HTTPS request. Automatic signed Sentinel security delivery and production trusted status stay OFF. A real installer would require independently-reviewed collector/source process binding, protected key custody, receiver ownership, rollback protection, off-host monitor failover, exact SHA/image acceptance and proper owner approval.

Production runtime evidence already obtained: Dell monitor 7/7 owned endpoints up HTTP200, correct three SHA256 code files, local NOC bridge live and healthy. NOC primary incident console still reports collector=simulated-only and integrations=disabled. External Hetrix DOWN/UP email drill is a distinct operational safety net.

Security review issue #3 remains open for commercial/customer release; GitGuardian historical variable-reference alert owner believes false positive, but its dashboard final disposition has not been verified. Do not merge stacked drafts without independent review. No production activation from this test.