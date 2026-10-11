# Sentinel supervised delivery outbox — staging contract

Date: 2026-10-10 AST. STATUS: offline staging only; no worker, no HTTP
sender, no Tiquet or Hub write, no production database migration.

`noc/sentinel_ticket_outbox.py` is a transactional SQLite record keeper.
A ticket can be queued only if an independent verified incident-source
callback and an independent human approval signature callback both
validate one exact event, tenant and digest. With either missing it fails
closed. The `integration_outbox` table for simulated incidents is separate
and cannot enter the new outbox.

The ledger uses one idempotent event ID and a unique incident ID, a bounded
human approval expiry (at most 15 minutes), event SHA-256 digest, and a
single-use approval ID. Replay and altered payloads are denied. Delivery
attempt bookkeeping supports exponential delays, expiry, cancellation and
one accepted Tiquet job reference. No code in this module sends a ticket.
A caller cannot mark a job accepted without future independent validation
of the Tiquet acknowledgement; no trusted caller exists or is mounted yet.

**Do not treat this as a completed production outbox sender.** The actual
delivery worker must enforce active Hub machine entitlement, active
human-reviewer status and approval expiry for EACH attempt, sign an
individual authorized event with an owner-only service key, verify an
authenticated Tiquet receipt and job reference, guard concurrent worker
leases, and securely alert operators on failure. None of those
network-operational gates are yet wired.

Seven synthetic isolated ledger tests passed; NOC regression suite
82/82 passed on the staging worktree. Real NOC and Tiquet unchanged.
