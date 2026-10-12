# V79 Sentinel — PRIVATE Docker migration preparation (G2.21 parity-gated)

**Status: STAGING PACKAGE ONLY. No production cutover. No customer traffic.**
The authoritative active operator NOC is still running from the Acer's
`/home/firelion/V79-Sentinel/g221-mobilefix-isolated-review` at port 8788.
Original monitor still runs from `/home/firelion/V79-Sentinel/sentinel` at port 8787.
Do not stop either Acer service until the full authenticated feature comparison and
data/rollback validation pass.

## Critical source gate — do not skip

GitHub private Sentinel baseline `b8d6c4588c21228523790902b57375f340b6d28a`
matched `github-baseline-review` across eight inspected files, but NOT the
active G2.21 worktree. Compared with that baseline, active G2.21 differs in:
- `noc/web/index.html`
- `noc/web/enterprise-center.js`
- `noc/web/mission-native.js`

The canonical legacy Acer checkout is older still and missing several native
Command Center assets. This Docker PR is based on the GitHub baseline to prepare
a safe layout; **it is NOT an approved replacement for active G2.21**.
First audit tracked/untracked active source, run Acer tests and authenticated
screenshots, then cherry-pick only the audited mobile UI changes into a reviewed
private GitHub release branch. Never copy .env, database, credentials, tokens,
private keys, screenshots, raw packet captures or user data to source control.

## Network topology

```text
Nginx Proxy Manager container (proxy_network)
         [NOT configured to route to staging]
                        |
               proxy_network
                        |
              noc container namespace
                ^         ^       ^
                |         |       |
       nginx sidecar:8080  |       |
                 loopback NOC:8788 |
                                loopback monitor:8787
```

- **Host port is NOT 3000.** `select-private-port.py` chooses the first
  loopback-only free port, preferring 13078 and then 13079..13149.
- Host binding is `127.0.0.1:<selected>:8080` only; it cannot be reached via
  the server public/LAN interface. Proxy-network peers technically can reach
  Nginx port 8080, so **do not create an NPM public proxy host yet**.
- Docker Compose's primary `noc` container alone joins the external
  `proxy_network`. Monitor and Nginx share its Docker network namespace,
  allowing existing read-only Mission Control calls to localhost:8787 while
  preserving the NOC's enforced loopback-only listener on 8788.
- Nginx proxies **only** the authenticated NOC (8788). The unauthenticated
  original monitor is NOT independently exposed.
- All containers are read-only-rootfs where possible, no privileged mode,
  no Docker socket, no host network, no Edge enrollment and no packet capture.
- NOC and monitor have independent **new** staging Docker volumes. They do not
  mount or migrate existing Acer or V79 app databases. Operator login requires
  explicit synthetic staging bootstrap; the service intentionally refuses to
  run with no operator.
- NOC owner-only evidence points to the old Acer directory by default and will
  show **unavailable** in Docker until a separately reviewed owner-only,
  read-only evidence sync is established. Never label missing evidence as live.
- NetPulse container counters are labeled container namespace counters, **not**
  host, switch-mirror, WAN, LAN, or customer packet captures.
- Browser QA requires external Chrome/Playwright and is not included in these
  Docker images; historical Acer QA remains separate.

## Server-side preflight — only after G2.21 source parity passes

1. Confirm a *tested*, independently restorable backup of both Acer SQLite
   databases and original systemd unit files. Retain original services.
2. Use the reviewed pinned Sentinel migration checkout on `v79sl`.
3. From the repository root on `v79sl`:

```bash
docker network inspect proxy_network --format '{{.Name}}'
python3 -B deploy/docker/select-private-port.py
docker compose --env-file deploy/docker/.env -f deploy/docker/compose.yaml config --quiet
docker compose --env-file deploy/docker/.env -f deploy/docker/compose.yaml build
```

The port selector does not alter existing containers. `.env` is ignored by Git
and created mode 0600; it contains only chosen local port and local HTTP origin.
Do not regenerate it unless you independently confirm why the old one must change.

## Isolated synthetic operator bootstrap

The staging NOC intentionally requires a local test operator; this must be a
NEW staging database, **not** a copy of the existing Acer NOC operator DB.
Do not pass a production password on a command line, in Docker env or in chat.
Generate the test credential **inside the staging volume** while it is mounted
by a disposable NOC container (UID 10001), and keep the password file 0600.
Bootstrap using `noc.server --bootstrap-operator` and
`--bootstrap-password-file`. Do not automatically overwrite an existing
operator or password file. The service refuses uninitialized login data.

Only after a successful bootstrap, start the three pilot services using:
```bash
docker compose --env-file deploy/docker/.env -f deploy/docker/compose.yaml up -d
docker compose --env-file deploy/docker/.env -f deploy/docker/compose.yaml ps
```

Do not change running V79 Hub, Tiquet, WiPay, Marketing, POS, or NPM routing.
Observe RAM/swap and image identities before/after.

## Access from Acer (no public host)

On Acer, forward **the selected actual server port** over your existing SSH:
```bash
ssh -N -L <selected-port>:127.0.0.1:<selected-port> firelion@v79sl
```
Then visit `http://127.0.0.1:<selected-port>` in the Acer browser. Only
use the *synthetic staging* operator. Confirm login, logout, CSRF, all eleven
native navigation routes, charts, NetPulse import, owner-pilot "unavailable"
indication where evidence is absent, desktop/mobile, and no unexpected JS
errors. Repeat with active G2.21 reference screenshots.

## Internal-only go/no-go

- Exact source parity with active Acer G2.21; repeat complete feature inventory.
- New synthetic DB can start and stay healthy. Old Acer DB untouched.
- Authenticated NOC + original Mission Control integration both work.
- No accidental unauthenticated exposure of port 8787 or operator APIs.
- Memory/CPU budget acceptable on ~7 GiB V79 server; no simultaneous large
  Ollama jobs during acceptance.
- Full source tests, browser QA, safe backup restore and rollback validated.
- Independent V79 customer security review and MFA/recovery hardening still
  mandatory before inviting external users.

Rollback of staging uses `docker compose ... down` **without `-v`**,
leaving staging volumes and every existing V79/Acer record intact. Never run
`down -v`, prune volumes, delete legacy data or change NPM routing as a
substitute for correcting failed migration tests.
