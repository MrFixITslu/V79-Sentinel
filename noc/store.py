"""Sentinel NOC v0.1: isolated local state and deterministic incident lifecycle.

No production V79 integration. Agent telemetry is SIMULATED only and scoped to
the authenticated agent's customer/site, never to agent-supplied tenant IDs.
"""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import pathlib
import secrets
import sqlite3
import time
import uuid

def new_id():
    return str(uuid.uuid4())

def timestamp():
    return int(time.time())

def checked_string(x, label, maximum=100):
    if not isinstance(x, str) or not 1 <= len(x.strip()) <= maximum or any(ord(c)<32 for c in x):
        raise ValueError(f"Invalid {label}")
    return x.strip()

class NocStore:
    def __init__(self, path):
        self.path=pathlib.Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.touch(exist_ok=True,mode=0o600)
        self.path.chmod(0o600)
        with self.db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS customers (
              id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sites (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              name TEXT NOT NULL, UNIQUE(customer_id,name));
            CREATE TABLE IF NOT EXISTS assets (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              site_id TEXT NOT NULL REFERENCES sites(id), name TEXT NOT NULL,
              address TEXT NOT NULL, type TEXT NOT NULL, UNIQUE(site_id,name));
            CREATE TABLE IF NOT EXISTS checks (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              site_id TEXT NOT NULL REFERENCES sites(id),
              asset_id TEXT NOT NULL REFERENCES assets(id), label TEXT NOT NULL,
              domain TEXT NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0,
              recovery_count INTEGER NOT NULL DEFAULT 0,
              state TEXT NOT NULL DEFAULT 'unknown', UNIQUE(asset_id,label));
            CREATE TABLE IF NOT EXISTS agents (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              site_id TEXT NOT NULL REFERENCES sites(id), name TEXT NOT NULL,
              token_digest TEXT NOT NULL UNIQUE, last_seq INTEGER NOT NULL DEFAULT 0,
              last_seen INTEGER, revoked INTEGER NOT NULL DEFAULT 0,
              UNIQUE(site_id,name));
            CREATE TABLE IF NOT EXISTS observations (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              site_id TEXT NOT NULL REFERENCES sites(id),
              agent_id TEXT NOT NULL REFERENCES agents(id),
              check_id TEXT NOT NULL REFERENCES checks(id),
              sequence INTEGER NOT NULL, seen INTEGER NOT NULL, ok INTEGER NOT NULL,
              latency REAL, note TEXT NOT NULL, UNIQUE(agent_id,sequence,check_id));
            CREATE TABLE IF NOT EXISTS incidents (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              site_id TEXT NOT NULL REFERENCES sites(id), domain TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
              severity TEXT NOT NULL, opened INTEGER NOT NULL, resolved INTEGER,
              acknowledged INTEGER, assignee TEXT, title TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_domain
              ON incidents(customer_id,site_id,domain)
              WHERE state IN ('open','acknowledged');
            CREATE TABLE IF NOT EXISTS maintenance_windows (
              id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
              site_id TEXT NOT NULL REFERENCES sites(id),
              reason TEXT NOT NULL, starts INTEGER NOT NULL, ends INTEGER NOT NULL,
              created INTEGER NOT NULL, CHECK(ends>starts));
            CREATE INDEX IF NOT EXISTS idx_maintenance_site_window
              ON maintenance_windows(site_id,starts,ends);
            CREATE TABLE IF NOT EXISTS incident_checks (
              incident_id TEXT NOT NULL REFERENCES incidents(id),
              check_id TEXT NOT NULL REFERENCES checks(id),
              active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(incident_id,check_id));
            CREATE TABLE IF NOT EXISTS incident_history (
              id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id),
              seen INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS integration_outbox (
              id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id),
              event TEXT NOT NULL, payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS operators (
              id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL, role TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
              digest TEXT PRIMARY KEY, operator_id TEXT NOT NULL REFERENCES operators(id),
              csrf TEXT NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
              code_hash TEXT PRIMARY KEY,
              operator_id TEXT NOT NULL REFERENCES operators(id),
              created INTEGER NOT NULL,
              used_at INTEGER);
            CREATE TABLE IF NOT EXISTS audit (
              id TEXT PRIMARY KEY, actor TEXT NOT NULL,
              action TEXT NOT NULL, reference TEXT NOT NULL, seen INTEGER NOT NULL);
            """)
            # Additive-only migration: preserve the existing staging admin and sessions.
            # A future migration framework should version and checksum changes.
            operator_cols={r["name"] for r in c.execute("PRAGMA table_info(operators)")}
            for name,ddl in (
                ("disabled","INTEGER NOT NULL DEFAULT 0"),
                ("mfa_secret","TEXT"),
                ("mfa_pending","TEXT"),
                ("mfa_pending_until","INTEGER"),
                ("mfa_pending_attempts","INTEGER NOT NULL DEFAULT 0"),
                ("mfa_last_counter","INTEGER NOT NULL DEFAULT -1"),
            ):
                if name not in operator_cols:
                    c.execute(f"ALTER TABLE operators ADD COLUMN {name} {ddl}")

    @contextmanager
    def db(self):
        c=sqlite3.connect(str(self.path),timeout=8)
        c.row_factory=sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=8000")
        try:
            yield c
            c.commit()
        except:
            c.rollback()
            raise
        finally:
            c.close()

    def audit(self,c,actor,action,reference):
        c.execute("INSERT INTO audit VALUES(?,?,?,?,?)",
                  (new_id(),actor,action,reference,timestamp()))

    def customer(self,name):
        name=checked_string(name,"customer")
        id=new_id()
        with self.db() as c:
            c.execute("INSERT INTO customers VALUES(?,?,?)",(id,name,timestamp()))
            self.audit(c,"provider","customer.created",id)
        return id

    def site(self,customer_id,name):
        name=checked_string(name,"site")
        id=new_id()
        with self.db() as c:
            if not c.execute("SELECT 1 FROM customers WHERE id=?",(customer_id,)).fetchone():
                raise ValueError("Unknown customer")
            c.execute("INSERT INTO sites VALUES(?,?,?)",(id,customer_id,name))
            self.audit(c,"provider","site.created",id)
        return id

    def asset(self,site_id,name,address,kind="router"):
        name=checked_string(name,"asset")
        kind=checked_string(kind,"asset type",40)
        try: address=str(ipaddress.ip_address(address))
        except (ValueError,TypeError): raise ValueError("Asset requires a numeric IP address")
        id=new_id()
        with self.db() as c:
            s=c.execute("SELECT customer_id FROM sites WHERE id=?",(site_id,)).fetchone()
            if not s: raise ValueError("Unknown site")
            c.execute("INSERT INTO assets VALUES(?,?,?,?,?,?)",
                      (id,s["customer_id"],site_id,name,address,kind))
            self.audit(c,"provider","asset.created",id)
        return id

    def check(self,asset_id,label,domain=None):
        label=checked_string(label,"check")
        id=new_id()
        with self.db() as c:
            a=c.execute("SELECT customer_id,site_id FROM assets WHERE id=?",(asset_id,)).fetchone()
            if not a: raise ValueError("Unknown asset")
            # Failure domains are chosen by the operator, never received from agents.
            domain=checked_string(domain or asset_id,"failure domain",100)
            c.execute("""INSERT INTO checks
                       (id,customer_id,site_id,asset_id,label,domain) VALUES(?,?,?,?,?,?)""",
                      (id,a["customer_id"],a["site_id"],asset_id,label,domain))
            self.audit(c,"provider","check.created",id)
        return id

    def enroll(self,site_id,name):
        name=checked_string(name,"agent")
        credential="sea_"+secrets.token_urlsafe(40)
        id=new_id()
        with self.db() as c:
            s=c.execute("SELECT customer_id FROM sites WHERE id=?",(site_id,)).fetchone()
            if not s: raise ValueError("Unknown site")
            c.execute("INSERT INTO agents VALUES(?,?,?,?,?,0,NULL,0)",
                      (id,s["customer_id"],site_id,name,
                       hashlib.sha256(credential.encode()).hexdigest()))
            self.audit(c,"provider","agent.enrolled",id)
        return {"agent_id":id,"credential":credential}

    def revoke(self,agent_id):
        with self.db() as c:
            n=c.execute("UPDATE agents SET revoked=1 WHERE id=? AND revoked=0",(agent_id,)).rowcount
            if n!=1: raise ValueError("Agent unknown or already revoked")
            self.audit(c,"provider","agent.revoked",agent_id)

    def maintenance(self,site_id,reason,hours=1):
        """Schedule immediate lab maintenance to suppress new incident creation.

        Measurements and check state continue to be recorded. Existing active
        incidents remain open, so planned work never erases prior evidence.
        """
        reason=checked_string(reason,"maintenance reason",160)
        if type(hours) is not int or not 1<=hours<=336:
            raise ValueError("Maintenance hours must be an integer from 1 to 336")
        start=timestamp()
        end=start+hours*3600
        with self.db() as c:
            site=c.execute("SELECT customer_id FROM sites WHERE id=?",(site_id,)).fetchone()
            if not site: raise ValueError("Unknown site")
            current=c.execute("""SELECT 1 FROM maintenance_windows
                  WHERE site_id=? AND starts<=? AND ends>? LIMIT 1""",
                  (site_id,start,start)).fetchone()
            if current: raise ValueError("Site already has an active maintenance window")
            mid=new_id()
            c.execute("INSERT INTO maintenance_windows VALUES(?,?,?,?,?,?,?)",
                      (mid,site["customer_id"],site_id,reason,start,end,start))
            self.audit(c,"provider","maintenance.started",mid)
        return {"id":mid,"ends":end}

    def event(self,c,incident_id,action,detail):
        detail=json.dumps(detail,sort_keys=True)
        c.execute("INSERT INTO incident_history VALUES(?,?,?,?,?)",
                  (new_id(),incident_id,timestamp(),action,detail))
        if action in ("incident.opened","incident.resolved"):
            # Mock integration outbox ONLY. No Tiquet/Hub network transport exists.
            c.execute("INSERT INTO integration_outbox VALUES(?,?,?,?,0)",
                      (new_id(),incident_id,action,detail))

    def _apply(self,c,agent,reading,seq):
        check=c.execute("SELECT * FROM checks WHERE id=?",(reading["check_id"],)).fetchone()
        failures=0 if reading["ok"] else check["failure_count"]+1
        recoveries=check["recovery_count"]+1 if reading["ok"] else 0
        state=check["state"]
        if not reading["ok"] and failures>=2: state="alarm"
        elif reading["ok"] and recoveries>=2: state="healthy"
        c.execute("""UPDATE checks SET failure_count=?,recovery_count=?,state=?
                     WHERE id=?""",(failures,recoveries,state,check["id"]))
        c.execute("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (new_id(),agent["customer_id"],agent["site_id"],agent["id"],
                   check["id"],seq,timestamp(),int(reading["ok"]),
                   reading["latency"],reading["note"]))
        if state=="alarm" and not reading["ok"]:
            incident=c.execute("""SELECT id FROM incidents WHERE customer_id=? AND site_id=?
                               AND domain=? AND state IN ('open','acknowledged')""",
                               (agent["customer_id"],agent["site_id"],check["domain"])).fetchone()
            if incident: incident_id=incident["id"]
            else:
                # Suppress only NEW incidents for explicitly authorized planned
                # maintenance. Do not discard telemetry or close old incidents.
                suppressed=c.execute("""SELECT 1 FROM maintenance_windows WHERE
                    site_id=? AND customer_id=? AND starts<=? AND ends>? LIMIT 1""",
                    (agent["site_id"],agent["customer_id"],timestamp(),timestamp())).fetchone()
                if suppressed:
                    return
                incident_id=new_id()
                c.execute("""INSERT INTO incidents
                             (id,customer_id,site_id,domain,state,severity,opened,title)
                             VALUES(?,?,?,?,'open','major',?,?)""",
                          (incident_id,agent["customer_id"],agent["site_id"],check["domain"],
                           timestamp(),"Suspected shared failure: "+check["domain"]))
                self.event(c,incident_id,"incident.opened",
                           {"customer_id":agent["customer_id"],"site_id":agent["site_id"],
                            "failure_domain":check["domain"],"evidence":"simulated"})
            c.execute("""INSERT INTO incident_checks VALUES(?,?,1)
                         ON CONFLICT(incident_id,check_id) DO UPDATE SET active=1""",
                      (incident_id,check["id"]))
        elif state=="healthy" and reading["ok"]:
            affected=c.execute("""SELECT i.id FROM incident_checks ic
                                  JOIN incidents i ON i.id=ic.incident_id
                                  WHERE ic.check_id=? AND i.state IN ('open','acknowledged')""",
                               (check["id"],)).fetchall()
            for incident in affected:
                iid=incident["id"]
                c.execute("UPDATE incident_checks SET active=0 WHERE incident_id=? AND check_id=?",
                          (iid,check["id"]))
                if c.execute("SELECT count(*) FROM incident_checks WHERE incident_id=? AND active=1",
                             (iid,)).fetchone()[0]==0:
                    c.execute("UPDATE incidents SET state='resolved',resolved=? WHERE id=?",
                              (timestamp(),iid))
                    self.event(c,iid,"incident.resolved",{"resolution":"two consecutive recovery checks"})

    def ingest(self,credential,payload):
        if not isinstance(credential,str) or not credential.startswith("sea_") or len(credential)>128:
            raise PermissionError("Invalid agent credential")
        if not isinstance(payload,dict) or set(payload)!={"sequence","readings"}:
            raise ValueError("Invalid telemetry envelope")
        seq=payload["sequence"]
        if type(seq) is not int or seq<1 or seq>2**63-1: raise ValueError("Invalid telemetry sequence")
        readings=payload["readings"]
        if not isinstance(readings,list) or not 1<=len(readings)<=40:
            raise ValueError("Provide 1-40 readings")
        seen=set()
        clean=[]
        for r in readings:
            if not isinstance(r,dict) or set(r)-{"check_id","ok","latency","note"}:
                raise ValueError("Unexpected reading fields")
            check_id=checked_string(r.get("check_id"),"check ID",50)
            if check_id in seen: raise ValueError("Repeated check ID")
            seen.add(check_id)
            if type(r.get("ok")) is not bool: raise ValueError("ok must be boolean")
            lat=r.get("latency")
            if lat is not None and (type(lat) not in (float,int) or not 0<=lat<=60000):
                raise ValueError("Invalid latency")
            note=r.get("note","")
            if not isinstance(note,str) or len(note)>160 or any(ord(x)<32 for x in note):
                raise ValueError("Invalid note")
            clean.append({"check_id":check_id,"ok":r["ok"],"latency":lat,"note":note})
        digest=hashlib.sha256(credential.encode()).hexdigest()
        with self.db() as c:
            agent=c.execute("SELECT * FROM agents WHERE token_digest=?",(digest,)).fetchone()
            if not agent or agent["revoked"]: raise PermissionError("Unknown or revoked agent")
            if seq<=agent["last_seq"]:
                return {"status":"duplicate","accepted":0,"sequence":agent["last_seq"]}
            # Do not advance over missing offline packets. A future packet arriving
            # first would otherwise make earlier observations permanently stale.
            if seq!=agent["last_seq"]+1:
                raise ValueError("Agent telemetry sequence gap; replay oldest packet first")
            # Verify whole batch BEFORE any inserts. An agent cannot choose tenant IDs.
            for r in clean:
                ch=c.execute("SELECT site_id,customer_id FROM checks WHERE id=?",(r["check_id"],)).fetchone()
                if not ch or ch["site_id"]!=agent["site_id"] or ch["customer_id"]!=agent["customer_id"]:
                    raise PermissionError("Attempt to report another site's check")
            for r in clean: self._apply(c,agent,r,seq)
            c.execute("UPDATE agents SET last_seq=?,last_seen=? WHERE id=?",
                      (seq,timestamp(),agent["id"]))
        return {"status":"accepted","accepted":len(clean),"sequence":seq}

    def heartbeat(self,credential):
        """Authenticated contact without a fabricated device observation.

        Telemetry sequence remains unchanged; disconnected agents can retry
        heartbeats without discarding queued observations.
        """
        if not isinstance(credential,str) or not credential.startswith("sea_") or len(credential)>128:
            raise PermissionError("Invalid agent credential")
        digest=hashlib.sha256(credential.encode()).hexdigest()
        with self.db() as c:
            agent=c.execute("SELECT id,revoked,last_seq FROM agents WHERE token_digest=?",
                            (digest,)).fetchone()
            if not agent or agent["revoked"]:
                raise PermissionError("Unknown or revoked agent")
            c.execute("UPDATE agents SET last_seen=? WHERE id=?",
                      (timestamp(),agent["id"]))
            return {"status":"online","sequence":agent["last_seq"]}

    def acknowledge(self,incident_id,operator_id):
        with self.db() as c:
            i=c.execute("SELECT state FROM incidents WHERE id=?",(incident_id,)).fetchone()
            if not i: raise ValueError("Unknown incident")
            if i["state"]=="resolved": raise ValueError("Cannot acknowledge resolved incident")
            if i["state"]=="open":
                c.execute("UPDATE incidents SET state='acknowledged',acknowledged=?,assignee=? WHERE id=?",
                          (timestamp(),operator_id,incident_id))
                self.event(c,incident_id,"incident.acknowledged",{"operator_id":operator_id})

    def incident_report_rows(self, limit=5000):
        """Operator-only reporting data; caller must enforce authentication.

        A bounded export avoids an unbounded read on heavily used installations.
        """
        if type(limit) is not int or not 1<=limit<=5000:
            raise ValueError("Invalid report limit")
        with self.db() as c:
            return [dict(r) for r in c.execute("""
                SELECT i.id,c.name AS customer,s.name AS site,
                    i.title,i.severity,i.state,i.opened,i.acknowledged,
                    i.resolved,i.domain,
                    (SELECT count(*) FROM incident_checks ic
                     WHERE ic.incident_id=i.id) AS related_checks
                FROM incidents i JOIN customers c ON c.id=i.customer_id
                JOIN sites s ON s.id=i.site_id
                ORDER BY i.opened DESC,i.id DESC LIMIT ?""",(limit,))]

    def snapshot(self):
        with self.db() as c:
            def rows(sql):
                return [dict(r) for r in c.execute(sql)]
            customers=rows("SELECT id,name FROM customers ORDER BY name")
            sites=rows("SELECT s.id,s.customer_id,s.name,c.name customer_name FROM sites s JOIN customers c ON c.id=s.customer_id ORDER BY s.name")
            assets=rows("SELECT id,customer_id,site_id,name,address,type FROM assets ORDER BY name")
            checks=rows("SELECT id,customer_id,site_id,asset_id,label,domain,state FROM checks ORDER BY label")
            agents=rows("SELECT id,customer_id,site_id,name,last_seen,last_seq,revoked FROM agents ORDER BY name")
            incidents=rows("""SELECT i.*,c.name customer_name,s.name site_name,
              (SELECT count(*) FROM incident_checks x WHERE x.incident_id=i.id AND x.active=1) affected_checks
              FROM incidents i JOIN customers c ON c.id=i.customer_id JOIN sites s ON s.id=i.site_id
              ORDER BY i.opened DESC LIMIT 100""")
            maintenance=rows("""SELECT m.id,m.customer_id,m.site_id,m.reason,
                      m.starts,m.ends,s.name AS site_name,c.name AS customer_name
                      FROM maintenance_windows m
                      JOIN sites s ON s.id=m.site_id
                      JOIN customers c ON c.id=m.customer_id
                      WHERE m.ends>=strftime('%s','now')
                      ORDER BY m.ends ASC LIMIT 100""")
            outbox_count=c.execute("SELECT count(*) FROM integration_outbox WHERE delivered=0").fetchone()[0]
            history=rows("""SELECT h.seen,h.action,i.title,c.name AS customer_name,
                            s.name AS site_name,h.incident_id
                            FROM incident_history h
                            JOIN incidents i ON i.id=h.incident_id
                            JOIN customers c ON c.id=i.customer_id
                            JOIN sites s ON s.id=i.site_id
                            ORDER BY h.seen DESC,h.rowid DESC LIMIT 30""")
            totals=c.execute("""SELECT COUNT(*) AS total,
                          SUM(CASE WHEN state='resolved' THEN 1 ELSE 0 END) AS resolved,
                          AVG(CASE WHEN resolved IS NOT NULL THEN
                             MAX(0,resolved-opened) END) AS recovery_seconds
                          FROM incidents""").fetchone()
        for agent in agents:
            last=agent["last_seen"]
            agent["connection"]="revoked" if agent["revoked"] else "never_seen" if last is None else (
                "offline" if timestamp()-last>180 else "online")
        return {"customers":customers,"sites":sites,"assets":assets,"checks":checks,
                "agents":agents,"incidents":incidents,"history":history,
                "maintenance":maintenance,
                "metrics":{"total_incidents":totals["total"],
                           "resolved_incidents":totals["resolved"] or 0,
                           "mean_recovery_seconds":round(totals["recovery_seconds"])
                               if totals["recovery_seconds"] is not None else None},
                "simulated":True,"pending_mock_events":outbox_count,
                "future_integrations":"disabled","generated_at":timestamp()}
