"""Real signed agent observations correlate incidents server-side, never in the agent."""
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from uuid import uuid4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.store import NocStore
from noc.sentinel_real_edge import (
    VERSION,canonical,initialize,ingest_signed_measurement,independently_verified_incident)


class RealSignedCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix="v79-real-edge-test-")
        self.addCleanup(self.temp.cleanup)
        self.store=NocStore(Path(self.temp.name)/"isolated.sqlite3")
        initialize(self.store)
        self.customer=self.store.customer("V79 OWNER SYNTHETIC")
        self.site=self.store.site(self.customer,"Synthetic WAN")
        self.asset=self.store.asset(self.site,"Synthetic Gateway","192.0.2.60")
        self.check=self.store.check(self.asset,"TCP 443 reachability","wan")
        self.agent=self.store.enroll(self.site,"Synthetic Keyed Agent")["agent_id"]
        self.signer=Ed25519PrivateKey.generate()
        pub=self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.keys={self.agent:pub}
        self.targets={self.check:{"ip":"192.0.2.60","port":443,
            "customer_id":self.customer,"site_id":self.site,"agent_id":self.agent}}
        self.now=int(time.time())

    def observation(self,seq,seen,ok=False,**changes):
        claims={"version":VERSION,"receipt_id":str(uuid4()),
            "customer_id":self.customer,"site_id":self.site,
            "agent_id":self.agent,"check_id":self.check,"sequence":seq,
            "observed_at":seen,"ok":ok,"target_ip":"192.0.2.60",
            "target_port":443,"probe_kind":"tcp"}
        claims.update(changes)
        return {"claims":claims,"signature":self.signer.sign(canonical(claims)).hex()}

    def ingest(self,observation):
        return ingest_signed_measurement(self.store,observation,
            self.keys,self.targets,now=self.now)

    def test_agent_does_not_provide_incident_id_server_correlates_failures(self):
        a=self.ingest(self.observation(1,self.now-40))
        self.assertEqual(a["status"],"observed")
        b=self.ingest(self.observation(2,self.now-5))
        self.assertEqual(b["status"],"open")
        self.assertIsNotNone(b["incident_id"])
        self.assertTrue(independently_verified_incident(self.store,b["incident_id"],
                         self.keys,self.targets,now=self.now))
        c=self.ingest(self.observation(3,self.now-2,ok=True))
        self.assertEqual(c["status"],"open")
        d=self.ingest(self.observation(4,self.now-1,ok=True))
        self.assertEqual(d["status"],"resolved")
        self.assertFalse(independently_verified_incident(self.store,b["incident_id"],
                         self.keys,self.targets,now=self.now))

    def test_unsigned_tampered_cross_scope_replayed_and_revoked_denied(self):
        with self.assertRaises(PermissionError):
            self.ingest({"claims":self.observation(1,self.now-40)["claims"],
                         "signature":"0"*128})
        with self.assertRaises(PermissionError):
            self.ingest(self.observation(1,self.now-40,target_ip="10.1.1.1"))
        with self.assertRaises(PermissionError):
            self.ingest(self.observation(1,self.now-40,customer_id=str(uuid4())))
        self.ingest(self.observation(1,self.now-40))
        with self.assertRaises(ValueError):
            self.ingest(self.observation(1,self.now-20))
        with self.store.db() as db:
            db.execute("UPDATE agents SET revoked=1 WHERE id=?",(self.agent,))
        with self.assertRaises(PermissionError):
            self.ingest(self.observation(2,self.now-5))
        self.assertEqual(self.store.snapshot()["metrics"]["total_incidents"],0)

    def test_maintenance_suppresses_new_incident_but_preserves_readings(self):
        with self.store.db() as db:
            db.execute("""INSERT INTO maintenance_windows
              VALUES(?,?,?,?,?,?,?)""",(str(uuid4()),self.customer,self.site,
              "synthetic planned maintenance",self.now-100,self.now+100,self.now-100))
        self.ingest(self.observation(1,self.now-45))
        result=self.ingest(self.observation(2,self.now-5))
        self.assertEqual(result["status"],"observed")
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sentinel_real_measurements").fetchone()[0],2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sentinel_real_incidents").fetchone()[0],0)


if __name__=="__main__":
    unittest.main()
