"""Edge sampler tests never leave local loopback."""
from pathlib import Path
from tempfile import TemporaryDirectory
import socket
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.sentinel_agent_sampler import (
    tcp_probe,sign_observation,post_local_observation,
    queue_signed_reading,acknowledge_signed_reading)
from noc.sentinel_real_edge import verify_agent_measurement


class SamplerTests(unittest.TestCase):
    def setUp(self):
        temp=TemporaryDirectory(prefix="sentinel-sampler-test-")
        self.addCleanup(temp.cleanup)
        self.db=Path(temp.name)/"agent-journal.sqlite3"
        self.agent=str(uuid4());self.check=str(uuid4())
        self.policy={"ip":"127.0.0.1","port":47865,
            "customer_id":str(uuid4()),"site_id":str(uuid4()),
            "agent_id":self.agent,"check_id":self.check}
        self.signer=Ed25519PrivateKey.generate()

    def test_tcp_probe_is_explicit_and_scope_restricted(self):
        listener=socket.socket()
        listener.bind(("127.0.0.1",0))
        listener.listen(1)
        try:
            policy={**self.policy,"port":listener.getsockname()[1]}
            self.assertTrue(tcp_probe(policy,timeout=.4))
        finally:listener.close()
        self.assertFalse(tcp_probe(policy,timeout=.4))
        with self.assertRaises(ValueError):tcp_probe({**policy,"ip":"not-an-ip"})
        with self.assertRaises(ValueError):tcp_probe(policy,timeout=999)

    def test_agent_key_signs_exact_fixed_check_reading(self):
        from cryptography.hazmat.primitives import serialization
        proof=sign_observation(self.policy,1,self.signer,False)
        pub=self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        check={self.check:{k:v for k,v in self.policy.items() if k!="check_id"}}
        claims=verify_agent_measurement(proof,{self.agent:pub},check)
        self.assertEqual(claims["sequence"],1)
        with self.assertRaises(PermissionError):
            verify_agent_measurement({**proof,"signature":"0"*128},{self.agent:pub},check)

    def test_local_publish_defaults_off_and_remote_url_rejected(self):
        self.assertEqual(post_local_observation({},enabled=False),{"status":"disabled"})
        with self.assertRaises(PermissionError):
            post_local_observation({},enabled=True,endpoint="https://evil.example")

    def test_retry_keeps_the_same_signed_packet_until_acknowledged(self):
        first=queue_signed_reading(self.db,self.policy,self.signer,False)
        replay=queue_signed_reading(self.db,self.policy,self.signer,True)
        self.assertEqual(first,replay)
        self.assertEqual(replay["claims"]["sequence"],1)
        self.assertEqual(replay["claims"]["ok"],False)
        with self.assertRaises(ValueError):
            acknowledge_signed_reading(self.db,self.agent,str(uuid4()),
                {"accepted":True,"status":"observed"})
        self.assertTrue(acknowledge_signed_reading(self.db,self.agent,
            first["claims"]["receipt_id"],{"accepted":True,"status":"observed"}))
        self.assertEqual(self.db.stat().st_mode&0o077,0)
        second=queue_signed_reading(self.db,self.policy,self.signer,True)
        self.assertEqual(second["claims"]["sequence"],2)
        self.assertTrue(second["claims"]["ok"])



if __name__=="__main__":
    unittest.main()
