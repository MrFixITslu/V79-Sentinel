"""Edge replay, identity and telemetry transport regression tests."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import error
import json
import threading

from noc.edge_sim import OfflineQueue, allowed_endpoint, flush, post_event
from noc.store import NocStore

class EdgeReplayTests(TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory(prefix="sentinel-edge-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.store=NocStore(self.root/"noc.db")
        self.customer=self.store.customer("DEMO Offline Customer")
        self.site=self.store.site(self.customer,"Branch")
        self.asset=self.store.asset(self.site,"WAN","192.168.1.1")
        self.check=self.store.check(self.asset,"WAN check","wan")
        self.agent=self.store.enroll(self.site,"Edge")
        self.queue=OfflineQueue(self.root/"spool.db")
    def reading(self,ok):
        return [{"check_id":self.check,"ok":ok,"note":"SIMULATED offline replay"}]
    def test_offline_restart_preserves_sequence_and_replays_in_order(self):
        self.assertEqual(self.queue.enqueue(self.reading(False)),1)
        self.assertEqual(self.queue.enqueue(self.reading(False)),2)
        self.assertEqual(self.queue.size(),2)
        reopened=OfflineQueue(self.root/"spool.db")
        def local_send(endpoint,credential,payload):
            return self.store.ingest(credential,json.loads(payload))
        with mock.patch("noc.edge_sim.post_event",side_effect=local_send):
            result=flush(reopened,"http://127.0.0.1:8788",self.agent["credential"])
        self.assertEqual(result,{"sent":2,"remaining":0})
        self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"open")
        self.assertEqual(reopened.enqueue(self.reading(True)),3)
        self.assertEqual(reopened.enqueue(self.reading(True)),4)
        with mock.patch("noc.edge_sim.post_event",side_effect=local_send):
            self.assertEqual(flush(reopened,"http://127.0.0.1:8788",self.agent["credential"])["sent"],2)
        self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"resolved")
    def test_server_refuses_sequence_gap_without_discarding_history(self):
        with self.assertRaisesRegex(ValueError,"sequence gap"):
            self.store.ingest(self.agent["credential"],{"sequence":3,"readings":self.reading(False)})
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT last_seq FROM agents").fetchone()[0],0)
            self.assertEqual(db.execute("SELECT count(*) FROM observations").fetchone()[0],0)
        self.assertEqual(self.store.ingest(self.agent["credential"],{
            "sequence":1,"readings":self.reading(False)})["status"],"accepted")
    def test_ambiguous_network_ack_retries_idempotently(self):
        self.queue.enqueue(self.reading(False))
        attempts=[0]
        def timeout_after_commit(_endpoint,credential,payload):
            attempts[0]+=1
            ack=self.store.ingest(credential,json.loads(payload))
            if attempts[0]==1: raise TimeoutError("lost acknowledgement")
            return ack
        with mock.patch("noc.edge_sim.post_event",side_effect=timeout_after_commit):
            self.assertEqual(flush(self.queue,"http://127.0.0.1:8788",self.agent["credential"])["remaining"],1)
            self.assertEqual(flush(self.queue,"http://127.0.0.1:8788",self.agent["credential"])["remaining"],0)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM observations").fetchone()[0],1)
    def test_mismatched_ack_keeps_queue(self):
        self.queue.enqueue(self.reading(True))
        with mock.patch("noc.edge_sim.post_event",return_value={
            "status":"accepted","accepted":1,"sequence":2}):
            with self.assertRaisesRegex(RuntimeError,"acknowledgement mismatch"):
                flush(self.queue,"http://127.0.0.1:8788",self.agent["credential"])
        self.assertEqual(self.queue.size(),1)
    def test_partial_ack_keeps_queue(self):
        self.queue.enqueue(self.reading(True))
        with mock.patch("noc.edge_sim.post_event",return_value={
            "status":"accepted","accepted":0,"sequence":1}):
            with self.assertRaisesRegex(RuntimeError,"Observation count mismatch"):
                flush(self.queue,"http://127.0.0.1:8788",self.agent["credential"])
        self.assertEqual(self.queue.size(),1)
    def test_stale_agent_revocation_blocks_heartbeat_and_telemetry(self):
        token=self.agent["credential"]
        self.assertEqual(self.store.heartbeat(token)["sequence"],0)
        self.store.revoke(self.agent["agent_id"])
        with self.assertRaises(PermissionError):self.store.heartbeat(token)
        with self.assertRaises(PermissionError):
            self.store.ingest(token,{"sequence":1,"readings":self.reading(True)})
    def test_heartbeat_keeps_agent_online_without_claiming_device_health(self):
        token=self.agent["credential"]
        self.store.heartbeat(token)
        dashboard=self.store.snapshot()
        self.assertEqual(dashboard["agents"][0]["connection"],"online")
        self.assertEqual(len(dashboard["incidents"]),0)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM observations").fetchone()[0],0)
    def test_rejects_unapproved_endpoint(self):
        for endpoint in ["http://192.168.1.3:8788","http://example.net",
                         "http://127.0.0.1:8080","https://user:secret@somehost.net",
                         "https://somehost.net/redirect","https://example.net?next=secret"]:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):
                allowed_endpoint(endpoint)
    def test_redirect_never_forwards_agent_bearer_credential(self):
        paths=[]
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                paths.append(self.path)
                self.send_response(307)
                self.send_header("Location","/unexpected-sink")
                self.end_headers()
        server=HTTPServer(("127.0.0.1",0),Redirect)
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),worker.join(timeout=5)))
        target=f"http://127.0.0.1:{server.server_port}"
        with mock.patch("noc.edge_sim.allowed_endpoint",return_value=target):
            with self.assertRaises(error.HTTPError) as caught:
                post_event(target,self.agent["credential"],json.dumps({
                    "sequence":1,"readings":self.reading(True)}))
        self.assertEqual(caught.exception.code,307)
        self.assertEqual(paths,["/api/v1/agent/telemetry"])

    def test_offline_queue_rejects_invalid_data_before_persist(self):
        for batch in [[{"check_id":self.check,"ok":True,"latency":-1}],
                      [{"check_id":self.check,"ok":True,"note":"bad\nline"}],
                      [{"check_id":self.check,"ok":True},{"check_id":self.check,"ok":False}]]:
            with self.assertRaises(ValueError):
                self.queue.enqueue(batch)
        self.assertEqual(self.queue.size(),0)
