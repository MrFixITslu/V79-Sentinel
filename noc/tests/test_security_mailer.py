import unittest
from noc.security_mailer import send_security_notification, ENDPOINT

class Response:
    status=202
    def __enter__(self): return self
    def __exit__(self,*args): pass

class Notifications(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.base={"id":"a"*64,"ts":1800000000,"severity":"high",
                   "host":"v79sl","rule":"unexpected_ssh_login","summary":"redacted"}
    def transport(self,request,timeout):
        self.assertEqual(request.full_url,ENDPOINT)
        self.assertEqual(request.get_method(),"POST")
        self.assertEqual(timeout,5)
        self.calls.append(request.data)
        return Response()
    def send(self,**overrides):
        kw={"enabled":True,"api_key":"synthetic-api-key-no-real-emails","from_address":"alerts@v79sl.com",
            "to_address":"owner@example.invalid","transport":self.transport}
        kw.update(overrides)
        return send_security_notification(self.base,**kw)
    def test_disabled_or_unconfigured_makes_zero_external_calls(self):
        self.assertFalse(self.send(enabled=False))
        self.assertFalse(self.send(api_key=None))
        self.assertFalse(self.send(from_address="bad-address"))
        self.assertFalse(self.send(to_address="bad\r\nBcc:attacker@example.com"))
        self.assertEqual(self.calls,[])
    def test_confirmed_provider_sends_only_sanitized_evidence(self):
        self.assertTrue(self.send())
        content=self.calls[0].decode()
        self.assertNotIn("redacted",content)
        self.assertNotIn("synthetic-api-key",content)
        self.assertIn("does NOT confirm",content)
    def test_untrusted_or_malformed_incident_not_forwarded(self):
        self.assertFalse(send_security_notification({**self.base,"rule":"x\r\nFake"},enabled=True,
            api_key="synthetic-api-key-no-real-emails",from_address="alerts@v79sl.com",
            to_address="owner@example.invalid",transport=self.transport))
        self.assertEqual(self.calls,[])

if __name__=="__main__": unittest.main()
