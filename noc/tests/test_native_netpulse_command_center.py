"""Sentinel native Command Center and NetPulse host-counter authorization."""
from pathlib import Path
import unittest
from unittest.mock import patch
from noc.tests.test_mission_control_bridge import MissionHttpTests
from noc.sentinel_netpulse_interfaces import sample_host_interfaces,_rows

class NetPulseSourceTests(unittest.TestCase):
    def test_real_host_counters_not_simulated(self):
        with patch("noc.sentinel_netpulse_interfaces.Path.read_text",return_value=
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
            "wlp3s0: 3072 0 0 0 0 0 0 0 8096 0 0 0 0 0 0 0\n"
            "lo: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n"):
            data=sample_host_interfaces()
        self.assertEqual(data["source"],"acer-host:/proc/net/dev")
        self.assertEqual(data["interfaces"][0]["name"],"wlp3s0")
        self.assertEqual(data["interfaces"][0]["totalReceivedBytes"],3072)
        self.assertEqual(data["interfaces"][0]["totalTransmittedBytes"],8096)
        self.assertIn("local Acer",data["scope"])

    def test_malformed_interface_names_filtered(self):
        raw="header\nheader\n evil/iface: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\n"
        self.assertFalse(_rows(raw))

class NativeHttpTests(MissionHttpTests):
    def test_private_counters_require_operator_auth(self):
        with patch("noc.server.sample_host_interfaces") as fn:
            self.assertEqual(self.request("GET","/api/v1/netpulse/interfaces")[0],401)
            fn.assert_not_called()

    def test_authenticated_counters_from_allowlisted_local_source(self):
        cookie=self.login()
        with patch("noc.server.sample_host_interfaces",return_value={
            "source":"acer-host:/proc/net/dev",
            "interfaces":[{"name":"wlp3s0","totalReceivedBytes":12,"totalTransmittedBytes":41}]
        }):
            status,headers,body=self.request("GET","/api/v1/netpulse/interfaces",cookie=cookie)
        self.assertEqual(status,200)
        self.assertEqual(body["interfaces"][0]["name"],"wlp3s0")
        self.assertEqual(headers["Cache-Control"],"no-store")

    def test_native_dashboard_has_no_nested_app_and_has_lab(self):
        status,_,body=self.request("GET","/")
        self.assertEqual(status,200)
        for element in (b'id="missionControlPanel"',b'id="nativeTrend"',
                        b'id="nativeQA"',b'id="netpulseLab"',b'id="netpulseImport"',
                        b'id="netpulseNicRows"',b'/mission-native.css',
                        b'/mission-native.js'):
            self.assertIn(element,body)
        self.assertNotIn(b"<iframe",body)
        self.assertNotIn(b"missionFullFrame",body)
        for path in ("/mission-native.js","/mission-native.css"):
            status,_,content=self.request("GET",path)
            self.assertEqual(status,200)
            self.assertGreater(len(content),1500)

if __name__=="__main__":unittest.main()
