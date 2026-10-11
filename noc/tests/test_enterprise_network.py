"""Enterprise inventory and diagnostics remain authenticated, bounded, non-scanning."""
import unittest
from unittest.mock import patch, Mock
from noc.sentinel_network_lab import inventory, capabilities, diagnostic
from noc.tests.test_mission_control_bridge import MissionHttpTests

class NetworkLabTests(unittest.TestCase):
    def test_neighbor_evidence_is_not_complete_inventory(self):
        result=Mock(stdout='[{"dst":"192.168.100.1","dev":"wlp3s0","lladdr":"aa:bb:cc:dd:ee:ff","state":["STALE"]},{"dst":"8.8.8.8","dev":"eth0"},{"dst":"evil","dev":"eth0"}]')
        with patch('noc.sentinel_network_lab.shutil.which',return_value='/usr/sbin/ip'),patch('noc.sentinel_network_lab.subprocess.run',return_value=result) as run:
            data=inventory()
        self.assertEqual(len(data['devices']),1)
        self.assertEqual(data['devices'][0]['state'],['STALE'])
        self.assertIn('not proof',data['scope'])
        self.assertEqual(run.call_args.args[0],['/usr/sbin/ip','-j','neigh','show'])

    def test_no_capture_privileges_or_fabricated_pcap_support(self):
        self.assertFalse(capabilities()['capture'])
        self.assertFalse(capabilities()['pcapImport'])

    def test_unapproved_target_and_kind_rejected_before_process(self):
        with patch('noc.sentinel_network_lab.subprocess.run') as run:
            for body in [{'target':'evil.example','kind':'tcp'},{'target':'Hub','kind':'shell'},{'target':'Hub','kind':'tcp','host':'127.0.0.1'}]:
                with self.assertRaises(ValueError):diagnostic(body)
            run.assert_not_called()

    def test_private_dns_rebinding_rejected_before_socket(self):
        answer=Mock(stdout='[[2,1,6,"",["127.0.0.1",443]]]')
        with patch('noc.sentinel_network_lab.subprocess.run',return_value=answer),patch('noc.sentinel_network_lab.socket.socket') as sock:
            with self.assertRaises(ValueError):diagnostic({'target':'Hub','kind':'tcp'})
            sock.assert_not_called()

    def test_route_pins_resolved_address_and_bounds_command(self):
        answer=Mock(stdout='[[2,1,6,"",["93.184.216.34",443]]]')
        route=Mock(stdout='one hop')
        with patch('noc.sentinel_network_lab.subprocess.run',side_effect=[answer,route]) as run,patch('noc.sentinel_network_lab.shutil.which',return_value='/usr/bin/traceroute'):
            result=diagnostic({'target':'Hub','kind':'route'})
        self.assertEqual(result['resolvedAddress'],'93.184.216.34')
        self.assertEqual(run.call_args.args[0],['/usr/bin/traceroute','-n','-m','12','-w','1','-q','1','93.184.216.34'])
        self.assertEqual(run.call_args.kwargs['timeout'],20)

class NetworkHttpTests(MissionHttpTests):
    def test_inventory_requires_auth(self):
        with patch('noc.server.network_inventory') as fn:
            self.assertEqual(self.request('GET','/api/v1/network/inventory')[0],401)
            fn.assert_not_called()

    def test_inventory_is_read_only_and_no_store(self):
        cookie=self.login()
        with patch('noc.server.network_inventory',return_value={'devices':[],'scope':'kernel only'}):
            status,headers,body=self.request('GET','/api/v1/network/inventory',cookie=cookie)
        self.assertEqual(status,200)
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(body['devices'],[])

    def test_diagnostics_get_is_not_action_and_csrf_required(self):
        cookie=self.login()
        with patch('noc.server.network_diagnostic') as fn:
            self.assertEqual(self.request('GET','/api/v1/network/diagnostic',cookie=cookie)[0],404)
            self.assertEqual(self.request('POST','/api/v1/network/diagnostic',body={'target':'Hub','kind':'tcp'},cookie=cookie)[0],403)
            fn.assert_not_called()

    def diagnostic_request(self,cookie):
        import http.client,json
        csrf=self.request('GET','/api/v1/session',cookie=cookie)[2]['csrf']
        con=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        con.request('POST','/api/v1/network/diagnostic',json.dumps({'target':'Hub','kind':'tcp'}),{'Cookie':cookie,'Content-Type':'application/json','Origin':f'http://127.0.0.1:{self.server.server_port}','X-Sentinel-CSRF':csrf})
        response=con.getresponse();status=response.status;response.read();con.close()
        return status

    def test_diagnostic_admin_allowed_viewer_denied(self):
        cookie=self.login()
        with patch('noc.server.network_diagnostic',return_value={'kind':'tcp'}) as fn:
            self.assertEqual(self.diagnostic_request(cookie),200)
            fn.assert_called_once_with({'target':'Hub','kind':'tcp'})
        with self.server.store.db() as db:
            db.execute("UPDATE operators SET role='viewer' WHERE username='mission-admin'")
        with patch('noc.server.network_diagnostic') as fn:
            self.assertEqual(self.diagnostic_request(cookie),403)
            fn.assert_not_called()

    def test_inventory_timeout_is_sanitized(self):
        import subprocess
        cookie=self.login()
        with patch('noc.server.network_inventory',side_effect=subprocess.TimeoutExpired('ip',3)):
            status,_,body=self.request('GET','/api/v1/network/inventory',cookie=cookie)
        self.assertEqual(status,503)
        self.assertEqual(body['error'],'Network observation source unavailable')

    def test_enterprise_static_files_present(self):
        for path in ('/enterprise-center.js','/enterprise-center.css','/netpulse-model.js'):
            status,_,body=self.request('GET',path)
            self.assertEqual(status,200)
            self.assertGreater(len(body),1000)

if __name__=='__main__':unittest.main()
