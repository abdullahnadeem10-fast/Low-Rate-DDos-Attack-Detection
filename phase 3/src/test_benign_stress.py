"""Engineering guards for the separate legitimate stress runner."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import csv
import socket
import dpkt
from declare_benign_stress import entries, build, LAB
from runner import configuration, prepare
from replay_stress_session import extract


class BenignStress(unittest.TestCase):
    def test_roles_profiles_repeats(self):
        rows=entries(); self.assertEqual(len(rows),36)
        self.assertEqual(len({(r['role'],r['condition'],r['repeat']) for r in rows}),36)
        self.assertEqual({r['role'] for r in rows},{'T','C1','C2','V'})

    def test_all_effective_seeds_are_disjoint(self):
        plan=build('sha256:fixture')
        values=[s for e in plan['development_entries']+plan['excluded_preflights'] for s in e['client_seeds']+[e['down_seed'],e['up_seed']]]
        self.assertEqual(len(values),len(set(values)))

    def test_isolation_and_capabilities(self):
        cfg=configuration(Path('fixture').resolve(),entries()[0],'sha256:fixture')
        self.assertTrue(all(n['internal'] and not n['enable_ipv6'] for n in cfg['networks'].values()))
        self.assertTrue(all(not s.get('ports') and not s.get('privileged') and s.get('network_mode')!='host' for s in cfg['services'].values()))
        self.assertEqual(cfg['services']['router']['cap_add'],['NET_ADMIN'])
        self.assertEqual(cfg['services']['capture']['network_mode'],'service:web')

    def test_exact_payload_sizes(self):
        with tempfile.TemporaryDirectory() as temp:
            result=prepare(Path(temp)/'session',entries()[0],'sha256:fixture','fixture')
            self.assertEqual([result['payloads']['/'+n]['bytes'] for n in ('small.bin','medium.bin','large.bin','bulk.bin')],[4096,65536,262144,1048576])

    def test_legitimate_failures_are_outcomes(self):
        spec=importlib.util.spec_from_file_location('stress_client',LAB/'client.py'); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertTrue(module.outcome_is_failure({'complete':False,'error':'TimeoutError'}))
        self.assertFalse(module.outcome_is_failure({'complete':True,'status':200}))

    def test_profiles_only_complete_request_workloads(self):
        plan=build('sha256:fixture')
        self.assertEqual({p['workload'] for p in plan['profiles'].values()},{'mixed','bulk'})
        self.assertGreater(plan['profiles']['congested_mixed']['downlink']['loss_percent'],0)
        self.assertFalse(plan['study_training_ready'])

    def test_observed_idle_tail_expires_state_and_keeps_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); capture=root/'fixture.pcap'
            tcp=dpkt.tcp.TCP(sport=12345,dport=80,flags=dpkt.tcp.TH_SYN)
            ip=dpkt.ip.IP(src=socket.inet_aton('172.28.240.10'),dst=socket.inet_aton('172.28.241.10'),p=6,data=tcp)
            ip.len=len(ip)
            eth=dpkt.ethernet.Ethernet(src=b'123456',dst=b'654321',type=dpkt.ethernet.ETH_TYPE_IP,data=ip)
            with capture.open('wb') as f:
                writer=dpkt.pcap.Writer(f); writer.writepkt(bytes(eth),ts=102.2)
            result=extract(capture,100.1,145.9,root/'features.csv')
            with (root/'features.csv').open(newline='') as f: rows=list(csv.DictReader(f))
            self.assertEqual(result['rows'],44)
            by_second={int(r['utc_second']):r for r in rows}
            self.assertEqual(by_second[120]['history_complete'],'1')
            self.assertEqual(by_second[131]['active_connections'],'1')
            self.assertEqual(by_second[133]['active_connections'],'0')
            self.assertEqual(by_second[144]['packets_in_mean_20'],'0.0')


if __name__=='__main__': unittest.main()
