"""Engineering guards for the separate legitimate stress runner."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import csv
import socket
import dpkt
import http.client
import io
import json
from declare_benign_stress_v4 import entries, build, LAB
from stress_runner_v4 import configuration, prepare
from replay_stress_session_v4 import extract
from audit_stress_session_v4 import audit, sha


def failure_fixture(root, capture_drops=0):
    for name in ('capture','server','router','client1','client2','client3'):
        (root/name).mkdir()
    def save(name,value): (root/name).write_text(json.dumps(value),encoding='utf-8')
    schedule=dict(warmup_start_utc=101,measurement_start_utc=131,measurement_end_utc=141)
    mac='00:00:00:00:00:01'; web_mac='00:00:00:00:00:02'; profile={'shaping':False}
    with (root/'capture/traffic.pcap').open('wb') as f:
        writer=dpkt.pcap.Writer(f)
        for index in (1,2,3):
            tcp=dpkt.tcp.TCP(sport=12345,dport=80,flags=dpkt.tcp.TH_SYN)
            ip=dpkt.ip.IP(src=socket.inet_aton(f'172.28.240.{9+index}'),dst=socket.inet_aton('172.28.240.100'),p=6,data=tcp); ip.len=len(ip)
            eth=dpkt.ethernet.Ethernet(src=bytes.fromhex(mac.replace(':','')),dst=bytes.fromhex(web_mac.replace(':','')),type=2048,data=ip)
            writer.writepkt(bytes(eth),ts=135+index*.01)
    m=dict(state='collected_audit_pending',label='BENIGN',cleanup_exit_code=0,web_alive_after_measurement=True,
           isolation=dict(one_internal_bridge_forced_router_host_routes=True,published_ports=False,host_network=False,host_nic_modified=False),
           schedule=schedule,pcap_sha256=sha(root/'capture/traffic.pcap'),client_seeds=[1,2,3],
           payloads={'/small.bin':{'bytes':4096,'sha256':'fixture'}},profile=profile,
           session='fixture',role='T',condition='mixed_keepalive',repeat=1,plan_sha256='fixture')
    save('session.json',m)
    save('capture/capture.json',dict(premature_exit=False,tcpdump_exit_code=0,ready_utc=100,stop_signal_utc=145,
          start_utc=99,copy_finished_utc=146,web_mac=web_mac,filter=f'tcp port 80 and ether host {web_mac}'))
    (root/'capture/tcpdump.log').write_text(f'3 packets captured\n{capture_drops} packets dropped by kernel\n',encoding='utf-8')
    (root/'server/access.tsv').write_text('',encoding='utf-8')
    save('router/ready.json',dict(icmp_redirects_disabled=True,router_mac=mac,profile=profile,routes=[]))
    save('router/final.json',dict(tc_after={'eth0':[dict(kind='prio',drops=7),dict(kind='netem',drops=3,packets=1),dict(kind='netem',drops=4,packets=1)]}))
    for index in (1,2,3):
        save(f'client{index}/ready.json',dict(effective_seed=index,ready_utc=100,client_addresses=[f'172.28.240.{9+index}'],service_addresses=['172.28.240.100'],routes=[]))
        save(f'client{index}/client.json',dict(effective_seed=index,schedule=schedule,totals=dict(attempts=1,complete=0,failed=1,bytes=0)))
        row=dict(request_id=f'c{index}-r0',method='GET',path='/small.bin',start_utc=135,end_utc=137,seconds=2,complete=False,bytes=0,error='TimeoutError')
        (root/f'client{index}/requests.jsonl').write_text(json.dumps(row)+'\n',encoding='utf-8')


class BenignStress(unittest.TestCase):
    def test_full_audit_retains_legitimate_failures_and_counts_leaf_drops_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); failure_fixture(root)
            result=audit(root)
            self.assertTrue(result['engineering_quality_pass'])
            self.assertEqual(result['client_outcomes']['failed'],3)
            self.assertEqual(result['router_qdisc_drops'],7)

    def test_capture_loss_rejects_same_legitimate_workload(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); failure_fixture(root,capture_drops=1)
            with self.assertRaisesRegex(ValueError,'Capture kernel loss'): audit(root)

    def test_head_then_get_reuses_http_connection(self):
        spec=importlib.util.spec_from_file_location('stress_client_v3',LAB/'client.py'); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        class Socket:
            responses=[b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n',b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDATA']
            def makefile(self,*args): return io.BytesIO(self.responses.pop(0))
            def sendall(self,data): pass
            def close(self): pass
        connection=http.client.HTTPConnection('fixture'); connection.sock=Socket()
        connection.request('HEAD','/fixture'); response=connection.getresponse()
        self.assertEqual(module.read_response_chunk(response,'HEAD'),b'')
        self.assertTrue(response.isclosed())
        connection.request('GET','/fixture'); response=connection.getresponse()
        self.assertEqual(module.read_response_chunk(response,'GET'),b'DATA')
        self.assertTrue(response.isclosed()); connection.close()

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
            ip=dpkt.ip.IP(src=socket.inet_aton('172.28.240.10'),dst=socket.inet_aton('172.28.240.100'),p=6,data=tcp)
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
