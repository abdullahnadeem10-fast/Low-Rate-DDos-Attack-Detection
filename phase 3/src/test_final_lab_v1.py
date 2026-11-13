import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from final_lab_policy_v1 import matrix,seed_values
from packet_model_policy import ROOT
sys.path.insert(0,str(ROOT/'lab/final_v1'))
import collector
from audit_final_lab_v1 import truth_rows,corroborated_initial
sys.path.insert(0,str(ROOT/'lab/stress_v5'))
spec=importlib.util.spec_from_file_location('final_agent_fixture',ROOT/'lab/final_v1/agent.py');agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)


class Acquisition(unittest.TestCase):
    def test_exact_factorial_and_benign_repetitions(self):
        units,pref=matrix();a=[u for u in units if u['kind']=='attack'];b=[u for u in units if u['kind']=='benign']
        self.assertEqual((len(a),len(b),len(pref)),(40,20,3))
        from collections import Counter
        self.assertEqual(set(Counter((u['mechanism'],u['sources'],u['connections'],u['interval']) for u in a).values()),{5})
        self.assertEqual(set(Counter(u['condition'] for u in b).values()),{5})

    def test_effective_seeds_are_unique_and_exclude_prior_history(self):
        reserved=seed_values({'old_client_seeds':[1,2,100000000],'net_seed':4,'not_random':7})
        units,pref=matrix(reserved);seeds=[s for u in units+pref for s in u['agent_seeds']+u['net_seeds']]
        self.assertEqual(len(seeds),567);self.assertEqual(len(set(seeds)),567);self.assertFalse(set(seeds)&reserved)

    def test_order_deterministic_and_preflights_only_benign(self):
        self.assertEqual(matrix(),matrix());units,pref=matrix();self.assertEqual(sorted(u['run_order'] for u in units),list(range(60)))
        self.assertTrue(all(u['kind']=='benign' and u['preflight'] for u in pref));self.assertTrue(all(not u['preflight'] for u in units))

    def test_bounded_durations_and_no_intensity_retuning(self):
        units,pref=matrix()
        for u in units+pref:
            collector.require_entry(u);self.assertEqual(u['warmup'],60)
            if u['kind']=='attack':self.assertEqual(u['duration'],240)

    def test_configuration_has_no_external_or_published_paths(self):
        units,_=matrix()
        for unit in [units[0],next(u for u in units if u.get('sources')==3)]:
            c=collector.configuration(Path('/fixture'),unit);self.assertTrue(c['networks']['private']['internal']);self.assertFalse(c['networks']['private']['enable_ipv6'])
            for service in c['services'].values():
                self.assertNotIn('ports',service);self.assertFalse(service.get('privileged'));self.assertNotEqual(service.get('network_mode'),'host')
                self.assertNotIn('SYS_ADMIN',service.get('cap_add',[]))

    def test_web_config_keeps_request_read_timeouts_and_fixed_CGI(self):
        self.assertNotIn('RequestReadTimeout',collector.SERVER_CONFIG);self.assertNotIn('reqtimeout_module',collector.SERVER_CONFIG)
        self.assertIn('LoadModule cgid_module',collector.SERVER_CONFIG);self.assertIn('Timeout 60',collector.SERVER_CONFIG)

    def test_preflight_never_has_a_slow_agent(self):
        _,pref=matrix()
        for unit in pref:self.assertTrue(all(a['role']!='slow' for a in collector.agents(unit).values()))

    def test_declared_source_count_has_exact_fixed_addresses(self):
        units,_=matrix();unit=next(u for u in units if u.get('sources')==3)
        self.assertEqual({a['own'] for a in collector.agents(unit).values() if a['role']=='slow'},{'172.28.240.20','172.28.240.21','172.28.240.22'})

    def test_prepare_bodies_and_CGI_hash_are_exact(self):
        units,_=matrix()
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'unit';m=collector.prepare(out,units[0],{})
            for path,item in m['payloads'].items():
                if path=='/sink/':self.assertEqual(item['sha256'],hashlib.sha256(b'ok\n').hexdigest());continue
                body=(out/'htdocs'/path[1:]).read_bytes();self.assertEqual(len(body),item['bytes']);self.assertEqual(hashlib.sha256(body).hexdigest(),item['sha256'])

    def test_raw_collector_and_auditor_have_no_fitting_or_scoring(self):
        for file in ('lab/final_v1/collector.py','src/audit_final_lab_v1.py','src/run_final_lab_v1.py'):
            tree=ast.parse((ROOT/file).read_text())
            calls=[n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
            self.assertFalse(set(calls)&{'fit','predict_proba','score_samples','score'})

    def test_both_partial_requests_are_bounded_and_fixed_to_private_service(self):
        a=agent.initial_request('incomplete_header','fixture');b=agent.initial_request('slow_request_body','fixture')
        self.assertLess(len(a),512);self.assertNotIn(b'\r\n\r\n',a);self.assertLess(len(b),512);self.assertTrue(b.endswith(b'\r\n\r\nx'))
        self.assertIn(b'Content-Length: 65536',b)

    def test_no_slow_agent_can_use_a_public_or_other_lab_target_address(self):
        s=dict(role='slow',own='8.8.8.8',mechanism='incomplete_header',connections=10,interval=20)
        with patch.object(agent.time,'time',return_value=90):
            with self.assertRaisesRegex(ValueError,'outside lab'):agent.validate(s,dict(warmup_start_utc=100,measurement_start_utc=160,measurement_end_utc=400))

    def test_no_longer_or_higher_intensity_schedule_can_run(self):
        s=dict(role='slow',own='172.28.240.20',mechanism='incomplete_header',connections=100000,interval=1)
        with patch.object(agent.time,'time',return_value=100):
            with self.assertRaises(ValueError):agent.validate(s,dict(warmup_start_utc=100,measurement_start_utc=160,measurement_end_utc=400))
            s.update(connections=10,interval=20)
            with self.assertRaises(ValueError):agent.validate(s,dict(warmup_start_utc=100,measurement_start_utc=160,measurement_end_utc=500))

    def test_final_adapter_uses_unchanged_full_clock_replay_core(self):
        import audit_final_lab_v1,replay_stress_session_v5
        self.assertIs(audit_final_lab_v1.extract,replay_stress_session_v5.extract)

    def test_attack_can_never_be_an_excluded_benign_preflight(self):
        units,_=matrix();u=next(v for v in units if v['kind']=='attack').copy();u['preflight']=True
        with self.assertRaisesRegex(ValueError,'preflight'):collector.require_entry(u)


class Truth(unittest.TestCase):
    schedule=dict(warmup_start_utc=100,measurement_start_utc=160,measurement_end_utc=400)

    def test_unknown_observation_tail_is_not_benign(self):
        rows=list(truth_rows([99,100,159,160,399,400],dict(kind='benign',condition='ordinary'),self.schedule,None))
        self.assertEqual([r['y'] for r in rows],[-1,0,0,0,0,-1])

    def test_no_successful_attack_payload_is_unknown_not_benign(self):
        u=dict(kind='attack',condition='slow_request_body',mechanism='slow_request_body')
        self.assertEqual([r['y'] for r in truth_rows([159,160,180],u,self.schedule,None)],[0,-1,-1])

    def test_first_partial_second_is_unknown_and_campaign_label_not_impact(self):
        u=dict(kind='attack',condition='incomplete_header',mechanism='incomplete_header')
        self.assertEqual([r['y'] for r in truth_rows([160,161,162,399,400],u,self.schedule,161.2)],[-1,-1,1,1,-1])

    def test_complete_headers_are_not_incomplete_header_proof(self):
        prefix=b'GET /small.bin HTTP/1.1\r\nHost: web\r\nX-Research-Token: fixed\r\n'
        self.assertTrue(corroborated_initial(prefix,'fixed','incomplete_header'));self.assertFalse(corroborated_initial(prefix+b'\r\n','fixed','incomplete_header'))

    def test_slow_body_requires_fixed_length_and_correct_token(self):
        p=b'POST /sink/ HTTP/1.1\r\nContent-Length: 65536\r\nX-Research-Token: fixed\r\n\r\nx'
        self.assertTrue(corroborated_initial(p,'fixed','slow_request_body'));self.assertFalse(corroborated_initial(p,'other','slow_request_body'))

    def test_bad_intensity_and_seed_overlap_are_rejected(self):
        units,_=matrix();u=next(u for u in units if u['kind']=='attack').copy();u['connections']=10000
        with self.assertRaises(ValueError):collector.require_entry(u)
        u=units[0].copy();u['agent_seeds']=[1]*7
        with self.assertRaises(ValueError):collector.require_entry(u)


if __name__=='__main__':unittest.main()
