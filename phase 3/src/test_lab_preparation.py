"""Offline guards for isolated benign-lab preparation; no Docker traffic runs."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

LAB=Path(__file__).resolve().parents[1]/'lab'


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,LAB/filename)
    result=importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


class LabPreparationChecks(unittest.TestCase):
    def test_runtime_has_no_published_ports_or_external_network(self):
        lab=module('lab_runner_fixture','run_benign_session.py')
        config=lab.configuration(Path('fixture'),3,'ordinary',60,30,7)
        self.assertEqual(config['networks'],{'isolated':{'internal':True}})
        for name,service in config['services'].items():
            self.assertNotIn('ports',service)
            self.assertFalse(service.get('privileged',False))
            if name=='capture':
                self.assertEqual(service['network_mode'],'service:web')
                self.assertEqual(set(service['cap_add']),{'NET_RAW','NET_ADMIN'})
            else:
                self.assertEqual(service['networks'],['isolated'])

    def test_client_refuses_a_public_service_resolution(self):
        client=module('lab_client_fixture','client.py')
        with patch.dict(os.environ,{'LAB_DURATION':'1','LAB_WARMUP':'20','LAB_CONDITION':'ordinary'}),\
                patch.object(client.socket,'getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',80))]):
            with self.assertRaisesRegex(ValueError,'private network'):
                client.run()


if __name__=='__main__': unittest.main(verbosity=2)
