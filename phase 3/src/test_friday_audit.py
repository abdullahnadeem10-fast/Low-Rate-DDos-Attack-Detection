"""Controlled clock and count-join fixtures; no real reserved data is read."""
from collections import Counter
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

import friday_packet_audit as audit


class AuditChecks(unittest.TestCase):
    def fixture_dir(self):
        d=Path(__file__).resolve().parents[1]/'results/test_fixtures'/self._testMethodName
        d.mkdir(parents=True,exist_ok=True)
        return d

    def key(self,n):
        return (socket.inet_aton('192.0.2.1'),40000+n,socket.inet_aton('192.168.10.50'),80,6)

    def group(self,label='BENIGN'):
        return {'labels':{label},'intervals':[(100000,100065)],'fwd':2,'bwd':1,'rows':1}

    def test_reverse_rows_share_a_canonical_key(self):
        key=self.key(0)
        canonical,direct=audit.canonical_key(key)
        backwards,reverse_direct=audit.canonical_key(audit.reverse(key))
        self.assertEqual(canonical,backwards)
        self.assertTrue(direct)
        self.assertFalse(reverse_direct)

    def test_clock_uses_benign_keys_not_attack_volume(self):
        groups={self.key(i):self.group() for i in range(40)}
        groups[self.key(99)]=self.group('DDoS')
        packets=[(100010+16*3600,key,100) for key in list(groups)[:40]]
        packets += [(100010+4*3600,self.key(99),100)]*1000
        with patch.object(audit,'packets',return_value=iter(packets)):
            offset,report=audit.pass_one(Path('fixture'),groups)
        self.assertEqual(offset,16*3600)
        self.assertEqual(report['benign_key_votes_by_offset_hours'],{16:40})

    def test_insufficient_clock_evidence_rejected(self):
        key=self.key(0)
        with patch.object(audit,'packets',return_value=iter([(100010,key,100)])):
            with self.assertRaises(ValueError): audit.pass_one(Path('fixture'),{key:self.group()})

    def test_exact_directional_counts_and_mismatches_separate(self):
        a,b=self.key(0),self.key(1)
        groups={a:self.group('DDoS'),b:self.group()}
        packets=[(100010,a,100),(100011,a,100),(100012,audit.reverse(a),100),(100013,b,100)]
        with patch.object(audit,'OUT',self.fixture_dir()),patch.object(audit,'packets',return_value=iter(packets)):
            report=audit.pass_two(Path('fixture'),groups,0)
        self.assertEqual(report['exact_directional_packet_count_groups'],{'DDoS':1})
        self.assertEqual(report['directional_count_mismatch_groups'],{'BENIGN':1})
        self.assertIn('NOT exact packet ground truth',report['label_join_status'])

    def test_two_direction_candidates_are_not_guessed(self):
        a=self.key(0)
        groups={a:self.group(),audit.reverse(a):self.group('DDoS')}
        with patch.object(audit,'OUT',self.fixture_dir()),patch.object(audit,'packets',return_value=iter([(100010,a,100)])):
            report=audit.pass_two(Path('fixture'),groups,0)
        self.assertEqual(report['packet_matching']['unmatched_or_multi_direction_packets'],1)
        self.assertFalse(report['exact_directional_packet_count_groups'])


if __name__=='__main__': unittest.main(verbosity=2)
