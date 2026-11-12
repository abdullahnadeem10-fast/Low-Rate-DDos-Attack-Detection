"""Boundary and observed-connection leakage tests; no research holdout access."""
import hashlib
import io
import csv
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

import dpkt

from causal_features import Event
from replay_public_partitions import HashingReader, Partition, add_interval, covered, open_capture, quarantine_shared, reasons, validate_plan
import replay_public_partitions as replay_module
from summarize_study_development import timeline


def spec(role='T', start=0, end=120, kind='attack_block', service='192.0.2.1:80'):
    return {'id': role, 'role': role, 'kind': kind, 'service': service,
            'raw_start': start, 'raw_end': end, 'eligible_start': start + 20, 'eligible_end': end,
            'accepted_status': 'attack_present' if kind == 'attack_block' else 'benign_only',
            'y': int(kind == 'attack_block')}


def event(t, flags=16, inbound=True, port=40000):
    return Event(t, '198.51.100.2', port, inbound, 100, flags)


class PublicPartitionChecks(unittest.TestCase):
    def test_sparse_label_rows_do_not_become_contiguous(self):
        self.assertEqual(timeline([1, 2, 5, 6, 7, 20]), {
            'labelled_runs': 3, 'longest_consecutive_labelled_run_seconds': 3, 'gaps_between_retained_rows': 2})
        with self.assertRaises(ValueError):
            timeline([1, 1])

    def test_complete_fixture_replay_preserves_unknown_input_then_masks_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'src').mkdir()
            (root/'results/development').mkdir(parents=True)
            for name in ('causal_features.py', 'declare_public_partitions.py', 'replay_public_partitions.py'):
                (root/'src'/name).write_bytes((Path(__file__).parent/name).read_bytes())
            empty = Partition(spec())
            empty.finish(1)
            predictors = [k for k in empty.rows[0] if k not in ('utc_second', 'history_complete')]
            (root/'results/development/benign_development_manifest.json').write_text(json.dumps({'predictor_columns': predictors}))
            capture = root/'fixture.pcap'
            def frame(flags, seq, inbound=True, port=80):
                src, dst = ('198.51.100.2', '192.0.2.1') if inbound else ('192.0.2.1', '198.51.100.2')
                tcp = dpkt.tcp.TCP(sport=40000 if inbound else port, dport=port if inbound else 40000, flags=flags, seq=seq)
                ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
                ip.len = len(ip)
                return bytes(dpkt.ethernet.Ethernet(src=b'\x01'*6, dst=b'\x02'*6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
            packets = [(999.1, frame(16, 1, port=9191)), (1025.1, frame(2, 10)),
                       (1025.2, frame(18, 20, False)), (1025.3, frame(16, 11)),
                       (1205.1, frame(16, 11)), (1260.1, frame(2, 30)), (1400.1, frame(16, 1, port=9191))]
            with capture.open('wb') as f:
                writer = dpkt.pcapng.Writer(f)
                for ts, packet in packets:
                    writer.writepkt(packet, ts)
            blocks = [spec('T', 1000, 1120), spec('V', 1180, 1300)]
            for b in blocks:
                path = root/(b['id'] + '-labels.csv')
                rows = [(1025, 3)] if b['role'] == 'T' else [(1205, 1), (1260, 1)]
                with path.open('w', newline='') as f:
                    w = csv.writer(f)
                    w.writerow(['utc_second', 'packets', 'status'])
                    w.writerows((sec, n, 'attack_present') for sec, n in rows)
                b.update(label_table=path.name, label_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), condition='public_known_ddos')
            plan = {'blocks': blocks, 'reorder_seconds': 1, 'connection_influence_guard_seconds': 50,
                    'feature_core': {'path': 'src/causal_features.py', 'sha256': hashlib.sha256((root/'src/causal_features.py').read_bytes()).hexdigest()},
                    'capture': {'path': capture.name, 'bytes': capture.stat().st_size, 'sha256': hashlib.sha256(capture.read_bytes()).hexdigest(), 'expected_frames': len(packets)},
                    'evidence': {}, 'limitations': []}
            plan_path = root/'fixture-plan.json'
            plan_path.write_text(json.dumps(plan))
            with patch.object(replay_module, 'ROOT', root), redirect_stdout(io.StringIO()):
                replay_module.replay(plan_path)
            report = json.loads((root/'results/development/public_partitioned_v1.json').read_text())
            self.assertTrue(report['feature_engineering_quality_passed'])
            self.assertEqual(report['retained_windows_by_role_and_y'], {'T': {'1': 1}, 'V': {'1': 1}})
            folder = root/'data/development/public_partitioned_v1/V'
            with (folder/'features.csv').open(newline='') as f:
                features = {int(r['utc_second']): r for r in csv.DictReader(f)}
            self.assertEqual(features[1205]['packets_in'], '1')
            self.assertEqual(features[1205]['unknown_age_connections'], '1')
            with (folder/'eligibility.csv').open(newline='') as f:
                eligibility = {int(r['utc_second']): r for r in csv.DictReader(f)}
            self.assertEqual(eligibility[1205]['retained'], '0')
            self.assertIn('unknown_connection_influence', eligibility[1205]['exclusion_reasons'])
            self.assertEqual(eligibility[1260]['retained'], '1')

    def test_capture_magic_not_filename_and_complete_hash(self):
        for writer_class in (dpkt.pcap.Writer, dpkt.pcapng.Writer):
            raw = io.BytesIO()
            writer = writer_class(raw)
            writer.writepkt(b'fixture-frame', ts=25.1)
            value = raw.getvalue()
            stream, reader = open_capture(io.BytesIO(value))
            packets = list(reader)
            self.assertEqual(len(packets), 1)
            self.assertEqual(packets[0][1], b'fixture-frame')
            self.assertEqual(stream.bytes, len(value))
            self.assertEqual(stream.sha.hexdigest(), hashlib.sha256(value).hexdigest())

    def test_sequential_hash_covers_every_byte(self):
        data = b'capture-header\x00' * 500
        stream = HashingReader(io.BytesIO(data))
        consumed = stream.read(24) + stream.read(150) + stream.read()
        self.assertEqual(consumed, data)
        self.assertEqual(stream.bytes, len(data))
        self.assertEqual(stream.sha.hexdigest(), hashlib.sha256(data).hexdigest())
        self.assertFalse(hasattr(stream, 'seek'))

    def test_half_open_boundaries_and_fresh_history(self):
        a, b = Partition(spec()), Partition(spec('V', 180, 300))
        a.add(event(1.1, 2), 11)
        a.add(event(2.1, 18, False), 22)
        a.add(event(3.1), 12)
        a.finish(120)
        b.add(event(180.1), 12)
        b.finish(201)
        self.assertEqual(a.rows[3]['active_age_max'], 2.9)
        self.assertEqual(b.rows[0]['unknown_age_connections'], 1)
        self.assertEqual(b.rows[0]['known_age_connections'], 0)
        self.assertEqual(b.rows[18]['history_complete'], 0)
        self.assertEqual(b.rows[19]['history_complete'], 1)
        self.assertEqual(b.rows[19]['packets_in_mean_20'], .05)
        with self.assertRaises(ValueError):
            a.add(event(120), 11)

    def test_unknown_start_masks_state_and_history_influence(self):
        p = Partition(spec())
        p.add(event(25.1), 100)
        p.finish(90)
        self.assertFalse(covered(24, p.unknown))
        self.assertTrue(covered(25, p.unknown))
        self.assertTrue(covered(75, p.unknown))
        self.assertFalse(covered(76, p.unknown))
        # Masking does not remove packets or state from the causal input.
        self.assertEqual(p.rows[25]['packets_in'], 1)
        self.assertEqual(p.rows[26]['unknown_age_connections'], 1)
        self.assertIn('unknown_connection_influence', reasons(p, p.rows[25], {'status': 'attack_present'}))

    def test_same_syn_across_roles_masks_both_partitions(self):
        a, b = Partition(spec()), Partition(spec('V', 180, 300))
        a.add(event(25.1, 2), 123)
        a.add(event(26.1, 4), 124)
        b.add(event(205.1, 2), 123)
        a.finish(120)
        b.finish(300)
        self.assertEqual(quarantine_shared([a, b]), 1)
        self.assertTrue(covered(25, a.shared))
        self.assertTrue(covered(76, a.shared))
        self.assertTrue(covered(205, b.shared))
        self.assertFalse(covered(204, b.shared))

    def test_reused_tuple_distinct_syn_is_not_same_connection(self):
        a, b = Partition(spec()), Partition(spec('V', 180, 300))
        a.add(event(25.1, 2), 123)
        b.add(event(205.1, 2), 456)
        self.assertEqual(quarantine_shared([a, b]), 0)
        self.assertFalse(a.unknown)
        self.assertFalse(b.unknown)

    def test_incomplete_tracker_with_changed_syn_is_ambiguous(self):
        p = Partition(spec())
        p.add(event(25.1, 2), 123)
        p.add(event(26.1, 2), 456)
        p.add(event(27.1), 457)
        self.assertTrue(covered(27, p.unknown))
        self.assertTrue(covered(77, p.unknown))
        p.add(event(28.1, 4), 457)
        p.add(event(29.1, 2), 789)
        p.finish(90)
        self.assertEqual(p.rows[29]['known_age_connections'], 1)
        self.assertFalse(covered(79, p.unknown))

    def test_whole_benign_destination_retains_unknown_ages(self):
        p = Partition(spec(kind='benign_destination'))
        p.add(event(25.1), 100)
        p.finish(30)
        self.assertEqual(p.counts['unknown_or_ambiguous_start_packets'], 1)
        self.assertFalse(p.unknown)
        self.assertEqual(reasons(p, p.rows[25], {'status': 'benign_only'}), [])
        self.assertEqual(reasons(p, p.rows[26], {}), ['label_not_labelled'])

    def test_expired_connection_cannot_reuse_old_identity(self):
        p = Partition(spec())
        p.add(event(1.1, 2), 123)
        p.add(event(40.1), 124)
        self.assertTrue(covered(40, p.unknown))
        self.assertEqual(p.influence[next(iter(p.influence))], [1, 1])

    def test_merge_and_development_plan_guards(self):
        intervals = []
        for a, b in [(1, 52), (2, 53), (53, 104), (110, 161)]:
            add_interval(intervals, a, b)
        self.assertEqual(intervals, [(1, 104), (110, 161)])
        a, b = spec(), spec('V', 180, 300)
        validate_plan({'blocks': [a, b], 'connection_influence_guard_seconds': 50})
        b['raw_start'] = 169
        with self.assertRaises(ValueError):
            validate_plan({'blocks': [a, b], 'connection_influence_guard_seconds': 50})
        b = spec('V', 180, 300, 'benign_destination')
        a['kind'] = 'benign_destination'
        with self.assertRaises(ValueError):
            validate_plan({'blocks': [a, b], 'connection_influence_guard_seconds': 50})


if __name__ == '__main__':
    unittest.main()
