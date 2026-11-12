"""A sorted cache is insufficient unless physical capture chronology is proven."""
import contextlib
import io
from pathlib import Path
import socket
import tempfile
import unittest

import dpkt
import numpy as np
from inventory_cic2019_packets import DTYPE
from replay_cic2019_validation import chronology, extract_cache
from replay_causal_features import extract
from replay_public_partitions import write_csv


class CIC2019ReplayChecks(unittest.TestCase):
    def test_chronology_rejects_regression_overlap_or_missing_context(self):
        a = {'link_type': 1, 'first_utc_timestamp': .1, 'last_utc_timestamp': 2., 'max_adjacent_timestamp_regression_seconds': 0.}
        b = {**a, 'first_utc_timestamp': 2.1, 'last_utc_timestamp': 4.}
        self.assertTrue(chronology([a, b])['all_members_monotonic'])
        for bad in ({**b, 'max_adjacent_timestamp_regression_seconds': .00001},
                    {**b, 'first_utc_timestamp': 1.9}, {**b, 'first_utc_timestamp': 3.1}):
            with self.assertRaises(ValueError):
                chronology([a, bad])

    def test_cached_raw_features_equal_direct_one_second_bounded_replay(self):
        client, server = socket.inet_aton('198.51.100.2'), socket.inet_aton('192.0.2.1')
        inputs = [(0.1, True, 16, 9191), (1.2, True, 2, 443), (1.3, False, 18, 443),
                  (1.4, True, 16, 443), (7.1, True, 16, 443), (25.1, True, 4, 443), (27.3, True, 16, 9191)]
        cached = []
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            with (path/'raw.pcap').open('wb') as f:
                writer = dpkt.pcap.Writer(f)
                for n, (ts, incoming, flags, port) in enumerate(inputs):
                    tcp = dpkt.tcp.TCP(sport=40000 if incoming else port, dport=port if incoming else 40000, flags=flags)
                    ip = dpkt.ip.IP(src=client if incoming else server, dst=server if incoming else client, p=6, data=tcp)
                    ip.len = len(ip)
                    frame = bytes(dpkt.ethernet.Ethernet(src=b'\x01'*6, dst=b'\x02'*6, type=0x0800, data=ip))
                    writer.writepkt(frame, ts)
                    if port == 443:
                        row = np.zeros(1, dtype=DTYPE)
                        row['timestamp'], row['client'], row['port'] = ts, int.from_bytes(client, 'big'), 40000
                        row['inbound'], row['flags'], row['length'] = incoming, flags, len(frame)
                        cached.append(row)
            with contextlib.redirect_stdout(io.StringIO()):
                extract(path/'raw.pcap', '192.0.2.1:443', path/'reference.csv')
            features, counts = extract_cache(np.concatenate(cached), 1, 27)
            write_csv(path/'cache.csv', list(features[0]), features)
            self.assertEqual((path/'reference.csv').read_bytes(), (path/'cache.csv').read_bytes())
            self.assertEqual(counts['selected_tcp_in_full_seconds'], 5)

    def test_outside_partial_seconds_are_explicit_and_unsorted_input_fails(self):
        rows = np.zeros(2, dtype=DTYPE)
        rows['timestamp'] = [.5, 1.5]
        rows['client'], rows['port'], rows['inbound'], rows['length'] = 1, 40000, True, 100
        features, counts = extract_cache(rows, 1, 4)
        self.assertEqual(counts['outside_complete_capture_seconds'], 1)
        self.assertEqual(sum(r['packets_in'] for r in features), 1)
        with self.assertRaises(ValueError):
            extract_cache(rows[::-1], 1, 4)


if __name__ == '__main__':
    unittest.main()
