"""Whole-source allocation must not quietly retain temporal validation blocks."""
import unittest
import numpy as np

from causal_features import Event
from index_friday_tcp import DTYPE
from replay_public_partitions import Partition
from replay_public_whole_capture import destination_overlap, validate_whole_ownership


class WholeCaptureChecks(unittest.TestCase):
    def test_unknown_age_is_retained_for_wholly_owned_destination(self):
        b = {'raw_start': 0, 'raw_end': 120, 'kind': 'whole_capture_attack_destination', 'service': '192.0.2.1:80'}
        p = Partition(b)
        p.add(Event(25.1, 'fixture-client', 40000, True, 100, 16), 100)
        p.finish(30)
        self.assertEqual(p.counts['unknown_or_ambiguous_start_packets'], 1)
        self.assertFalse(p.unknown)
        self.assertEqual(p.rows[25]['unknown_age_connections'], 1)
        self.assertEqual(p.rows[25]['packets_in'], 1)

    def test_duplicate_whole_destination_is_invalid_even_disjoint_in_time(self):
        whole = {'kind': 'whole_capture_attack_destination', 'service': '192.0.2.1:80', 'role': 'T'}
        validate_whole_ownership([whole])
        with self.assertRaises(ValueError):
            validate_whole_ownership([whole, {'kind': 'attack_block', 'service': '192.0.2.1:80', 'role': 'V'}])

    def test_packet_overlap_checks_port_address_and_half_open_time(self):
        rows = np.zeros(4, dtype=DTYPE)
        rows['timestamp'] = [10., 19., 20., 15.]
        rows['client'] = [0xc0000201] * 4
        rows['port'] = [80, 40000, 80, 80]
        rows['client'][3] = 0xc0000202
        b = {'service': '192.0.2.1:80', 'raw_start': 10, 'raw_end': 20}
        self.assertEqual(destination_overlap(rows, [b]), 1)


if __name__ == '__main__':
    unittest.main()
