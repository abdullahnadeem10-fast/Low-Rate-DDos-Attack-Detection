"""Protocol fixtures for conservative full-capture connection attribution."""
import hashlib
import unittest

import numpy as np
from index_friday_tcp import DTYPE
from tcp_incarnations import attribute_key


def packet(t, incoming, flags, seq, ack=0, payload=0):
    signature = hashlib.sha256(repr((incoming, flags, seq, ack, payload)).encode()).digest()
    return (t, 1, 40000, incoming, flags, seq, ack, payload, 100 + payload, int(t * 10), signature)


def analyze(packets):
    rows = np.array(packets, dtype=DTYPE)
    return rows, *attribute_key(rows, list(range(len(rows))))


class IncarnationChecks(unittest.TestCase):
    def handshake(self, t=0, c=100, s=500):
        return [packet(t+.1, True, 2, c), packet(t+.2, False, 18, s, (c+1)&0xffffffff),
                packet(t+.3, True, 16, (c+1)&0xffffffff, (s+1)&0xffffffff)]

    def test_post_rst_ack_remains_same_identity(self):
        packets = self.handshake() + [packet(.4, True, 20, 101, 501), packet(.5, True, 16, 101, 501)]
        rows, groups, assigned, reasons = analyze(packets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(assigned), len(rows))
        self.assertEqual(groups[0].post_close_packets, 1)
        self.assertTrue(groups[0].handshake_ack)
        self.assertIn('exact_repeat', reasons[4])

    def test_fin_close_then_final_ack_is_attributed(self):
        packets = self.handshake() + [packet(.4, True, 17, 101, 501), packet(.5, False, 17, 501, 102),
                                      packet(.6, True, 16, 102, 502)]
        rows, groups, assigned, reasons = analyze(packets)
        self.assertEqual(len(assigned), len(rows))
        self.assertEqual(groups[0].post_close_packets, 1)
        self.assertEqual(groups[0].first_close, .5)

    def test_new_isn_port_reuse_is_distinct_without_timeout_guess(self):
        rows, groups, assigned, reasons = analyze(self.handshake() + [packet(.4, True, 20, 101, 501)] + self.handshake(180, 10000, 20000))
        self.assertEqual(len(groups), 2)
        self.assertEqual(set(assigned.values()), {0, 1})
        self.assertEqual(groups[0].last, .4)
        self.assertEqual(groups[1].first, 180.1)

    def test_retransmitted_same_syn_keeps_identity_across_long_gap(self):
        packets = self.handshake() + [packet(180.1, True, 2, 100)]
        rows, groups, assigned, reasons = analyze(packets)
        self.assertEqual(len(groups), 1)
        self.assertEqual(assigned[0], assigned[3])
        self.assertEqual(groups[0].last, 180.1)

    def test_missing_syn_is_unresolved_even_repeated_header(self):
        rows, groups, assigned, reasons = analyze([packet(.1, True, 16, 101, 501), packet(.2, True, 16, 101, 501)])
        self.assertFalse(groups)
        self.assertFalse(assigned)
        self.assertEqual(set(reasons.values()), {'no_supported_identity'})

    def test_conflicting_server_isns_are_not_chosen_by_recency(self):
        packets = self.handshake() + [packet(.4, False, 18, 999, 101)]
        rows, groups, assigned, reasons = analyze(packets)
        self.assertTrue(groups[0].ambiguous)
        self.assertFalse(assigned)

    def test_sequence_wrap_is_supported_but_gap_is_unresolved(self):
        packets = self.handshake(c=0xfffffffe) + [packet(.4, True, 24, 0xffffffff, 501, 3),
                                                 packet(.5, False, 16, 501, 2),
                                                 packet(.6, True, 24, 1000, 501, 10)]
        rows, groups, assigned, reasons = analyze(packets)
        self.assertIn(4, assigned)
        self.assertNotIn(5, assigned)
        self.assertEqual(groups[0].coverage_in, [(0, 4)])

    def test_ack_of_unobserved_bytes_is_unresolved(self):
        rows, groups, assigned, reasons = analyze(self.handshake() + [packet(.4, True, 16, 101, 999)])
        self.assertNotIn(3, assigned)

    def test_syn_rejection_with_no_server_isn_and_late_reset(self):
        packets = [packet(.1, True, 2, 100), packet(.2, False, 20, 0, 101), packet(.3, False, 20, 0, 101)]
        rows, groups, assigned, reasons = analyze(packets)
        self.assertEqual(len(assigned), 3)
        self.assertIsNone(groups[0].server_isn)
        self.assertEqual(groups[0].post_close_packets, 1)

    def test_multiple_sequence_candidates_remain_ambiguous(self):
        packets = self.handshake() + [packet(.4, True, 24, 101, 501, 100)] + self.handshake(1, 150, 550)
        packets += [packet(1.4, True, 16, 151, 551)]
        rows, groups, assigned, reasons = analyze(packets)
        # Client bytes overlap both identities; ACK beyond the first server's
        # observed coverage still uniquely identifies the second handshake.
        self.assertEqual(assigned[7], 1)
        ambiguous = self.handshake() + [packet(.4, True, 24, 101, 501, 100), packet(.5, False, 24, 501, 201, 100)]
        ambiguous += self.handshake(1, 150, 550)
        rows, groups, assigned, reasons = analyze(ambiguous)
        self.assertNotIn(7, assigned)
        self.assertEqual(reasons[7], 'ambiguous_identity')


if __name__ == '__main__':
    unittest.main()
