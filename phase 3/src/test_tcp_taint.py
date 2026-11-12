"""Unsafe feature-state influence must survive supported packet refreshes."""
import unittest

from causal_features import Event
from replay_public_partitions import covered
from replay_public_v2 import TaintReplay, supported_identity


def spec():
    return {'raw_start': 0, 'raw_end': 200}


def packet(ts, flags=16, incoming=True, port=40000):
    return Event(ts, 'fixture-client', port, incoming, 100, flags)


class TaintChecks(unittest.TestCase):
    def test_supported_refresh_does_not_clear_unsafe_state(self):
        p = TaintReplay(spec())
        p.add(packet(.1, 2), True)
        for ts in (20.1, 40.1, 60.1, 80.1):
            p.add(packet(ts), False)
        self.assertTrue(covered(130, p.intervals))
        self.assertFalse(covered(131, p.intervals))
        self.assertEqual(p.counts['tracker_taint_propagated_packets'], 4)

    def test_expiry_clears_state_but_not_history_guard(self):
        p = TaintReplay(spec())
        p.add(packet(.1, 2), True)
        p.add(packet(40.1, 2), False)
        self.assertFalse(p.tainted)
        self.assertTrue(covered(50, p.intervals))
        self.assertFalse(covered(51, p.intervals))

    def test_close_and_completed_handshake_syn_reset(self):
        p = TaintReplay(spec())
        p.add(packet(.1, 2), True)
        p.add(packet(.2, 18, False), False)
        p.add(packet(.3), False)
        p.add(packet(1.1, 2), False)
        self.assertFalse(p.tainted)
        p.add(packet(2.1, 4), True)
        self.assertFalse(p.tainted)
        p.add(packet(3.1, 2), False)
        self.assertFalse(p.tainted)

    def test_incomplete_new_syn_does_not_clear_tracker_taint(self):
        p = TaintReplay(spec())
        p.add(packet(.1, 2), True)
        p.add(packet(20.1, 2), False)
        self.assertTrue(p.tainted)
        self.assertTrue(covered(70, p.intervals))

    def test_identity_boundaries_and_unresolved_key_are_strict(self):
        b = {'raw_start': 10, 'raw_end': 100}
        g = {'first': 10., 'last': 99.999, 'ambiguous': False}
        self.assertTrue(supported_identity(g, b, False))
        self.assertFalse(supported_identity(g, b, True))
        self.assertFalse(supported_identity({**g, 'last': 100.}, b, False))
        self.assertFalse(supported_identity({**g, 'first': 9.99}, b, False))
        self.assertFalse(supported_identity({**g, 'ambiguous': True}, b, False))


if __name__ == '__main__':
    unittest.main()
