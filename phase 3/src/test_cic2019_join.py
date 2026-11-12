"""No guessed clock or benign label may fill missing source evidence."""
import unittest
from corroborate_cic2019_validation import clock_winner, contains, status


class CIC2019JoinChecks(unittest.TestCase):
    def test_clock_needs_distinct_group_support_and_clear_winner(self):
        def score(offset, n, packets=100):
            return {'offset_seconds': offset, 'exact_nonempty_groups': n, 'corroborated_packets': packets}
        self.assertEqual(clock_winner([score(10800, 5), score(0, 2)]), 10800)
        self.assertIsNone(clock_winner([score(10800, 5), score(0, 5)]))
        self.assertIsNone(clock_winner([score(10800, 1)]))
        self.assertIsNone(clock_winner([score(10800, 5), score(0, 4)]))
        self.assertIsNone(clock_winner([]))

    def test_join_uses_real_intervals_not_minute_wide_assumptions(self):
        group = {'_starts': [100., 200.], 'intervals': [[100., 100.1], [200., 200.2]]}
        self.assertTrue(contains(group, 10900.05, 10800))
        self.assertFalse(contains(group, 10930., 10800))
        self.assertFalse(contains(group, 11000.5, 10800))

    def test_partial_and_idle_evidence_cannot_become_benign(self):
        self.assertEqual(status(10, 10, 0, 10), 'benign_only')
        self.assertEqual(status(10, 9, 0, 10), 'uncertain')
        self.assertEqual(status(10, 0, 0, 0), 'not_labelled')
        self.assertEqual(status(10, 0, 1, 1), 'attack_present')
        with self.assertRaises(ValueError):
            status(0, 0, 0, 0)
        with self.assertRaises(ValueError):
            status(10, 10, 1, 10)


if __name__ == '__main__':
    unittest.main()
