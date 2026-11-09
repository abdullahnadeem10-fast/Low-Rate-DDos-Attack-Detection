"""Guard against benign-by-default labels and inconsistent packet joins."""
import csv
from pathlib import Path
import unittest

from assess_packet_development import assess
from causal_features import CausalFeatures, Event


class ReadinessChecks(unittest.TestCase):
    def tables(self, labelled_packets=1):
        directory = Path(__file__).resolve().parents[1] / 'data/test_fixtures/readiness'
        directory.mkdir(parents=True, exist_ok=True)
        core = CausalFeatures()
        core.add(Event(100.1, '192.0.2.1', 40000, True, 60, 2))
        rows = core.finish(102)
        features = directory / 'features.csv'
        with features.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
        labels = directory / 'labels.csv'
        with labels.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['utc_second', 'packets', 'verified_benign_packets',
                'verified_attack_packets', 'uncorroborated_packets', 'status'])
            writer.writeheader()
            writer.writerow({'utc_second': 100, 'packets': labelled_packets,
                'verified_benign_packets': labelled_packets, 'verified_attack_packets': 0,
                'uncorroborated_packets': 0, 'status': 'benign_only'})
        return features, labels

    def test_unlabelled_empty_second_is_not_benign(self):
        report = assess(*self.tables())
        self.assertEqual(report['window_status'], {'benign_only': 1, 'not_labelled': 1})
        self.assertFalse(report['training_ready'])

    def test_mismatched_packet_counts_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'Packet count disagreement'):
            assess(*self.tables(labelled_packets=2))


if __name__ == '__main__':
    unittest.main(verbosity=2)
