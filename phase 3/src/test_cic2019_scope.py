"""Acquisition must not consume reserved candidate/final sources or wrong ranges."""
import unittest

from declare_cic2019_validation import build
from download_cic2019_validation import approved, valid_range


class CIC2019ScopeChecks(unittest.TestCase):
    def test_only_declared_03_11_archives_are_allowed(self):
        plan = build()
        self.assertEqual(len(plan['allowed_downloads']), 2)
        for item in plan['allowed_downloads']:
            self.assertIn('03-11', item['path'])
            self.assertEqual(approved(item).suffix, '.zip')
        item = dict(plan['allowed_downloads'][0])
        item['path'] = 'pcaps/01-12/PCAP-01-12_0750-0818.zip'
        with self.assertRaises(ValueError):
            approved(item)

    def test_revision_bytes_and_private_destination_cannot_be_substituted(self):
        original = build()['allowed_downloads'][0]
        with self.assertRaises(ValueError):
            approved({**original, 'bytes': original['bytes'] - 1})
        with self.assertRaises(ValueError):
            approved({**original, 'local': '../../outside.zip'})

    def test_partial_or_redirect_range_mismatch_is_rejected(self):
        self.assertTrue(valid_range('HTTP/2 206\r\nContent-Range: bytes 10-19/100\r\n', 10, 19, 100))
        self.assertFalse(valid_range('Content-Range: bytes 0-9/100\r\n', 10, 19, 100))
        self.assertFalse(valid_range('Content-Range: bytes 10-19/200\r\n', 10, 19, 100))
        self.assertFalse(valid_range('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n', 10, 19, 100))
        self.assertFalse(valid_range('Content-Range: bytes 10-19/100\r\n\r\nContent-Range: bytes 0-9/100\r\n', 10, 19, 100))

    def test_final_candidate_is_reserved_not_declared_qualified(self):
        p = build()
        self.assertIn('Entire 01-12', p['reserved_final_K_candidate'])
        self.assertFalse(p['final_K_candidate_qualified'])
        self.assertFalse(p['independent_attack_V_accepted'])
        self.assertFalse(p['study_training_ready'])


if __name__ == '__main__':
    unittest.main()
