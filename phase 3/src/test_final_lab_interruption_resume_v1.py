"""Offline refusal fixtures for the new unscheduled-setup exception only."""
import json
from pathlib import Path
import tempfile
import unittest

from final_lab_interruption_resume_v1 import AGENTS, unscheduled_setup


class UnscheduledRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.entry = {'id': 'final-a-015'}
        self.record = dict(entry=self.entry, state='prepared')
        for name in ('control', 'server', 'capture', *AGENTS):
            (self.path / name).mkdir()
        (self.path / 'server/access.tsv').write_text('')
        for agent in AGENTS:
            (self.path / agent / 'ready.json').write_text('{}')
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        (self.path / 'session.json').write_text(json.dumps(self.record))

    def refuse(self):
        with self.assertRaises(ValueError):
            unscheduled_setup(self.path, self.entry)

    def test_only_clean_unscheduled_setup_accepted(self):
        self.assertFalse(unscheduled_setup(self.path, self.entry)['schedule_released'])

    def test_released_schedule_file_refused(self):
        (self.path / 'control/schedule.json').write_text('{}'); self.refuse()

    def test_schedule_in_session_refused(self):
        self.record['schedule'] = {}; self.save(); self.refuse()

    def test_collecting_state_refused(self):
        self.record['state'] = 'collecting'; self.save(); self.refuse()

    def test_even_empty_request_output_refused(self):
        (self.path / 'probe/requests.jsonl').write_text(''); self.refuse()

    def test_even_empty_slow_output_refused(self):
        (self.path / 'slow1/events.jsonl').write_text(''); self.refuse()

    def test_server_http_output_refused(self):
        (self.path / 'server/access.tsv').write_text('GET /'); self.refuse()

    def test_existing_raw_capture_refused(self):
        (self.path / 'capture/traffic.pcap').write_bytes(b''); self.refuse()

    def test_existing_qualification_refused(self):
        (self.path / 'qualified_v1').mkdir(); self.refuse()

    def test_missing_readiness_refused(self):
        (self.path / 'slow3/ready.json').unlink(); self.refuse()

    def test_different_entry_refused(self):
        with self.assertRaises(ValueError):
            unscheduled_setup(self.path, {'id': 'different'})


if __name__ == '__main__':
    unittest.main()
