"""Capture-to-feature integration: bounded disorder must not rewrite closed seconds."""
import csv
import io
import json
from pathlib import Path
import socket
import unittest

import dpkt
from replay_causal_features import extract


class ReplayChecks(unittest.TestCase):
    def test_late_packet_is_dropped_without_backfilling(self):
        directory=Path(__file__).resolve().parents[1]/'data/test_fixtures'
        directory.mkdir(parents=True,exist_ok=True)
        stream=io.BytesIO(); writer=dpkt.pcap.Writer(stream)
        def frame(port=80,flags=2):
            tcp=dpkt.tcp.TCP(sport=40000,dport=port,flags=flags)
            ip=dpkt.ip.IP(src=socket.inet_aton('192.0.2.1'),dst=socket.inet_aton('192.168.10.50'),p=6,data=tcp)
            return bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP,data=ip))
        writer.writepkt(frame(port=22),ts=.1)
        writer.writepkt(frame(),ts=1.1)
        writer.writepkt(frame(port=22),ts=4.0)  # closes second 1 with one packet
        writer.writepkt(frame(flags=4),ts=1.4)  # deliberately late; cannot revise second 1
        writer.writepkt(frame(flags=16),ts=4.2)
        writer.writepkt(frame(port=22),ts=6.1)
        raw=directory/'late_fixture.pcap'; raw.write_bytes(stream.getvalue())
        out=directory/'late_fixture.csv'
        extract(raw,'192.168.10.50:80',out)
        with out.open(newline='') as f: rows=list(csv.DictReader(f))
        metadata=json.loads(out.with_suffix('.json').read_text())
        self.assertEqual(metadata['counts']['late_selected_dropped'],1)
        self.assertEqual(rows[0]['utc_second'],'1')
        self.assertEqual(rows[0]['packets_in'],'1')
        self.assertEqual(rows[0]['rst_in'],'0')
        self.assertEqual(rows[-1]['utc_second'],'5')


if __name__=='__main__': unittest.main(verbosity=2)
