"""Archived-source format, timestamp and transport-scope guards."""
import socket
import unittest

import dpkt
from inventory_cic2019_labels import count_value, printed_timestamp, syn_member
from inventory_cic2019_packets import fast_scope, pcap_members, prefix_marker


class CIC2019InventoryChecks(unittest.TestCase):
    def test_only_unique_nonreserved_syn_member_is_selected(self):
        self.assertEqual(syn_member(['CSV-03-11/LDAP.csv', 'CSV-03-11/Syn.csv']), 'CSV-03-11/Syn.csv')
        with self.assertRaises(ValueError):
            syn_member(['a/Syn.csv', 'b/Syn.csv'])
        with self.assertRaises(ValueError):
            syn_member(['CSV-01-12/Syn.csv'])

    def test_actual_rotation_names_need_no_pcap_extension(self):
        values = ['SAT-03-11-2018_0100', 'SAT-03-11-2018_02', 'SAT-03-11-2018_0', 'SAT-03-11-2018_01']
        self.assertEqual(pcap_members(values), [values[2], values[3], values[1], values[0]])
        with self.assertRaises(ValueError):
            pcap_members(['01-12/0.pcap'])

    def test_timestamp_is_iso_not_ambiguous_folder_calendar(self):
        a = printed_timestamp('2018-11-03 10:00:00.000001')
        b = printed_timestamp('2018-11-03T07:00:00.000001-03:00')
        self.assertEqual(a, b)
        with self.assertRaises(ValueError):
            printed_timestamp('03/11/2018 10:00:00')

    def test_invalid_packet_totals_cannot_corroborate_labels(self):
        self.assertEqual(count_value('2.0'), 2)
        for value in ('-1', 'inf', 'nan', '1.2'):
            with self.assertRaises(ValueError):
                count_value(value)

    def test_fast_transport_scope_preserves_fragments_and_reverse_traffic(self):
        server, client = socket.inet_aton('192.168.50.4'), socket.inet_aton('172.16.0.5')
        endpoints, addresses = {(server, 80): 0}, {server}
        def frame(incoming=True, port=80, proto=6, fragment=False):
            transport = dpkt.tcp.TCP(sport=40000 if incoming else port, dport=port if incoming else 40000)
            ip = dpkt.ip.IP(src=client if incoming else server, dst=server if incoming else client, p=proto, data=transport)
            if fragment:
                ip.mf = 1
            ip.len = len(ip)
            return bytes(dpkt.ethernet.Ethernet(src=b'\x01'*6, dst=b'\x02'*6, type=0x0800, data=ip))
        self.assertEqual(fast_scope(frame(), endpoints, addresses)[0], 'decode')
        self.assertEqual(fast_scope(frame(False), endpoints, addresses)[0], 'decode')
        self.assertEqual(fast_scope(frame(port=5000), endpoints, addresses), ('other_tcp_port', 5000))
        self.assertEqual(fast_scope(frame(proto=17), endpoints, addresses)[0], 'non_tcp_ipv4')
        self.assertEqual(fast_scope(frame(port=5000, fragment=True), endpoints, addresses)[0], 'decode')

    def test_service_prefix_evidence_is_not_filename_evidence(self):
        self.assertEqual(prefix_marker(b'GET / HTTP/1.1\r\nHost: fixture\r\n'), 1)
        self.assertEqual(prefix_marker(b'HTTP/1.1 200 OK\r\n'), 2)
        self.assertEqual(prefix_marker(b'\x16\x03\x03\x00\x10'), 3)
        self.assertEqual(prefix_marker(b'not-an-http-record'), 0)


if __name__ == '__main__':
    unittest.main()
