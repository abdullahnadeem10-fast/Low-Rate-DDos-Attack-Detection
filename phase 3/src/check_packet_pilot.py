"""Controlled fixture: packet direction, bounded prefix, and no future influence."""
from collections import Counter
import io
import socket

import dpkt
from packet_pilot import collect, make_windows


def frame(source, dest, sport, dport, flags):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags)
    ip = dpkt.ip.IP(src=socket.inet_aton(source), dst=socket.inet_aton(dest), p=6, data=tcp)
    return bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def capture(future_packet_count):
    target, client = '192.168.10.50', '192.168.10.20'
    incoming = frame(client,target,45000,80,dpkt.tcp.TH_SYN)
    outgoing = frame(target,client,80,45000,dpkt.tcp.TH_ACK)
    irrelevant = frame(client,target,46000,22,dpkt.tcp.TH_SYN)
    stream = io.BytesIO()
    writer = dpkt.pcap.Writer(stream)
    writer.writepkt(irrelevant,ts=99.1)
    writer.writepkt(incoming,ts=104.1)
    writer.writepkt(outgoing,ts=104.2)
    for i in range(future_packet_count):
        writer.writepkt(incoming,ts=106.1+i/100)
    writer.writepkt(irrelevant,ts=107.1)
    return stream.getvalue(), len(incoming), len(outgoing)


raw, inbound, outbound = capture(1)
groups, a, b, stats, usable, _ = collect(raw + bytes(5))
assert usable == len(raw) and stats['frames_read'] == 5 and stats['selected_tcp_frames'] == 3
rows = make_windows(groups[('192.168.10.50',80)],a,b)
by_second = {r['second']:r for r in rows}
r = by_second[104]
assert (r['packets_in'],r['packets_out'],r['bytes_in'],r['bytes_out']) == (1,1,inbound,outbound)
assert (r['syn_in'],r['sources_in'],r['packets_in_last5']) == (1,1,1)
assert by_second[105]['packets_in'] == 0 and by_second[105]['packets_in_last5'] == 1
changed, _, _ = capture(3)
groups, a, b, *_ = collect(changed)
new_rows = make_windows(groups[('192.168.10.50',80)],a,b)
assert rows[:2] == new_rows[:2] and rows[2] != new_rows[2]
assert make_windows({},100,105)[0]['packets_in_last5'] == 0
print('PASS: complete records, directional counts, idle windows, history reset, and no future influence.')
