"""Attribute conservative service-IP fragment flags without changing replay evidence.

The replay flags fragments before transport decoding. This independent protocol/
port inventory can distinguish unrelated protocols from unresolved TCP input loss.
It does not relabel data or waive observed-connection/persistence exclusions.
"""
from collections import Counter
import json
import socket
import struct
import time

import dpkt
from declare_public_partitions import ROOT, digest
from replay_public_partitions import open_capture


def main():
    started = time.perf_counter()
    plan_path = ROOT/'plan/public_partitions_v1.json'
    replay_path = ROOT/'results/development/public_partitioned_v1.json'
    plan, replay = (json.loads(p.read_text()) for p in (plan_path, replay_path))
    frames, fragments = 0, []
    endpoints = [(socket.inet_aton(b['service'].split(':')[0]), int(b['service'].split(':')[1]), b) for b in plan['blocks']]
    first = min(b['raw_start'] for b in plan['blocks'])
    last = max(b['raw_end'] for b in plan['blocks'])
    with (ROOT/plan['capture']['path']).open('rb') as raw:
        stream, reader = open_capture(raw)
        for ts, frame in reader:
            frames += 1
            if not first <= ts < last:
                continue
            ip = dpkt.ethernet.Ethernet(frame).data
            if not isinstance(ip, dpkt.ip.IP) or not (ip.offset or ip.mf):
                continue
            matches = [(address, port, b) for address, port, b in endpoints if address in (ip.src, ip.dst) and b['raw_start'] <= ts < b['raw_end']]
            if not matches:
                continue
            ports = None
            if ip.offset == 0 and ip.p in (6, 17):
                payload = bytes(ip.data)
                if len(payload) >= 4:
                    ports = list(struct.unpack('!HH', payload[:4]))
            fragments.append({'utc_timestamp': float(ts), 'source': socket.inet_ntoa(ip.src), 'destination': socket.inet_ntoa(ip.dst),
                              'ip_id': ip.id, 'ip_protocol': ip.p, 'fragment_offset_bytes': ip.offset * 8, 'more_fragments': bool(ip.mf),
                              'first_fragment_ports': ports, 'matching_blocks': [b['id'] for a, port, b in matches]})
        if stream.bytes != plan['capture']['bytes'] or stream.sha.hexdigest() != plan['capture']['sha256'] or frames != plan['capture']['expected_frames']:
            raise ValueError('Full capture integrity gate failed')
    if len(fragments) != replay['selected_fragmented_tcp_frames']:
        raise ValueError('Independent fragment count disagrees with conservative replay flag')
    tcp = [f for f in fragments if f['ip_protocol'] == 6]
    result = {
        'date': '2026-11-12', 'scope': 'Independent attribution of conservative service-IP fragment flags; no model fitting.',
        'plan_sha256': digest(plan_path), 'replay_evidence_sha256': digest(replay_path),
        'capture_sha256': stream.sha.hexdigest(), 'capture_bytes_hashed': stream.bytes, 'frames_read': frames,
        'source_sha256': digest(ROOT/'src/audit_public_fragments.py'),
        'service_ip_fragment_frames': len(fragments), 'fragment_frames_by_ip_protocol': dict(Counter(f['ip_protocol'] for f in fragments)),
        'potentially_relevant_tcp_fragment_frames': len(tcp), 'all_flagged_fragments_proven_non_tcp': bool(fragments) and not tcp,
        'fragments': fragments, 'elapsed_seconds': round(time.perf_counter() - started, 3),
        'interpretation': 'Original replay field selected_fragmented_tcp_frames actually conservatively counts all protocols touching selected service IPs. Preserve its failed flag; this supplemental audit attributes the protocol explicitly. TCP fragment presence would remain unresolved rather than being waived.',
        'unknown_connection_exclusions_unchanged': True, 'study_training_ready': False,
    }
    (ROOT/'results/development/public_fragment_attribution_v1.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: result[k] for k in ('service_ip_fragment_frames', 'fragment_frames_by_ip_protocol', 'potentially_relevant_tcp_fragment_frames', 'elapsed_seconds')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
