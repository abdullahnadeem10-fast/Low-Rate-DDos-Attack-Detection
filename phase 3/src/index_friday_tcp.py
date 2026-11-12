"""Hash-verified TCP metadata index for the already-allowed Friday target only.

Grouping/audit metadata is private data, never model predictors. Does not read a
label archive, fit models, alter v1 evidence, or access reserved capture sources.
"""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import socket
import time

import dpkt
import numpy as np
from declare_public_partitions import ROOT, digest
from replay_public_partitions import open_capture

DTYPE = np.dtype([
    ('timestamp', '<f8'), ('client', '<u4'), ('port', '<u2'), ('inbound', 'u1'),
    ('flags', 'u1'), ('seq', '<u4'), ('ack', '<u4'), ('payload', '<u4'),
    ('length', '<u4'), ('frame', '<u4'), ('tcp_sha256', 'V32'),
])


def declare():
    previous = ROOT/'plan/public_partitions_v1.json'
    replay = ROOT/'results/development/public_partitioned_v1.json'
    p, r = (json.loads(x.read_text(encoding='utf-8')) for x in (previous, replay))
    plan = {
        'date': '2026-11-12', 'version': 'tcp_boundary_audit_v1',
        'scope': 'Development-only cause audit; no revised feature/eligibility rule or model outcomes.',
        'capture': p['capture'], 'service': '192.168.10.50:80',
        'public_plan_sha256': digest(previous), 'public_replay_sha256': digest(replay),
        'frozen_v1_replay_source_sha256': r['source_sha256']['replay_public_partitions.py'],
        'blocks': [b for b in p['blocks'] if b['kind'] == 'attack_block'],
        'expected_v1_unknown_packets': {b['id']: b['packet_counts']['unknown_or_ambiguous_start_packets'] for b in r['partitions'] if b['kind'] == 'attack_block'},
        'index_fields': DTYPE.names,
        'index_policy': 'All full-capture IPv4 TCP packets at the selected service, independent of labels. Full input hash, frame count, decoding and fragment guards. Stable event-time order; retain original frame indices.',
        'audit_policy': [
            'Replay frozen v1 independently per block and reconcile exact unknown counts and feature table bytes.',
            'Use whole-capture endpoint-key observations, initiating SYN sequence identities, SYN-ACK/ACK relationships and sequence coverage; no arbitrary payload/sequence distance threshold.',
            'Retain closed-incarnation evidence for post-close packets; distinguish exact TCP segment repeats from merely plausible sequence/ACK relationships.',
            'Ambiguous/missing SYN, conflicting handshake, sequence gaps, multiple candidates or unresolved port reuse remain unresolved.',
            'Report raw block ownership/spans for all assigned observations and unresolved canonical keys; never infer independence from no shared observed SYNs alone.',
            'Any more precise eligibility policy requires a new immutable public v2 declaration before selection; preserve v1 and all negative findings.'],
        'reserved_sources_unused': True, 'study_training_ready': False,
    }
    path = ROOT/'plan/tcp_boundary_audit_v1.json'
    content = (json.dumps(plan, indent=2) + '\n').encode('utf-8')
    if path.exists() and path.read_bytes() != content:
        raise FileExistsError('Audit declaration changed; create a new version')
    path.write_bytes(content)
    return path, plan


def build_index(plan_path, plan):
    started = time.perf_counter()
    path = ROOT/plan['capture']['path']
    if path.stat().st_size != plan['capture']['bytes']:
        raise ValueError('Capture size mismatch')
    if digest(ROOT/'src/replay_public_partitions.py') != plan['frozen_v1_replay_source_sha256']:
        raise ValueError('Frozen v1 source changed')
    address_text, port_text = plan['service'].split(':')
    address, port = socket.inet_aton(address_text), int(port_text)
    counts, chunks, batch = Counter(), [], []
    previous, maximum_regression = -math.inf, 0.
    with path.open('rb') as raw:
        stream, reader = open_capture(raw)
        if reader.datalink() != dpkt.pcap.DLT_EN10MB:
            raise ValueError('Ethernet capture required')
        for timestamp, frame in reader:
            counts['frames'] += 1
            try:
                ip = dpkt.ethernet.Ethernet(frame).data
                if isinstance(ip, dpkt.ip.IP) and ip.p == 6:
                    if ip.offset or ip.mf:
                        if address in (ip.src, ip.dst):
                            counts['service_ip_tcp_fragment_frames'] += 1
                        continue
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    tcp = ip.data
                    incoming = ip.dst == address and tcp.dport == port
                    outgoing = ip.src == address and tcp.sport == port
                    if incoming or outgoing:
                        ts = float(timestamp)
                        maximum_regression = max(maximum_regression, previous - ts)
                        previous = ts
                        batch.append((ts, int.from_bytes(ip.src if incoming else ip.dst, 'big'),
                                      tcp.sport if incoming else tcp.dport, incoming, tcp.flags,
                                      tcp.seq, tcp.ack, len(tcp.data), len(frame), counts['frames'],
                                      hashlib.sha256(bytes(tcp)).digest()))
                        counts['selected_tcp'] += 1
                        if len(batch) == 100000:
                            chunks.append(np.array(batch, dtype=DTYPE))
                            batch.clear()
            except (dpkt.UnpackError, ValueError):
                counts['decode_errors'] += 1
            if counts['frames'] % 2000000 == 0:
                print(f'TCP index: {counts["frames"]:,} frames; {time.perf_counter() - started:.1f}s', flush=True)
        if stream.bytes != plan['capture']['bytes'] or stream.sha.hexdigest() != plan['capture']['sha256'] or counts['frames'] != plan['capture']['expected_frames']:
            raise ValueError('Full input integrity gate failed')
    if batch:
        chunks.append(np.array(batch, dtype=DTYPE))
    if counts['decode_errors'] or counts['service_ip_tcp_fragment_frames'] or maximum_regression >= 1:
        raise ValueError('TCP input-quality/reordering gate failed')
    rows = np.concatenate(chunks)
    rows = rows[np.argsort(rows['timestamp'], kind='stable')]
    target = ROOT/'data/development/friday_tcp_boundary_v1'
    target.mkdir(parents=True, exist_ok=True)
    index_path = target/'packets.npy'
    if index_path.exists():
        raise FileExistsError('Index already exists; verify/reuse it rather than overwriting')
    np.save(index_path, rows, allow_pickle=False)
    report = {
        'date': '2026-11-12', 'scope': plan['scope'], 'plan_sha256': digest(plan_path),
        'capture_sha256': stream.sha.hexdigest(), 'capture_bytes_hashed': stream.bytes,
        'counts': dict(counts), 'max_selected_adjacent_timestamp_regression_seconds': maximum_regression,
        'index': str(index_path.relative_to(ROOT)).replace('\\', '/'), 'index_sha256': digest(index_path),
        'index_bytes': index_path.stat().st_size, 'fields': list(DTYPE.names),
        'source_sha256': digest(ROOT/'src/index_friday_tcp.py'),
        'elapsed_seconds': round(time.perf_counter() - started, 3),
        'source_order_for_equal_timestamps_preserved': True, 'passed': True,
        'study_training_ready': False, 'identifiers_sequences_hashes_are_grouping_metadata_only': True,
    }
    out = ROOT/'results/development/friday_tcp_index_v1.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    declaration, plan = declare()
    build_index(declaration, plan)
