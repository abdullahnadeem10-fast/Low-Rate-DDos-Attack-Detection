"""Stream the pinned 03-11 PCAP archive into unfiltered candidate TCP metadata.

No causal features or labels are created here. ZIP rotations remain one declared
source, not independent sessions. Payloads outside candidate endpoints are never
stored; candidate sequences/hashes are grouping metadata, never predictors.
"""
from collections import Counter
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import socket
import time
from zipfile import ZipFile

import dpkt
import numpy as np
from declare_cic2019_validation import ROOT
from download_cic2019_validation import approved, sha
from replay_public_partitions import open_capture

DTYPE = np.dtype([
    ('timestamp', '<f8'), ('service', 'u1'), ('client', '<u4'), ('port', '<u2'),
    ('inbound', 'u1'), ('flags', 'u1'), ('length', '<u4'), ('seq', '<u4'), ('ack', '<u4'),
    ('payload', '<u4'), ('frame', '<u8'), ('member', '<u4'), ('http', 'u1'), ('tcp_sha256', 'V32'),
])


def pcap_members(names):
    def permitted(n):
        p = PurePosixPath(n.replace('\\', '/'))
        return p.suffix.lower() in ('.pcap', '.pcapng', '.cap') or bool(re.fullmatch(r'SAT-03-11-2018_\d+', p.name))
    selected = [n for n in names if permitted(n) and '__MACOSX' not in n]
    if not selected or any('01-12' in n for n in selected):
        raise ValueError('No permitted development PCAP members')
    return sorted(selected, key=lambda n: (re.sub(r'\d+$', '', n), int(re.search(r'\d+$', n).group()) if re.search(r'\d+$', n) else -1))


def fast_scope(frame, endpoints, addresses):
    """Skip only plainly off-scope Ethernet/IPv4 traffic; malformed/VLAN falls back."""
    if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4:
        return 'decode', None
    if frame[23] != 6:
        return 'non_tcp_ipv4', None
    src, dst = frame[26:30], frame[30:34]
    if src not in addresses and dst not in addresses:
        return 'other_tcp_address', None
    hlen = (frame[14] & 15) * 4
    if hlen < 20 or int.from_bytes(frame[20:22], 'big') & 0x3fff or int.from_bytes(frame[16:18], 'big') > len(frame) - 14 or len(frame) < 14 + hlen + 4:
        return 'decode', None
    start = 14 + hlen
    sport, dport = int.from_bytes(frame[start:start+2], 'big'), int.from_bytes(frame[start+2:start+4], 'big')
    destination_port = dport if dst in addresses else None
    if (src, sport) in endpoints or (dst, dport) in endpoints:
        return 'decode', destination_port
    return 'other_tcp_port', destination_port


def prefix_marker(payload):
    request = bool(re.match(rb'^(GET|HEAD|POST|OPTIONS|PUT|DELETE|CONNECT|TRACE|PATCH) [^\r\n]+ HTTP/1\.[01]\r\n', payload))
    response = bool(re.match(rb'^HTTP/1\.[01] [0-9]{3}', payload))
    tls = len(payload) >= 5 and payload[0] == 22 and payload[1] == 3 and payload[2] <= 4
    return 1 if request else 2 if response else 3 if tls else 0


def main():
    started = time.perf_counter()
    plan_path = ROOT/'plan/cic2019_validation_v1.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    item = next(x for x in plan['allowed_downloads'] if x['id'] == 'pcaps-03-11')
    path = approved(item)
    if path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
        raise ValueError('Declared PCAP archive integrity failed')
    services = plan['endpoint_metadata_candidates']
    endpoints = {(socket.inet_aton(s.split(':')[0]), int(s.split(':')[1])): i for i, s in enumerate(services)}
    addresses = {a for a, p in endpoints}
    counts, service_counts = Counter(), {s: Counter() for s in services}
    members, chunks, batch = [], [], []
    destination_ports = Counter()
    with ZipFile(path) as archive:
        names = pcap_members(archive.namelist())
        for mid, name in enumerate(names):
            info = archive.getinfo(name)
            member_counts, first, last, previous, regression = Counter(), math.inf, -math.inf, -math.inf, 0.
            with archive.open(name) as raw:
                stream, reader = open_capture(raw)
                link = reader.datalink()
                if link != dpkt.pcap.DLT_EN10MB:
                    while stream.read(1024 * 1024):
                        pass
                    counts['unsupported_link_members'] += 1
                else:
                    for stamp, frame in reader:
                        ts = float(stamp)
                        counts['frames'] += 1
                        member_counts['frames'] += 1
                        first, last = min(first, ts), max(last, ts)
                        regression, previous = max(regression, previous - ts), ts
                        if counts['frames'] % 2000000 == 0:
                            print(f'CIC2019 packet inventory: {counts["frames"]:,} frames, member {mid+1}/{len(names)}; {time.perf_counter()-started:.0f}s', flush=True)
                        scope, dport = fast_scope(frame, endpoints, addresses)
                        if dport is not None:
                            destination_ports[str(dport)] += 1
                        if scope != 'decode':
                            counts['fast_skipped_' + scope] += 1
                            continue
                        try:
                            ip = dpkt.ethernet.Ethernet(frame).data
                            if not isinstance(ip, dpkt.ip.IP) or ip.p != 6:
                                continue
                            if ip.offset or ip.mf:
                                if ip.src in addresses or ip.dst in addresses:
                                    counts['candidate_ip_tcp_fragment_frames'] += 1
                                continue
                            if (ip.src in addresses or ip.dst in addresses) and ip.len > len(ip):
                                counts['candidate_ip_truncated_tcp_packets'] += 1
                            if not isinstance(ip.data, dpkt.tcp.TCP):
                                continue
                            tcp = ip.data
                            matches = []
                            if (ip.dst, tcp.dport) in endpoints:
                                matches.append((endpoints[ip.dst, tcp.dport], True))
                            if (ip.src, tcp.sport) in endpoints:
                                matches.append((endpoints[ip.src, tcp.sport], False))
                            if len(matches) > 1:
                                counts['frames_matching_multiple_candidates'] += 1
                            for sid, incoming in matches:
                                c = service_counts[services[sid]]
                                c['packets'] += 1
                                c['inbound' if incoming else 'outbound'] += 1
                                c['initial_syn'] += int(incoming and tcp.flags & 2 and not tcp.flags & 16)
                                marker = prefix_marker(bytes(tcp.data))
                                if marker:
                                    c[{1: 'request_prefix', 2: 'response_prefix', 3: 'tls_record_prefix'}[marker]] += 1
                                if ip.len > len(ip):
                                    counts['candidate_truncated_ip_packets'] += 1
                                batch.append((ts, sid, int.from_bytes(ip.src if incoming else ip.dst, 'big'),
                                              tcp.sport if incoming else tcp.dport, incoming, tcp.flags, len(frame),
                                              tcp.seq, tcp.ack, len(tcp.data), counts['frames'], mid, marker,
                                              hashlib.sha256(bytes(tcp)).digest()))
                                counts['candidate_metadata_rows'] += 1
                                if len(batch) == 100000:
                                    chunks.append(np.array(batch, dtype=DTYPE))
                                    batch.clear()
                        except (dpkt.UnpackError, ValueError):
                            counts['decode_errors'] += 1
                if stream.bytes != info.file_size:
                    raise ValueError('PCAP reader did not consume complete member')
            members.append({'name': name, 'bytes': info.file_size, 'crc32': f'{info.CRC:08x}',
                            'sha256': stream.sha.hexdigest(), 'link_type': link, 'frames': member_counts['frames'],
                            'first_utc_timestamp': first if first != math.inf else None,
                            'last_utc_timestamp': last if last != -math.inf else None,
                            'max_adjacent_timestamp_regression_seconds': regression})
    if batch:
        chunks.append(np.array(batch, dtype=DTYPE))
    rows = np.concatenate(chunks) if chunks else np.empty(0, dtype=DTYPE)
    if len(rows):
        rows = rows[np.argsort(rows['timestamp'], kind='stable')]
    directory = ROOT/'data/development/cic2019_v'
    index = directory/'candidate_tcp.npy'
    np.save(index, rows, allow_pickle=False)
    ordered = sorted([m for m in members if m['first_utc_timestamp'] is not None], key=lambda m: m['first_utc_timestamp'])
    overlaps = []
    for a, b in zip(ordered, ordered[1:]):
        if b['first_utc_timestamp'] < a['last_utc_timestamp']:
            overlaps.append({'earlier': a['name'], 'later': b['name'], 'overlap_seconds': a['last_utc_timestamp'] - b['first_utc_timestamp']})
    report = {
        'date': '2026-11-12', 'scope': 'Raw development source/endpoint inventory; no labels/features/model scoring.',
        'plan_sha256': sha(plan_path), 'archive_sha256': item['sha256'], 'counts': dict(counts),
        'candidate_services': {s: dict(c) for s, c in service_counts.items()},
        'top_tcp_destination_ports_at_candidate_server_ips': destination_ports.most_common(20),
        'members': members, 'adjacent_member_time_overlaps': overlaps,
        'index': str(index.relative_to(ROOT)).replace('\\', '/'), 'index_sha256': sha(index), 'index_rows': len(rows),
        'index_fields_are_grouping_metadata_not_predictors': True,
        'source_sha256': sha(ROOT/'src/inventory_cic2019_packets.py'), 'elapsed_seconds': round(time.perf_counter()-started, 3),
        'independent_attack_V_accepted': False, 'study_training_ready': False,
        'limits': ['ZIP members are source rotations, not independent traffic replications.',
                  'Plainly off-scope IPv4 addresses/ports and non-TCP IPv4 payloads are skipped before transport decoding; integrity hashes still cover every byte. Quality counters apply to candidate TCP input.',
                  'Exact repeated TCP bytes can be retransmissions or capture duplication; no automatic deduplication is performed.',
                  'HTTP/TLS prefixes are service-context evidence, not reassembled complete-request counts.',
                  'Metadata sorting is for audit only; future causal replay requires declared session/gap/order handling and current-window label corroboration.'],
    }
    (ROOT/'results/development/cic2019_packet_inventory_v1.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'members': len(members), 'counts': report['counts'], 'services': report['candidate_services']}, indent=2), flush=True)


if __name__ == '__main__':
    main()
