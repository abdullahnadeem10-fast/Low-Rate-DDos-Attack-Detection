"""Corroborate controlled benign PCAPs against complete-request logs and scope.

This is offline ground-truth/quality auditing, not predictor construction or final
research evaluation. PREFLIGHT sessions never enter a model partition.
"""
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import socket
import struct

import dpkt


def assemble(segments, base):
    """Reassemble a bounded TCP stream, validating gaps and overlapping bytes."""
    output = bytearray()
    for sequence, payload in sorted(segments, key=lambda x: ((x[0]-base) & 0xffffffff)):
        offset = (sequence-base) & 0xffffffff
        if offset > len(output):
            raise ValueError('TCP stream has a missing range')
        overlap = min(len(payload), len(output)-offset)
        if output[offset:offset+overlap] != payload[:overlap]:
            raise ValueError('TCP retransmission has conflicting bytes')
        output.extend(payload[overlap:])
    return bytes(output)


def frames(path):
    """Yield full PCAP records with original lengths, refusing partial tails."""
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\xa1\xb2\xc3\xd4': ('>', 1e6),
               b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
    with path.open('rb') as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError('Expected a complete lab PCAP header')
        order, precision = formats[header[:4]]
        if struct.unpack_from(order+'I', header, 20)[0] != dpkt.pcap.DLT_EN10MB:
            raise ValueError('Ethernet link type required')
        while raw := f.read(16):
            if len(raw) != 16:
                raise ValueError('Truncated PCAP record header')
            second, fraction, caplen, wirelen = struct.unpack(order+'IIII', raw)
            if caplen > wirelen or caplen > 262144:
                raise ValueError('Invalid PCAP record lengths')
            frame = f.read(caplen)
            if len(frame) != caplen:
                raise ValueError('Truncated PCAP frame')
            yield second+fraction/precision, frame, wirelen


def register_tcp(streams, key, tcp, incoming, response_bytes):
    """Keep separate handshake incarnations when a client reuses a TCP port."""
    bucket = streams.setdefault(key, [])
    if incoming and tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
        if not any(s['syn'] == tcp.seq for s in bucket):
            bucket.append({'in': [], 'out': [], 'syn': tcp.seq, 'synack': None})
    elif not incoming and tcp.flags & dpkt.tcp.TH_SYN:
        candidates = [s for s in bucket if (s['syn']+1) & 0xffffffff == tcp.ack]
        if len(candidates) != 1:
            raise ValueError('SYN-ACK lacks one matching observed client handshake')
        state = candidates[0]
        if state['synack'] is not None and state['synack'] != tcp.seq:
            raise ValueError('Conflicting SYN-ACK initial sequence')
        state['synack'] = tcp.seq
    if tcp.data:
        base_name = 'syn' if incoming else 'synack'
        # Controlled one-request connections have bounded payloads. Reject an
        # ambiguous incarnation rather than guessing from a reused tuple alone.
        limit = 8192 if incoming else response_bytes+8192
        candidates = [s for s in bucket if s[base_name] is not None and
            ((tcp.seq-(s[base_name]+1)) & 0xffffffff) <= limit]
        if len(candidates) != 1:
            raise ValueError('Payload does not identify one handshake incarnation')
        candidates[0]['in' if incoming else 'out'].append((tcp.seq, bytes(tcp.data)))


def audit_session(directory):
    directory = Path(directory)
    manifest = json.loads((directory/'session.json').read_text())
    if manifest['state'] != 'collected_audit_pending' or manifest['role'] not in ('PREFLIGHT','T','C1','C2','V'):
        raise ValueError('Session is not a completed permitted benign collection')
    pcap = directory/'capture/traffic.pcap'
    with pcap.open('rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
    if digest != manifest['pcap_sha256']:
        raise ValueError('Session capture hash changed')
    body = (directory/'htdocs/payload.txt').read_bytes()
    server, port_text = manifest['service'].rsplit(':', 1)
    port = int(port_text)
    issues = []
    if manifest.get('cleanup_exit_code',0)!=0:
        issues.append('Owned lab project cleanup did not succeed')
    logs = []; starts = []; ends = []; expected_clients = set()
    for i in range(1, manifest['clients']+1):
        client = directory/f'client{i}'
        metadata = json.loads((client/'client.json').read_text())
        network = json.loads((client/'network.json').read_text())
        if network['service_addresses'] != [server] or network['ipv4_default_routes']:
            issues.append(f'client{i}: service DNS/default route outside policy')
        expected_clients.update(network.get('client_addresses', []))
        requests = [json.loads(s) for s in (client/'requests.jsonl').read_text().splitlines()]
        if not requests or any(not r.get('complete') or r.get('status') != 200 or r.get('bytes') != len(body) for r in requests):
            issues.append(f'client{i}: failed/incomplete HTTP request')
        measured = [r['start_utc'] for r in requests if r['phase'] == 'measurement']
        if not measured:
            issues.append(f'client{i}: no measurement requests')
        else:
            starts.append(min(measured))
        ends.append(metadata['end_utc']); logs.extend(requests)
    if len(expected_clients) != manifest['clients']:
        issues.append('Client address identity evidence is incomplete')
    capture = json.loads((directory/'capture/capture.json').read_text())
    if capture['tcpdump_exit_code'] != 0:
        issues.append('tcpdump did not close cleanly')
    text = (directory/'capture/tcpdump.log').read_text()
    statistics = {}
    for name, pattern in [('captured',r'(\d+) packets captured'), ('received_by_filter',r'(\d+) packets received by filter'),
                          ('dropped_by_kernel',r'(\d+) packets dropped by kernel')]:
        match = re.search(pattern, text)
        if not match:
            issues.append('Missing tcpdump statistics: '+name)
        else:
            statistics[name] = int(match[1])
    if statistics.get('dropped_by_kernel', 1):
        issues.append('Nonzero or unknown kernel-reported packet drops')
    if not (directory/'capture/offloads.json').exists():
        issues.append('Missing web offload-policy evidence')
    streams = {}; counts = Counter(); clients_seen = set()
    previous = -math.inf; largest_regression = 0.; maximum = 0
    for ts, frame, original in frames(pcap):
        counts['frames'] += 1; maximum = max(maximum, len(frame))
        counts['truncated_frames'] += int(len(frame) != original)
        largest_regression = max(largest_regression, previous-ts); previous = ts
        ip = dpkt.ethernet.Ethernet(frame).data
        if not isinstance(ip, dpkt.ip.IP) or ip.offset or not isinstance(ip.data, dpkt.tcp.TCP):
            counts['unexpected_protocol_or_fragment'] += 1; continue
        tcp = ip.data; src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        incoming = dst == server and tcp.dport == port
        outgoing = src == server and tcp.sport == port
        if not incoming and not outgoing:
            counts['off_scope_packets'] += 1; continue
        client = src if incoming else dst
        clients_seen.add(client)
        if client not in expected_clients:
            counts['unknown_client_packets'] += 1
        key = (client, tcp.sport if incoming else tcp.dport)
        register_tcp(streams,key,tcp,incoming,len(body))
    complete = 0; stream_errors = Counter()
    for state in (state for bucket in streams.values() for state in bucket):
        if not state['in'] and not state['out']:
            continue
        try:
            if state['syn'] is None or state['synack'] is None:
                raise ValueError('Missing observed handshake sequence base')
            request = dpkt.http.Request(assemble(state['in'], (state['syn']+1) & 0xffffffff))
            response = dpkt.http.Response(assemble(state['out'], (state['synack']+1) & 0xffffffff))
            if request.method != 'GET' or request.uri != '/payload.txt' or response.status != '200' or response.body != body:
                raise ValueError('HTTP request/status/body differs from controlled workload')
            complete += 1
        except (ValueError, dpkt.UnpackError) as error:
            stream_errors[str(error)] += 1
    if stream_errors:
        issues.append('Some captured TCP/HTTP streams failed reconstruction')
    if complete != len(logs):
        issues.append('Captured complete HTTP exchanges disagree with request logs')
    if counts['frames'] != statistics.get('captured'):
        issues.append('PCAP frame count disagrees with tcpdump captured count')
    if maximum > 1514:
        issues.append('Frames above the intended Ethernet MTU counting basis')
    if any(counts[n] for n in ('truncated_frames','unexpected_protocol_or_fragment','off_scope_packets','unknown_client_packets')):
        issues.append('Capture truncation/protocol/scope anomaly')
    if largest_regression >= 1:
        issues.append('Timestamp disorder exceeds the proposed replay budget')
    measurement = [math.ceil(max(starts)), math.floor(min(ends))] if len(starts) == manifest['clients'] else None
    if not measurement or measurement[1] <= measurement[0]:
        issues.append('No common complete measurement seconds')
    result = {'session': manifest['session'], 'role': manifest['role'], 'condition': manifest['condition'],
        'seed': manifest['seed'], 'clients': manifest['clients'], 'scope': manifest['scope'],
        'capture_sha256': digest, 'capture_bytes': pcap.stat().st_size, 'counts': dict(counts),
        'tcpdump': statistics, 'max_frame_bytes': maximum, 'largest_timestamp_regression_seconds': largest_regression,
        'logged_http_requests': len(logs), 'complete_captured_http_exchanges': complete,
        'stream_errors': dict(stream_errors), 'observed_clients': len(clients_seen),
        'tcp_connection_incarnations':sum(len(bucket) for bucket in streams.values()),
        'reused_endpoint_tuples':sum(len(bucket)>1 for bucket in streams.values()),
        'measurement_utc_seconds_exclusive_end': measurement, 'passed': not issues, 'issues': issues,
        'training_ready': False, 'image_ids': manifest['image_ids'],
        'limitations': ['Controlled synthetic benign development, not final stressed-traffic performance.',
            'No-default-route/internal-bridge and endpoint checks are bounded scope evidence, not a general network-security proof.',
            'No packet checksum validation; virtual capture hooks can expose checksum-offload artefacts.',
            'Public/lab source and service confounding, controlled congestion and full split integration remain unresolved.']}
    (directory/'audit.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session', type=Path)
    result = audit_session(parser.parse_args().session)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
