"""Bounded CIC-IDS2017 packet pilot. No final datasets or attack traffic generation."""
import argparse
from collections import Counter, defaultdict, deque
import csv
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import time

import dpkt
import numpy as np
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / 'data/pilot/monday-first-32MiB.partial'
OUT = ROOT / 'results/pilot'
REVISION = '811c007f08d693a8a8b4226c197c138391806ce6'
WEB_IPS = {'192.168.10.50', '205.174.165.68'}  # UNB's published web-server addresses
WEB_PORTS = {80, 443}
HISTORY = 5
FEATURES = ('packets_in', 'packets_out', 'bytes_in', 'bytes_out', 'syn_in',
            'rst_in', 'sources_in', 'packets_in_last5')


def complete_capture(raw):
    """Keep complete records in a byte-range capture, refusing invalid headers."""
    magic = raw[:4]
    if magic == b'\x0a\x0d\x0d\x0a':
        pos = 0
        order = None
        while pos + 12 <= len(raw):
            if raw[pos:pos+4] == magic:
                order = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}[raw[pos+8:pos+12]]
            length = struct.unpack_from(order+'I', raw, pos+4)[0]
            if length < 12 or length % 4:
                raise ValueError(f'Invalid PCAPNG block length at {pos}')
            if pos + length > len(raw):
                break
            if struct.unpack_from(order+'I', raw, pos+length-4)[0] != length:
                raise ValueError(f'PCAPNG block lengths differ at {pos}')
            pos += length
        return dpkt.pcapng.Reader, pos
    orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    if magic not in orders or len(raw) < 24:
        raise ValueError('Not a supported packet capture')
    pos = 24
    while pos + 16 <= len(raw):
        size = struct.unpack_from(orders[magic]+'I', raw, pos+8)[0]
        if pos + 16 + size > len(raw):
            break
        pos += 16 + size
    return dpkt.pcap.Reader, pos


def collect(raw, endpoints=None):
    reader_class, length = complete_capture(raw)
    reader = reader_class(io.BytesIO(raw[:length]))
    if reader.datalink() != dpkt.pcap.DLT_EN10MB:
        raise ValueError('Pilot requires Ethernet capture')
    groups = defaultdict(dict)
    if endpoints is None:
        endpoints = {(ip,port) for ip in WEB_IPS for port in WEB_PORTS}
    stats = Counter()
    first, last, previous = float('inf'), float('-inf'), float('-inf')
    for ts, frame in reader:
        ts = float(ts)
        first, last = min(first, ts), max(last, ts)
        stats['frames_read'] += 1
        stats['out_of_order_frames'] += int(ts < previous)
        previous = ts
        try:
            ip = dpkt.ethernet.Ethernet(frame).data
        except (dpkt.UnpackError, ValueError):
            stats['decode_errors'] += 1
            continue
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        if (dst, tcp.dport) in endpoints:
            service, direction = (dst, tcp.dport), 'in'
        elif (src, tcp.sport) in endpoints:
            service, direction = (src, tcp.sport), 'out'
        else:
            continue
        stats['selected_tcp_frames'] += 1
        key = int(ts)
        if key not in groups[service]:
            groups[service][key] = (Counter(), set())
        counts, sources = groups[service][key]
        counts['packets_'+direction] += 1
        counts['bytes_'+direction] += len(frame)
        if direction == 'in':
            sources.add(src)
            counts['syn_in'] += int(bool(tcp.flags & dpkt.tcp.TH_SYN) and not tcp.flags & dpkt.tcp.TH_ACK)
            counts['rst_in'] += int(bool(tcp.flags & dpkt.tcp.TH_RST))
    if not stats['frames_read']:
        raise ValueError('No complete packets in the capture')
    # Drop both edge seconds: the range need not start or end at a second boundary.
    return groups, int(first)+1, int(last), dict(stats), length, last-first


def make_windows(group, start, stop):
    """Build causally defined offline features; no wall-clock latency claim."""
    rows, past = [], deque(maxlen=HISTORY)
    for second in range(start, stop):
        counts, sources = group.get(second, (Counter(), set()))
        past.append(counts['packets_in'])
        if len(past) == HISTORY:
            rows.append({'second': second, **{f:counts[f] for f in FEATURES[:6]},
                         'sources_in':len(sources), 'packets_in_last5':sum(past)})
    return rows


def model_smoke(rows):
    """Same-capture chronological smoke check, not independent validation."""
    n = len(rows)
    a, b = n//2, 3*n//4
    blocks = [rows[:a], rows[a+HISTORY:b], rows[b+HISTORY:]]
    if min(map(len, blocks)) < 12 or any(not any(r['packets_in'] for r in part) for part in blocks):
        return {'status':'insufficient active seconds in all three blocks', 'windows':list(map(len, blocks))}
    x = [np.array([[row[name] for name in FEATURES] for row in part]) for part in blocks]
    clf = IsolationForest(n_estimators=64, random_state=7, n_jobs=1).fit(x[0])
    scores_cal = -clf.score_samples(x[1])
    tau = float(np.quantile(scores_cal, .99, method='higher'))
    scores = -clf.score_samples(x[2])
    return {'status':'ran', 'model':'Isolation Forest pilot baseline', 'seed':7,
            'fit_windows':len(x[0]), 'calibration_windows':len(x[1]), 'later_windows':len(x[2]),
            'threshold':tau, 'later_alerts':int(sum(scores > tau)),
            'caution':'One benign prefix only; alert count is diagnostic, not final FPR or attack recall.'}


def run(path, endpoint=None):
    started = time.perf_counter()
    raw = path.read_bytes()
    if len(raw) != 33554432:
        raise ValueError(f'Expected the exact 32 MiB pilot range; received {len(raw)} bytes')
    groups, start, stop, stats, complete_bytes, duration = collect(raw, {endpoint} if endpoint else None)
    if not groups:
        raise ValueError('No matching service traffic in the capture prefix')
    # Choose an active endpoint from the predefined web-service allowlist, on benign development data only.
    service = max(sorted(groups), key=lambda key:sum(c['packets_in'] for c,_ in groups[key].values()))
    rows = make_windows(groups[service], start, stop)
    if not rows or not any(row['packets_in'] for row in rows):
        raise ValueError('No usable active one-second windows')
    model = model_smoke(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT/'monday_windows.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['second', *FEATURES]); writer.writeheader(); writer.writerows(rows)
    info = {'source':f'https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/{REVISION}/pcaps/Monday-WorkingHours.pcap',
            'publisher':'https://www.unb.ca/cic/datasets/ids-2017.html',
            'range_inclusive':[0,len(raw)-1], 'range_sha256':hashlib.sha256(raw).hexdigest(),
            'complete_capture_bytes':complete_bytes, 'discarded_partial_tail_bytes':len(raw)-complete_bytes,
            'observed_duration_seconds':round(duration,3), 'packet_stats':stats,
            'service':f'{service[0]}:{service[1]}', 'windows':len(rows),
            'scope': 'Benign engineering pilot; service and features are not the final experiment.',
            'windows_with_inbound_packets':sum(row['packets_in']>0 for row in rows),
            'model_smoke':model, 'processing_seconds':round(time.perf_counter()-started,3)}
    (OUT/'monday_pilot.json').write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(info,indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, default=PILOT)
    parser.add_argument('--service', help='Exact IPv4:port used only for the benign smoke test')
    args = parser.parse_args()
    endpoint = None
    if args.service:
        address, port = args.service.rsplit(':',1)
        socket.inet_aton(address)
        endpoint = (address,int(port))
    run(args.pcap, endpoint)
