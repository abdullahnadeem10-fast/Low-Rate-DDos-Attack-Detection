"""Split-first Friday development replay with observed-connection quarantine.

Saved labels are applied only after every partition's unfiltered packet features
exist. No final holdout, fitting, calibration or live detection claim is involved.
"""
from collections import Counter, defaultdict
import csv
import hashlib
import heapq
import json
import math
from pathlib import Path
import socket
import time

import dpkt
from causal_features import CausalFeatures, Event
from declare_public_partitions import ROOT, digest


class HashingReader:
    """Hash the exact bytes consumed in one sequential parse (no seeking)."""
    def __init__(self, stream):
        self.stream = stream
        self.sha = hashlib.sha256()
        self.bytes = 0

    def read(self, size=-1):
        value = self.stream.read(size)
        self.sha.update(value)
        self.bytes += len(value)
        return value


def open_capture(raw):
    # The archived .pcap filename contains PCAPNG. Detect magic before the
    # sequential hashing pass, then hash every byte exactly once from offset 0.
    magic = raw.read(4)
    raw.seek(0)
    stream = HashingReader(raw)
    reader = dpkt.pcapng.Reader(stream) if magic == b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(stream)
    return stream, reader


def add_interval(intervals, start, end):
    """Merge chronological half-open influence intervals without per-event growth."""
    if intervals and start <= intervals[-1][1]:
        intervals[-1] = (intervals[-1][0], max(end, intervals[-1][1]))
    else:
        intervals.append((start, end))


def covered(second, intervals):
    return any(a <= second < b for a, b in intervals)


def validate_plan(plan):
    ids = [b['id'] for b in plan['blocks']]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate block IDs')
    for b in plan['blocks']:
        if b['role'] not in ('T', 'C1', 'C2', 'V'):
            raise ValueError('Only development roles allowed')
        if not b['raw_start'] <= b['eligible_start'] < b['eligible_end'] <= b['raw_end']:
            raise ValueError('Invalid half-open interval')
        if any(type(b[k]) is not int for k in ('raw_start', 'raw_end', 'eligible_start', 'eligible_end')):
            raise ValueError('Integer full-second boundaries required')
        if b['role'] in ('C1', 'C2') and b['y'] != 0:
            raise ValueError('Calibration must be benign-only')
        for other in plan['blocks']:
            if other is b or other['service'] != b['service']:
                continue
            if b['kind'] == 'benign_destination' and b['role'] != other['role']:
                raise ValueError('Benign destination appears in multiple roles')
            if max(b['raw_start'], other['raw_start']) < min(b['raw_end'], other['raw_end']):
                raise ValueError('Overlapping blocks for same service')
            a, z = sorted((b, other), key=lambda x: x['raw_start'])
            if z['raw_start'] - a['raw_end'] < plan['connection_influence_guard_seconds']:
                raise ValueError('Insufficient temporal purge')


class Partition:
    def __init__(self, spec, guard=50):
        self.spec, self.guard = spec, guard
        self.core = CausalFeatures(timeout=30)
        self.core.second = spec['raw_start']
        self.rows = []
        self.fingerprints = {}  # observed tracker key -> current initiating SYN identity
        self.ambiguous = set()
        self.influence = {}    # initiating SYN identity -> first/last observed event second
        self.unknown = []
        self.shared = []
        self.counts = Counter()

    def finish(self, boundary):
        boundary = min(self.spec['raw_end'], max(self.spec['raw_start'], boundary))
        self.rows.extend(self.core.finish(boundary))

    def add(self, event, tcp_seq):
        if not self.spec['raw_start'] <= event.timestamp < self.spec['raw_end']:
            raise ValueError('Packet routed outside allocated block')
        if event.timestamp < self.core.last_timestamp or event.timestamp < self.core.second:
            self.counts['late_selected_dropped'] += 1
            return
        # Close earlier seconds before inspecting tracker expiry at this event.
        self.finish(int(event.timestamp))
        key = (event.client, event.client_port)
        state = self.core.connections.get(key)
        if state is not None and event.timestamp - state['last'] >= 30:
            state = None
        syn = bool(event.inbound and event.flags & 2 and not event.flags & 16)
        reset = state is None or syn and state['complete']
        if reset:
            self.fingerprints.pop(key, None)
            self.ambiguous.discard(key)
        fingerprint = (self.spec['service'], event.client, event.client_port, tcp_seq)
        if syn:
            if reset:
                self.fingerprints[key] = fingerprint
            elif self.fingerprints.get(key) != fingerprint:
                # Core intentionally lacks ISNs; do not silently upgrade its
                # incomplete/unknown tuple state to a verified TCP incarnation.
                self.ambiguous.add(key)
        known = self.fingerprints.get(key)
        sec = int(event.timestamp)
        if known is not None:
            if known not in self.influence:
                self.influence[known] = [sec, sec]
            else:
                self.influence[known][1] = sec
        if known is None or key in self.ambiguous:
            self.counts['unknown_or_ambiguous_start_packets'] += 1
            if self.spec['kind'] == 'attack_block':
                add_interval(self.unknown, sec, sec + self.guard + 1)
        self.rows.extend(self.core.add(event))
        self.counts['selected_tcp'] += 1
        if key not in self.core.connections:
            self.fingerprints.pop(key, None)
            self.ambiguous.discard(key)


def quarantine_shared(partitions):
    owners = defaultdict(set)
    for p in partitions:
        for fingerprint in p.influence:
            owners[fingerprint].add(p.spec['role'])
    shared = {f for f, roles in owners.items() if len(roles) > 1}
    for p in partitions:
        intervals = sorted((a, b + p.guard + 1) for f, (a, b) in p.influence.items() if f in shared)
        for a, b in intervals:
            add_interval(p.shared, a, b)
        p.counts['cross_role_syn_fingerprints'] = sum(f in shared for f in p.influence)
    return len(shared)


def reasons(p, row, label):
    sec = row['utc_second']
    flags = []
    if not p.spec['eligible_start'] <= sec < p.spec['eligible_end']:
        flags.append('boundary_guard')
    if not row['history_complete']:
        flags.append('history_incomplete')
    if covered(sec, p.unknown):
        flags.append('unknown_connection_influence')
    if covered(sec, p.shared):
        flags.append('cross_role_connection_influence')
    if label.get('status', 'not_labelled') != p.spec['accepted_status']:
        flags.append('label_' + label.get('status', 'not_labelled'))
    return flags


def write_csv(path, columns, rows):
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def describe(rows):
    if not rows:
        return {'windows': 0}
    return {'windows': len(rows), 'packets': sum(r['packets_in'] + r['packets_out'] for r in rows),
            'empty_windows': sum(r['packets_in'] + r['packets_out'] == 0 for r in rows),
            'mean_active_connections': sum(r['active_connections'] for r in rows) / len(rows),
            'mean_unknown_age_connections': sum(r['unknown_age_connections'] for r in rows) / len(rows)}


def publish_partition(p, labels, output, predictors):
    output.mkdir(parents=True, exist_ok=True)
    columns = list(p.rows[0])
    if set(columns) != set(predictors) | {'utc_second', 'history_complete'}:
        raise ValueError('Predictor schema mismatch')
    if [r['utc_second'] for r in p.rows] != list(range(p.spec['raw_start'], p.spec['raw_end'])):
        raise ValueError('Missing/duplicated feature seconds')
    eligibility, selected, rejected = [], [], []
    all_reasons, primary, statuses = Counter(), Counter(), Counter()
    retained_seconds = set()
    for row in p.rows:
        if any(not math.isfinite(float(v)) for v in row.values()):
            raise ValueError('Non-finite causal feature')
        sec = row['utc_second']
        label = labels.get(sec, {})
        status = label.get('status', 'not_labelled')
        statuses[status] += 1
        if label and row['packets_in'] + row['packets_out'] != int(label['packets']):
            raise ValueError('Label/feature packet-count mismatch at ' + str(sec))
        flags = reasons(p, row, label)
        all_reasons.update(flags)
        primary[flags[0] if flags else 'retained'] += 1
        eligibility.append({'utc_second': sec, 'status': status, 'retained': int(not flags), 'exclusion_reasons': '|'.join(flags)})
        if flags:
            rejected.append(row)
        else:
            selected.append({'session_id': p.spec['id'], 'role': p.spec['role'], 'condition': p.spec['condition'], 'y': p.spec['y'], **row})
            retained_seconds.add(sec)
    write_csv(output/'features.csv', columns, p.rows)
    write_csv(output/'eligibility.csv', ['utc_second', 'status', 'retained', 'exclusion_reasons'], eligibility)
    write_csv(output/'model_windows.csv', ['session_id', 'role', 'condition', 'y'] + columns, selected)
    stats = {**p.spec, 'packet_counts': dict(p.counts), 'raw_status_windows': dict(statuses),
             'primary_exclusion_windows': dict(primary), 'all_exclusion_flags_windows': dict(all_reasons),
             'unknown_influence_intervals': p.unknown, 'shared_influence_intervals': p.shared,
             'retained': describe(selected), 'excluded': describe(rejected),
             'files': {name: {'relative_path': str((output/name).relative_to(ROOT)).replace('\\', '/'), 'sha256': digest(output/name)}
                       for name in ('features.csv', 'eligibility.csv', 'model_windows.csv')}}
    return stats, retained_seconds


def replay(plan_path):
    started = time.perf_counter()
    plan = json.loads(plan_path.read_text())
    validate_plan(plan)
    core_spec = plan['feature_core']
    if digest(ROOT/core_spec['path']) != core_spec['sha256']:
        raise ValueError('Frozen causal core changed')
    for path, sha in plan['evidence'].items():
        if digest(ROOT/path) != sha:
            raise ValueError('Planning evidence changed: ' + path)
    labels = {}
    for b in plan['blocks']:
        path = ROOT/b['label_table']
        if digest(path) != b['label_sha256']:
            raise ValueError('Label table changed')
        with path.open(newline='', encoding='utf-8') as f:
            table = list(csv.DictReader(f))
        labels[b['id']] = {int(r['utc_second']): r for r in table}
        if len(table) != len(labels[b['id']]):
            raise ValueError('Duplicate label seconds')
    path = ROOT/plan['capture']['path']
    if path.stat().st_size != plan['capture']['bytes']:
        raise ValueError('Capture size mismatch')
    partitions = [Partition(b, plan['connection_influence_guard_seconds']) for b in plan['blocks']]
    index = defaultdict(list)
    for p in partitions:
        ip, port = p.spec['service'].rsplit(':', 1)
        index[(socket.inet_aton(ip), int(port))].append(p)
    heap, sequence, frames = [], 0, 0
    maximum, last_close = -math.inf, -math.inf
    decode_errors = fragments = 0
    first_ts, last_ts = None, None

    def drain(before):
        while heap and heap[0][0] < before:
            _, _, i, event, seq = heapq.heappop(heap)
            partitions[i].add(event, seq)

    with path.open('rb') as raw:
        stream, reader = open_capture(raw)
        if reader.datalink() != dpkt.pcap.DLT_EN10MB:
            raise ValueError('Ethernet required')
        for timestamp, frame in reader:
            ts = float(timestamp)
            frames += 1
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
            maximum = max(maximum, ts)
            try:
                ip = dpkt.ethernet.Ethernet(frame).data
                if isinstance(ip, dpkt.ip.IP) and (ip.offset or ip.mf):
                    # Noninitial fragments have no transport ports: conservatively
                    # count any fragment touching an allocated service IP as a
                    # quality failure rather than silently claiming zero loss.
                    if any(address in (ip.src, ip.dst) and any(p.spec['raw_start'] <= ts < p.spec['raw_end'] for p in parts)
                           for (address, port), parts in index.items()):
                        fragments += 1
                elif isinstance(ip, dpkt.ip.IP) and isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    destinations = index.get((ip.dst, tcp.dport), [])
                    sources = index.get((ip.src, tcp.sport), [])
                    matches = [(p, True) for p in destinations if p.spec['raw_start'] <= ts < p.spec['raw_end']]
                    matches += [(p, False) for p in sources if p.spec['raw_start'] <= ts < p.spec['raw_end']]
                    if len(matches) > 1:
                        raise RuntimeError('Packet matches more than one selected service/block')
                    if matches:
                        p, inbound = matches[0]
                        event = Event(ts, socket.inet_ntoa(ip.src if inbound else ip.dst), tcp.sport if inbound else tcp.dport, inbound, len(frame), tcp.flags)
                        sequence += 1
                        heapq.heappush(heap, (ts, sequence, partitions.index(p), event, tcp.seq))
            except (dpkt.UnpackError, ValueError):
                decode_errors += 1
            watermark = maximum - plan['reorder_seconds']
            drain(watermark)
            boundary = math.floor(watermark)
            if boundary > last_close:
                for p in partitions:
                    p.finish(boundary)
                last_close = boundary
            if frames % 2000000 == 0:
                print(f'Partition replay: {frames:,} frames; {time.perf_counter() - started:.1f}s', flush=True)
        drain(math.inf)
        for p in partitions:
            p.finish(p.spec['raw_end'])
        # No derived outputs are published before the full sequential byte hash.
        if stream.bytes != plan['capture']['bytes'] or stream.sha.hexdigest() != plan['capture']['sha256'] or frames != plan['capture']['expected_frames']:
            raise ValueError('Full capture integrity gate failed')
    if any(p.spec['raw_start'] < math.ceil(first_ts) or p.spec['raw_end'] > math.floor(last_ts) for p in partitions):
        raise ValueError('Allocated interval includes partial/unobserved capture boundary')
    shared = quarantine_shared(partitions)
    predictors = json.loads((ROOT/'results/development/benign_development_manifest.json').read_text())['predictor_columns']
    reports, retained_owners = [], defaultdict(set)
    for p in partitions:
        stats, selected = publish_partition(p, labels[p.spec['id']], ROOT/'data/development/public_partitioned_v1'/p.spec['id'], predictors)
        reports.append(stats)
        for fingerprint, (a, b) in p.influence.items():
            if any(a <= sec < b + p.guard + 1 for sec in selected):
                retained_owners[fingerprint].add(p.spec['role'])
    retained_shared = sum(len(roles) > 1 for roles in retained_owners.values())
    if retained_shared:
        raise ValueError('Cross-role observed connection remains after quarantine')
    totals = defaultdict(Counter)
    for r in reports:
        totals[r['role']][str(r['y'])] += r['retained']['windows']
    quality = not decode_errors and not fragments and not any(p.counts['late_selected_dropped'] for p in partitions)
    result = {
        'date': '2026-11-12', 'scope': 'Split-first public development feature engineering; no fitted/final detector.',
        'plan': str(plan_path.relative_to(ROOT)).replace('\\', '/'), 'plan_sha256': digest(plan_path),
        'source_sha256': {f: digest(ROOT/'src'/f) for f in ('causal_features.py', 'declare_public_partitions.py', 'replay_public_partitions.py')},
        'capture_sha256': plan['capture']['sha256'], 'capture_bytes_hashed_during_parse': stream.bytes,
        'frames_read': frames, 'decode_errors_all_capture': decode_errors, 'selected_fragmented_tcp_frames': fragments,
        'cross_role_observed_syn_fingerprints_before_quarantine': shared,
        'cross_role_retained_syn_fingerprints_after_quarantine': retained_shared,
        'feature_engineering_quality_passed': quality, 'retained_windows_by_role_and_y': dict(totals),
        'partitions': reports, 'predictor_columns': predictors,
        'metadata_columns_excluded_from_predictors': ['session_id', 'role', 'condition', 'y', 'utc_second', 'history_complete'],
        'all_service_packets_extracted_before_label_or_connection_masks': True,
        'elapsed_seconds': round(time.perf_counter() - started, 3),
        'study_training_ready': False, 'main_packet_window_model_trained': False,
        'limitations': plan['limitations'] + [
            'SYN sequence identities and unknown-start quarantine are observational controls, not proof of OS TCP incarnation identity.',
            'The unchanged feature core tracks client endpoint tuples without sequence numbers; connection counts/ages are approximations.',
            'Unknown-start influence is conservatively quarantined only for the sliced same-service attack partitions; wholly assigned benign destinations retain legitimate unknown ages.',
            'Eligible model CSVs are sparse labelled rows. Preserve the full features/eligibility timeline for persistence; never join missing seconds as consecutive evidence.',
            'Independent final known-attack K is unallocated; benign diversity/repetition and source/path controls remain unfinished.']}
    out = ROOT/'results/development/public_partitioned_v1.json'
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: result[k] for k in ('frames_read', 'feature_engineering_quality_passed', 'retained_windows_by_role_and_y', 'cross_role_observed_syn_fingerprints_before_quarantine', 'elapsed_seconds', 'study_training_ready')}, indent=2), flush=True)


if __name__ == '__main__':
    replay(ROOT/'plan/public_partitions_v1.json')
