"""Explain frozen v1 exclusions using full-capture TCP metadata, never labels.

Preserves v1 and publishes descriptive audit evidence. Any later eligibility
change must be declared separately before creating a v2 selection.
"""
from collections import Counter, defaultdict
import csv
import io
import json
import socket
import time

import numpy as np
from causal_features import Event
from declare_public_partitions import ROOT, digest
from replay_public_partitions import Partition
from tcp_incarnations import attribute_key


def event(row):
    return Event(float(row['timestamp']), socket.inet_ntoa(int(row['client']).to_bytes(4, 'big')),
                 int(row['port']), bool(row['inbound']), int(row['length']), int(row['flags']))


def feature_digest(rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    import hashlib
    return hashlib.sha256(stream.getvalue().encode('utf-8')).hexdigest()


def run():
    started = time.perf_counter()
    plan_path = ROOT/'plan/tcp_boundary_audit_v1.json'
    index_report_path = ROOT/'results/development/friday_tcp_index_v1.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    index_report = json.loads(index_report_path.read_text(encoding='utf-8'))
    if digest(plan_path) != index_report['plan_sha256'] or digest(ROOT/'src/replay_public_partitions.py') != plan['frozen_v1_replay_source_sha256']:
        raise ValueError('Audit plan/frozen source changed')
    index_path = ROOT/index_report['index']
    if digest(index_path) != index_report['index_sha256']:
        raise ValueError('TCP index changed')
    rows = np.load(index_path, allow_pickle=False, mmap_mode='r')
    previous = json.loads((ROOT/'results/development/public_partitioned_v1.json').read_text(encoding='utf-8'))
    unknown, block_members, block_reports = {}, {}, {}
    for block in plan['blocks']:
        p = Partition(block)
        selected = np.flatnonzero((rows['timestamp'] >= block['raw_start']) & (rows['timestamp'] < block['raw_end']))
        flagged = []
        for index in selected:
            index = int(index)
            before = p.counts['unknown_or_ambiguous_start_packets']
            p.add(event(rows[index]), int(rows[index]['seq']))
            if p.counts['unknown_or_ambiguous_start_packets'] > before:
                flagged.append(index)
        p.finish(block['raw_end'])
        original = next(r for r in previous['partitions'] if r['id'] == block['id'])
        if len(flagged) != plan['expected_v1_unknown_packets'][block['id']] or feature_digest(p.rows) != original['files']['features.csv']['sha256']:
            raise ValueError('Index replay does not reproduce frozen v1 evidence')
        unknown[block['id']] = flagged
        block_members[block['id']] = selected
        block_reports[block['id']] = {'raw_packets': len(selected), 'v1_unknown_packets_reproduced': len(flagged),
                                     'v1_feature_table_sha256_reproduced': feature_digest(p.rows)}
        print(f'Reproduced {block["id"]}: {len(flagged):,} unknown packets, exact feature SHA-256', flush=True)
    by_key = defaultdict(list)
    for i, row in enumerate(rows):
        by_key[(int(row['client']), int(row['port']))].append(i)
    assignments = np.full(len(rows), -1, dtype=np.int64)
    incarnations, why, unresolved_keys = [], {}, set()
    flagged_set = {i for flagged in unknown.values() for i in flagged}
    for number, (key, indices) in enumerate(by_key.items(), 1):
        groups, assigned, reasons = attribute_key(rows, indices, len(incarnations))
        incarnations.extend(groups)
        for i, identity in assigned.items():
            assignments[i] = identity
        if len(assigned) != len(indices) or any(c.ambiguous for c in groups):
            unresolved_keys.add(key)
        why.update({i: reasons[i] for i in indices if i in flagged_set})
        if number % 10000 == 0:
            print(f'TCP provenance: {number:,}/{len(by_key):,} endpoint keys; {time.perf_counter()-started:.1f}s', flush=True)
    # Save private assignment evidence for versioned, post-declaration selection.
    directory = ROOT/'data/development/friday_tcp_boundary_v1'
    assign_path = directory/'assignments.npy'
    np.save(assign_path, assignments, allow_pickle=False)
    group_rows = []
    for c in incarnations:
        owners = [b['id'] for b in plan['blocks'] if any(b['raw_start'] <= rows[i]['timestamp'] < b['raw_end'] for i in c.members)]
        group_rows.append({'identity': c.identity, 'client': c.key[0], 'port': c.key[1], 'client_isn': c.client_isn,
                           'server_isn': c.server_isn, 'first': c.first if c.members else None, 'last': c.last if c.members else None,
                           'packets': len(c.members), 'ambiguous': c.ambiguous, 'handshake_ack': c.handshake_ack,
                           'first_close': c.first_close, 'post_close_packets': c.post_close_packets,
                           'exact_repeats': c.exact_repeats, 'observed_block_owners': owners,
                           'canonical_key_has_unresolved_observations': c.key in unresolved_keys})
    groups_path = directory/'incarnations.json'
    groups_path.write_text(json.dumps(group_rows, separators=(',', ':')) + '\n', encoding='utf-8', newline='\n')
    keys_path = directory/'unresolved_keys.npy'
    np.save(keys_path, np.array(sorted(unresolved_keys), dtype=np.uint64), allow_pickle=False)
    for block in plan['blocks']:
        name = block['id']
        status, flags, close_status, causes = Counter(), Counter(), Counter(), Counter()
        for i in unknown[name]:
            row = rows[i]
            flags[f'{"in" if row["inbound"] else "out"}/flags={int(row["flags"])}/payload={"yes" if row["payload"] else "no"}'] += 1
            identity = int(assignments[i])
            key = (int(row['client']), int(row['port']))
            causes[why.get(i, 'unresolved')] += 1
            if identity < 0:
                status['unresolved_packet'] += 1
                continue
            c = incarnations[identity]
            if c.first_close is not None and row['timestamp'] > c.first_close:
                close_status['after_observed_close'] += 1
            else:
                close_status['before_or_at_observed_close'] += 1
            if key in unresolved_keys:
                status['assigned_but_key_has_unresolved_observations'] += 1
            elif block['raw_start'] <= c.first and c.last < block['raw_end'] and not c.ambiguous:
                status['fully_attributed_incarnation_inside_raw_block'] += 1
            else:
                status['attributed_incarnation_crosses_raw_boundary_or_ambiguous'] += 1
        block_reports[name].update(unknown_packet_attribution=dict(status), unknown_flags=dict(flags),
                                   unknown_close_relationship=dict(close_status), unknown_assignment_evidence=dict(causes))
    report = {
        'date': '2026-11-12', 'scope': plan['scope'], 'plan_sha256': digest(plan_path),
        'index_report_sha256': digest(index_report_path), 'capture_sha256': index_report['capture_sha256'],
        'source_sha256': {n: digest(ROOT/'src'/n) for n in ('audit_tcp_boundaries.py', 'tcp_incarnations.py')},
        'indexed_tcp_packets': len(rows), 'canonical_endpoint_keys': len(by_key),
        'observed_syn_identities': len(incarnations), 'assigned_packets': int(np.sum(assignments >= 0)),
        'unresolved_packets': int(np.sum(assignments < 0)), 'canonical_keys_with_any_unresolved_or_ambiguous_evidence': len(unresolved_keys),
        'conflicting_handshake_identities': sum(c.ambiguous for c in incarnations),
        'identities_with_observations_in_both_development_blocks': sum(len(g['observed_block_owners']) > 1 for g in group_rows),
        'blocks': block_reports,
        'private_evidence': {p.name: {'path': str(p.relative_to(ROOT)).replace('\\', '/'), 'sha256': digest(p)} for p in (assign_path, groups_path, keys_path)},
        'elapsed_seconds': round(time.perf_counter() - started, 3),
        'v1_feature_bytes_and_unknown_counts_reproduced': True, 'study_training_ready': False,
        'limitations': ['Sequence/ACK consistency and segment hashes are capture evidence, not OS TCP state or complete packet ground truth.',
                        'Missing/ambiguous evidence is not repaired by temporal proximity; an entire canonical key remains suspect if any full-capture observation cannot be attributed.',
                        'No labels, model scores or new eligibility selections enter this audit. A new plan must precede any v2 row selection.',
                        'One attack episode, source/path confounding, sparse benign labels and unallocated independent final K remain.'],
    }
    (ROOT/'results/development/tcp_boundary_audit_v1.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(report['blocks'], indent=2), flush=True)


if __name__ == '__main__':
    run()
