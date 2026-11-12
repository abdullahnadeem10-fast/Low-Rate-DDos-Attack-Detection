"""Declare and replay an independently recorded, count-corroborated V stream.

All raw service packets enter the frozen causal core before label selection.
Cache replay is allowed only with a proof of monotonic full-capture order; this
ensures numeric equivalence to the fixed one-second raw replay reorder policy.
"""
from collections import Counter
import csv
import json
import math
import socket

import numpy as np
from causal_features import CausalFeatures, Event
from declare_cic2019_validation import ROOT
from download_cic2019_validation import sha
from replay_public_partitions import describe, write_csv


def chronology(members):
    if not members or any(m['link_type'] != 1 or m['first_utc_timestamp'] is None or m['max_adjacent_timestamp_regression_seconds'] != 0 for m in members):
        raise ValueError('No exact monotonic-capture proof; raw-order replay is required')
    gaps = []
    for a, b in zip(members, members[1:]):
        gap = b['first_utc_timestamp'] - a['last_utc_timestamp']
        if gap < 0 or gap > 1:
            raise ValueError('Capture rotation overlap/gap requires a new declared observation policy')
        gaps.append(gap)
    return {'all_members_monotonic': True, 'natural_rotation_order_is_chronological': True,
            'rotation_overlaps': 0, 'max_rotation_gap_seconds': max(gaps, default=0.),
            'one_second_reorder_budget_cannot_drop_selected_packets_in_this_monotonic_source': True}


def extract_cache(rows, start, end):
    core = CausalFeatures(timeout=30)
    core.second = start
    features, counts = [], Counter()
    previous = -math.inf
    for row in rows:
        stamp = float(row['timestamp'])
        if stamp < previous:
            raise ValueError('Cached service packets are not chronological')
        previous = stamp
        if not start <= stamp < end:
            counts['outside_complete_capture_seconds'] += 1
            continue
        packet = Event(stamp, socket.inet_ntoa(int(row['client']).to_bytes(4, 'big')),
                       int(row['port']), bool(row['inbound']), int(row['length']), int(row['flags']))
        features.extend(core.add(packet))
        counts['selected_tcp_in_full_seconds'] += 1
    features.extend(core.finish(end))
    return features, dict(counts)


def main():
    out = ROOT/'results/development'
    allocation_path = ROOT/'plan/cic2019_validation_v1.json'
    source_plan = json.loads(allocation_path.read_text(encoding='utf-8'))
    join_path, packet_path = out/'cic2019_corroboration_v1.json', out/'cic2019_packet_inventory_v1.json'
    join, packets = (json.loads(p.read_text(encoding='utf-8')) for p in (join_path, packet_path))
    if join['packet_inventory_sha256'] != sha(packet_path) or not join['packet_input_quality_passed'] or not join['label_metadata_quality_passed']:
        raise ValueError('Source corroboration/quality evidence changed')
    name = join['selected_metadata_candidate']
    if name is None:
        raise ValueError('No corroborated compatible V service; preserve feasibility failure')
    candidate = next(s for s in join['services'] if s['service'] == name)
    proof = chronology(packets['members'])
    index_path = ROOT/packets['index']
    if sha(index_path) != packets['index_sha256'] or sha(ROOT/candidate['label_table']) != candidate['label_sha256']:
        raise ValueError('Cached raw metadata or labels changed')
    start = math.floor(packets['members'][0]['first_utc_timestamp']) + 1
    end = math.floor(packets['members'][-1]['last_utc_timestamp'])
    evidence_paths = [allocation_path, join_path, packet_path, out/'cic2019_label_inventory_v1.json', out/'study_development_manifest_v3.json']
    plan = {
        'date': '2026-11-12', 'version': 'cic2019_features_v1', 'role': 'V',
        'group_id': 'cic2019-03-11-syn-tcp443-v', 'parent_source_group': 'entire provided CIC-DDoS2019 03-11 source',
        'scope': 'Preliminary independently recorded known-SYN validation component; no final research scoring.',
        'evidence_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in evidence_paths},
        'source_sha256': {n: sha(ROOT/'src'/n) for n in ('replay_cic2019_validation.py', 'causal_features.py')},
        'service': name, 'service_index': candidate['service_index'],
        'raw_start': start, 'raw_end': end, 'eligible_start': start + 50, 'eligible_end': end - 50,
        'chronology_proof': proof, 'reorder_seconds': 1, 'history_seconds': 20, 'timeout_seconds': 30,
        'cache_policy': 'Entire raw selected-service stream from hash-pinned metadata, no packet filtering by labels. Monotonic complete-source proof makes closed-window values equal the one-second bounded raw replay; this is not a measured live-latency result.',
        'observation_policy': '146 chronological contiguous rotations are one recorded source, not 146 independent sessions. Fresh core for the complete observed V stream; unknown initial connection ages remain observed unknowns.',
        'label_policy': 'Unchanged +3-hour count/interval corroboration after features; y=1 only on attack_present seconds. Idle/uncertain/unlabelled context remains unknown.',
        'reserved_final_candidate': source_plan['reserved_final_K_candidate'], 'final_K_candidate_qualified': False,
        'study_training_ready': False,
    }
    plan_path = ROOT/'plan/cic2019_features_v1.json'
    value = (json.dumps(plan, indent=2) + '\n').encode('utf-8')
    if plan_path.exists() and plan_path.read_bytes() != value:
        raise FileExistsError('Immutable feature plan changed')
    plan_path.write_bytes(value)
    print(f'Declared V service/stream before features; SHA-256 {sha(plan_path)}', flush=True)
    metadata = np.load(index_path, allow_pickle=False, mmap_mode='r')
    selected_raw = metadata[metadata['service'] == candidate['service_index']]
    features, counts = extract_cache(selected_raw, start, end)
    if [r['utc_second'] for r in features] != list(range(start, end)):
        raise ValueError('Noncontiguous or missing raw observation windows')
    # Labels are opened only after the complete raw feature stream exists.
    with (ROOT/candidate['label_table']).open(newline='', encoding='utf-8') as f:
        labels = {int(r['utc_second']): r for r in csv.DictReader(f)}
    selected, excluded, eligibility = [], [], []
    reasons, statuses = Counter(), Counter()
    for row in features:
        sec = row['utc_second']
        label = labels.get(sec, {})
        status = label.get('status', 'not_labelled')
        statuses[status] += 1
        if label and row['packets_in'] + row['packets_out'] != int(label['packets']):
            raise ValueError('Raw feature/label packet totals disagree')
        flags = []
        if not plan['eligible_start'] <= sec < plan['eligible_end']:
            flags.append('boundary_guard')
        if not row['history_complete']:
            flags.append('history_incomplete')
        if status != 'attack_present':
            flags.append('label_' + status)
        if any(not math.isfinite(float(v)) for v in row.values()):
            raise ValueError('Non-finite raw feature')
        reasons[flags[0] if flags else 'retained'] += 1
        eligibility.append({'utc_second': sec, 'status': status, 'retained': int(not flags), 'exclusion_reasons': '|'.join(flags)})
        if flags:
            excluded.append(row)
        else:
            selected.append({'session_id': plan['group_id'], 'role': 'V', 'condition': 'public_syn_tcp443', 'y': 1, **row})
    directory = ROOT/'data/development/cic2019_v/causal_v1'
    directory.mkdir(parents=True, exist_ok=True)
    columns = list(features[0])
    write_csv(directory/'features.csv', columns, features)
    write_csv(directory/'eligibility.csv', ['utc_second', 'status', 'retained', 'exclusion_reasons'], eligibility)
    write_csv(directory/'model_windows.csv', ['session_id', 'role', 'condition', 'y'] + columns, selected)
    report = {
        'date': '2026-11-12', 'scope': plan['scope'], 'plan': str(plan_path.relative_to(ROOT)).replace('\\', '/'),
        'plan_sha256': sha(plan_path), 'group_id': plan['group_id'], 'role': 'V', 'condition': 'public_syn_tcp443',
        'service': name, 'raw_window_count': len(features), 'raw_status_windows': dict(statuses), 'primary_exclusion_windows': dict(reasons),
        'counts': counts, 'selected_raw_metadata_packets': len(selected_raw), 'late_selected_dropped': 0,
        'late_zero_basis': 'Proven monotonic raw capture order, not an assumption from sorted cache alone.',
        'retained': describe(selected), 'excluded': describe(excluded),
        'files': {n: {'path': str((directory/n).relative_to(ROOT)).replace('\\', '/'), 'sha256': sha(directory/n)}
                  for n in ('features.csv', 'eligibility.csv', 'model_windows.csv')},
        'source_sha256': plan['source_sha256'], 'recorded_attack_validation_sources': 1,
        'independent_attack_V_packet_component_available': bool(selected), 'study_training_ready': False,
        'main_packet_window_model_trained': False, 'final_attack_tests_run': 0,
        'limitations': ['This is a sparse TCP/443 slice of a predominantly other-port SYN campaign; it is not a measurement of whole-host or HTTPS denial impact.',
                        'No TLS payload prefix was observed at this endpoint. Port compatibility and SYN labels do not prove a functioning HTTPS application or every packet malicious.',
                        'Flow directional counts/intervals corroborate labels, not exact packet or onset ground truth.',
                        'One independent validation recording does not create one independent experiment per labelled second or archive rotation.',
                        'Sparse coverage, class/service/path/source confounding and broader benign congestion/diversity/repetitions remain unresolved.'],
    }
    (out/'cic2019_causal_v1.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'raw_windows': len(features), 'raw_packets': len(selected_raw), 'retained_attack_windows': len(selected), 'study_training_ready': False}, indent=2), flush=True)


if __name__ == '__main__':
    main()
