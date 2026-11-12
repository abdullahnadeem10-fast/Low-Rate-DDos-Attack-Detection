"""Allocate the complete Friday target stream to T; leave attack V unallocated.

The unsuccessful v1/v2 temporal splits remain immutable negative evidence.
Whole-destination ownership avoids splitting TCP groups between development roles,
but supplies only one attack training episode, not independent validation/testing.
"""
from datetime import datetime
import csv
import json
import math

import numpy as np
from audit_tcp_boundaries import event
from declare_public_partitions import ROOT, digest
from replay_public_partitions import Partition, publish_partition


def destination_overlap(rows, benign_blocks):
    """A target-service packet can also match another service only at client :80."""
    import socket
    count = 0
    for b in benign_blocks:
        ip, port = b['service'].split(':')
        address = int.from_bytes(socket.inet_aton(ip), 'big')
        count += int(np.sum((rows['client'] == address) & (rows['port'] == int(port))
                            & (rows['timestamp'] >= b['raw_start']) & (rows['timestamp'] < b['raw_end'])))
    return count


def validate_whole_ownership(blocks):
    for b in blocks:
        if b['kind'] == 'whole_capture_attack_destination':
            if any(other is not b and other['service'] == b['service'] for other in blocks):
                raise ValueError('Whole-capture destination cannot have another allocated block')


def run():
    parent_path = ROOT/'plan/public_partitions_v1.json'
    parent = json.loads(parent_path.read_text(encoding='utf-8'))
    if digest(ROOT/parent['feature_core']['path']) != parent['feature_core']['sha256']:
        raise ValueError('Frozen feature core changed')
    index_path = ROOT/'results/development/friday_tcp_index_v1.json'
    index_report = json.loads(index_path.read_text(encoding='utf-8'))
    if digest(ROOT/index_report['index']) != index_report['index_sha256']:
        raise ValueError('Full-capture metadata index changed')
    rows = np.load(ROOT/index_report['index'], allow_pickle=False, mmap_mode='r')
    benign = [b for b in parent['blocks'] if b['kind'] == 'benign_destination']
    overlap = destination_overlap(rows, benign)
    if overlap:
        raise ValueError('Raw packets shared with a different development destination role')
    capture_audit_path = ROOT/'results/development/friday_packet_audit.json'
    capture_audit = json.loads(capture_audit_path.read_text(encoding='utf-8'))
    if capture_audit['capture_sha256'] != index_report['capture_sha256']:
        raise ValueError('Capture coverage evidence changed')
    times = capture_audit['clock_audit']
    first = math.floor(datetime.fromisoformat(times['capture_first_utc']).timestamp()) + 1
    last = math.floor(datetime.fromisoformat(times['capture_last_utc']).timestamp())
    old = next(b for b in parent['blocks'] if b['kind'] == 'attack_block' and b['role'] == 'T')
    block = {**old, 'id': 'friday-ddos-whole-t', 'kind': 'whole_capture_attack_destination',
             'raw_start': first, 'raw_end': last, 'eligible_start': first + 50, 'eligible_end': last - 50}
    validate_whole_ownership(benign + [block])
    evidence_paths = [parent_path, capture_audit_path, index_path] + [ROOT/'results/development'/n for n in (
        'public_partitioned_v1.json', 'public_partitioned_v2.json', 'tcp_boundary_audit_v1.json', 'public_fragment_attribution_v1.json')]
    source_names = ['replay_public_whole_capture.py', 'replay_public_partitions.py', 'causal_features.py']
    plan = {
        'date': '2026-11-12', 'version': 'public_partitions_v3',
        'scope': 'Whole observed Friday target destination allocated to supervised T only; independent attack V and final K remain unallocated.',
        'evidence_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): digest(p) for p in evidence_paths},
        'source_sha256': {n: digest(ROOT/'src'/n) for n in source_names},
        'capture': parent['capture'], 'blocks': benign + [block],
        'metadata_preflight_shared_raw_packets_across_destination_roles': overlap,
        'allocation_policy': 'All observed Friday target-service TCP groups and context belong to T. No target-service packet, TCP incarnation or earlier/later segment is allocated to V/C1/C2/K. Other six destination groups and lab sessions keep their declared roles.',
        'feature_policy': 'Replay the complete raw target stream from a fresh frozen core, omit partial global capture seconds, warm up history and retain all packets regardless of label. Unknown tracker ages are valid observations of this wholly assigned group, not evidence of inter-role leakage.',
        'label_policy': 'Apply unchanged corroborated current-window labels after extraction; retain only attack_present rows as y=1. No unknown/idle/uncertain row is labelled benign. Preserve full timelines.',
        'independent_attack_validation_V': 'UNALLOCATED: a different permitted known-attack capture is required before V-based attack model selection.',
        'final_known_attack_K': parent['final_known_attack_K'], 'reserved': parent['reserved'],
        'reason': 'v1 and metadata-refined v2 blocks both retained zero positive rows. Whole-source ownership preserves observed connection groups without weakening ambiguous TCP attribution or filtering raw packets.',
        'study_training_ready': False,
    }
    plan_path = ROOT/'plan/public_partitions_v3.json'
    value = (json.dumps(plan, indent=2) + '\n').encode('utf-8')
    if plan_path.exists() and plan_path.read_bytes() != value:
        raise FileExistsError('Immutable v3 plan changed')
    plan_path.write_bytes(value)
    print(f'Declared whole-capture T before feature creation; plan SHA-256 {digest(plan_path)}', flush=True)
    # The frozen Partition masks unknowns for sliced attack_block streams only.
    # This explicitly declared whole-destination kind has one role for all TCP
    # groups, exactly like whole assigned benign destinations. Features stay identical.
    p = Partition(block)
    for row in rows:
        ts = float(row['timestamp'])
        if first <= ts < last:
            p.add(event(row), int(row['seq']))
    p.finish(last)
    if p.unknown or p.shared or p.counts['late_selected_dropped']:
        raise ValueError('Unexpected whole-group mask/drop')
    predictors = json.loads((ROOT/'results/development/benign_development_manifest.json').read_text(encoding='utf-8'))['predictor_columns']
    # Open labels only after all raw features have been created.
    if digest(ROOT/block['label_table']) != block['label_sha256']:
        raise ValueError('Corroborated label evidence changed')
    with (ROOT/block['label_table']).open(newline='', encoding='utf-8') as f:
        labels = {int(r['utc_second']): r for r in csv.DictReader(f)}
    result, selected = publish_partition(p, labels, ROOT/'data/development/public_partitioned_v3'/block['id'], predictors)
    parent_report = json.loads((ROOT/'results/development/public_partitioned_v1.json').read_text(encoding='utf-8'))
    reports = [{**b, 'lineage': 'Unchanged whole-destination v1 benign component.'} for b in parent_report['partitions'] if b['kind'] == 'benign_destination'] + [result]
    totals = {role: {'0': 0, '1': 0} for role in ('T', 'C1', 'C2', 'V')}
    for b in reports:
        totals[b['role']][str(b['y'])] += b['retained']['windows']
    report = {
        'date': '2026-11-12', 'scope': plan['scope'], 'plan': str(plan_path.relative_to(ROOT)).replace('\\', '/'),
        'plan_sha256': digest(plan_path), 'source_sha256': plan['source_sha256'],
        'capture_sha256': parent['capture']['sha256'], 'partitions': reports,
        'retained_windows_by_role_and_y': totals, 'predictor_columns': predictors,
        'metadata_columns_excluded_from_predictors': parent_report['metadata_columns_excluded_from_predictors'],
        'target_service_assigned_to_only_one_role': True, 'shared_raw_packets_across_destination_roles': overlap,
        'newly_replayed_whole_attack_streams': 1, 'unchanged_parent_benign_streams': 6,
        'observed_attack_episodes_in_T': 1, 'independent_attack_V_available': False, 'independent_final_K_allocated': False,
        'supervised_T_positive_component_available': bool(selected),
        'public_packet_quality_after_independent_fragment_attribution': True,
        'study_training_ready': False, 'main_packet_window_model_trained': False, 'final_attack_tests_run': 0,
        'limitations': ['Whole-source T ownership prevents observed target-connection overlap between roles, but supplies only one known-attack training episode.',
                        'Independent permitted known-attack validation and final K remain unallocated. No previously inspected Friday block can become an untouched final set.',
                        'Captured connection state/ages are approximate; the frozen endpoint-key core is unchanged.',
                        'Corroborated attack presence is not exact packet/onset ground truth; unknown/idle cells remain unknown.',
                        'Different target/benign services and paths remain confounded with class. Broader benign congestion/diversity/repetition and a gap-aware calibration policy are unfinished.'],
    }
    (ROOT/'results/development/public_partitioned_v3.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(totals, indent=2), flush=True)


if __name__ == '__main__':
    run()
