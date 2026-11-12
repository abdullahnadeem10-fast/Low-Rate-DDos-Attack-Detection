"""Versioned TCP-provenance eligibility with unchanged causal predictors.

Declare before selecting. All packets enter fresh feature instances; only later
row eligibility changes. Unsafe tracker state remains tainted until an actual
reset/close/expiry, including refreshes by otherwise supported incarnations.
"""
from collections import Counter, defaultdict
import csv
import json
import math

import numpy as np
from causal_features import CausalFeatures
from audit_tcp_boundaries import event, feature_digest
from declare_public_partitions import ROOT, digest
from replay_public_partitions import add_interval, covered, describe, write_csv


class TaintReplay:
    def __init__(self, spec, guard=50):
        self.spec, self.guard = spec, guard
        self.core = CausalFeatures(timeout=30)
        self.core.second = spec['raw_start']
        self.rows, self.intervals = [], []
        self.tainted = set()
        self.counts = Counter()

    def add(self, packet, unsafe):
        if not self.spec['raw_start'] <= packet.timestamp < self.spec['raw_end']:
            raise ValueError('Packet outside allocated block')
        self.rows.extend(self.core.finish(int(packet.timestamp)))
        key = packet.client, packet.client_port
        state = self.core.connections.get(key)
        if state and packet.timestamp - state['last'] >= 30:
            state = None
        syn = packet.inbound and packet.flags & 2 and not packet.flags & 16
        if state is None or syn and state['complete']:
            self.tainted.discard(key)
        inherited = key in self.tainted
        if unsafe or inherited:
            self.tainted.add(key)
            sec = int(packet.timestamp)
            add_interval(self.intervals, sec, sec + self.guard + 1)
            self.counts['direct_unsafe_packets' if unsafe else 'tracker_taint_propagated_packets'] += 1
        self.rows.extend(self.core.add(packet))
        self.counts['selected_tcp'] += 1
        if key not in self.core.connections:
            self.tainted.discard(key)

    def finish(self):
        self.rows.extend(self.core.finish(self.spec['raw_end']))


def declare():
    parent_path = ROOT/'plan/public_partitions_v1.json'
    parent = json.loads(parent_path.read_text(encoding='utf-8'))
    paths = [parent_path] + [ROOT/'results/development'/n for n in (
        'public_partitioned_v1.json', 'public_fragment_attribution_v1.json',
        'friday_tcp_index_v1.json', 'tcp_boundary_audit_v1.json')]
    audit = json.loads(paths[-1].read_text(encoding='utf-8'))
    plan = {
        'date': '2026-11-12', 'version': 'public_partitions_v2',
        'scope': 'Development-only eligibility revision supported by metadata audit, not blind preregistration or final evaluation.',
        'parent': str(parent_path.relative_to(ROOT)).replace('\\', '/'),
        'evidence_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): digest(p) for p in paths},
        'source_sha256': {n: digest(ROOT/'src'/n) for n in ('replay_public_v2.py', 'tcp_incarnations.py', 'causal_features.py')},
        'capture': parent['capture'], 'blocks': parent['blocks'],
        'private_tcp_evidence': audit['private_evidence'],
        'unchanged': ['raw block boundaries and destination roles', 'all 30 predictors and signed-rate schema',
                      'feature core and fresh per-block state', 'six wholly assigned benign destination tables',
                      'label evidence and accepted statuses', '50-second eligibility edge guards', 'final source reservations'],
        'eligibility_policy': [
            'An observed TCP identity is supported only if all its attributed observations lie inside this raw block, with no ambiguous handshake.',
            'Quarantine every observation of any endpoint key with any unresolved/conflicting full-capture packet evidence; do not salvage individual rows from that key.',
            'Mark all other observations (unsupported/missing identity or identity crossing either raw edge) unsafe.',
            'Feed every raw packet to the frozen fresh causal core, regardless of safety/label. Track unsafe influence independently.',
            'Unsafe input taints that endpoint-key feature state. Refreshing that state with a supported packet does not clear taint. Only actual frozen-core expiry, close or its completed-handshake/new-SYN reset clears state taint.',
            'Mask every direct or propagated tainted packet second and 50 following seconds, conservatively covering residual connection state and history.',
            'Apply label confidence, warm-up, boundary and safety masks only after complete raw features exist. Never compress gaps for persistence.'],
        'final_known_attack_K': parent['final_known_attack_K'], 'reserved': parent['reserved'],
        'study_training_ready': False,
    }
    path = ROOT/'plan/public_partitions_v2.json'
    value = (json.dumps(plan, indent=2) + '\n').encode('utf-8')
    if path.exists() and path.read_bytes() != value:
        raise FileExistsError('Immutable v2 plan differs; create a new version')
    path.write_bytes(value)
    print(f'Declared v2 eligibility before selection; plan SHA-256 {digest(path)}', flush=True)
    return path, plan


def supported_identity(group, block, unresolved_key):
    return bool(not unresolved_key and not group['ambiguous'] and group['first'] is not None
                and block['raw_start'] <= group['first'] <= group['last'] < block['raw_end'])


def save_attack(p, original):
    block = p.spec
    label_path = ROOT/block['label_table']
    if digest(label_path) != block['label_sha256']:
        raise ValueError('Label bytes changed')
    with label_path.open(newline='', encoding='utf-8') as f:
        labels = {int(r['utc_second']): r for r in csv.DictReader(f)}
    selected, rejected, eligibility = [], [], []
    flags_count, primary, status_count = Counter(), Counter(), Counter()
    for row in p.rows:
        sec = row['utc_second']
        label = labels.get(sec, {})
        status = label.get('status', 'not_labelled')
        status_count[status] += 1
        if label and row['packets_in'] + row['packets_out'] != int(label['packets']):
            raise ValueError('Label/feature packet count mismatch')
        flags = []
        if not block['eligible_start'] <= sec < block['eligible_end']:
            flags.append('boundary_guard')
        if not row['history_complete']:
            flags.append('history_incomplete')
        if covered(sec, p.intervals):
            flags.append('unsafe_tcp_tracker_influence')
        if status != block['accepted_status']:
            flags.append('label_' + status)
        if any(not math.isfinite(float(v)) for v in row.values()):
            raise ValueError('Non-finite feature')
        flags_count.update(flags)
        primary[flags[0] if flags else 'retained'] += 1
        eligibility.append({'utc_second': sec, 'status': status, 'retained': int(not flags), 'exclusion_reasons': '|'.join(flags)})
        if flags:
            rejected.append(row)
        else:
            selected.append({'session_id': block['id'], 'role': block['role'], 'condition': block['condition'], 'y': block['y'], **row})
    directory = ROOT/'data/development/public_partitioned_v2'/block['id']
    directory.mkdir(parents=True, exist_ok=True)
    columns = list(p.rows[0])
    write_csv(directory/'features.csv', columns, p.rows)
    write_csv(directory/'model_windows.csv', ['session_id', 'role', 'condition', 'y'] + columns, selected)
    write_csv(directory/'eligibility.csv', ['utc_second', 'status', 'retained', 'exclusion_reasons'], eligibility)
    if digest(directory/'features.csv') != original['files']['features.csv']['sha256']:
        raise ValueError('v2 changed causal feature bytes')
    return {**block, 'lineage': 'Fresh v2 replay; features byte-identical to v1; versioned metadata eligibility only.',
            'packet_counts': dict(p.counts), 'unsafe_influence_intervals': p.intervals,
            'raw_status_windows': dict(status_count), 'primary_exclusion_windows': dict(primary),
            'all_exclusion_flags_windows': dict(flags_count), 'retained': describe(selected), 'excluded': describe(rejected),
            'files': {name: {'relative_path': str((directory/name).relative_to(ROOT)).replace('\\', '/'), 'sha256': digest(directory/name)}
                      for name in ('features.csv', 'model_windows.csv', 'eligibility.csv')}}


def run(plan_path, plan):
    for name, pinned in plan['evidence_sha256'].items():
        if digest(ROOT/name) != pinned:
            raise ValueError('v2 planning evidence changed')
    for name, pinned in plan['source_sha256'].items():
        if digest(ROOT/'src'/name) != pinned:
            raise ValueError('Declared v2 source changed')
    for item in plan['private_tcp_evidence'].values():
        if digest(ROOT/item['path']) != item['sha256']:
            raise ValueError('TCP assignment evidence changed')
    index_report = json.loads((ROOT/'results/development/friday_tcp_index_v1.json').read_text(encoding='utf-8'))
    if digest(ROOT/index_report['index']) != index_report['index_sha256']:
        raise ValueError('Raw metadata index changed')
    rows = np.load(ROOT/index_report['index'], allow_pickle=False, mmap_mode='r')
    assignments = np.load(ROOT/plan['private_tcp_evidence']['assignments.npy']['path'], allow_pickle=False)
    groups = json.loads((ROOT/plan['private_tcp_evidence']['incarnations.json']['path']).read_text(encoding='utf-8'))
    unresolved = {tuple(map(int, key)) for key in np.load(ROOT/plan['private_tcp_evidence']['unresolved_keys.npy']['path'], allow_pickle=False)}
    parent = json.loads((ROOT/'results/development/public_partitioned_v1.json').read_text(encoding='utf-8'))
    reports = [{**p, 'lineage': 'Unchanged whole-destination v1 benign component.'} for p in parent['partitions'] if p['kind'] == 'benign_destination']
    retained_identity_roles = defaultdict(set)
    for block in plan['blocks']:
        if block['kind'] != 'attack_block':
            continue
        p = TaintReplay(block)
        attribution_counts = Counter()
        selected_indices = np.flatnonzero((rows['timestamp'] >= block['raw_start']) & (rows['timestamp'] < block['raw_end']))
        for i in selected_indices:
            row = rows[i]
            key = int(row['client']), int(row['port'])
            identity = int(assignments[i])
            safe = identity >= 0 and supported_identity(groups[identity], block, key in unresolved)
            attribution_counts['supported_input_packets' if safe else 'unsafe_input_packets'] += 1
            p.add(event(row), not safe)
        p.finish()
        original = next(x for x in parent['partitions'] if x['id'] == block['id'])
        if feature_digest(p.rows) != original['files']['features.csv']['sha256']:
            raise ValueError('Frozen feature replay changed')
        result = save_attack(p, original)
        result['tcp_provenance_packets'] = dict(attribution_counts)
        reports.append(result)
        # Exact post-mask connection overlap check includes each identity's
        # conservative influence through 50 seconds after its last event.
        retained_seconds = {r['utc_second'] for r in p.rows if block['eligible_start'] <= r['utc_second'] < block['eligible_end'] and not covered(r['utc_second'], p.intervals)}
        for g in groups:
            if g['first'] is not None and any(g['first'] <= sec + 1 and sec < g['last'] + 51 for sec in retained_seconds):
                if supported_identity(g, block, (g['client'], g['port']) in unresolved):
                    retained_identity_roles[g['identity']].add(block['role'])
        print(f'v2 {block["role"]}: {result["retained"]["windows"]} retained attack windows; feature SHA unchanged', flush=True)
    if any(len(roles) > 1 for roles in retained_identity_roles.values()):
        raise ValueError('A retained observed identity spans roles')
    totals = defaultdict(lambda: {'0': 0, '1': 0})
    for p in reports:
        totals[p['role']][str(p['y'])] += p['retained']['windows']
    report = {
        'date': '2026-11-12', 'scope': plan['scope'], 'plan': str(plan_path.relative_to(ROOT)).replace('\\', '/'),
        'plan_sha256': digest(plan_path), 'capture_sha256': plan['capture']['sha256'],
        'source_sha256': plan['source_sha256'], 'partitions': reports,
        'retained_windows_by_role_and_y': dict(totals), 'predictor_columns': parent['predictor_columns'],
        'metadata_columns_excluded_from_predictors': parent['metadata_columns_excluded_from_predictors'],
        'newly_replayed_attack_streams': 2, 'unchanged_parent_benign_streams': 6,
        'attack_feature_tables_byte_identical_to_v1': True, 'retained_cross_role_supported_identities': 0,
        'public_packet_quality_after_independent_fragment_attribution': True,
        'public_known_attack_component_has_retained_labels': all(totals[role]['1'] > 0 for role in ('T', 'V')),
        'study_training_ready': False, 'main_packet_window_model_trained': False, 'final_attack_tests_run': 0,
        'limitations': ['Metadata-based observed identity consistency is not OS socket ground truth; whole-key unresolved quarantine and taint propagation remain conservative.',
                        'The unchanged endpoint-key core still approximates ages/handshakes and can conflate incomplete tuple reuse. Metadata identities never become predictors.',
                        'v2 is a documented development eligibility revision after v1 failure, not blind preregistration.',
                        'Two blocks from one attack episode are not independent attack sessions. Independent final K remains unallocated.',
                        'Source/path confounding, sparse benign calibration, congestion/diversity/repetition and final freeze remain unfinished.'],
    }
    (ROOT/'results/development/public_partitioned_v2.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(report['retained_windows_by_role_and_y'], indent=2), flush=True)


if __name__ == '__main__':
    path, plan = declare()
    run(path, plan)
