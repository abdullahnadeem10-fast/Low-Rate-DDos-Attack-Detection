"""Whitelist public/lab development tables and expose coverage/confounding limits.

Descriptive development evidence only. Does not fit a model, infer idle labels,
compress timelines for persistence, or touch any final source.
"""
from collections import Counter, defaultdict
import csv
import json
import math

from declare_public_partitions import ROOT, digest


def timeline(seconds):
    values = sorted(seconds)
    if len(values) != len(set(values)):
        raise ValueError('Duplicated second within a group')
    runs, current = [], 0
    previous = None
    for sec in values:
        if previous is None or sec == previous + 1:
            current += 1
        else:
            runs.append(current)
            current = 1
        previous = sec
    if current:
        runs.append(current)
    return {'labelled_runs': len(runs), 'longest_consecutive_labelled_run_seconds': max(runs, default=0),
            'gaps_between_retained_rows': max(0, len(runs) - 1)}


def distribution(values):
    values = sorted(values)
    if not values:
        return {'n': 0}
    def q(f):
        pos = (len(values) - 1) * f
        lo, hi = math.floor(pos), math.ceil(pos)
        return values[lo] + (values[hi] - values[lo]) * (pos - lo)
    return {'n': len(values), 'p10': q(.1), 'median': q(.5), 'p90': q(.9),
            'zero_fraction': sum(v == 0 for v in values) / len(values)}


def main():
    out = ROOT/'results/development'
    public_path, lab_path = out/'public_partitioned_v1.json', out/'benign_batch_v3.json'
    public, lab = (json.loads(p.read_text()) for p in (public_path, lab_path))
    fragment_path = out/'public_fragment_attribution_v1.json'
    fragment = json.loads(fragment_path.read_text()) if fragment_path.exists() else None
    fragment_override = bool(fragment and fragment['replay_evidence_sha256'] == digest(public_path)
                             and fragment['all_flagged_fragments_proven_non_tcp'])
    late_drops = sum(p['packet_counts'].get('late_selected_dropped', 0) for p in public['partitions'])
    public_packet_quality = bool(not public['decode_errors_all_capture'] and not late_drops
                                 and (public['feature_engineering_quality_passed'] or fragment_override))
    if public['plan_sha256'] != digest(ROOT/public['plan']):
        raise ValueError('Declared plan bytes changed')
    predictors = public['predictor_columns']
    metadata = public['metadata_columns_excluded_from_predictors']
    groups = []
    for p in public['partitions']:
        table = p['files']['model_windows.csv']
        groups.append({'id': p['id'], 'role': p['role'], 'condition': p['condition'], 'source': 'Friday_public',
                       'table': table['relative_path'], 'sha256': table['sha256'], 'expected_rows': p['retained']['windows'],
                       'capture_sha256': public['capture_sha256'], 'raw_start': p['raw_start'], 'raw_end': p['raw_end'],
                       'group_unit': p['kind'], 'expected_y': p['y'],
                       'packet_extraction_quality_accepted': public_packet_quality})
    for p in lab['sessions']:
        groups.append({'id': p['session'], 'role': p['role'], 'condition': p['condition'], 'source': 'lab_benign_v3',
                       'table': p['relative_session_path'] + '/model_windows.csv', 'sha256': p['model_windows_sha256'],
                       'expected_rows': p['model_windows'], 'capture_sha256': p['capture_sha256'],
                       'group_unit': 'whole_fresh_lab_session', 'expected_y': 0,
                       'packet_extraction_quality_accepted': True})
    if len({g['id'] for g in groups}) != len(groups):
        raise ValueError('Duplicate group ID')
    counts = defaultdict(Counter)
    descriptive = defaultdict(lambda: defaultdict(list))
    diagnostics = ['packets_in', 'packets_out', 'inbound_iat_mean', 'packet_length_mean', 'active_connections',
                   'unknown_age_connections', 'packet_rate_change', 'uncompleted_fraction']
    for g in groups:
        path = ROOT/g['table']
        if digest(path) != g['sha256']:
            raise ValueError('Table bytes changed: ' + g['id'])
        with path.open(newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if set(reader.fieldnames) != set(predictors + metadata):
                raise ValueError('Predictor/metadata schema mismatch')
            rows = list(reader)
        if len(rows) != g['expected_rows']:
            raise ValueError('Row count changed')
        for r in rows:
            if (r['session_id'], r['role'], r['condition'], int(r['y']), int(r['history_complete'])) != (g['id'], g['role'], g['condition'], g['expected_y'], 1):
                raise ValueError('Wrong group, role, label or incomplete history')
            if any(not math.isfinite(float(r[f])) for f in predictors):
                raise ValueError('Non-finite model input')
            counts[g['role']][str(g['expected_y'])] += 1
            for feature in diagnostics:
                descriptive[g['source'] + '/' + g['condition'] + '/y=' + str(g['expected_y'])][feature].append(float(r[feature]))
        g['timeline_coverage'] = timeline([int(r['utc_second']) for r in rows])
    result = {
        'date': '2026-11-12', 'version': 'study_development_manifest_v1',
        'scope': 'Exact engineering-table registry with explicit quality status, not a training/final-research release.',
        'source_evidence_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): digest(p) for p in [public_path, lab_path, out/'benign_development_manifest.json'] + ([fragment_path] if fragment else [])},
        'source_code_sha256': digest(ROOT/'src/summarize_study_development.py'),
        'predictor_columns': predictors, 'metadata_columns_excluded_from_predictors': metadata,
        'ae_signed_predictor_columns': ['packet_rate_change'], 'ae_signed_column_indices': [predictors.index('packet_rate_change')],
        'groups': groups, 'windows_by_role_and_y': dict(counts),
        'selected_lab_sessions': len(lab['sessions']), 'public_destination_groups': 6, 'public_attack_blocks': 2,
        'public_known_attack_episodes': 1, 'final_known_attack_K_allocated': False,
        'original_public_replay_quality_flag': public['feature_engineering_quality_passed'],
        'public_packet_quality_after_independent_fragment_attribution': public_packet_quality,
        'public_known_attack_component_has_retained_labels': any(g['expected_y'] == 1 and g['expected_rows'] > 0 for g in groups),
        'study_training_ready': False, 'main_packet_window_model_trained': False, 'final_attack_tests_run': 0,
        'reserved_slow_family_and_entire_external_source_unused': True,
        'descriptive_feature_distributions': {group: {f: distribution(v) for f, v in data.items()} for group, data in descriptive.items()},
        'interpretation': [
            'Table counts are correlated windows; six destinations and two blocks do not create independent attack episodes.',
            'All public attack labels occur on one local service, while public benign labels occur on external services. Lab development contains benign traffic only. Class is therefore confounded with service/path and source environment.',
            'No matching target-benign comparison, causal service/path effect estimate or cross-environment generalization is established.',
            'Nonempty count-corroborated public benign seconds are selected observations. Idle and uncertain seconds remain unknown.',
            'Public calibration rows are sparse. C2 persistence must run on full chronological features and account for unknown evaluation labels; never treat adjacent CSV rows as adjacent seconds.',
            'Observed-connection quarantine may remove all attack labels. Do not relax it after seeing detector outcomes; any revised allocation/control requires a new declared version.'],
        'remaining_gates': [
            'Review retained/excluded public coverage and connection quarantine; establish sufficient safe known-attack development and independent final K groups.',
            'Resolve or explicitly constrain service/path/source confounding before interpreting detection efficacy.',
            'Add controlled congestion, long-lived/diverse legitimate traffic and independent benign repetitions with failed legitimate requests retained.',
            'Prespecify a gap-aware timeline calibration policy and evaluate empirical uncertainty for sparse public C1/C2 coverage.',
            'Only then fit matched packet-window branches/baselines, calibrate and freeze before reserved final tests.'],
        'engineering_findings': ['Initial replay startup assumed PCAP from the filename and stopped before outputs; header detection was corrected to support PCAPNG and regression-tested.',
                                 'Conservative replay fragment flag covers every IPv4 protocol touching service IPs. The independent attribution report preserves this negative flag and checks whether the frames are actually TCP.',
                                 'Unknown/ambiguous-start influence excluded every candidate attack-labelled row in both declared blocks; no supervised attack development component is accepted.'],
    }
    target = out/'study_development_manifest_v1.json'
    target.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: result[k] for k in ('selected_lab_sessions', 'public_destination_groups', 'public_attack_blocks', 'windows_by_role_and_y', 'study_training_ready')}, indent=2))


if __name__ == '__main__':
    main()
