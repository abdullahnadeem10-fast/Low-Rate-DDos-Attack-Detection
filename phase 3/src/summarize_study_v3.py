"""Current engineering-table registry: complete Friday target belongs to T only."""
from collections import defaultdict
import csv
import json
import math

from declare_public_partitions import ROOT, digest
from summarize_study_development import timeline, distribution


def run():
    out = ROOT/'results/development'
    public_path = out/'public_partitioned_v3.json'
    base_path = out/'study_development_manifest_v1.json'
    public, base = (json.loads(p.read_text(encoding='utf-8')) for p in (public_path, base_path))
    if digest(ROOT/public['plan']) != public['plan_sha256']:
        raise ValueError('Whole-capture declaration changed')
    # Retain only the six unchanged public benign and twelve canonical lab
    # groups. Never carry either zero-row temporal attack block into this version.
    groups = [dict(g) for g in base['groups'] if g['expected_y'] == 0]
    p = next(p for p in public['partitions'] if p['kind'] == 'whole_capture_attack_destination')
    table = p['files']['model_windows.csv']
    groups.append({'id': p['id'], 'role': p['role'], 'condition': p['condition'], 'source': 'Friday_public',
                   'table': table['relative_path'], 'sha256': table['sha256'], 'expected_rows': p['retained']['windows'],
                   'capture_sha256': public['capture_sha256'], 'raw_start': p['raw_start'], 'raw_end': p['raw_end'],
                   'group_unit': 'whole_capture_attack_destination', 'expected_y': 1,
                   'packet_extraction_quality_accepted': True})
    if len(groups) != 19 or len({g['id'] for g in groups}) != 19:
        raise ValueError('Unexpected whitelist or duplicate groups')
    predictors, metadata = public['predictor_columns'], public['metadata_columns_excluded_from_predictors']
    counts = {r: {'0': 0, '1': 0} for r in ('T', 'C1', 'C2', 'V')}
    descriptive = defaultdict(lambda: defaultdict(list))
    diagnostics = ['packets_in', 'packets_out', 'inbound_iat_mean', 'packet_length_mean',
                   'active_connections', 'unknown_age_connections', 'packet_rate_change', 'uncompleted_fraction']
    for g in groups:
        path = ROOT/g['table']
        if digest(path) != g['sha256']:
            raise ValueError('Model input bytes changed: ' + g['id'])
        with path.open(newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if set(reader.fieldnames) != set(predictors + metadata):
                raise ValueError('Feature/metadata schema changed')
            rows = list(reader)
        if len(rows) != g['expected_rows']:
            raise ValueError('Unexpected row count')
        for row in rows:
            if (row['session_id'], row['role'], row['condition'], int(row['y']), int(row['history_complete'])) != (g['id'], g['role'], g['condition'], g['expected_y'], 1):
                raise ValueError('Wrong group/role/label/history')
            if any(not math.isfinite(float(row[f])) for f in predictors):
                raise ValueError('Non-finite feature')
            counts[g['role']][str(g['expected_y'])] += 1
            for feature in diagnostics:
                descriptive[g['source'] + '/' + g['condition'] + '/y=' + str(g['expected_y'])][feature].append(float(row[feature]))
        g['timeline_coverage'] = timeline([int(r['utc_second']) for r in rows])
    evidence = [public_path, base_path, out/'benign_batch_v3.json', out/'tcp_boundary_audit_v1.json', out/'public_partitioned_v2.json']
    result = {
        'date': '2026-11-12', 'version': 'study_development_manifest_v3',
        'scope': 'Current engineering whitelist with whole-target supervised T component; independent attack V and final K unfinished.',
        'source_evidence_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): digest(p) for p in evidence},
        'source_code_sha256': digest(ROOT/'src/summarize_study_v3.py'),
        'predictor_columns': predictors, 'metadata_columns_excluded_from_predictors': metadata,
        'ae_signed_predictor_columns': ['packet_rate_change'], 'ae_signed_column_indices': [predictors.index('packet_rate_change')],
        'groups': groups, 'windows_by_role_and_y': counts,
        'selected_lab_sessions': 12, 'public_benign_destination_groups': 6, 'whole_public_attack_training_groups': 1,
        'supervised_T_positive_component_available': counts['T']['1'] > 0,
        'independent_attack_V_available': False, 'independent_final_K_allocated': False,
        'study_training_ready': False, 'main_packet_window_model_trained': False, 'final_attack_tests_run': 0,
        'reserved_slow_family_and_entire_external_source_unused': True,
        'descriptive_feature_distributions': {group: {f: distribution(values) for f, values in data.items()} for group, data in descriptive.items()},
        'negative_history_preserved': ['public_partitions_v1: zero retained temporal-block attack rows',
                                       'public_partitions_v2: zero retained rows after full TCP identity and unsafe-state propagation checks'],
        'remaining_gates': ['Acquire/audit a distinct permitted known TCP-denial capture for attack V; allocate independent final K before opening final tests.',
                            'Constrain class/service/path/source confounding; one Friday training episode is not independent replication.',
                            'Extend controlled-congestion, long-lived/diverse legitimate traffic and independent benign repetitions; retain legitimate failures.',
                            'Use complete timelines and a prespecified missing-label policy for C2 persistence, then fit/calibrate/freeze matched models.'],
        'index_timing_note': 'Index elapsed counter jumped between progress checkpoints; the recorded 47062.551 seconds is execution bookkeeping, not a throughput/runtime benchmark.',
    }
    (out/'study_development_manifest_v3.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(counts, indent=2), flush=True)


if __name__ == '__main__':
    run()
