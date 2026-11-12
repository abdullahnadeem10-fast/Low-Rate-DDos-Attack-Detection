"""Add the independent but sparse CIC2019 V component to the exact input registry."""
from collections import defaultdict
import csv
import json
import math

from declare_cic2019_validation import ROOT
from download_cic2019_validation import sha
from summarize_study_development import timeline, distribution


def main():
    out = ROOT/'results/development'
    base_path, component_path = out/'study_development_manifest_v3.json', out/'cic2019_causal_v1.json'
    base, component = (json.loads(p.read_text(encoding='utf-8')) for p in (base_path, component_path))
    if not component['independent_attack_V_packet_component_available'] or sha(ROOT/component['plan']) != component['plan_sha256']:
        raise ValueError('Independent V component did not pass declared extraction')
    source_path = out/'cic2019_packet_inventory_v1.json'
    source = json.loads(source_path.read_text(encoding='utf-8'))
    plan = json.loads((ROOT/component['plan']).read_text(encoding='utf-8'))
    table = component['files']['model_windows.csv']
    groups = [dict(g) for g in base['groups']]
    groups.append({'id': component['group_id'], 'role': 'V', 'condition': component['condition'], 'source': 'CIC-DDoS2019_03-11',
                   'table': table['path'], 'sha256': table['sha256'], 'expected_rows': component['retained']['windows'],
                   'source_archive_sha256': source['archive_sha256'], 'packet_inventory_sha256': sha(source_path),
                   'raw_start': plan['raw_start'], 'raw_end': plan['raw_end'],
                   'group_unit': 'whole_provided_source_destination_stream', 'parent_recording': 'CIC-DDoS2019/03-11',
                   'expected_y': 1, 'packet_extraction_quality_accepted': True,
                   'onset_evidence': 'Count-corroborated current-window proxy; no exact onset or denial-impact claim.'})
    if len(groups) != 20 or len({g['id'] for g in groups}) != 20:
        raise ValueError('Unexpected whitelist/groups')
    predictors, metadata = base['predictor_columns'], base['metadata_columns_excluded_from_predictors']
    counts = {r: {'0': 0, '1': 0} for r in ('T', 'C1', 'C2', 'V')}
    descriptive = defaultdict(lambda: defaultdict(list))
    diagnostic = ['packets_in', 'packets_out', 'inbound_iat_mean', 'packet_length_mean',
                  'active_connections', 'unknown_age_connections', 'packet_rate_change', 'uncompleted_fraction']
    for g in groups:
        path = ROOT/g['table']
        if sha(path) != g['sha256']:
            raise ValueError('Input table changed: ' + g['id'])
        with path.open(newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if set(reader.fieldnames) != set(predictors + metadata):
                raise ValueError('Predictor/metadata schema changed')
            rows = list(reader)
        if len(rows) != g['expected_rows']:
            raise ValueError('Row count mismatch')
        for row in rows:
            if (row['session_id'], row['role'], row['condition'], int(row['y']), int(row['history_complete'])) != (g['id'], g['role'], g['condition'], g['expected_y'], 1):
                raise ValueError('Group/label/history mismatch')
            if any(not math.isfinite(float(row[f])) for f in predictors):
                raise ValueError('Non-finite model input')
            counts[g['role']][str(g['expected_y'])] += 1
            for feature in diagnostic:
                descriptive[g['source']+'/'+g['condition']+'/y='+str(g['expected_y'])][feature].append(float(row[feature]))
        g['timeline_coverage'] = timeline([int(r['utc_second']) for r in rows])
    evidence = [base_path, component_path, source_path, out/'cic2019_corroboration_v1.json', out/'cic2019_acquisition_v1.json']
    result = {
        'date': '2026-11-12', 'version': 'study_development_manifest_v4',
        'scope': 'Current engineering whitelist with preliminary independent SYN-labelled TCP/443 V component; not trained/final research results.',
        'source_evidence_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in evidence},
        'source_code_sha256': sha(ROOT/'src/summarize_study_v4.py'),
        'predictor_columns': predictors, 'metadata_columns_excluded_from_predictors': metadata,
        'ae_signed_predictor_columns': ['packet_rate_change'], 'ae_signed_column_indices': [predictors.index('packet_rate_change')],
        'groups': groups, 'windows_by_role_and_y': counts,
        'selected_lab_sessions': 12, 'public_benign_destination_groups': 6, 'known_attack_training_recordings': 1,
        'independent_attack_validation_recordings': 1, 'independent_attack_V_packet_component_available': True,
        'validation_coverage_adequate_for_headline_denial_or_generalization_claims': False,
        'reserved_known_final_candidate': 'Entire CIC-DDoS2019 01-12 payload/context/labels; unopened and unqualified.',
        'independent_final_K_qualified': False, 'reserved_slow_family_and_entire_external_source_unused': True,
        'study_training_ready': False, 'main_packet_window_model_trained': False, 'final_attack_tests_run': 0,
        'descriptive_feature_distributions': {group: {f: distribution(v) for f, v in values.items()} for group, values in descriptive.items()},
        'negative_history_preserved': base['negative_history_preserved'],
        'remaining_gates': ['Extend controlled-congestion, long-lived/diverse legitimate traffic and independent benign repetitions, retaining legitimate failures.',
                            'Review/expand known-validation representativeness; this 44-second TCP/443 slice is sparse and does not demonstrate functioning HTTPS or service denial.',
                            'Constrain class/service/path/source confounding and define missing-label/gap-aware full-rule calibration before fitting.',
                            'Fit matched branches/baselines, calibrate, freeze, then qualify/score reserved final data without tuning to test results.'],
    }
    (out/'study_development_manifest_v4.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(counts, indent=2), flush=True)


if __name__ == '__main__':
    main()
