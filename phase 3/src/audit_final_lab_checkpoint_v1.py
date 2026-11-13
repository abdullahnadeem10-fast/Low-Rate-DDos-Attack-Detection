"""Read-only checkpoint reconciliation; never collect, score, fit or tune.

Use after the collector exits. Requires the original private qualification and
capture bundles. Writes one new audit record and refuses an existing output.
This analysis utility is outside the immutable acquisition/model source set.
"""
import argparse
import csv
import json

from pathlib import Path
from audit_benign_session import frames
from frozen_suite import verify_freeze, authorize_qualification, validate_qualification
from packet_model_policy import ROOT, read, sha, require


def check(version, previous, new_units):
    require(version > previous >= 5, 'Expected a new checkpoint after v5')
    require(len(set(new_units)) == len(new_units) > 0, 'Distinct new unit IDs required')
    output = ROOT / f'results/final/final_lab_checkpoint_v{version}_audit.json'
    require(not output.exists(), 'Preserve existing audit; do not overwrite')
    require(not (ROOT / 'data/final_lab_v1/collection.lock').exists(), 'Collector still locked')
    frozen, gate = verify_freeze()
    for slot in ('lab_benign', 'lab_slow'):
        authorize_qualification(slot)
    seal = read(ROOT / 'results/qualification/final_lab_resolution_seal_v1.json')
    require(sha(ROOT / seal['path']) == seal['sha256'], 'Recovery seal changed')
    recovery = read(ROOT / seal['path'])
    for name, expected in recovery['source_sha256'].items():
        require(sha(ROOT / name) == expected, 'Recovery source changed')
    for key in ('original_ledger_snapshot', 'failure_evidence', 'validation'):
        item = recovery[key]
        require(sha(ROOT / item['path']) == item['sha256'], 'Recovery evidence changed')
    checkpoint_path = ROOT / f'results/final/final_lab_checkpoint_v{version}.json'
    summary = read(checkpoint_path)
    source = ROOT / f'src/summarize_final_lab_checkpoint_v{version}.py'
    require(sha(source) == summary['source_sha256'], 'Summary source changed')
    require(summary['freeze_sha256'] == gate['freeze_sha256'], 'Mixed freeze')
    table = ROOT / summary['case_summary_CSV']['path']
    require(sha(table) == summary['case_summary_CSV']['sha256'], 'CSV changed')
    old = read(ROOT / f'results/final/final_lab_checkpoint_v{previous}.json')
    old_audit = read(ROOT / f'results/final/final_lab_checkpoint_v{previous}_audit.json')
    require(sha(ROOT / f'results/final/final_lab_checkpoint_v{previous}.json') == old_audit['checkpoint_sha256'], 'Previous JSON changed')
    require(sha(ROOT / f'src/summarize_final_lab_checkpoint_v{previous}.py') == old['source_sha256'] == old_audit['source_sha256'], 'Previous source changed')
    require(sha(ROOT / old['case_summary_CSV']['path']) == old['case_summary_CSV']['sha256'] == old_audit['CSV_sha256'], 'Previous CSV changed')
    require(all(summary['result_sha256'].get(name) == expected for name, expected in old['result_sha256'].items()), 'Previously scored result fingerprint changed')
    units = [u for slot in ('lab_benign', 'lab_slow') for u in read(ROOT / f'plan/final_lab_{slot}_acquisition_v1.json')['planned_units']]
    units.sort(key=lambda u: u['run_order'])
    catalog = {u['id']: u for u in units}
    complete = {u['unit_id']: u for u in summary['units']}
    old_ids = {u['unit_id'] for u in old['units']}
    require(set(complete) - old_ids == set(new_units) and old_ids <= set(complete), 'Unexpected completed-unit delta')
    require([u['unit_id'] for u in summary['units']] == [u['id'] for u in units[:len(complete)]], 'Fixed catalog prefix changed')
    require(summary['completed_final_sessions'] == len(complete), 'Session count mismatch')
    require(summary['final_benign_completed'] == sum(u['kind'] == 'benign' for u in complete.values()), 'Benign count mismatch')
    require(summary['final_attack_completed'] == sum(u['kind'] == 'attack' for u in complete.values()), 'Attack count mismatch')
    require(summary['remaining_catalog_sessions'] == len(units) - len(complete), 'Remaining count mismatch')
    require(summary['next_catalog_unit'] == (units[len(complete)] if len(complete) < len(units) else None), 'Next unit mismatch')
    ledger = read(ROOT / 'results/qualification/final_lab_resolution_batch_v1.json')
    original = read(ROOT / 'results/qualification/final_lab_batch_v1.json')
    require(all(a['state'] == 'scored_all_cases' for a in ledger['attempts']) and not summary['unresolved_attempts'], 'Unresolved attempt retained; review before audit')
    audits = {a['unit_id']: a['audit'] for a in original['attempts'] + ledger['attempts'] if 'audit' in a}
    with table.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    cases = set(frozen['cases'])
    require(len(rows) == len(complete) * len(cases) == summary['case_summary_CSV']['rows'], 'CSV row count mismatch')
    require(len({(r['unit_id'], r['case_id']) for r in rows}) == len(rows), 'Duplicate CSV row')
    require({r['unit_id'] for r in rows} == set(complete), 'CSV unit mismatch')
    for uid, unit in complete.items():
        require(all(unit[k] == catalog[uid][k if k != 'unit_id' else 'id'] for k in ('unit_id', 'kind', 'condition', 'run_order')), 'Summary catalog metadata differs')
        path = f'results/final/{uid}.json'
        require(sha(ROOT / path) == summary['result_sha256'][path], 'Result bytes changed')
        result = read(ROOT / path)
        require(result['freeze_sha256'] == gate['freeze_sha256'], 'Result freeze differs')
        require(result['all_cases_completed'] and len(result['results']) == len(cases), 'Incomplete result')
        by_case = {v['case_id']: v for v in result['results']}
        require(set(by_case) == cases, 'Case set changed')
        directory = ROOT / 'data/final_lab_v1' / uid / 'qualified_v1'
        qpath = directory / ('qualification_recovery_v1.json' if (directory / 'qualification_recovery_v1.json').exists() else 'qualification.json')
        require(sha(qpath) == result['qualification_sha256'], 'Scored qualification changed')
        q = read(qpath)
        validate_qualification(q, frozen, gate['freeze_sha256'])
        raw_directory = ROOT / 'data/final_lab_v1' / uid
        require(sha(raw_directory / 'capture/traffic.pcap') == q['raw_sha256'] == read(raw_directory / 'session.json')['pcap_sha256'], 'Raw qualification/session capture hash differs')
        for item in [q['features'], q['ground_truth'], *q['qualification_evidence'].values()]:
            require(sha(ROOT / item['path']) == item['sha256'], 'Qualified input/evidence changed')
        selected = [r for r in rows if r['unit_id'] == uid]
        require({r['case_id'] for r in selected} == cases, 'CSV case set differs')
        for row in selected:
            value = by_case[row['case_id']]
            expected = dict(unit_id=uid, kind=unit['kind'], condition=unit['condition'], case_id=row['case_id'])
            for k in ('TP', 'FN', 'FP', 'TN', 'recall', 'fpr', 'excluded_known_positive', 'excluded_known_benign'):
                expected[k] = value['window_common'][k]
            for k in ('qualified_false_alert_starts', 'eligible_benign_seconds'):
                expected[k] = value['alert_burden'][k]
            expected.update(exact_scorable_episodes=value['episode_summary']['scorable_exact_episodes'], episode_hits=value['episode_summary']['hits'], episode_misses=value['episode_summary']['misses'], mean_penalty_coded_restricted_delay_seconds=value['episode_summary']['mean_penalty_coded_restricted_delay_seconds'])
            require(row == {k: '' if v is None else str(v) for k, v in expected.items()}, 'CSV cell differs from result')
        for phase, endpoints in unit['observed_load_and_service']['service_by_endpoint'].items():
            for endpoint in endpoints.values():
                require(sum(endpoint['failure_reason_counts'].values()) == endpoint['failed_or_skipped'], 'Failure reason sum differs')
                require(endpoint['timely_successes'] + endpoint['failed_or_skipped'] == endpoint['scheduled_slots'], 'Probe slots differ')
            for k in ('scheduled_slots', 'timely_successes', 'failed_or_skipped'):
                require(sum(e[k] for e in endpoints.values()) == audits[uid]['impact'][phase][k], 'Probe ledger differs')
        for method in ('hybrid', 'AE'):
            primary = by_case[f'main:{method}:7']
            require(unit['main'][method]['window'] == primary['window_common'], 'Primary window summary differs')
            for k in ('episodes', 'episode_summary', 'alert_burden'):
                require(unit['main'][method][k] == primary[k], 'Primary episode/burden summary differs')
    require(set(summary['result_sha256']) == {f'results/final/{uid}.json' for uid in complete}, 'Result proof set differs')
    for method in ('hybrid', 'AE'):
        for k in ('TP', 'FN', 'FP', 'TN'):
            require(sum(int(r[k]) for r in rows if r['case_id'] == f'main:{method}:7') == summary['primary_pooled_counts'][method][k], 'Pooled confusion sum differs')
        pooled = summary['primary_pooled_counts'][method]
        for numerator, denominator, key in [('FP', pooled['FP'] + pooled['TN'], 'observed_pooled_fpr'), ('TP', pooled['TP'] + pooled['FN'], 'observed_pooled_recall')]:
            require(pooled[key] == (pooled[numerator] / denominator if denominator else None), 'Pooled rate differs')
        for condition, cell in summary['benign_counts_by_condition'].items():
            for k in ('FP', 'TN'):
                require(sum(int(r[k]) for r in rows if r['case_id'] == f'main:{method}:7' and r['condition'] == condition) == cell[method][k], 'Benign condition sum differs')
    require(len(summary['attack_factor_coverage']) == 8, 'Attack factor coverage differs')
    for cell in summary['attack_factor_coverage']:
        ids = {u['id'] for u in units if u['kind'] == 'attack' and (u['condition'], u['sources'], u['connections'], u['interval']) == (cell['family'], cell['sources'], cell['connections_per_source'], cell['interval_seconds'])}
        require(len(ids) == cell['planned_trials'] == 5 and set(cell['scored_trial_ids']) == ids & set(complete) and set(cell['remaining_unscored_ids']) == ids - set(complete), 'Attack coverage IDs differ')
    for condition, cell in summary['benign_condition_coverage'].items():
        ids = {u['id'] for u in units if u['kind'] == 'benign' and u['condition'] == condition}
        require(len(ids) == cell['planned_trials'] == 5 and set(cell['scored_trial_ids']) == ids & set(complete), 'Benign coverage differs')
    attacks = [u for u in complete.values() if u['kind'] == 'attack']
    accounting = summary['attack_trial_accounting']
    expected_accounting = dict(completed_planned_trials=len(attacks), trials_with_observed_payload_onset=sum(u['main']['hybrid']['episode_summary']['total_recorded_episodes'] > 0 for u in attacks), no_corroborated_payload_trials=sum(u['qualification_exclusions'].get('no_corroborated_initial_payload', 0) for u in attacks), primary_exact_scorable_episodes=sum(u['main']['hybrid']['episode_summary']['scorable_exact_episodes'] for u in attacks), primary_censored_or_unscored_episodes=sum(u['main']['hybrid']['episode_summary']['unscored_or_censored_episodes'] for u in attacks))
    require(all(accounting[k] == v for k, v in expected_accounting.items()), 'Attack trial accounting differs')
    checks = []
    for uid in new_units:
        directory = ROOT / 'data/final_lab_v1' / uid
        raw = directory / 'capture/traffic.pcap'
        raw_sha = sha(raw)
        require(raw_sha == read(directory / 'session.json')['pcap_sha256'], 'Capture bytes changed')
        require(raw_sha == read(directory / 'qualified_v1/qualification_recovery_v1.json')['raw_sha256'], 'Qualified capture fingerprint differs')
        n = 0
        for timestamp, frame, wire in frames(raw):
            require(len(frame) == wire and 54 <= wire <= 1514 and frame[12:14] == b'\x08\x00' and frame[14] >> 4 == 4 and frame[23] == 6, 'Unexpected/truncated packet record')
            require(int.from_bytes(frame[20:22], 'big') & 0x3fff == 0, 'Fragmented record')
            n += 1
        require(n == audits[uid]['counts']['frames'] and audits[uid]['kernel_capture_drops'] == 0, 'Capture count/drop mismatch')
        checks.append(dict(unit=uid, pcap_sha256=raw_sha, frames=n, full_Ethernet_IPv4_TCP_records=True, MF_or_fragment_offset_nonzero=0))
    report = dict(checkpoint_sha256=sha(checkpoint_path), source_sha256=sha(source), CSV_sha256=sha(table), audit_source_sha256=sha(Path(__file__)), rows=len(rows), canonical_sessions=len(complete), cases_per_session=len(cases), all_result_hashes_match=True, all_CSV_cells_match_scored_results=True, all_CSV_confusion_and_condition_counts_match=True, all_private_qualification_input_evidence_hashes_match=True, probe_failure_reason_and_slot_counts_match_qualification_ledgers=True, factor_coverage_matches_fixed_catalog=True, previous_checkpoint_version=previous, previous_source_JSON_CSV_bytes_preserved=True, original_model_acquisition_recovery_seals_intact=True, new_capture_structural_checks=checks, unresolved_attempts=0, collector_lock_present=False, scope='Read-only actual data/hash/row/factor/probe/packet reconciliation. Previously passed 225 engineering checks remain on unchanged sealed sources; no fitting, tuning, recollection or public held-out access. Probe reason categories do not change criteria/counts. This audit does not establish model performance, independence or live latency.')
    return output, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', type=int, required=True)
    parser.add_argument('--previous', type=int, required=True)
    parser.add_argument('--new-units', nargs='+', required=True)
    args = parser.parse_args()
    output, report = check(args.version, args.previous, args.new_units)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(audit_pass=True, rows=report['rows'], sessions=report['canonical_sessions'], new_frames=sum(v['frames'] for v in report['new_capture_structural_checks']), audit_sha256=sha(output))))


if __name__ == '__main__':
    main()
