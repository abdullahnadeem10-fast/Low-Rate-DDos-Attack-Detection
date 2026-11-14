"""Export complete-lab descriptive tables from an audited frozen checkpoint.

Reads only published result evidence, never raw datasets, models or scores.
Preserves all configurations; primary seed 7 is displayed without selection.
"""
import csv
import json
from collections import defaultdict
from pathlib import Path

from packet_model_policy import ROOT, read, sha, require


INTEGER_COLUMNS = ('TP', 'FN', 'FP', 'TN', 'excluded_known_positive',
                   'excluded_known_benign', 'qualified_false_alert_starts',
                   'eligible_benign_seconds', 'exact_scorable_episodes',
                   'episode_hits', 'episode_misses')


def aggregate(rows):
    counts = {key: sum(int(r[key]) for r in rows) for key in INTEGER_COLUMNS}
    require(len({r['unit_id'] for r in rows}) == len(rows), 'Duplicate unit within case/stratum')
    n = counts['exact_scorable_episodes']
    delays = []
    for row in rows:
        episodes = int(row['exact_scorable_episodes'])
        value = row['mean_penalty_coded_restricted_delay_seconds']
        require((value != '') == (episodes > 0), 'Missing or unsupported restricted delay')
        if episodes:
            delays.append(float(value) * episodes)
    tp, fn, fp, tn = (counts[k] for k in ('TP', 'FN', 'FP', 'TN'))
    return dict(sessions=len(rows), **counts,
                recall=tp / (tp + fn) if tp + fn else None,
                fpr=fp / (fp + tn) if fp + tn else None,
                precision=tp / (tp + fp) if tp + fp else None,
                f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
                false_alert_starts_per_hour=counts['qualified_false_alert_starts'] * 3600 / counts['eligible_benign_seconds'] if counts['eligible_benign_seconds'] else None,
                episode_recall=counts['episode_hits'] / n if n else None,
                miss_inclusive_mean_restricted_delay_seconds=sum(delays) / n if n else None)


def write_csv(path, rows):
    with path.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def percentage(value):
    return 'N/A' if value is None else f'{100 * value:.2f}%'


def main():
    summary_path = ROOT / 'results/final/final_lab_checkpoint_v8.json'
    audit_path = ROOT / 'results/final/final_lab_checkpoint_v8_audit.json'
    totals_path = ROOT / 'results/final/final_lab_case_totals_v2.csv'
    strata_path = ROOT / 'results/final/final_lab_case_strata_v2.csv'
    manifest_path = ROOT / 'results/final/final_lab_results_v2.json'
    report_path = ROOT / 'plan/FINAL_LAB_RESULTS_V2.md'
    require(not any(p.exists() for p in (totals_path, strata_path, manifest_path, report_path)), 'Preserve completed report; use a new version')
    summary, audit = read(summary_path), read(audit_path)
    require(sha(summary_path) == audit['checkpoint_sha256'], 'Checkpoint bytes changed')
    require(summary['lab_catalog_complete'] and summary['completed_final_sessions'] == 60 and summary['final_benign_completed'] == 20 and summary['final_attack_completed'] == 40 and not summary['unresolved_attempts'], 'Complete qualified/scored catalog required')
    require(not summary['headline_generalization_readiness'], 'Do not promote lab completion to headline readiness')
    table = ROOT / summary['case_summary_CSV']['path']
    require(sha(table) == summary['case_summary_CSV']['sha256'] == audit['CSV_sha256'], 'Audited CSV changed')
    with table.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == 7020 and len({(r['unit_id'], r['case_id']) for r in rows}) == 7020, 'Unexpected full-catalog rows')
    units = {u['unit_id']: u for u in summary['units']}
    by_case, by_stratum = defaultdict(list), defaultdict(list)
    for row in rows:
        unit = units[row['unit_id']]
        factors = unit['factors']
        key = (row['case_id'], unit['kind'], unit['condition'], factors['sources'], factors['connections'], factors['interval'])
        by_case[row['case_id']].append(row)
        by_stratum[key].append(row)
    require(len(by_case) == 117 and len(by_stratum) == 117 * 12, 'Unexpected case or stratum coverage')
    totals = [dict(case_id=case, **aggregate(values)) for case, values in sorted(by_case.items())]
    strata = []
    for (case, kind, condition, sources, connections, interval), values in sorted(by_stratum.items(), key=lambda item: str(item[0])):
        require(len(values) == 5, 'Five fixed repetitions per cell required')
        strata.append(dict(case_id=case, kind=kind, condition=condition, sources=sources, connections_per_source=connections, interval_seconds=interval, **aggregate(values)))
    for total in totals:
        require(total['sessions'] == 60, 'Incomplete case total')
        selected = [s for s in strata if s['case_id'] == total['case_id']]
        for key in INTEGER_COLUMNS:
            require(sum(s[key] for s in selected) == total[key], 'Stratum and total counts differ')
    total_lookup = {r['case_id']: r for r in totals}
    for method in ('hybrid', 'AE'):
        require(all(total_lookup[f'main:{method}:7'][k] == summary['primary_pooled_counts'][method][k] for k in ('TP', 'FN', 'FP', 'TN')), 'Primary totals differ')
    write_csv(totals_path, totals)
    write_csv(strata_path, strata)
    lines = ['# Complete frozen lab results — v2', '',
             'All 60 declared same-host lab trials are qualified and scored: 20 benign sessions and 40 controlled campaigns, 117 configurations per session (7,020 case/session evaluations). All eight campaign cells and four benign conditions have five repetitions. This completes the lab catalog; public-source transfer and separate feature/inference/live-latency measurements remain pending.', '',
             'These are descriptive measurements on this host and acquisition design. Windows and algorithm seeds are not independent recordings or environments. No thresholds, models, seeds or trial order were changed from final outcomes. Campaign exposure does not prove denial or resource exhaustion. Detector delays are offline window-end plus one-second reorder proxies. Failed service probes include HTTP/socket/read errors and skips, not only elapsed-deadline overruns; latency quantiles condition on success.', '',
             'An interrupted setup was archived before schedule release; seven agents failed at the schedule gate with no research logs or HTTP records. A separately sealed continuation retained every prior result and ran the original remaining entries without changing settings or seeds. The preserved setup is engineering history, not an additional independent trial. The host/engine restart is disclosed.', '',
             '## Prespecified primary seed and matched baselines', '',
             '| Method (seed 7) | TP / eligible positive | FP / eligible benign | Recall | FPR | Eligible episodes hit | Miss-inclusive restricted delay |',
             '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for case in ['main:rate:7', 'main:LR:7', 'main:RF:7', 'main:IF:7', 'main:HGB:7', 'main:AE:7', 'main:hybrid:7']:
        r = total_lookup[case]
        delay = r['miss_inclusive_mean_restricted_delay_seconds']
        lines.append(f"| {case.split(':')[1]} | {r['TP']}/{r['TP'] + r['FN']} | {r['FP']}/{r['FP'] + r['TN']} | {percentage(r['recall'])} | {percentage(r['fpr'])} | {r['episode_hits']}/{r['exact_scorable_episodes']} | {delay:.2f}s |" if delay is not None else f"| {case.split(':')[1]} | {r['TP']}/{r['TP'] + r['FN']} | {r['FP']}/{r['FP'] + r['TN']} | {percentage(r['recall'])} | {percentage(r['fpr'])} | {r['episode_hits']}/{r['exact_scorable_episodes']} | N/A |")
    lines.extend(['', 'Miss-inclusive restricted delays retain fully observed misses at the frozen 180-second limit; they are not detected-only medians or measured live latency. Preserve all unscorable/censored episodes and known-label exclusions in the source evidence. An episode hit does not erase missed positive windows, preexisting alarms or false-positive occupancy.', '',
                  '## Primary hybrid and AE by declared stratum', '',
                  '| Condition / profile (five trials each) | Hybrid TP or FP / support | AE TP or FP / support |',
                  '| --- | ---: | ---: |'])
    primary_strata = [r for r in strata if r['case_id'] == 'main:hybrid:7']
    for r in primary_strata:
        other = next(v for v in strata if v['case_id'] == 'main:AE:7' and all(v[k] == r[k] for k in ('kind', 'condition', 'sources', 'connections_per_source', 'interval_seconds')))
        label = r['condition'] if r['kind'] == 'benign' else f"{r['condition']}, {r['sources']} source(s), {r['connections_per_source']} connections/source, {r['interval_seconds']}s"
        num, extra = ('TP', 'FN') if r['kind'] == 'attack' else ('FP', 'TN')
        lines.append(f"| {label} | {num} {r[num]}/{r[num] + r[extra]} | {num} {other[num]}/{other[num] + other[extra]} |")
    lines.extend(['', '## Evidence and interpretation', '',
                  'All 117 configurations, controls, ablations and prescribed seeds remain in `../results/final/final_lab_case_totals_v2.csv` and `final_lab_case_strata_v2.csv`; no best-performing variant was selected. Totals are sums of eligible counts; pooled rates reflect the declared mixture. False-alert starts/hour remain distinct from false-positive window rates. Every stratum total reconciles with the all-session total. See `final_lab_results_v2.json` for source hashes and the exact frozen paired-parent uncertainty output.', '',
                  'Any available paired-parent intervals resample observed recordings within declared strata and average algorithm seeds inside sessions. They describe conditional same-host session variability; they do not establish independent-domain transfer, a population FPR guarantee or hybrid superiority. Preserve negative findings, healthy-service/ineffective campaigns and any missing/censored outcomes.', '',
                  'Complete public Wednesday slow/context, supplied CIC2019 01-12 and CSE-CIC-IDS2018 remain unopened/unqualified. Friday stays development T and 03-11 V. Final lab raw/context/warmup remains excluded from development/calibration. Later model redesign requires separate development and new independent final evidence.', ''])
    with report_path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write('\n'.join(lines))
    manifest = dict(version='final_lab_results_v2', source_sha256=sha(Path(__file__)), checkpoint_path=summary_path.relative_to(ROOT).as_posix(), checkpoint_sha256=sha(summary_path), checkpoint_audit_sha256=sha(audit_path), input_CSV_sha256=sha(table), total_case_rows=len(totals), stratum_case_rows=len(strata), canonical_sessions=60, case_session_evaluations=7020, all_strata_reconcile_to_totals=True, lab_catalog_complete=True, study_tests_complete=False, headline_generalization_readiness=False, primary_seed=7, matched_primary_cases={k: v for k, v in total_lookup.items() if k.startswith('main:') and k.endswith(':7')}, preserved_pre_schedule_interruption=summary['preserved_pre_schedule_interruption'], uncertainty=summary['uncertainty'], uncertainty_interpretation=summary['uncertainty_interpretation'], scope='Descriptive frozen same-host lab catalog. No fitting, tuning, new evaluation rule, variant promotion, live-latency, population, denial-efficacy or independent-domain claim.', artifacts={path.relative_to(ROOT).as_posix(): sha(path) for path in (totals_path, strata_path, report_path)})
    with manifest_path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(report_complete=True, total_case_rows=len(totals), stratum_case_rows=len(strata), manifest_sha256=sha(manifest_path))))


if __name__ == '__main__':
    main()
