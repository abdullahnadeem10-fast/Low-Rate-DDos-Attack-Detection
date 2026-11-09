"""Check replay/label consistency and record readiness, without fitting any model.

Labels describe only seconds with packet-count corroboration in the allowlisted
CSV envelope. A missing label, including an empty second, is never benign by default.
"""
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'results/development'


def sha256(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def assess(features, labels):
    """Fail on inconsistent counts/schema; retain uncertainty in readiness counts."""
    with labels.open(newline='', encoding='utf-8') as f:
        evidence = {}
        for row in csv.DictReader(f):
            second = int(row['utc_second'])
            if second in evidence:
                raise ValueError('Duplicate label second')
            if row['status'] not in ('attack_present', 'benign_only', 'uncertain'):
                raise ValueError('Unknown label status')
            evidence[second] = row
    counts = Counter()
    by_status = Counter()
    warmed = Counter()
    ranges = {}
    previous = None
    with features.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        names = reader.fieldnames
        if not names or 'utc_second' not in names or 'history_complete' not in names:
            raise ValueError('Missing feature metadata')
        predictors = [n for n in names if n not in ('utc_second', 'history_complete')]
        if len(predictors) != 30:
            raise ValueError('Unexpected feature schema')
        for row in reader:
            second = int(row['utc_second'])
            if previous is not None and second != previous + 1:
                raise ValueError('Replay seconds are not contiguous')
            previous = second
            if row['history_complete'] not in ('0', '1'):
                raise ValueError('Invalid history flag')
            if any(not math.isfinite(float(row[n])) for n in predictors):
                raise ValueError('Non-finite feature')
            counts['windows'] += 1
            packet_count = int(row['packets_in']) + int(row['packets_out'])
            counts['packets_in_emitted_windows'] += packet_count
            counts['empty_windows'] += int(packet_count == 0)
            label = evidence.get(second)
            if label is None:
                status = 'not_labelled'
            else:
                counts['overlapping_label_seconds'] += 1
                if packet_count != int(label['packets']):
                    raise ValueError(f'Packet count disagreement at second {second}')
                parts = sum(int(label[n]) for n in (
                    'verified_benign_packets', 'verified_attack_packets', 'uncorroborated_packets'))
                if parts != packet_count:
                    raise ValueError('Label evidence packet totals disagree')
                status = label['status']
                if status == 'benign_only' and (int(label['uncorroborated_packets']) or
                                               int(label['verified_attack_packets'])):
                    raise ValueError('Invalid benign-only evidence')
                if status == 'attack_present' and not int(label['verified_attack_packets']):
                    raise ValueError('Attack status lacks corroborating packets')
            by_status[status] += 1
            if row['history_complete'] == '1':
                warmed[status] += 1
            if status not in ranges:
                ranges[status] = {'first_utc_second': second, 'last_utc_second': second}
            ranges[status]['last_utc_second'] = second
    if not counts['windows']:
        raise ValueError('Empty feature table')
    return {'counts': dict(counts), 'predictors': predictors,
            'window_status': dict(by_status), 'fully_warmed_window_status': dict(warmed),
            'status_extent_not_continuous_intervals': ranges,
            'consistency': 'All overlapping per-second packet totals agree.',
            'training_ready': False,
            'blocking_work': [
                'Acquire and audit compatible benign target-service traffic: this Friday label member may provide no fully corroborated benign-only windows; unlabelled idle time is not a negative class.',
                'Reset connection/history state at declared development split boundaries and audit cross-boundary keys.',
                'Audit whether corroborated-label coverage supplies adequate independent benign/attack sessions; do not select solely easy labelled windows.',
                'Define treatment of uncertain/unlabelled/idle windows before model fitting; do not infer benign from silence.',
                'Collect separate benign ordinary/stress development sessions before full alert calibration and freeze.'
            ],
            'limitations': [
                'Count corroboration is not independent packet ground truth or exact attack-onset timing.',
                'Continuous capture features are engineering evidence; no split-safe final model has been fitted.',
                'Known flooding development data cannot establish slow-family or distributed low-rate detection.'
            ]}


def main():
    features = ROOT / 'data/development/friday_causal_windows.csv'
    labels = OUT / 'friday_service_corroborated_labels.csv'
    result = assess(features, labels)
    result['feature_table_sha256'] = sha256(features)
    result['label_table_sha256'] = sha256(labels)
    (OUT / 'friday_packet_readiness.json').write_text(
        json.dumps(result, indent=2) + '\n', encoding='utf-8')
    source = json.loads((ROOT / 'data/development/Friday-WorkingHours.source.json').read_text())
    audit = json.loads((OUT / 'friday_packet_audit.json').read_text())
    manifest = {
        'date': '2026-11-09', 'role': 'Known-family development only',
        'capture': {**source, 'relative_path': 'data/development/Friday-WorkingHours.pcap'},
        'labels': {'archive_sha256': '7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a',
                   'member_opened': audit['labels_opened'],
                   'clock_offset_seconds': audit['offset_seconds'],
                   'precision': 'Minute-only start timestamps; possible intervals, not exact starts.',
                   'mapping': 'Private endpoint/port identity with canonical bidirectional tuples; no NAT substitution inferred.'},
        'service': '192.168.10.50:80',
        'feature_table': {'relative_path': str(features.relative_to(ROOT)).replace('\\', '/'),
                          'sha256': result['feature_table_sha256'], 'windows': result['counts']['windows']},
        'split_state': 'Not allocated: continuous replay must not be used as a split-safe training table.',
        'reserved_data': {'CICIDS2017_slow_families': 'No raw capture fetched; no slow-family label member opened.',
                          'CSE_CIC_IDS2018_entire_source': 'Not fetched or used.'},
        'next_action': result['blocking_work'][0]
    }
    (OUT / 'development_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
