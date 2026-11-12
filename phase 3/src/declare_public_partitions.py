"""Declare development groups before public feature creation; never allocate final data.

Coverage is previously inspected label-quality evidence, not a blind preregistration.
No packet-window model or scores participate in this allocation.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def second(clock):
    return int(datetime.fromisoformat('2017-07-07T' + clock).replace(tzinfo=timezone.utc).timestamp())


def build():
    audit_path = ROOT/'results/development/friday_public_http_audit.json'
    audit = json.loads(audit_path.read_text())
    readiness = json.loads((ROOT/'results/development/friday_packet_readiness.json').read_text())
    candidates = sorted(audit['services'], key=lambda s: (-s['nonempty_second_status'].get('benign_only', 0), s['service']))
    eligible = [s for s in candidates if s['nonempty_second_status'].get('benign_only', 0) >= 50]
    if len(eligible) != 6:
        raise ValueError('Reviewed allocation expects six services; declare a new plan if inventory changes')
    blocks = []
    for s, role in zip(eligible, ('T', 'C1', 'C2', 'T', 'V', 'V'), strict=True):
        blocks.append({
            'id': 'friday-http-' + s['service'].replace('.', '-').replace(':', '-'),
            'service': s['service'], 'role': role, 'condition': 'public_http', 'kind': 'benign_destination',
            'raw_start': second('18:25:00'), 'raw_end': second('20:02:40'),
            'eligible_start': second('18:30:00'), 'eligible_end': second('20:01:50'),
            'label_table': s['label_table_relative_path'], 'label_sha256': s['label_table_sha256'],
            'accepted_status': 'benign_only', 'y': 0,
            'prior_corroborated_seconds': s['nonempty_second_status']['benign_only'],
        })
    for role, start, end in (('T', '18:56:00', '19:04:00'), ('V', '19:06:00', '19:16:00')):
        a, b = second(start), second(end)
        blocks.append({
            'id': 'friday-ddos-' + role.lower(), 'service': '192.168.10.50:80',
            'role': role, 'condition': 'public_known_ddos', 'kind': 'attack_block',
            'raw_start': a, 'raw_end': b, 'eligible_start': a + 50, 'eligible_end': b - 50,
            'label_table': 'results/development/friday_service_corroborated_labels.csv',
            'label_sha256': readiness['label_table_sha256'], 'accepted_status': 'attack_present', 'y': 1,
        })
    for b in blocks:
        if digest(ROOT/b['label_table']) != b['label_sha256']:
            raise ValueError('Label table hash mismatch: ' + b['id'])
    return {
        'version': 'public_partitions_v1', 'date': '2026-11-12',
        'scope': 'Permitted Friday development only; no final K/U or external allocation.',
        'allocation_basis': 'Previously inspected label-quality coverage >=50 nonempty benign seconds; descending coverage roles T,C1,C2,T,V,V. Not model-score selection or blind preregistration.',
        'capture': {'path': 'data/development/Friday-WorkingHours.pcap', 'bytes': 8839309056,
                    'sha256': audit['capture_sha256'], 'expected_frames': 9997874},
        'evidence': {str(p.relative_to(ROOT)).replace('\\', '/'): digest(p) for p in (
            audit_path, ROOT/'results/development/friday_packet_readiness.json',
            ROOT/'results/development/benign_batch_v3.json', ROOT/'results/development/benign_development_manifest.json')},
        'feature_core': {'path': 'src/causal_features.py', 'sha256': digest(ROOT/'src/causal_features.py')},
        'reorder_seconds': 1, 'timeout_seconds': 30, 'history_seconds': 20,
        'connection_influence_guard_seconds': 50, 'blocks': blocks,
        'excluded_sparse_services': [s['service'] for s in candidates if s not in eligible],
        'boundary_policy': 'Half-open integer UTC blocks; fresh core per block, all raw service packets before any label/mask selection. Same-service blocks separated by 120 seconds plus observed-connection quarantine.',
        'connection_policy': 'Sliced attack blocks exclude unknown/ambiguous-start influence through 50 seconds after each event and all influence of a shared initiating-SYN fingerprint. Benign destinations are wholly assigned to one role; unknown ages are retained there.',
        'lab_selection': 'results/development/benign_batch_v3.json',
        'final_known_attack_K': 'UNALLOCATED: independent source/episodes required. Friday has already been development-audited and auxiliary-scored.',
        'reserved': ['entire Slowloris/Slowhttptest groups and context', 'entire CSE-CIC-IDS2018 source including benign', 'all final lab sessions'],
        'limitations': ['One Friday attack episode split into blocks is not independent attack replication.',
                        'External benign endpoints versus local attacked service confound path/service with class.',
                        'Sparse nonempty benign labels cannot justify labelling intervening idle time benign or calibrating contiguous persistence from a compressed table.',
                        'Aggregate counts/minute envelopes corroborate current-window labels, not exact onsets or packet ground truth.'],
        'study_training_ready': False,
    }


if __name__ == '__main__':
    out = ROOT/'plan/public_partitions_v1.json'
    content = json.dumps(build(), indent=2) + '\n'
    if out.exists() and out.read_bytes() != content.encode():
        raise FileExistsError('Immutable plan exists with different bytes; create a new version')
    out.write_text(content, encoding='utf-8', newline='\n')
    print(f'Declared {out.name}; SHA-256 {digest(out)}', flush=True)
