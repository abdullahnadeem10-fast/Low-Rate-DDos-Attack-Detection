"""Empirical clock/count join for candidate V services, without classifier scores.

Clock hypotheses must be supported by distinct nonempty canonical groups, with
an unambiguous winning directional-count match. Unmatched/idle cells stay unknown.
"""
from bisect import bisect_right
from collections import Counter, defaultdict
import csv
import json
import time

import numpy as np
from declare_cic2019_validation import ROOT
from download_cic2019_validation import sha

TOLERANCE = 1e-6


def contains(group, timestamp, offset):
    value = timestamp - offset
    i = bisect_right(group['_starts'], value + TOLERANCE) - 1
    return i >= 0 and value <= group['intervals'][i][1] + TOLERANCE


def clock_winner(scores):
    ordered = sorted(scores, key=lambda r: (-r['exact_nonempty_groups'], -r['corroborated_packets'], abs(r['offset_seconds']), r['offset_seconds']))
    if not ordered:
        return None
    winner = ordered[0]
    runner = ordered[1]['exact_nonempty_groups'] if len(ordered) > 1 else 0
    # A tiny/ambiguous sample is a source-readiness failure, not a guessed timezone.
    return winner['offset_seconds'] if winner['exact_nonempty_groups'] >= 2 and winner['exact_nonempty_groups'] > runner and winner['exact_nonempty_groups'] >= 2 * max(1, runner) else None


def status(total, benign, attack, possible):
    if total <= 0 or benign < 0 or attack < 0 or benign + attack > total:
        raise ValueError('Invalid corroborated packet totals')
    if attack:
        return 'attack_present'
    if benign == total:
        return 'benign_only'
    return 'uncertain' if possible else 'not_labelled'


def main():
    started = time.perf_counter()
    directory = ROOT/'data/development/cic2019_v'
    out = ROOT/'results/development'
    plan_path = ROOT/'plan/cic2019_validation_v1.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    label_path, packet_path = out/'cic2019_label_inventory_v1.json', out/'cic2019_packet_inventory_v1.json'
    labels, packets = (json.loads(p.read_text(encoding='utf-8')) for p in (label_path, packet_path))
    if any(r['plan_sha256'] != sha(plan_path) for r in (labels, packets)):
        raise ValueError('Inventory belongs to another source allocation')
    if sha(ROOT/labels['private_group_table']) != labels['private_group_sha256'] or sha(ROOT/packets['index']) != packets['index_sha256']:
        raise ValueError('Private audit data changed')
    groups = json.loads((ROOT/labels['private_group_table']).read_text(encoding='utf-8'))
    for g in groups.values():
        g['_starts'] = [a for a, b in g['intervals']]
        g['_pure'] = {x.casefold() for x in g['labels']}
    rows = np.load(ROOT/packets['index'], allow_pickle=False, mmap_mode='r')
    # Cache only public candidate endpoints; every packet in these raw streams is
    # retained here regardless of confidence or clock match.
    prepared = []
    for r in rows:
        key = f'{int(r["service"])}|{int(r["client"])}|{int(r["port"])}'
        prepared.append((int(r['service']), float(r['timestamp']), bool(r['inbound']), key))
    scores = []
    actual_by_offset = {}
    for hours in range(-26, 27):
        offset = hours * 3600
        actual = defaultdict(lambda: [0, 0])
        for sid, ts, incoming, key in prepared:
            g = groups.get(key)
            if g and not g['quarantined'] and contains(g, ts, offset):
                actual[key][0 if incoming else 1] += 1
        matched = {k for k, c in actual.items() if c == [groups[k]['expected_in'], groups[k]['expected_out']]
                   and sum(c) > 0 and groups[k]['_pure'] in ({'syn'}, {'benign'})}
        scores.append({'offset_seconds': offset, 'exact_nonempty_groups': len(matched),
                       'corroborated_packets': sum(sum(actual[k]) for k in matched)})
        actual_by_offset[offset] = matched
    winner = clock_winner(scores)
    services = []
    for sid, name in enumerate(plan['endpoint_metadata_candidates']):
        seconds = defaultdict(Counter)
        for i, ts, incoming, key in prepared:
            if i != sid:
                continue
            c = seconds[int(ts)]
            c['packets'] += 1
            g = groups.get(key)
            if winner is None or not g or g['quarantined'] or not contains(g, ts, winner):
                continue
            c['possible'] += 1
            if key in actual_by_offset[winner]:
                c['attack' if g['_pure'] == {'syn'} else 'benign'] += 1
        table, statuses = [], Counter()
        for sec, c in sorted(seconds.items()):
            s = status(c['packets'], c['benign'], c['attack'], c['possible'])
            statuses[s] += 1
            table.append({'utc_second': sec, 'packets': c['packets'], 'corroborated_benign_packets': c['benign'],
                          'corroborated_attack_packets': c['attack'], 'uncorroborated_packets': c['packets'] - c['benign'] - c['attack'], 'status': s})
        path = directory/(name.replace('.', '-').replace(':', '-') + '-labels.csv')
        with path.open('w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['utc_second', 'packets', 'corroborated_benign_packets', 'corroborated_attack_packets', 'uncorroborated_packets', 'status'])
            writer.writeheader()
            writer.writerows(table)
        services.append({'service': name, 'service_index': sid, 'nonempty_second_status': dict(statuses),
                         'corroborated_attack_packets': sum(c['attack'] for c in seconds.values()),
                         'raw_packets': sum(c['packets'] for c in seconds.values()),
                         'label_table': str(path.relative_to(ROOT)).replace('\\', '/'), 'label_sha256': sha(path)})
    ranked = sorted(services, key=lambda x: (-x['nonempty_second_status'].get('attack_present', 0), x['service']))
    packet_quality = not any(packets['counts'].get(k, 0) for k in ('unsupported_link_members', 'decode_errors', 'candidate_ip_tcp_fragment_frames', 'candidate_ip_truncated_tcp_packets', 'candidate_truncated_ip_packets'))
    label_quality = not any(labels['counts'].get(k, 0) for k in ('wrong_width_rows', 'invalid_metadata_rows', 'invalid_candidate_ipv4'))
    quality = packet_quality and label_quality
    selected = ranked[0]['service'] if winner is not None and quality and ranked[0]['nonempty_second_status'].get('attack_present', 0) else None
    result = {
        'date': '2026-11-12', 'scope': 'Independent-source clock/count feasibility; not model fitting/final evaluation.',
        'plan_sha256': sha(plan_path), 'label_inventory_sha256': sha(label_path), 'packet_inventory_sha256': sha(packet_path),
        'clock_hypotheses': sorted(scores, key=lambda r: -r['exact_nonempty_groups']),
        'clock_offset_seconds': winner, 'timestamp_join_tolerance_seconds': TOLERANCE,
        'clock_basis': 'Pure SYN or BENIGN canonical directional-count concordance on allowed development V data; not a detector score or a presumed publisher timezone.',
        'services': services, 'packet_input_quality_passed': packet_quality, 'label_metadata_quality_passed': label_quality, 'selected_metadata_candidate': selected,
        'independent_attack_V_accepted': False, 'study_training_ready': False,
        'source_sha256': sha(ROOT/'src/corroborate_cic2019_validation.py'), 'elapsed_seconds': round(time.perf_counter()-started, 3),
        'next_gate': 'If a candidate exists, declare raw stream/service/gap handling before fresh causal extraction; otherwise preserve negative compatibility evidence and find another source.',
        'limitations': ['Aggregate flow counts and interval correspondence corroborate current-window labels, not exact packet or onset ground truth.',
                        'SYN traffic at arbitrary ports is not silently pooled into a web-service stream.',
                        'No uncertain, unlabelled or idle time is inferred benign; sparse selected cells are not independent episodes.',
                        'The reserved 01-12 known-test candidate remains unopened and unqualified; slow/external sources remain reserved.'],
    }
    (out/'cic2019_corroboration_v1.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'clock_offset_seconds': winner, 'quality': quality, 'selected_candidate': selected, 'services': services}, indent=2), flush=True)


if __name__ == '__main__':
    main()
