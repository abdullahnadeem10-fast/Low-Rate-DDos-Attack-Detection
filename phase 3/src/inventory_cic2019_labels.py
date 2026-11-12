"""Inventory only the declared Syn.csv member; no features or class inference.

CSV times remain as-printed numeric UTC surrogates until empirical clock joining.
Full uncompressed bytes are hashed and compared with an independent mirror pin.
"""
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import PurePosixPath
import time
from zipfile import ZipFile

from declare_cic2019_validation import ROOT
from download_cic2019_validation import approved, sha


def syn_member(names):
    matches = [n for n in names if PurePosixPath(n.replace('\\', '/')).name.lower() == 'syn.csv']
    if len(matches) != 1 or any('01-12' in n for n in matches):
        raise ValueError('Expected one nonreserved Syn.csv member')
    return matches[0]


def printed_timestamp(value):
    parsed = datetime.fromisoformat(value.strip())
    return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)).timestamp()


def count_value(value):
    x = float(value)
    if not math.isfinite(x) or x < 0 or not x.is_integer():
        raise ValueError('Invalid packet total')
    return int(x)


def main():
    started = time.perf_counter()
    plan_path = ROOT/'plan/cic2019_validation_v1.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    item = next(x for x in plan['allowed_downloads'] if x['id'] == 'labels-03-11')
    path = approved(item)
    if path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
        raise ValueError('Declared label archive integrity failed')
    services = plan['endpoint_metadata_candidates']
    endpoints = {(str(s.split(':')[0]), int(s.split(':')[1])): i for i, s in enumerate(services)}
    labels, protocols, ports, counts = Counter(), Counter(), Counter(), Counter()
    service_rows = {s: Counter() for s in services}
    groups = {}
    first, last = math.inf, -math.inf
    digest = hashlib.sha256()
    uncompressed = 0
    with ZipFile(path) as archive:
        name = syn_member(archive.namelist())
        info = archive.getinfo(name)
        expected = plan['independent_syn_csv_crosscheck']
        if info.file_size != expected['bytes']:
            raise ValueError('Syn member size disagrees with independent mirror')
        with archive.open(name) as raw:
            def lines():
                nonlocal uncompressed
                for n, line in enumerate(raw):
                    digest.update(line)
                    uncompressed += len(line)
                    yield line.decode('utf-8-sig' if n == 0 else 'utf-8')
            reader = csv.reader(lines())
            header = [x.strip() for x in next(reader)]
            needed = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp',
                      'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Label']
            if any(h not in header for h in needed):
                raise ValueError('Unexpected Syn CSV schema')
            indices = {h: header.index(h) for h in needed}
            for values in reader:
                counts['rows'] += 1
                if len(values) != len(header):
                    counts['wrong_width_rows'] += 1
                    continue
                r = {h: values[i].strip() for h, i in indices.items()}
                label = r['Label']
                if label.casefold() not in ('syn', 'benign'):
                    raise ValueError('Unexpected label in allowed SYN member; quarantine before further analysis')
                labels[label] += 1
                try:
                    proto = int(r['Protocol'])
                    protocols[str(proto)] += 1
                    sport, dport = int(r['Source Port']), int(r['Destination Port'])
                    ports[str(dport)] += 1
                    if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
                        raise ValueError('Invalid port')
                    stamp = printed_timestamp(r['Timestamp'])
                    first, last = min(first, stamp), max(last, stamp)
                except (ValueError, OverflowError):
                    counts['invalid_metadata_rows'] += 1
                    continue
                if proto != 6:
                    continue
                candidates = []
                if (r['Destination IP'], dport) in endpoints:
                    candidates.append((endpoints[r['Destination IP'], dport], r['Source IP'], sport, True))
                if (r['Source IP'], sport) in endpoints:
                    candidates.append((endpoints[r['Source IP'], sport], r['Destination IP'], dport, False))
                for sid, client, port, incoming in candidates:
                    service_rows[services[sid]][label] += 1
                    try:
                        client = int(ipaddress.IPv4Address(client))
                    except ipaddress.AddressValueError:
                        counts['invalid_candidate_ipv4'] += 1
                        continue
                    key = f'{sid}|{client}|{port}'
                    g = groups.setdefault(key, {'service_index': sid, 'client': client, 'port': port,
                                                'labels': set(), 'rows': 0, 'expected_in': 0, 'expected_out': 0,
                                                'intervals': [], 'quarantined': False})
                    g['labels'].add(label)
                    g['rows'] += 1
                    try:
                        duration = float(r['Flow Duration'])
                        fwd, bwd = count_value(r['Total Fwd Packets']), count_value(r['Total Backward Packets'])
                        if not math.isfinite(duration) or duration < 0:
                            raise ValueError('Invalid/negative duration')
                        g['expected_in'] += fwd if incoming else bwd
                        g['expected_out'] += bwd if incoming else fwd
                        g['intervals'].append([stamp, stamp + duration/1e6])
                    except ValueError:
                        g['quarantined'] = True
                        counts['invalid_candidate_duration_or_counts'] += 1
                if counts['rows'] % 500000 == 0:
                    print(f'Syn label inventory: {counts["rows"]:,} rows; {time.perf_counter()-started:.0f}s', flush=True)
    if uncompressed != expected['bytes'] or digest.hexdigest() != expected['sha256']:
        raise ValueError('Syn member bytes disagree with independent mirror SHA-256')
    for g in groups.values():
        g['labels'] = sorted(g['labels'])
        g['intervals'].sort()
        merged = []
        for a, b in g['intervals']:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        g['intervals'] = merged
    directory = ROOT/'data/development/cic2019_v'
    group_path = directory/'syn_candidate_groups.json'
    group_path.write_text(json.dumps(groups, separators=(',', ':')) + '\n', encoding='utf-8', newline='\n')
    report = {'date': '2026-11-12', 'scope': 'Allowed Syn.csv source/endpoint inventory; no features/models or final payloads.',
              'plan_sha256': sha(plan_path), 'archive_sha256': item['sha256'], 'member': name,
              'member_bytes': uncompressed, 'member_sha256': digest.hexdigest(), 'independent_mirror_bytes_match': True,
              'counts': dict(counts), 'label_counts': dict(labels), 'protocol_counts': dict(protocols),
              'top_destination_ports': ports.most_common(20), 'candidate_services': {s: dict(c) for s, c in service_rows.items()},
              'candidate_canonical_keys': len(groups), 'quarantined_candidate_keys': sum(g['quarantined'] for g in groups.values()),
              'printed_timestamp_min_as_utc_surrogate': datetime.fromtimestamp(first, timezone.utc).isoformat(),
              'printed_timestamp_max_as_utc_surrogate': datetime.fromtimestamp(last, timezone.utc).isoformat(),
              'private_group_table': str(group_path.relative_to(ROOT)).replace('\\', '/'), 'private_group_sha256': sha(group_path),
              'source_sha256': sha(ROOT/'src/inventory_cic2019_labels.py'), 'elapsed_seconds': round(time.perf_counter()-started, 3),
              'independent_attack_V_accepted': False, 'study_training_ready': False}
    (ROOT/'results/development/cic2019_label_inventory_v1.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: report[k] for k in ('label_counts', 'candidate_services', 'candidate_canonical_keys')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
