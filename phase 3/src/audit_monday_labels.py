"""Audit only the permitted Monday label member for benign service compatibility."""
from collections import Counter, defaultdict
import csv
from datetime import datetime
import io
import json
from pathlib import Path
import time
from zipfile import ZipFile

from friday_packet_audit import ARCHIVE, ZIP_SHA, digest

MEMBER = 'TrafficLabelling /Monday-WorkingHours.pcap_ISCX.csv'
HOSTS = ('192.168.10.50', '205.174.165.68')
OUT = Path(__file__).resolve().parents[1] / 'results/development'


def audit_rows(rows):
    labels = Counter(); endpoints = defaultdict(Counter)
    hosts = {host: Counter() for host in HOSTS}
    formats = Counter(); anomalies = Counter(); first = None; last = None
    for raw in rows:
        row = {k.strip(): v.strip() for k, v in raw.items()}
        if row['Label'] != 'BENIGN':
            raise ValueError('Monday audit encountered an unexpected attack label')
        labels[row['Label']] += 1
        stamp = None
        for fmt in ('%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M'):
            try:
                stamp = datetime.strptime(row['Timestamp'], fmt)
                formats[fmt] += 1
                break
            except ValueError:
                continue
        if stamp is None or stamp.date().isoformat() != '2017-07-03':
            raise ValueError('Unexpected Monday timestamp')
        first = min(first, stamp) if first else stamp
        last = max(last, stamp) if last else stamp
        anomalies['negative_duration_rows'] += int(float(row['Flow Duration']) < 0)
        for side in ('Source', 'Destination'):
            host, port = row[side + ' IP'], int(row[side + ' Port'])
            if host in hosts:
                hosts[host]['endpoint_occurrences_all_ports'] += 1
                if port in (80, 443):
                    hosts[host][f'port_{port}_occurrences'] += 1
            if int(row['Protocol']) == 6 and port in (80, 443):
                endpoints[(host, port)]['rows_touching_endpoint'] += 1
    return {
        'class_rows': dict(labels), 'timestamp_formats': dict(formats),
        'first_as_written': first.isoformat() if first else None,
        'last_as_written': last.isoformat() if last else None,
        'anomalies': dict(anomalies),
        'published_web_host_coverage': {h: dict(c) for h, c in hosts.items()},
        'distinct_tcp_web_endpoints': len(endpoints),
        'top_tcp_web_endpoints': [
            {'ip': h, 'port': p, **c} for (h, p), c in
            sorted(endpoints.items(), key=lambda item: (-item[1]['rows_touching_endpoint'], item[0]))[:20]],
        'matched_http_calibration_established': False,
        'limitations': [
            'CSV endpoint/label inventory only; not a packet join or proof that absent CSV flows mean no raw packets.',
            'Port 80/443 is a candidate service inventory, not payload-level protocol verification.',
            'Other external web endpoints do not automatically provide a matched negative class for the attacked local service.',
            'No slow-family member, external dataset, model fitting or final scoring is involved.'
        ]
    }


def main():
    started = time.perf_counter()
    if digest(ARCHIVE) != ZIP_SHA:
        raise ValueError('Label archive checksum mismatch')
    with ZipFile(ARCHIVE) as archive, archive.open(MEMBER) as member:
        result = audit_rows(csv.DictReader(io.TextIOWrapper(member, encoding='utf-8-sig', newline='')))
    result.update({'date': '2026-11-11', 'opened_member': MEMBER, 'archive_sha256': ZIP_SHA,
                   'seconds': round(time.perf_counter() - started, 3),
                   'next_action': 'Collect compatible benign HTTP sessions in the isolated lab; no full Monday capture download is justified solely by this inventory.'})
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'monday_service_label_audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
