"""Verify and audit one Friday CSV member. Other archive members stay unopened."""
from collections import Counter
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import time
from zipfile import ZipFile

from packet_pilot import ROOT, OUT, REVISION

ARCHIVE = ROOT/'data/quarantine/CICIDS2017-GeneratedLabelledFlows.zip'
SHA256 = '7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a'
MEMBER = 'TrafficLabelling /Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
TUPLE = (' Source IP',' Source Port',' Destination IP',' Destination Port',' Protocol')
started = time.perf_counter()
with ARCHIVE.open('rb') as f:
    assert hashlib.file_digest(f,'sha256').hexdigest() == SHA256, 'Archive hash mismatch'
counts, malformed, formats, key_counts = Counter(), Counter(), Counter(), Counter()
labels_per_key = {}
first, last = {}, {}
with ZipFile(ARCHIVE) as archive, archive.open(MEMBER) as member:
    reader = csv.DictReader(io.TextIOWrapper(member,encoding='utf-8-sig',newline=''))
    assert set((*TUPLE,' Timestamp',' Label')).issubset(reader.fieldnames)
    for row in reader:
        label = row[' Label'].strip()
        counts[label] += 1
        value = row[' Timestamp'].strip()
        parsed = None
        for fmt in ('%d/%m/%Y %H:%M:%S','%d/%m/%Y %H:%M'):
            try:
                parsed = datetime.strptime(value, fmt)
                formats[fmt] += 1
                break
            except ValueError:
                continue
        if parsed is None or any(not row[col].strip() for col in TUPLE):
            malformed[label] += 1
            continue
        first[label] = min(first.get(label, parsed), parsed)
        last[label] = max(last.get(label, parsed), parsed)
        key = (*(row[col].strip() for col in TUPLE),parsed)
        key_counts[key] += 1
        # Mark disagreement without overwriting the first observed label.
        if labels_per_key.setdefault(key,label) != label:
            labels_per_key[key] = 'CONFLICT'
assert counts['DDoS'] and counts['BENIGN']
assert set(counts) == {'BENIGN','DDoS'}, dict(counts)
report = {'source':f'https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/{REVISION}/csvs/GeneratedLabelledFlows.zip',
          'archive_sha256':SHA256, 'opened_member':MEMBER, 'label_counts':dict(counts),
          'unusable_rows_by_label':dict(malformed), 'timestamp_formats':dict(formats),
          'first_as_written':{k:v.isoformat() for k,v in first.items()},
          'last_as_written':{k:v.isoformat() for k,v in last.items()},
          'tuple_timestamp_keys_with_repeats':sum(n>1 for n in key_counts.values()),
          'tuple_timestamp_keys_with_conflicting_labels':sum(v=='CONFLICT' for v in labels_per_key.values()),
          'limitations':['CSV-only audit: no packet-level label join or model evaluation.',
                         'Timestamp values are as written. AM/PM and time-zone normalization must be validated against Friday PCAP before joining.'],
          'processing_seconds':round(time.perf_counter()-started,3)}
OUT.mkdir(exist_ok=True,parents=True)
(OUT/'friday_label_audit.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
