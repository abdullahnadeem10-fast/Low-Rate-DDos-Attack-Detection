"""Stream the known Friday capture; corroborate CSV labels, never open slow-family data.

Two passes: infer the timestamp offset from benign CSV keys, then compare packet
counts for canonical bidirectional tuples against CSV totals. Outputs retain uncertainty.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import socket
import time
from zipfile import ZipFile

import dpkt

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT/'data/development'
OUT = ROOT/'results/development'
ARCHIVE = ROOT/'data/quarantine/CICIDS2017-GeneratedLabelledFlows.zip'
MEMBER = 'TrafficLabelling /Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
PCAP_SHA = 'beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0'
PCAP_SIZE = 8839309056
ZIP_SHA = '7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a'
REV = '811c007f08d693a8a8b4226c197c138391806ce6'
SERVER = socket.inet_aton('192.168.10.50')
SERVICE = 80


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def canonical_key(key):
    a,b=sorted(((key[0],key[1]),(key[2],key[3])))
    result=(a[0],a[1],b[0],b[1],key[4])
    return result,result==key


def load_labels():
    if digest(ARCHIVE) != ZIP_SHA:
        raise ValueError('Label archive checksum mismatch')
    groups = {}
    rows = Counter(); invalid_duration=Counter(); invalid_keys=set()
    with ZipFile(ARCHIVE) as archive, archive.open(MEMBER) as f:
        reader = csv.DictReader(io.TextIOWrapper(f,encoding='utf-8-sig',newline=''))
        for raw in reader:
            row = {k.strip():v.strip() for k,v in raw.items()}
            label = row['Label']
            if label not in ('BENIGN','DDoS'):
                raise ValueError(f'Unexpected label {label}')
            rows[label] += 1
            key = (socket.inet_aton(row['Source IP']),int(row['Source Port']),
                   socket.inet_aton(row['Destination IP']),int(row['Destination Port']),int(row['Protocol']))
            key,direct=canonical_key(key)
            stamp = datetime.strptime(row['Timestamp'],'%d/%m/%Y %H:%M').replace(tzinfo=timezone.utc).timestamp()
            duration = int(row['Flow Duration']) / 1e6
            if duration < 0:
                invalid_duration[label]+=1; invalid_keys.add(key)
                continue
            group = groups.setdefault(key,{'labels':set(),'intervals':[], 'fwd':0,'bwd':0,'rows':0})
            group['labels'].add(label)
            group['intervals'].append((stamp,stamp+60+duration))
            fwd,bwd=int(row['Total Fwd Packets']),int(row['Total Backward Packets'])
            group['fwd'] += fwd if direct else bwd
            group['bwd'] += bwd if direct else fwd
            group['rows'] += 1
    removed_valid_rows=0
    for key in invalid_keys:
        if key in groups: removed_valid_rows+=groups.pop(key)['rows']
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'friday_label_exclusions.json').write_text(json.dumps({
        'negative_duration_rows_by_label':dict(invalid_duration),'quarantined_connection_keys':len(invalid_keys),
        'additional_valid_rows_quarantined_with_same_keys':removed_valid_rows,
        'policy':'Exclude the complete key if any row has an impossible negative duration; preserve raw row counts.'},indent=2)+'\n',encoding='utf-8')
    for group in groups.values():
        # Merge possible intervals. CSV minute precision remains explicit.
        merged = []
        for a,b in sorted(group['intervals']):
            if merged and a <= merged[-1][1]:
                merged[-1] = (merged[-1][0],max(b,merged[-1][1]))
            else:
                merged.append((a,b))
        group['intervals'] = merged
    return groups, dict(rows)


def packets(path):
    with path.open('rb') as f:
        magic = f.read(4); f.seek(0)
        reader = dpkt.pcapng.Reader(f) if magic == b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(f)
        if reader.datalink() != dpkt.pcap.DLT_EN10MB:
            raise ValueError('Unsupported link type')
        for timestamp,frame in reader:
            try:
                ip = dpkt.ethernet.Ethernet(frame).data
                if not isinstance(ip,dpkt.ip.IP) or ip.offset:
                    yield float(timestamp),None,len(frame); continue
                t = ip.data
                if not isinstance(t,(dpkt.tcp.TCP,dpkt.udp.UDP)):
                    yield float(timestamp),None,len(frame); continue
                key = (ip.src,t.sport,ip.dst,t.dport,ip.p)
                yield float(timestamp),key,len(frame)
            except (dpkt.UnpackError,ValueError):
                yield float(timestamp),None,len(frame)


def reverse(key):
    return (key[2],key[3],key[0],key[1],key[4])


def pass_one(path,groups):
    # One short, unambiguous benign row per key. Equal key weights prevent a flood
    # from deciding the clock offset by sheer packet volume.
    eligible = {key:g for key,g in groups.items() if g['labels']=={'BENIGN'}
                and g['rows']==1 and g['intervals'][0][1]-g['intervals'][0][0] <= 120}
    hits = defaultdict(set)
    stats = Counter()
    first,last,previous = float('inf'),float('-inf'),float('-inf')
    start = time.perf_counter()
    for ts,key,_ in packets(path):
        stats['frames'] += 1
        first,last = min(first,ts),max(last,ts)
        stats['out_of_order'] += int(ts < previous); previous=ts
        if key is not None:
            rev = reverse(key)
            for candidate in (key,rev):
                group = eligible.get(candidate)
                if group is None: continue
                a,b = group['intervals'][0]
                hours = int((ts-a)//3600)
                if -12 <= hours <= 24 and a+hours*3600 <= ts <= b+hours*3600:
                    hits[hours].add(candidate)
        if stats['frames'] % 2000000 == 0:
            print(f'Clock pass: {stats["frames"]:,} frames, {time.perf_counter()-start:.0f}s',flush=True)
    counts = Counter({hour:len(keys) for hour,keys in hits.items()})
    best = counts.most_common(2)
    if not best or best[0][1] < 30 or (len(best)>1 and best[0][1] < 5*best[1][1]):
        raise ValueError(f'Clock offset is ambiguous: {dict(counts)}')
    return best[0][0]*3600, {'eligible_benign_keys':len(eligible),
            'benign_key_votes_by_offset_hours':dict(sorted(counts.items())),
            'frames':dict(stats), 'capture_first_utc':datetime.fromtimestamp(first,timezone.utc).isoformat(),
            'capture_last_utc':datetime.fromtimestamp(last,timezone.utc).isoformat(),
            'elapsed_seconds':round(time.perf_counter()-start,2)}


def pass_two(path,groups,offset):
    # Restrict to the CSV's overall temporal envelope. Outside it, no labels are inferred.
    started=time.perf_counter(); frames_read=0
    start=min(a for g in groups.values() for a,b in g['intervals'])+offset
    end=max(b for g in groups.values() for a,b in g['intervals'])+offset
    actual=defaultdict(Counter)
    second_counts=defaultdict(Counter)
    group_ids={key:i for i,key in enumerate(groups)}
    service_key_counts=defaultdict(Counter)
    stats=Counter()
    for ts,key,size in packets(path):
        frames_read+=1
        if frames_read%2000000==0: print(f'Count pass: {frames_read:,} frames, {time.perf_counter()-started:.0f}s',flush=True)
        if not start <= ts <= end or key is None: continue
        direct,rev = groups.get(key),groups.get(reverse(key))
        candidates=[]
        for candidate,g,direction in ((key,direct,'fwd'),(reverse(key),rev,'bwd')):
            if g is not None and any(a+offset <= ts <= b+offset for a,b in g['intervals']):
                candidates.append((candidate,direction))
        if len(candidates)==1:
            candidate,direction = candidates[0]
            actual[candidate][direction] += 1
        else:
            candidate,direction = None,None
            stats['unmatched_or_multi_direction_packets'] += 1
        # Retain sparse per-tuple/per-second counts for a later strict count check.
        if key[4] == 6 and ((key[2]==SERVER and key[3]==SERVICE) or (key[0]==SERVER and key[1]==SERVICE)):
            second=int(ts)
            c=second_counts[second]
            c['packets'] += 1; c['bytes'] += size
            if candidate is not None:
                service_key_counts[second][group_ids[candidate]]+=1
                label=next(iter(groups[candidate]['labels'])) if len(groups[candidate]['labels'])==1 else 'CONFLICT'
                c[label] += 1
            else: c['UNMATCHED'] += 1
    exact=Counter(); mismatched=Counter(); missing=Counter(); service_exact=Counter(); service_total=Counter()
    verified=set()
    for key,g in groups.items():
        labels='/'.join(sorted(g['labels']))
        is_service=key[4]==6 and ((key[0]==SERVER and key[1]==SERVICE) or (key[2]==SERVER and key[3]==SERVICE))
        if is_service: service_total[labels]+=1
        counts=actual[key]
        if not sum(counts.values()): missing[labels]+=1
        elif counts['fwd']==g['fwd'] and counts['bwd']==g['bwd'] and len(g['labels'])==1:
            exact[labels]+=1; verified.add(key)
            if is_service: service_exact[labels]+=1
        else: mismatched[labels]+=1
    OUT.mkdir(parents=True,exist_ok=True)
    with (OUT/'friday_service_join_counts.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=['utc_second','packets','bytes','BENIGN','DDoS','CONFLICT','UNMATCHED'])
        writer.writeheader()
        for second,c in sorted(second_counts.items()): writer.writerow({'utc_second':second,**{k:c[k] for k in writer.fieldnames[1:]}})
    verified_labels={group_ids[key]:next(iter(groups[key]['labels'])) for key in verified}
    strict_status=Counter(); strict_packets=Counter()
    with (OUT/'friday_service_corroborated_labels.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=['utc_second','packets','verified_benign_packets','verified_attack_packets','uncorroborated_packets','status'])
        writer.writeheader()
        for second,c in sorted(second_counts.items()):
            tally=Counter()
            for gid,n in service_key_counts[second].items():
                if gid in verified_labels: tally[verified_labels[gid]]+=n
            unknown=c['packets']-tally['BENIGN']-tally['DDoS']
            status='attack_present' if tally['DDoS'] else ('benign_only' if unknown==0 else 'uncertain')
            strict_status[status]+=1; strict_packets['verified_benign']+=tally['BENIGN']
            strict_packets['verified_attack']+=tally['DDoS']; strict_packets['uncorroborated']+=unknown
            writer.writerow({'utc_second':second,'packets':c['packets'],'verified_benign_packets':tally['BENIGN'],
                             'verified_attack_packets':tally['DDoS'],'uncorroborated_packets':unknown,'status':status})
    return {'clock_offset_seconds':offset, 'all_csv_rows_to_be_shifted_by_hours':offset/3600,
            'tuple_groups':len(groups), 'exact_directional_packet_count_groups':dict(exact),
            'directional_count_mismatch_groups':dict(mismatched),'unseen_tuple_groups':dict(missing),
            'packet_matching':dict(stats),'service_observed_seconds':len(second_counts),
            'target_service_total_tuple_groups':dict(service_total),'target_service_count_agreement_groups':dict(service_exact),
            'target_service_corroborated_packet_counts':dict(strict_packets),
            'target_service_corroborated_second_status':dict(strict_status),
            'frames_read':frames_read,'elapsed_seconds':round(time.perf_counter()-started,2),
            'label_join_status':'possible-interval join, NOT exact packet ground truth',
            'limitations':['Minute-only timestamps define possible intervals, not exact flow starts.',
                'Count agreement is corroboration; overlapping/reused tuple intervals still need scrutiny.',
                'No predictor includes CSV identifiers, duration, labels or future totals.',
                'No reserved slow-family data or final model scoring occurred.']}


def main(path):
    OUT.mkdir(parents=True,exist_ok=True)
    if path.stat().st_size != PCAP_SIZE: raise ValueError('Incomplete Friday capture')
    print('Verifying full Friday SHA-256...',flush=True)
    if digest(path)!=PCAP_SHA: raise ValueError('Friday capture checksum mismatch')
    groups,rows=load_labels()
    offset,clock=pass_one(path,groups)
    partial={'capture_sha256':PCAP_SHA,'capture_bytes':PCAP_SIZE,'source_revision':REV,
             'labels_opened':MEMBER,'csv_counts':rows,'clock_audit':clock,'offset_seconds':offset}
    (OUT/'friday_clock_audit.json').write_text(json.dumps(partial,indent=2)+'\n',encoding='utf-8')
    print(f'Clock offset inferred from benign keys: {offset/3600:+g} hours. Comparing counts...',flush=True)
    partial['join_audit']=pass_two(path,groups,offset)
    (OUT/'friday_packet_audit.json').write_text(json.dumps(partial,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(partial,indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap',type=Path,default=DATA/'Friday-WorkingHours.pcap')
    main(parser.parse_args().pcap)
