"""One-pass corroboration of all pre-inventoried Friday benign HTTP candidates.

No model fitting or final holdout access. Raw service packets are counted without
label filtering; uncorroborated seconds are retained as uncertain, never benign.
"""
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re
import socket
import time

import dpkt
from friday_packet_audit import DATA, OUT, PCAP_SHA, PCAP_SIZE, load_labels, digest, canonical_key


def qualified_keys(groups, actual, http_keys):
    return {key for key,g in groups.items() if g['labels']=={'BENIGN'} and key in http_keys
            and actual[key]['fwd']==g['fwd'] and actual[key]['bwd']==g['bwd']}


def second_status(total, verified):
    if total <= 0:
        return 'not_labelled'
    if not 0 <= verified <= total:
        raise ValueError('Invalid corroborated packet counts')
    return 'benign_only' if total==verified else 'uncertain'


def main():
    started=time.perf_counter(); path=DATA/'Friday-WorkingHours.pcap'
    if path.stat().st_size!=PCAP_SIZE or digest(path)!=PCAP_SHA:
        raise ValueError('Pinned Friday capture integrity check failed')
    inventory=json.loads((OUT/'friday_benign_http_candidates.json').read_text())
    services=[r['service'] for r in inventory['top_endpoints'] if r['metadata_inventory_eligible']]
    if len(services)!=inventory['metadata_eligible_endpoints']:
        raise ValueError('Inventory does not expose the complete preselected candidate list')
    all_groups,_=load_labels()
    index={(socket.inet_aton(s.rsplit(':',1)[0]),int(s.rsplit(':',1)[1])):s for s in services}
    by_service={s:{} for s in services}
    for key,g in all_groups.items():
        if key[4]!=6: continue
        for endpoint in ((key[0],key[1]),(key[2],key[3])):
            if endpoint in index: by_service[index[endpoint]][key]=g
    groups={k:g for table in by_service.values() for k,g in table.items()}
    if any(g['labels']!={'BENIGN'} for g in groups.values()):
        raise ValueError('A preselected service has conflicting/nonbenign group labels')
    clock=json.loads((OUT/'friday_clock_audit.json').read_text())
    if clock['capture_sha256']!=PCAP_SHA: raise ValueError('Clock evidence belongs to a different input')
    offset=clock['offset_seconds']
    first=min(a for g in groups.values() for a,b in g['intervals'])+offset
    last=max(b for g in groups.values() for a,b in g['intervals'])+offset
    actual=defaultdict(Counter); http_keys=set(); markers={s:Counter() for s in services}
    seconds={s:defaultdict(Counter) for s in services}; second_keys={s:defaultdict(Counter) for s in services}
    frames=0; protocol_errors=Counter()
    with path.open('rb') as f:
        magic=f.read(4);f.seek(0)
        reader=dpkt.pcapng.Reader(f) if magic==b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(f)
        if reader.datalink()!=dpkt.pcap.DLT_EN10MB: raise ValueError('Ethernet required')
        for ts,frame in reader:
            frames+=1
            if frames%2000000==0: print(f'HTTP candidate audit: {frames:,} frames, {time.perf_counter()-started:.0f}s',flush=True)
            if not first<=ts<=last: continue
            try:
                ip=dpkt.ethernet.Ethernet(frame).data
                if not isinstance(ip,dpkt.ip.IP) or ip.offset or not isinstance(ip.data,dpkt.tcp.TCP): continue
                tcp=ip.data
                service=index.get((ip.src,tcp.sport)) or index.get((ip.dst,tcp.dport))
                if service is None: continue
                second=int(ts);seconds[service][second]['packets']+=1
                key,direct=canonical_key((ip.src,tcp.sport,ip.dst,tcp.dport,6))
                group=groups.get(key)
                if group is None or not any(a+offset<=ts<=b+offset for a,b in group['intervals']):
                    seconds[service][second]['unmatched']+=1; continue
                actual[key]['fwd' if direct else 'bwd']+=1
                second_keys[service][second][key]+=1
                payload=bytes(tcp.data)
                request=bool(re.match(rb'^(GET|HEAD|POST|OPTIONS|PUT|DELETE|CONNECT|TRACE|PATCH) [^\r\n]+ HTTP/1\.[01]\r\n',payload))
                response=bool(re.match(rb'^HTTP/1\.[01] [0-9]{3}',payload))
                if request or response: http_keys.add(key)
                markers[service]['request_prefix_packets']+=int(request)
                markers[service]['response_prefix_packets']+=int(response)
            except (dpkt.UnpackError,ValueError): protocol_errors['decode_errors_in_label_envelope']+=1
    verified=qualified_keys(groups,actual,http_keys)
    reports=[]
    for service,table in by_service.items():
        statuses=Counter();packets=Counter()
        directory=DATA/'public_http_candidates'/service.replace(':','_');directory.mkdir(parents=True,exist_ok=True)
        with (directory/'labels.csv').open('w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=['utc_second','packets','corroborated_benign_packets','uncorroborated_packets','status'])
            writer.writeheader()
            for second,c in sorted(seconds[service].items()):
                count=sum(n for key,n in second_keys[service][second].items() if key in verified)
                status=second_status(c['packets'],count);statuses[status]+=1
                packets['corroborated_benign']+=count;packets['uncorroborated']+=c['packets']-count
                writer.writerow({'utc_second':second,'packets':c['packets'],'corroborated_benign_packets':count,
                    'uncorroborated_packets':c['packets']-count,'status':status})
        exact=sum(actual[k]['fwd']==g['fwd'] and actual[k]['bwd']==g['bwd'] for k,g in table.items())
        reports.append({'service':service,'canonical_groups':len(table),'count_agreement_groups':exact,
            'http_marker_groups':sum(k in http_keys for k in table),'count_and_http_corroborated_groups':sum(k in verified for k in table),
            'http_payload_prefix_evidence':dict(markers[service]),'nonempty_second_status':dict(statuses),'packet_counts':dict(packets),
            'label_table_relative_path':str((directory/'labels.csv').relative_to(Path(__file__).resolve().parents[1])).replace('\\','/'),
            'label_table_sha256':digest(directory/'labels.csv')})
    result={'date':'2026-11-11','scope':'Allowed Friday development candidate audit; no training/final scoring.',
        'capture_sha256':PCAP_SHA,'clock_offset_seconds':offset,'selection_rule':inventory['eligibility_rule'],
        'selected_services_before_packet_scan':services,'frames_read':frames,'elapsed_seconds':round(time.perf_counter()-started,3),
        'protocol_errors':dict(protocol_errors),'services':reports,
        'total_corroborated_nonempty_benign_seconds':sum(r['nonempty_second_status'].get('benign_only',0) for r in reports),
        'training_ready':False,
        'limitations':['Minute-precision possible intervals, aggregate directional counts and HTTP prefixes corroborate labels; they are not exact packet ground truth.',
            'HTTP prefix counts are protocol evidence, not reassembled complete-request counts.',
            'Idle/unmatched/non-HTTP/mismatched seconds remain unlabelled or uncertain; report resulting selection coverage.',
            'External benign servers and the internal attacked server have different network paths; audit service/source effects and hold out destination/session groups.',
            'No causal feature partitions were built from these candidates and no final holdout was opened.']}
    (OUT/'friday_public_http_audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__': main()
