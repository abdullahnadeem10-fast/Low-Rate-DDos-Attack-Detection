"""Audit controlled legitimate stress; failures are outcomes, never exclusions."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import socket
import dpkt
from audit_benign_session import frames


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def audit(folder):
    m=read(folder/'session.json'); c=read(folder/'capture/capture.json')
    require(m['state']=='collected_audit_pending','Incomplete collection')
    require(m['label']=='BENIGN' and m['cleanup_exit_code']==0,'Label/cleanup mismatch')
    require(m['web_alive_after_measurement'],'Service exited')
    require(m['isolation']==dict(one_internal_bridge_forced_router_host_routes=True,published_ports=False,host_network=False,host_nic_modified=False),'Isolation differs')
    router=read(folder/'router/ready.json')
    require(router['icmp_redirects_disabled'],'Router redirects enabled')
    router_mac=bytes.fromhex(router['router_mac'].replace(':',''))
    web_mac=bytes.fromhex(c['web_mac'].replace(':',''))
    require(c['filter']==f'tcp port 80 and ether host {c["web_mac"]}','Capture scope filter differs')
    require(not c['premature_exit'] and c['tcpdump_exit_code']==0,'Capture ended unexpectedly')
    schedule=m['schedule']; start=schedule['measurement_start_utc']; end=schedule['measurement_end_utc']
    require(c['ready_utc']<schedule['warmup_start_utc'] and c['stop_signal_utc']>=end,'Incomplete observation interval')
    pcap=folder/'capture/traffic.pcap'
    require(sha(pcap)==m['pcap_sha256'],'PCAP hash differs')
    text=(folder/'capture/tcpdump.log').read_text(encoding='utf-8')
    def counter(pattern):
        values=re.findall(pattern,text)
        require(len(values)==1,'Missing/ambiguous tcpdump counter')
        return int(values[0])
    captured=counter(r'(\d+) packets captured')
    dropped=counter(r'(\d+) packets dropped by kernel')
    require(dropped==0,'Capture kernel loss')
    clients={f'172.28.240.{i}' for i in (10,11,12)}; web='172.28.240.100'
    counts=Counter(); first=None; last=None; max_regression=0.; previous=float('-inf')
    for ts,frame,wirelen in frames(pcap):
        require(len(frame)==wirelen and wirelen<=1514,'Truncated/aggregated frame')
        ethernet=dpkt.ethernet.Ethernet(frame); ip=ethernet.data
        require(isinstance(ip,dpkt.ip.IP) and not ip.offset and isinstance(ip.data,dpkt.tcp.TCP),'Unexpected packet type')
        tcp=ip.data; src,dst=socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst)
        incoming=src in clients and dst==web and tcp.dport==80
        outgoing=src==web and dst in clients and tcp.sport==80
        require(incoming or outgoing,'Packet outside declared endpoint scope')
        require((ethernet.src if incoming else ethernet.dst)==router_mac,'Packet bypassed declared router')
        require((ethernet.dst if incoming else ethernet.src)==web_mac,'Non-service bridge copy captured')
        require(c['start_utc']-2<=ts<=c['copy_finished_utc']+2,'Packet/capture clock disagreement')
        max_regression=max(max_regression,previous-ts); previous=ts
        first=ts if first is None else min(first,ts); last=ts if last is None else max(last,ts)
        counts['frames']+=1; counts['inbound' if incoming else 'outbound']+=1
        counts['measurement_frames']+=int(start<=ts<end)
    require(counts['frames']==captured and counts['measurement_frames']>0,'Capture count/measurement empty')
    require(max_regression<=1.,'Timestamp regression exceeds reorder budget')
    access=[]
    for line in (folder/'server/access.tsv').read_text(encoding='utf-8').splitlines():
        fields=line.split('\t'); require(len(fields)==8,'Access log format differs')
        access.append(fields)
    by_id={row[7]:row for row in access if row[7]!='-'}
    require(len(by_id)==sum(row[7]!='-' for row in access),'Duplicate server request identity')
    known=set(); outcomes=Counter(); durations=[]
    for index,seed in enumerate(m['client_seeds'],1):
        ready=read(folder/f'client{index}/ready.json'); final=read(folder/f'client{index}/client.json')
        require(ready['effective_seed']==final['effective_seed']==seed,'Client seed differs')
        require(final['schedule']==schedule and ready['ready_utc']<schedule['warmup_start_utc'],'Client schedule differs')
        require(ready['client_addresses']==[f'172.28.240.{9+index}'] and ready['service_addresses']==[web],'Resolution differs')
        require(not any(r.get('dst')=='default' for r in ready['routes']),'Client default route')
        rows=[json.loads(line) for line in (folder/f'client{index}/requests.jsonl').read_text(encoding='utf-8').splitlines()]
        totals=Counter()
        for row in rows:
            require(row.get('error') not in ('ResponseNotReady','CannotSendRequest','CannotSendHeader'),'HTTP client state-machine bug')
            rid=row['request_id']; require(rid not in known,'Repeated request ID'); known.add(rid)
            require(row['method'] in ('GET','HEAD') and row['path'] in m['payloads'],'Undeclared legitimate request')
            require(schedule['warmup_start_utc']<=row['start_utc']<end and row['end_utc']<=end+32,'Request outside bounded schedule')
            success=row['complete'] and row.get('status')==200
            if success:
                expected=m['payloads'][row['path']]
                require(int(row['content_length'])==expected['bytes'],'Response length differs')
                require(row['bytes']==(expected['bytes'] if row['method']=='GET' else 0),'Completed response size differs')
                require(row['method']=='HEAD' or row.get('body_integrity_ok') and row.get('body_sha256')==expected['sha256'],'Body integrity failure')
                require(rid in by_id and by_id[rid][2:6]==[f'172.28.240.{9+index}',row['method'],row['path'],'200'],'Completed request lacks matching server log')
            totals['attempts']+=1; totals['bytes']+=row['bytes']; totals['complete' if success else 'failed']+=1
            outcomes['complete' if success else 'failed']+=1
            outcomes['method_'+row['method']]+=1; durations.append(row['seconds'])
        require(all(totals[k]==v for k,v in final['totals'].items()),'Client counters differ')
    require(set(by_id)<=known,'Server request lacks declared client identity')
    router=read(folder/'router/ready.json'); after=read(folder/'router/final.json')
    require(router['profile']==m['profile'],'Impairment profile differs')
    require(not any(r.get('dst')=='default' for r in router['routes']),'Router default route')
    qdiscs=[q for items in after['tc_after'].values() for q in items]
    if m['profile']['shaping']:
        require(sum(q['kind']=='netem' for q in qdiscs)==2,'Declared shaping absent')
        require(all(q.get('packets',0)>0 for q in qdiscs if q['kind']=='netem'),'Configured shaping did not carry traffic')
    # Root prio counters can aggregate children: count leaf netem drops once.
    network_drops=sum(q.get('drops',0) for q in qdiscs if q['kind']=='netem')
    return {'session':m['session'],'role':m['role'],'condition':m['condition'],'repeat':m['repeat'],
        'engineering_quality_pass':True,'eligible_for_development':m['role']!='PREFLIGHT',
        'pcap_sha256':m['pcap_sha256'],'plan_sha256':m['plan_sha256'],'counts':dict(counts),
        'kernel_capture_drops':dropped,'router_qdisc_drops':network_drops,
        'router_qdisc_drops_are_legitimate_network_outcomes':True,
        'client_outcomes':dict(outcomes),'max_request_seconds':max(durations,default=0),
        'first_packet_utc':first,'last_packet_utc':last,'measurement_start_utc':start,'measurement_end_utc':end,
        'observation_ready_utc':c['ready_utc'],'observation_stop_signal_utc':c['stop_signal_utc'],
        'largest_timestamp_regression_seconds':max_regression,
        'failed_legitimate_requests_remain_benign':True,'study_training_ready':False,
        'scope':'Controlled declared legitimate scenario; not inferred public idle labels, final testing, model results or an unseen environment.'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('folder',type=Path); p.add_argument('--out',type=Path)
    args=p.parse_args(); result=audit(args.folder)
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
