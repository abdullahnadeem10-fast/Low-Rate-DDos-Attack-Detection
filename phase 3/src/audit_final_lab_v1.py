"""Score-blind capture/service/log qualification for declared final lab units."""
from collections import Counter
import csv
import json
import math
from pathlib import Path
import re
import socket
import sys
import time
import dpkt
from packet_model_policy import ROOT,read,sha,require
from audit_benign_session import frames
from replay_stress_session_v5 import extract
from frozen_suite import verify_freeze,validate_qualification
sys.path.insert(0,str(ROOT/'lab/final_v1'))
from collector import agents,SERVER_CONFIG


def jsonlines(path):return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def corroborated_initial(data,token,mechanism):
    marker=f'X-Research-Token: {token}\r\n'.encode('ascii')
    if marker not in data:return False
    if mechanism=='incomplete_header':return data.startswith(b'GET /small.bin HTTP/1.1\r\n') and b'\r\n\r\n' not in data
    return data.startswith(b'POST /sink/ HTTP/1.1\r\n') and b'Content-Length: 65536\r\n' in data and b'\r\n\r\n' in data and len(data.split(b'\r\n\r\n',1)[1])<65536


def truth_rows(seconds,entry,schedule,onset):
    """Controlled campaign exposure, not packet-maliciousness/denial labels.

All agents are purpose-controlled. Warmup/benign labels use that independent
provenance, never silence. An attempt with no corroborated initial payload
keeps its entire attack measurement unknown, and its episode unscorable.
"""
    a,b,c=(schedule[k] for k in ('warmup_start_utc','measurement_start_utc','measurement_end_utc'))
    for t in seconds:
        y=-1;family='unknown'
        if a<=t and t+1<=b:y=0;family='benign'
        elif b<=t and t+1<=c:
            if entry['kind']=='benign':y=0;family='benign'
            elif onset is not None and t>=math.ceil(onset):y=1;family=entry['mechanism']
        yield dict(utc_second=int(t),y=y,family=family,condition=entry['condition'])


def audit(folder):
    m=read(folder/'session.json');entry=m['entry'];c=read(folder/'capture/capture.json');schedule=m['schedule']
    require(m['state']=='collected_audit_pending' and m['cleanup_exit_code']==0,'Collection/cleanup incomplete')
    require(m['all_planned_outcomes_retained'] and m['model_scores_used_for_selection'] is False,'Outcome-selected unit')
    require(m['isolation']==dict(internal_bridge=True,no_published_ports=True,no_host_network=True,no_host_nic_changes=True),'Isolation differs')
    require((folder/'final.conf').read_text(encoding='utf-8')==SERVER_CONFIG,'Service configuration changed')
    require(sha(folder/'capture/traffic.pcap')==m['pcap_sha256'],'Capture bytes changed')
    require(not c['premature_exit'] and c['tcpdump_exit_code']==0,'Premature capture exit')
    require(c['ready_utc']<schedule['warmup_start_utc'] and c['stop_signal_utc']>=schedule['measurement_end_utc'],'Incomplete capture interval')
    probes=m['clock_probes'];require(len(probes)>=2 and probes[0]['host_after_utc']<schedule['warmup_start_utc'] and probes[-1]['host_before_utc']>=schedule['measurement_end_utc'],'Clock probes miss measurement')
    require(all(0<=p['host_after_utc']-p['host_before_utc']<=3 and p['host_before_utc']-.5<=p['container_utc']<=p['host_after_utc']+.5 for p in probes),'Clock disagreement')
    require(all(0<b['host_before_utc']-a['host_before_utc']<=20 and b['container_utc']>a['container_utc'] for a,b in zip(probes,probes[1:])),'Clock/probe gap')
    text=(folder/'capture/tcpdump.log').read_text(encoding='utf-8')
    def counter(pattern):
        v=re.findall(pattern,text);require(len(v)==1,'Missing capture counter');return int(v[0])
    kernel=counter(r'(\d+) packets dropped by kernel');captured=counter(r'(\d+) packets captured');require(kernel==0,'Kernel capture loss')
    router=read(folder/'router/ready.json');router_mac=bytes.fromhex(router['router_mac'].replace(':',''));web_mac=bytes.fromhex(c['web_mac'].replace(':',''))
    require(router['icmp_redirects_disabled'] and c['filter']==f'tcp port 80 and ether host {c["web_mac"]}','Route/capture scope differs')
    specs=agents(entry);addresses={s['own'] for s in specs.values()};tokens={};outcomes=Counter();all_requests=[];actual_slow_sources=set()
    for name,spec in specs.items():
        ready=read(folder/name/'ready.json');final=read(folder/name/'final.json')
        require(ready['spec']==final['spec']==spec and final['schedule']==schedule and final['completed'],'Agent identity/schedule differs')
        require(ready['ready_utc']<schedule['warmup_start_utc'] and not any(r.get('dst')=='default' for r in ready['routes']),'Agent route/start differs')
        require(final['finished_utc']<=schedule['measurement_end_utc']+32,'Agent outside bounded drain')
        if spec['role']=='slow':
            events=jsonlines(folder/name/'events.jsonl');initial=[v for v in events if v['event']=='initial_payload_sent']
            require(len(initial)==final['initial_payloads_sent'],'Slow initial counter differs')
            for v in initial:
                require(v['token'] not in tokens and v['source']==spec['own'] and schedule['measurement_start_utc']<=v['utc']<schedule['measurement_end_utc']+1,'Slow identity/start differs')
                tokens[v['token']]=dict(**v,mechanism=spec['mechanism'])
            outcomes['initial_slow_payloads']+=len(initial);outcomes['slow_attempts']+=final['attempts']
        else:
            requests=jsonlines(folder/name/'requests.jsonl');all_requests.extend((spec,v) for v in requests)
            attempts=[v for v in requests if not v.get('scheduler_skip')]
            require(len(attempts)==final['totals']['attempted'] and sum(v['success'] for v in attempts)==final['totals']['success'],'HTTP counters differ')
            for v in attempts:
                require(v['method'] in ('GET','HEAD','POST') and v['path'] in m['payloads'],'Undeclared complete request')
                require(not v.get('error') or not any(x in v['error'] for x in ('BodyIntegrityMismatch','ResponseNotReady','CannotSendRequest','CannotSendHeader')),'HTTP implementation/integrity defect')
                require(schedule['warmup_start_utc']<=v['start_utc']<schedule['measurement_end_utc'] and v['end_utc']<=schedule['measurement_end_utc']+32,'HTTP clock outside schedule')
                if v['success'] and v['method']!='HEAD':require(v['bytes']==m['payloads'][v['path']]['bytes'] and v['body_sha256']==m['payloads'][v['path']]['sha256'],'Successful body differs')
                outcomes[spec['role']+'_success' if v['success'] else spec['role']+'_failed']+=1
            if spec['role']=='probe':require(len(requests)==int(schedule['measurement_end_utc']-schedule['warmup_start_utc']),'Missing fixed probe slots')
    counts=Counter();corroborated={};previous=float('-inf');regression=0
    for ts,frame,wire in frames(folder/'capture/traffic.pcap'):
        require(len(frame)==wire and wire<=1514,'Truncated/aggregated frame')
        ethernet=dpkt.ethernet.Ethernet(frame);ip=ethernet.data
        require(isinstance(ip,dpkt.ip.IP) and not ip.offset and isinstance(ip.data,dpkt.tcp.TCP),'Unsupported packet/fragment')
        tcp=ip.data;src,dst=socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst)
        incoming=src in addresses and dst=='172.28.240.100' and tcp.dport==80
        outgoing=src=='172.28.240.100' and dst in addresses and tcp.sport==80
        require(incoming or outgoing,'Off-scope traffic')
        require((ethernet.src if incoming else ethernet.dst)==router_mac and (ethernet.dst if incoming else ethernet.src)==web_mac,'Router bypass/flooded nonservice copy')
        require(c['start_utc']-2<=ts<=c['copy_finished_utc']+2,'Capture clock mismatch')
        regression=max(regression,previous-ts);previous=ts;counts['frames']+=1;counts['measurement_frames']+=int(schedule['measurement_start_utc']<=ts<schedule['measurement_end_utc'])
        if incoming and src in ('172.28.240.20','172.28.240.21','172.28.240.22'):
            counts['attack_source_frames']+=1;actual_slow_sources.add(src)
            for match in re.finditer(rb'X-Research-Token: ([A-Za-z0-9-]+)\r\n',bytes(tcp.data)):
                token=match[1].decode();require(token in tokens,'Undeclared attack token');v=tokens[token]
                require((src,tcp.sport)==(v['source'],v['source_port']) and abs(ts-v['utc'])<=1 and corroborated_initial(bytes(tcp.data),token,v['mechanism']),'Attack payload/clock corroboration failed')
                corroborated[token]=min(ts,corroborated.get(token,ts))
    require(counts['frames']==captured and counts['measurement_frames']>0 and regression<=1,'Capture counts/reorder differ')
    require(set(tokens)==set(corroborated),'Uncorroborated initial slow payloads')
    onset=min(corroborated.values(),default=None)
    # Completed service logs independently corroborate successful GET/HEAD/POST.
    access=[]
    for line in (folder/'server/access.tsv').read_text(encoding='utf-8').splitlines():
        fields=line.split('\t');require(len(fields)==8,'Service log schema differs');access.append(fields)
    by_id={r[7]:r for r in access if r[7]!='-'};require(len(by_id)==sum(r[7]!='-' for r in access),'Duplicate service request id')
    require(set(by_id)<={v['request_id'] for _,v in all_requests},'Unattributed server request identity')
    for spec,v in all_requests:
        if v.get('success'):
            require(v['request_id'] in by_id and by_id[v['request_id']][2:6]==[spec['own'],v['method'],v['path'],'200'],'Successful request lacks server corroboration')
    cgi_warm=sum(v.get('success',False) and v.get('method')=='POST' and v.get('start_utc',float('inf'))<schedule['measurement_start_utc'] for _,v in all_requests)
    qdiscs=[q for items in read(folder/'router/final.json')['tc_after'].values() for q in items]
    require(not any(r.get('dst')=='default' for r in router['routes']),'Router default route')
    if entry['condition']=='long_lived_or_congested':require(sum(q['kind']=='netem' for q in qdiscs)==2 and all(q.get('packets',0)>0 for q in qdiscs if q['kind']=='netem'),'Declared netem did not carry traffic')
    probe_rows=[v for s,v in all_requests if s['role']=='probe']
    impact={}
    for label,a,b in [('warmup',schedule['warmup_start_utc'],schedule['measurement_start_utc']),('measurement',schedule['measurement_start_utc'],schedule['measurement_end_utc'])]:
        rows=[v for v in probe_rows if a<=v.get('scheduled_utc',-1)<b];ok=[v for v in rows if v['success']]
        impact[label]=dict(scheduled_slots=len(rows),timely_successes=len(ok),failed_or_skipped=len(rows)-len(ok),latencies_seconds=[v['seconds'] for v in ok])
    return dict(engineering_quality_pass=True,unit_id=entry['id'],kind=entry['kind'],preflight=entry['preflight'],counts=dict(counts),kernel_capture_drops=kernel,
        router_qdisc_drops=sum(q.get('drops',0) for q in qdiscs if q['kind']=='netem'),largest_timestamp_regression_seconds=regression,
        CGI_warm_complete_POSTs=cgi_warm,client_outcomes=dict(outcomes),actual_slow_source_count=len(actual_slow_sources),corroborated_initial_payloads=len(corroborated),
        observed_attack_onset_utc=onset,ineffective_or_no_initial_payload=entry['kind']=='attack' and onset is None,
        observation_ready_utc=c['ready_utc'],observation_stop_utc=c['stop_signal_utc'],impact=impact,
        label_scope='Controlled generator-exposure intervals, including ineffective attacks; not every packet malicious, resource occupancy or demonstrated denial.',
        model_scores_accessed=False,failed_legitimate_requests_retained=True)


def qualify(folder):
    """Fresh full-clock replay after audit; never load a model or score array."""
    out=folder/'qualified_v1';require(not out.exists(),'Preserve qualification attempt');out.mkdir()
    evidence=audit(folder);m=read(folder/'session.json');entry=m['entry'];frozen,gate=verify_freeze()
    report=extract(folder/'capture/traffic.pcap',evidence['observation_ready_utc'],evidence['observation_stop_utc'],out/'features.csv')
    with (out/'features.csv').open(encoding='utf-8',newline='') as stream:rows=list(csv.DictReader(stream))
    with (out/'truth.csv').open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['utc_second','y','family','condition']);writer.writeheader();writer.writerows(truth_rows([int(r['utc_second']) for r in rows],entry,m['schedule'],evidence['observed_attack_onset_utc']))
    def write(name,value):
        path=out/name;path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n');return dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path))
    provenance=write('provenance.json',dict(session_sha256=sha(folder/'session.json'),raw_sha256=m['pcap_sha256'],authorization=m['authorization'],all_planned_outcomes_retained=True))
    clock=write('clock_labels.json',dict(replay=report,audit=evidence,truth_policy='Controlled campaign exposure, onset first token-corroborated PCAP payload. Warmup/benign from declared agent provenance; no public idle inference. No payload=>unknown attack measurement.'))
    if entry['preflight']:
        require(evidence['CGI_warm_complete_POSTs']>0 or entry['condition']=='long_lived_or_congested','Preflight CGI functionality not demonstrated')
        write('preflight_result.json',dict(audit=evidence,replay=report,excluded_from_all_model_and_final_data=True));return evidence
    slot='lab_slow' if entry['kind']=='attack' else 'lab_benign';spec=frozen['source_slots'][slot];onset=evidence['observed_attack_onset_utc'];schedule=m['schedule']
    episodes=[]
    if entry['kind']=='attack' and onset is not None:episodes=[dict(id=entry['id'],family=entry['mechanism'],onset_low=onset,onset_high=onset,end=schedule['measurement_end_utc'],impact_class='See measured probe failures/latencies; no automatic denial assertion')]
    record=dict(freeze_sha256=gate['freeze_sha256'],acquisition_sha256=m['authorization']['acquisition_sha256'],source_slot=slot,source_id=spec['source_id'],role=spec['role'],
        parent_recording=entry['id'],group_id=entry['id'],raw_sha256=m['pcap_sha256'],qualification_pass=True,model_scores_used_for_qualification=False,
        unknown_or_idle_inferred_benign=False,feature_state_crosses_groups=False,feature_core_sha256=frozen['feature_core_sha256'],predictor_columns=frozen['predictor_columns'],
        qualified_after_seal_utc=time.time(),payload_access_started_utc=m['payload_access_started_utc'],capture_started_utc=m['capture_started_utc'],
        qualification_evidence=dict(provenance=provenance,clock_labels=clock),features=dict(path=(out/'features.csv').relative_to(ROOT).as_posix(),sha256=sha(out/'features.csv')),
        ground_truth=dict(path=(out/'truth.csv').relative_to(ROOT).as_posix(),sha256=sha(out/'truth.csv')),
        scorable_clock_segments=[dict(start=report['first_fully_observed_second'],end=report['exclusive_complete_boundary'],core_reset=True,boundary_guard_seconds=50)],
        evaluation_intervals=[[schedule['measurement_start_utc'],schedule['measurement_end_utc']]],episodes=episodes,
        packet_quality=dict(truncated_records=0,selected_fragmented_tcp=0,late_selected_dropped=report['late_packets'],kernel_capture_drops=0),
        service=dict(protocol='TCP',port=80),label_provenance_verified=True,clock_alignment_verified=True,isolated_private_lab_verified=True,all_planned_outcomes_retained=True,
        qualification_exclusions=dict(planned_episodes=int(entry['kind']=='attack'),no_corroborated_initial_payload=int(entry['kind']=='attack' and onset is None),no_silent_replacement=True))
    validate_qualification(record,frozen,gate['freeze_sha256']);write('qualification.json',record)
    return evidence
