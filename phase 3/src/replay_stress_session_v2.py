"""Fresh-state causal replay bounded by corroborated capture observation times.

Unlike the old PCAP-EOF wrapper, observed idle tails are advanced through the
unchanged feature core. Only complete seconds inside capture ready/stop bounds
are emitted; no endpoint state or history is shared between sessions.
"""
import argparse
import csv
import heapq
import json
import math
from pathlib import Path
import socket
import dpkt
from audit_benign_session import frames
from audit_stress_session_v2 import audit, read, require, sha
from causal_features import CausalFeatures, Event


def extract(pcap, ready, stop, output):
    first,boundary=math.ceil(ready),math.floor(stop)
    require(first<boundary,'No fully observed interval')
    core=CausalFeatures(timeout=30); core.second=first
    heap=[]; sequence=0; max_seen=float(first); last_processed=float('-inf')
    counts={'rows':0,'selected_packets':0,'late_packets':0}
    writer=None
    with output.open('w',encoding='utf-8',newline='') as f:
        def emit(rows):
            nonlocal writer
            for row in rows:
                if writer is None:
                    writer=csv.DictWriter(f,fieldnames=list(row)); writer.writeheader()
                writer.writerow(row); counts['rows']+=1
        def drain(before):
            nonlocal last_processed
            while heap and heap[0][0]<before:
                _,_,event=heapq.heappop(heap)
                if event.timestamp<last_processed or event.timestamp<core.second:
                    counts['late_packets']+=1; continue
                emit(core.add(event)); last_processed=event.timestamp
        for ts,frame,_ in frames(pcap):
            if not first<=ts<boundary: continue
            ip=dpkt.ethernet.Ethernet(frame).data
            require(isinstance(ip,dpkt.ip.IP) and isinstance(ip.data,dpkt.tcp.TCP),'Unexpected packet type')
            tcp=ip.data; inbound=socket.inet_ntoa(ip.dst)=='172.28.240.100' and tcp.dport==80
            outbound=socket.inet_ntoa(ip.src)=='172.28.240.100' and tcp.sport==80
            require(inbound or outbound,'Off-service packet')
            event=Event(ts,socket.inet_ntoa(ip.src if inbound else ip.dst),tcp.sport if inbound else tcp.dport,inbound,len(frame),tcp.flags)
            sequence+=1; counts['selected_packets']+=1; heapq.heappush(heap,(ts,sequence,event))
            max_seen=max(max_seen,ts); watermark=max_seen-1.
            drain(watermark); emit(core.finish(math.floor(watermark)))
        drain(boundary); emit(core.finish(boundary))
    require(counts['late_packets']==0,'Selected late events lost')
    require(counts['rows']==boundary-first,'Observation timeline incomplete')
    return dict(counts,first_fully_observed_second=first,exclusive_complete_boundary=boundary,
                observation_interval_source='Capture ready/stop-signal wall times, not packet EOF',
                features_sha256=sha(output),feature_core_sha256=sha(Path(__file__).with_name('causal_features.py')))


def replay(folder):
    evidence=audit(folder); m=read(folder/'session.json')
    output=folder/'causal_observed_v2'; output.mkdir(exist_ok=False)
    report=extract(folder/'capture/traffic.pcap',evidence['observation_ready_utc'],evidence['observation_stop_signal_utc'],output/'features.csv')
    with (output/'features.csv').open(encoding='utf-8',newline='') as f:
        rows=list(csv.DictReader(f))
    measurement=[r for r in rows if evidence['measurement_start_utc']<=int(r['utc_second'])<evidence['measurement_end_utc']]
    require(len(measurement)==m['duration'] and all(r['history_complete']=='1' for r in measurement),'Incomplete warmed measurement')
    report.update(session=m['session'],role=m['role'],condition=m['condition'],repeat=m['repeat'],
                  measurement_rows=len(measurement),eligible_for_development=m['role']!='PREFLIGHT',
                  all_measurement_labels=0,failed_legitimate_requests_retained=True,study_training_ready=False,
                  scope='Engineering replay only; PREFLIGHT excluded, no registry integration or model fitting.')
    (output/'replay.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('folder',type=Path); a=p.parse_args()
    print(json.dumps(replay(a.folder),indent=2))
