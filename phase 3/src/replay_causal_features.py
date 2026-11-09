"""Replay one permitted development service through bounded-lateness features.

The last partial second is omitted. A 1-second event-time reorder budget is an
explicit proposed policy; late events are counted and dropped, never backfilled.
No live latency or packet-label correctness is claimed by this extractor.
"""
import argparse
import csv
import heapq
import io
import json
import math
from pathlib import Path
import socket
import time

import dpkt
from causal_features import CausalFeatures, Event
from packet_pilot import complete_capture


def extract(path, service, out, prefix=False):
    ip_text,port_text=service.rsplit(':',1)
    address,port=socket.inet_aton(ip_text),int(port_text)
    started=time.perf_counter(); out.parent.mkdir(parents=True,exist_ok=True)
    if prefix:
        raw=path.read_bytes(); reader_class,end=complete_capture(raw)
        stream=io.BytesIO(raw[:end]); reader=reader_class(stream)
    else:
        stream=path.open('rb'); magic=stream.read(4); stream.seek(0)
        reader=dpkt.pcapng.Reader(stream) if magic==b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(stream)
    if reader.datalink()!=dpkt.pcap.DLT_EN10MB: raise ValueError('Ethernet required')
    core=CausalFeatures(timeout=30); heap=[]; writer=None
    counts={'frames':0,'selected_tcp':0,'late_selected_dropped':0,'decode_errors':0,'rows':0,'fully_warmed_rows':0}
    max_seen=-math.inf; first=None; last_processed=-math.inf; sequence=0
    max_adjacent_regression=0.; previous=-math.inf

    def emit(rows,f):
        nonlocal writer
        for row in rows:
            if writer is None:
                writer=csv.DictWriter(f,fieldnames=list(row)); writer.writeheader()
            writer.writerow(row); counts['rows']+=1; counts['fully_warmed_rows']+=row['history_complete']

    def drain(before,f):
        nonlocal last_processed
        while heap and heap[0][0] < before:
            _,_,event=heapq.heappop(heap)
            if event.timestamp < last_processed or core.second is not None and event.timestamp < core.second:
                counts['late_selected_dropped']+=1; continue
            emit(core.add(event),f); last_processed=event.timestamp

    with stream,out.open('w',newline='',encoding='utf-8') as f:
        for ts,frame in reader:
            ts=float(ts); counts['frames']+=1
            if first is None: first=math.floor(ts)+1
            max_adjacent_regression=max(max_adjacent_regression,previous-ts); previous=ts
            max_seen=max(max_seen,ts)
            try:
                ip=dpkt.ethernet.Ethernet(frame).data
                if isinstance(ip,dpkt.ip.IP) and not ip.offset and isinstance(ip.data,dpkt.tcp.TCP):
                    tcp=ip.data
                    inbound=ip.dst==address and tcp.dport==port
                    outbound=ip.src==address and tcp.sport==port
                    if (inbound or outbound) and ts>=first:
                        client=socket.inet_ntoa(ip.src if inbound else ip.dst)
                        client_port=tcp.sport if inbound else tcp.dport
                        event=Event(ts,client,client_port,inbound,len(frame),tcp.flags)
                        sequence+=1; counts['selected_tcp']+=1
                        heapq.heappush(heap,(ts,sequence,event))
            except (dpkt.UnpackError,ValueError): counts['decode_errors']+=1
            watermark=max_seen-1.
            drain(watermark,f)
            if core.second is not None: emit(core.finish(math.floor(watermark)),f)
            if counts['frames']%2000000==0: print(f'Features: {counts["frames"]:,} frames, {counts["rows"]:,} seconds',flush=True)
        if max_seen!=-math.inf:
            boundary=math.floor(max_seen)
            drain(boundary,f)
            if core.second is not None: emit(core.finish(boundary),f)
    if not counts['rows']: raise ValueError('No service rows extracted')
    report={'input_file':path.name,'service':service,'counts':counts,'reorder_budget_seconds':1.,
            'connection_inactivity_timeout_seconds':30,'history_seconds':[5,10,20],
            'largest_adjacent_timestamp_regression_seconds':max_adjacent_regression,
            'elapsed_seconds':round(time.perf_counter()-started,3),
            'scope':'Causal replay engineering features; no final labels, model scoring or live delay claim.'}
    out.with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap',type=Path,required=True); p.add_argument('--service',required=True)
    p.add_argument('--out',type=Path,required=True); p.add_argument('--prefix',action='store_true')
    args=p.parse_args(); extract(args.pcap,args.service,args.out,args.prefix)
