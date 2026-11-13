"""Bounded agents for one fixed, non-routable research lab; no arbitrary target.

Slow agents never run in preflight. All connection/rate/duration caps are local
and must also agree with the source-specific acquisition declaration.
"""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import socket
import sys
import threading
import time
sys.path.insert(0,'/stress')
from network import WEB,ROUTER_CLIENT,SERVER_SUBNET,command,device_for,no_default_route,offloads

OUTPUT=Path('/output');LOCK=threading.Lock()


def write(name,value):
    (OUTPUT/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def emit(stream,value):
    with LOCK:stream.write(json.dumps(value)+'\n');stream.flush()


def validate(spec,schedule):
    if WEB!='172.28.240.100' or spec['role'] not in ('benign','probe','slow'):raise ValueError('Fixed private scope only')
    a,b,c=(schedule[k] for k in ('warmup_start_utc','measurement_start_utc','measurement_end_utc'))
    if b-a!=60 or not 30<=c-b<=240 or c-time.time()>310:raise ValueError('Unbounded schedule')
    if spec['role']=='slow':
        if spec['mechanism'] not in ('incomplete_header','slow_request_body') or spec['connections'] not in (10,60) or spec['interval'] not in (5,20):raise ValueError('Undeclared slow scenario')
        if spec['own'] not in ('172.28.240.20','172.28.240.21','172.28.240.22'):raise ValueError('Slow agent address outside lab')
    elif spec['role']=='probe':
        if spec['own']!='172.28.240.30':raise ValueError('Probe address differs')
    elif spec['own'] not in ('172.28.240.10','172.28.240.11','172.28.240.12') or spec['condition'] not in ('ordinary','bursts','flash','long_lived_or_congested'):raise ValueError('Benign address/profile differs')


def initial_request(mechanism,token):
    if mechanism=='incomplete_header':return f'GET /small.bin HTTP/1.1\r\nHost: web\r\nX-Research-Token: {token}\r\n'.encode('ascii')
    if mechanism=='slow_request_body':return f'POST /sink/ HTTP/1.1\r\nHost: web\r\nX-Research-Token: {token}\r\nContent-Length: 65536\r\nConnection: close\r\n\r\nx'.encode('ascii')
    raise ValueError('Unapproved mechanism')


def request(connection,path,method,rid,expected,deadline):
    start=time.time();tick=time.perf_counter();n=0;digest=hashlib.sha256();status=None;error=None;complete=False
    body=b'complete' if method=='POST' else None
    try:
        connection.request(method,path,body=body,headers={'X-Request-Id':rid,'Content-Type':'application/octet-stream'})
        response=connection.getresponse();status=response.status
        if method=='HEAD':response.read();complete=True
        else:
            while time.time()<deadline:
                block=response.read1(16384)
                if not block:complete=True;break
                n+=len(block);digest.update(block)
        if not complete or time.time()>deadline:error='DeclaredReadDeadline'
        if complete and status==200 and method!='HEAD' and (n!=expected['bytes'] or digest.hexdigest()!=expected['sha256']):raise ValueError('BodyIntegrityMismatch')
    except Exception as e:error=type(e).__name__+':'+str(e)
    return dict(request_id=rid,path=path,method=method,start_utc=start,end_utc=time.time(),seconds=time.perf_counter()-tick,
        bytes=n,status=status,complete=complete,error=error,success=complete and status==200 and error is None,
        body_sha256=digest.hexdigest() if complete and method!='HEAD' else None)


def ordinary(spec,schedule,payloads,probe=False):
    start,end=schedule['warmup_start_utc'],schedule['measurement_end_utc'];rng=random.Random(spec['seed'])
    paths=['/small.bin','/medium.bin','/large.bin'];counter=0;totals={'attempted':0,'success':0,'failed':0,'scheduler_skips':0}
    with (OUTPUT/'requests.jsonl').open('w',encoding='utf-8') as stream:
        def one(sequence,scheduled=None):
            path='/sink/' if probe and sequence%2 else '/small.bin' if probe else '/bulk.bin' if spec['condition']=='long_lived_or_congested' else paths[sequence%len(paths)]
            method='POST' if path=='/sink/' else 'GET' if probe or sequence%5 else 'HEAD'
            budget=2 if probe else 90 if path=='/bulk.bin' else 6
            connection=http.client.HTTPConnection(WEB,80,timeout=1 if probe else 2 if budget==6 else 10)
            value=request(connection,path,method,f'{spec["unit_id"]}-{spec["own"].split(".")[-1]}-{sequence}',payloads[path],min(time.time()+budget,end+20))
            connection.close();value['scheduled_utc']=scheduled;emit(stream,value)
            with LOCK:
                totals['attempted']+=1;totals['success' if value['success'] else 'failed']+=1
        while time.time()<start:time.sleep(.05)
        if probe:
            # Fixed1Hz slots; bounded three workers. Missed slots remain failures
            # of the probe schedule, never silently disappear from availability.
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                pending=[]
                for slot in range(int(end-start)):
                    due=start+slot
                    while time.time()<due:time.sleep(.02)
                    for f in pending:
                        if f.done():f.result()
                    pending=[f for f in pending if not f.done()]
                    if time.time()-due>.5 or len(pending)>=3:
                        totals['scheduler_skips']+=1;emit(stream,dict(scheduled_utc=due,request_id=f'skipped-{slot}',scheduler_skip=True,success=False));continue
                    pending.append(pool.submit(one,slot,due))
                for future in pending:future.result()
        else:
            while time.time()<end and counter<2400:
                one(counter);counter+=1
                delay=3 if spec['condition']=='bursts' and counter%4==0 else .1 if spec['condition']=='bursts' else .15 if spec['condition']=='flash' else rng.uniform(.3,.8)
                time.sleep(min(delay,max(0,end-time.time())))
    write('final.json',dict(spec=spec,schedule=schedule,totals=totals,finished_utc=time.time(),completed=True))


def slow(spec,schedule):
    start,end=schedule['measurement_start_utc'],schedule['measurement_end_utc'];rng=random.Random(spec['seed'])
    active={};next_connect={i:start+rng.uniform(0,1) for i in range(spec['connections'])};generations={i:0 for i in next_connect};attempts=sent=0
    with (OUTPUT/'events.jsonl').open('w',encoding='utf-8') as stream:
        while time.time()<start:time.sleep(.05)
        while time.time()<end:
            now=time.time()
            for slot in range(spec['connections']):
                if time.time()>=end:break
                if slot not in active and now>=next_connect[slot] and attempts<15000:
                    attempts+=1;generations[slot]+=1;token=f'{spec["unit_id"]}-{spec["own"].split(".")[-1]}-{slot}-{generations[slot]}'
                    sock=None
                    try:
                        sock=socket.create_connection((WEB,80),timeout=.2);sock.sendall(initial_request(spec['mechanism'],token));local=sock.getsockname();sock.setblocking(False)
                        active[slot]=(sock,time.time()+spec['interval'],token,local[1]);sent+=1
                        emit(stream,dict(event='initial_payload_sent',utc=time.time(),token=token,source=local[0],source_port=local[1],slot=slot))
                    except Exception as e:
                        if sock:sock.close()
                        emit(stream,dict(event='connect_or_initial_send_failed',utc=time.time(),slot=slot,error=type(e).__name__));next_connect[slot]=time.time()+1
                if slot not in active:continue
                sock,due,token,port=active[slot];reason=None
                try:
                    try:
                        response=sock.recv(4096)
                        reason='peer_eof' if not response else 'server_response'
                    except BlockingIOError:pass
                    if reason is None and time.time()>=due:
                        payload=b'X-Keep: x\r\n' if spec['mechanism']=='incomplete_header' else b'x'
                        n=sock.send(payload)
                        if n!=len(payload):raise OSError('Partial keep write')
                        active[slot]=(sock,time.time()+spec['interval'],token,port)
                        emit(stream,dict(event='keep_payload_sent',utc=time.time(),token=token,source_port=port,bytes=n))
                except OSError as e:reason=type(e).__name__
                if reason:
                    sock.close();del active[slot];next_connect[slot]=time.time()+1
                    emit(stream,dict(event='connection_finished',utc=time.time(),token=token,source_port=port,reason=reason))
            time.sleep(.05)
        for sock,_,token,port in active.values():
            sock.close();emit(stream,dict(event='planned_stop_close',utc=time.time(),token=token,source_port=port))
    write('final.json',dict(spec=spec,schedule=schedule,attempts=attempts,initial_payloads_sent=sent,finished_utc=time.time(),completed=True,
        ineffective_attacks_retained=True,actual_connection_occupancy_not_inferred_from_socket_count=True))


def main():
    spec=json.loads(os.environ['AGENT_JSON']);device=device_for(spec['own'])
    command('ip','route','replace',SERVER_SUBNET,'via',ROUTER_CLIENT,'dev',device);settings=offloads(device);routes=no_default_route()
    write('ready.json',dict(spec=spec,ready_utc=time.time(),routes=routes,offloads=settings,service=WEB+':80'))
    tick=time.monotonic()
    while not Path('/control/schedule.json').exists():
        if time.monotonic()-tick>60:raise RuntimeError('No bounded schedule')
        time.sleep(.1)
    schedule=json.loads(Path('/control/schedule.json').read_text());validate(spec,schedule)
    if spec['role']=='slow':slow(spec,schedule)
    else:ordinary(spec,schedule,json.loads(Path('/control/payloads.json').read_text()),spec['role']=='probe')


if __name__=='__main__':main()
