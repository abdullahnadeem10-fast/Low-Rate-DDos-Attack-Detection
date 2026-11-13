"""Pre-access acquisition declarations; never collect traffic or score models."""
import argparse
import json
import random
import time
from packet_model_policy import ROOT,read,sha,require
from frozen_suite import verify_freeze

CONDITIONS=('ordinary','bursts','flash','long_lived_or_congested')
SOURCES=('lab_benign','lab_slow')
FILES=('lab/final_v1/agent.py','lab/final_v1/capture_final.py','lab/final_v1/collector.py','lab/final_v1/sink.sh',
       'src/final_lab_policy_v1.py','src/audit_final_lab_v1.py','src/run_final_lab_v1.py','src/test_final_lab_v1.py')


def seed_values(value):
    result=set()
    def integers(v):
        if isinstance(v,int) and not isinstance(v,bool):result.add(v)
        elif isinstance(v,list):
            for item in v:integers(item)
        elif isinstance(v,dict):
            for item in v.values():integers(item)
    def walk(v):
        if isinstance(v,dict):
            for key,item in v.items():
                if 'seed' in key.lower():integers(item)
                walk(item)
        elif isinstance(v,list):
            for item in v:walk(item)
    walk(value);return result


def matrix(reserved=()):
    rng=random.Random(20261114);used=set(reserved);units=[]
    def next_seed():
        while True:
            value=rng.randrange(100000000,2100000000)
            if value not in used:used.add(value);return value
    def entry(id,kind,condition,repeat,preflight=False,**extra):
        return dict(id=id,kind=kind,condition=condition,repeat=repeat,preflight=preflight,warmup=60,duration=30 if preflight else 240 if kind=='attack' else 180,
                    agent_seeds=[next_seed() for _ in range(7)],net_seeds=[next_seed() for _ in range(2)],**extra)
    for condition in CONDITIONS:
        for repeat in range(1,6):units.append(entry(f'final-b-{len(units)+1:03d}','benign',condition,repeat))
    n=0
    for mechanism in ('incomplete_header','slow_request_body'):
        for sources in (1,3):
            for connections,interval in ((10,20),(60,5)):
                for repeat in range(1,6):
                    n+=1;units.append(entry(f'final-a-{n:03d}','attack',mechanism,repeat,mechanism=mechanism,sources=sources,connections=connections,interval=interval))
    rng.shuffle(units)
    for order,u in enumerate(units):u['run_order']=order
    preflights=[entry(f'final-p-{i+1:02d}','benign',condition,0,True,run_order=i) for i,condition in enumerate(('ordinary','flash','long_lived_or_congested'))]
    return units,preflights


def declare():
    frozen,gate=verify_freeze();paths=[ROOT/f'plan/final_lab_{slot}_acquisition_v1.json' for slot in SOURCES]
    validation_path=ROOT/'results/development/validation_final_lab_seal_2026-11-13.json';validation=read(validation_path)
    require(validation['all_tests_passed'] and validation['tests_run']>=216 and validation['skipped']==0,'Final-lab fixtures incomplete')
    runtime_path=ROOT/'results/development/final_lab_runtime_checks_v1.json';runtime=read(runtime_path)
    require(runtime['corrected_no_network_Apache_syntax_check_passed'] and runtime['embedded_network_helper_sha256']==sha(ROOT/'lab/stress_v5/network.py'),'Pinned runtime capability check incomplete')
    seals=[ROOT/f'results/qualification/{slot}_acquisition_seal_v1.json' for slot in SOURCES]
    require(not any(p.exists() for p in [*paths,*seals,ROOT/'data/final_lab_v1']),'Never overwrite completed/attempted acquisition version')
    reserved=set()
    for path in (ROOT/'plan').glob('*.json'):reserved|=seed_values(read(path))
    units,preflights=matrix(reserved);source={name:sha(ROOT/name) for name in FILES};now=time.time()
    base=dict(version='final_lab_acquisition_v1',sealed_at_utc=now,freeze_sha256=gate['freeze_sha256'],
        declared_before_payload_access=True,model_scores_used_for_selection=False,source_sha256=source,collection_order_seed=20261114,
        engineering_validation=dict(path=validation_path.relative_to(ROOT).as_posix(),sha256=sha(validation_path),tests=validation['tests_run']),
        runtime_checks=dict(path=runtime_path.relative_to(ROOT).as_posix(),sha256=sha(runtime_path)),
        qualification_rules=dict(fixed_private_service='172.28.240.100:80',network='One internal IPv4 Docker bridge; forced /32 router path; no NAT, published ports, host networking/NIC changes, image pulls or target options.',
            capture='Web-MAC-scoped TCP80, nonpromiscuous, full snaplen, offloads disabled; reconcile tcpdump/frame counts, zero kernel drops/truncation/fragments/selected-late loss; router-MAC proof. Router qdisc drops are outcomes.',
            clocks='Host/VM probes<=3s uncertainty envelope with0.5s margin,<=20s gaps, host loop pauses<=5s. Capture ready before warmup through measurement/drain. Complete seconds only;50s start guard; fresh unchanged core per unit.',
            labels='Controlled agent provenance; all legitimate failures remain benign. Attack labels mean ongoing controlled campaign exposure after first log/token/PCAP-corroborated incomplete payload, including ineffective attacks. Not every packet malicious or demonstrated denial/occupancy. First partial second unknown; no initial payload=>unknown measurement and recorded unscorable planned episode. Observation tail unknown.',
            onset='First observed PCAP initial payload with declared unique token and source/port, within1s of agent send log. Exact observed traffic onset; no inference of resource exhaustion onset. Fixed measurement end,180s frozen evaluation horizon.',
            outcomes='Retain every attempt, service crash, ineffective attack, failed legitimate request and unsupported unit. No automatic recollection/replacement, threshold/model changes or exclusion from detector outcomes.',
            service='Pinned Apache event MPM plus bounded shell CGI body reader; existing mod_reqtimeout/default request-read limits unchanged, Timeout60/KeepAlive10/max8 preserved. Complete POST and GET/HEAD corroborated before attacks.',
            impact='Fixed1Hz alternating complete GET small/POST body probes, three bounded workers,2s request budget. Record late/failing/skipped slots and timely latency distributions separately for warmup/measurement. Probe evidence is service impact, not detector latency or population SLA.',
            inference='No model/score loading in collector/auditor. Gated frozen scoring is a separate later step.'),
        software=dict(tools_image='sha256:bcd95e916f898bfad243bd3d4e8ccaf542cbe9d870e782ee62c45e5473f8112b',
            apache_image='httpd:2.4@sha256:ce3b1e5ab31c4b1b6aba298b935cb88bc6ca1d643446b69d396406db5550bf68',
            new_scripts='Read-only bind mount, hashed above; no rebuild or package download.'),
        scheduling='One session at a time; fixed shuffled global order across60 final units.60s warmup;180s benign/240s attack measurement,<=32s bounded drain. Three30s benign-only preflights are excluded.',
        independence='Fresh per-unit containers/seeds/core; all same host/image/service. These are repeated trials, not independent environments. Parent is whole session; no windows/algorithm seeds as traffic replications.',
        preflight_gate='All three excluded preflights require quality/replay pass; ordinary/flash require complete warm POST, long requires actual shaped traffic. No final traffic until all pass. No preflight enters models/final scoring.',
        reserved_seed_values_avoided=len(reserved),final_payloads_previously_accessed=False,model_changes=False,mitigation_or_blocking=False)
    for slot,path,seal in zip(SOURCES,paths,seals):
        item=dict(base,source_slot=slot,planned_units=[u for u in units if u['kind']==('attack' if slot=='lab_slow' else 'benign')],excluded_preflights=preflights if slot=='lab_benign' else [])
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(item,indent=2)+'\n',encoding='utf-8',newline='\n')
        seal.parent.mkdir(parents=True,exist_ok=True);seal.write_text(json.dumps(dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path),sealed_at_utc=now),indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(dict(sealed_source_slots=list(SOURCES),attack_units=40,benign_units=20,excluded_preflights=3,final_traffic_generated=False)))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--declare',action='store_true',required=True);p.parse_args();declare()
