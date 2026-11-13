"""Predeclared same-content Docker reference recovery; preserve every old seal.

The failed original attempt had no output directory, container or traffic.
This separate runner retains that failure and the exact remaining catalog.
Only image resolution is adapted; original collector/auditor/scorer stay intact.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
from packet_model_policy import ROOT,read,sha,require
from frozen_suite import authorize_qualification,verify_freeze
sys.path.insert(0,str(ROOT/'lab/final_v1'))
import collector
from audit_final_lab_v1 import qualify
from score_qualified_final import main as score

IMAGE='sha256:ce3b1e5ab31c4b1b6aba298b935cb88bc6ca1d643446b69d396406db5550bf68'
PLAN='plan/final_lab_resolution_recovery_v1.json'
SEAL='results/qualification/final_lab_resolution_seal_v1.json'
LEDGER='results/qualification/final_lab_resolution_batch_v1.json'
SOURCES=('src/final_lab_resolution_recovery_v1.py','src/test_final_lab_resolution_recovery_v1.py')
ORIGINAL_DOCKER=collector.docker


def write(path,value,new=False):
    if new and path.exists():raise FileExistsError('Preserve completed evidence: '+str(path))
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n')


def identity(item):
    require(item['Id']==IMAGE and 'httpd@'+IMAGE in item['RepoDigests'],'Apache content identity differs; not an alias-only recovery')
    require(item['Architecture']=='amd64' and item['Os']=='linux' and item['RootFS']['Layers'],'Apache platform/layers missing')
    return dict(id=item['Id'],repo_digests=item['RepoDigests'],architecture=item['Architecture'],os=item['Os'],layers=item['RootFS']['Layers'])


def pretraffic_failure(batch,directory):
    failed=[a for a in batch['attempts'] if a['state']!='quality_pass']
    require(len(failed)==1 and failed[0]['unit_id']=='final-b-014' and failed[0]['state']=='failed_preserved' and failed[0]['error_type']=='CalledProcessError','Recovery requires the reviewed exact pre-traffic failure')
    require("'image', 'inspect'" in failed[0]['error'] and collector.WEB_IMAGE in failed[0]['error'],'Different failure requires separate review')
    require(not (directory/'final-b-014').exists() and not (directory/'collection.lock').exists(),'Cannot replay a failed unit with capture artifacts/active lock')
    return failed[0]


class ResolutionBridge:
    def __init__(self,original):self.original=original
    def __call__(self,*args,**kwargs):
        args=list(args)
        if args[:3]==['image','inspect',collector.WEB_IMAGE]:args[2]=IMAGE
        if args and args[0]=='compose':
            require(args.count('-f')==1,'Unexpected compose override chain')
            offset=args.index('-f');base=Path(args[offset+1]);config=read(base)
            require(config['services']['web']['image']==collector.WEB_IMAGE,'Unexpected declared web reference')
            overlay=base.with_name('image_resolution_overlay_v1.json');value={'services':{'web':{'image':IMAGE}}}
            if overlay.exists():require(read(overlay)==value,'Recovery overlay changed')
            else:write(overlay,value,new=True)
            args[offset+2:offset+2]=['-f',str(overlay)]
        result=self.original(*args,**kwargs)
        if args and args[0]=='inspect' and getattr(result,'stdout',None):
            for item in json.loads(result.stdout):
                if item.get('Config',{}).get('Labels',{}).get('com.docker.compose.service')=='web':require(item['Image']==IMAGE,'Actual web container content differs')
        return result


def declare():
    require(not (ROOT/PLAN).exists() and not (ROOT/SEAL).exists(),'Never overwrite a recovery declaration')
    authorizations={s:authorize_qualification(s) for s in ('lab_benign','lab_slow')};frozen,gate=verify_freeze()
    batch=read(ROOT/'results/qualification/final_lab_batch_v1.json');failure=pretraffic_failure(batch,ROOT/'data/final_lab_v1')
    validation=ROOT/'results/development/validation_final_lab_resolution_v1.json';v=read(validation)
    require(v['all_tests_passed'] and v['tests_run']>=225,'Recovery engineering checks incomplete')
    actual=identity(json.loads(ORIGINAL_DOCKER('image','inspect',IMAGE,capture_output=True,text=True).stdout)[0])
    expected=next(i for i in read(ROOT/'results/development/lab_software_manifest.json')['images'] if i['reference']==collector.WEB_IMAGE)
    require(actual['id']==expected['content_id'],'Content differs from original lab image')
    directory=ROOT/'data/final_lab_resolution_v1';directory.mkdir(exist_ok=False)
    snapshot=directory/'pre_resolution_batch.json';shutil.copyfile(ROOT/'results/qualification/final_lab_batch_v1.json',snapshot)
    proof=ROOT/'results/qualification/final_lab_resolution_failure_v1.json'
    write(proof,dict(unit_id=failure['unit_id'],original_attempt_start_utc=failure['start_utc'],failure_stage='Pinned tag@digest image inspect, before prepare/compose/traffic',
        original_error_type=failure['error_type'],failure_preserved=True,raw_directory_created=False,traffic_generated=False,
        original_ledger_snapshot_sha256=sha(snapshot),resolved_image_identity=actual,
        change='Resolve identical image content ID locally; overlay only services.web.image. No pulls/builds or changed settings.',private_command_path_redacted=True),new=True)
    catalogs=[read(ROOT/f'plan/final_lab_{s}_acquisition_v1.json') for s in authorizations]
    done={a['unit_id'] for a in batch['attempts'] if a['state']=='quality_pass'}
    remaining=sorted([u for p in catalogs for u in p['planned_units'] if u['id'] not in done],key=lambda u:u['run_order'])
    require(len(done)==1 and len(remaining)==59 and remaining[0]['id']==failure['unit_id'],'Catalog changed')
    value=dict(version='final_lab_resolution_recovery_v1',sealed_at_utc=time.time(),freeze_sha256=gate['freeze_sha256'],
        source_sha256={n:sha(ROOT/n) for n in SOURCES},original_acquisition_sha256={s:a['acquisition_sha256'] for s,a in authorizations.items()},
        original_ledger_snapshot=dict(path=snapshot.relative_to(ROOT).as_posix(),sha256=sha(snapshot)),
        failure_evidence=dict(path=proof.relative_to(ROOT).as_posix(),sha256=sha(proof)),validation=dict(path=validation.relative_to(ROOT).as_posix(),sha256=sha(validation)),
        exact_image_identity=actual,planned_units=remaining,declared_before_any_recovery_traffic=True,
        allowed_change='Inspect exact content ID and add compose overlay {services:{web:{image:<sameID>}}}; verify actual container Image. No other configuration mutation.',
        unchanged='All catalog entries, seeds, order, targets, schedules, traffic, network/resource/service settings, original sources, feature/label math, models, maps, thresholds, metrics.',
        failure_policy='Original pre-traffic failure remains; this is its explicit one-time reviewed recovery, never outcome-based recollection. Any new failed/partial capture stops the runner.',
        scope='Reference-resolution engineering only, no research result selected or tuning. All future outcomes retained.')
    write(ROOT/PLAN,value,new=True);write(ROOT/SEAL,dict(path=PLAN,sha256=sha(ROOT/PLAN),sealed_at_utc=value['sealed_at_utc']),new=True)
    print(json.dumps(dict(recovery_declared=True,remaining_units=59,exact_same_image=True,no_new_traffic=True)))


def execute(limit):
    require(limit>0,'Explicit positive batch limit required')
    seal=read(ROOT/SEAL);require(sha(ROOT/PLAN)==seal['sha256'],'Recovery seal changed');plan=read(ROOT/PLAN)
    for path,h in plan['source_sha256'].items():require(sha(ROOT/path)==h,'Recovery source changed')
    for key in ('original_ledger_snapshot','failure_evidence','validation'):
        item=plan[key];require(sha(ROOT/item['path'])==item['sha256'],'Recovery evidence changed')
    authorizations={s:authorize_qualification(s) for s in plan['original_acquisition_sha256']}
    require({s:a['acquisition_sha256'] for s,a in authorizations.items()}==plan['original_acquisition_sha256'],'Original acquisition changed')
    require(identity(json.loads(ORIGINAL_DOCKER('image','inspect',IMAGE,capture_output=True,text=True).stdout)[0])==plan['exact_image_identity'],'Local image changed')
    state=read(ROOT/LEDGER) if (ROOT/LEDGER).exists() else dict(recovery_sha256=seal['sha256'],attempts=[],all_recovery_units_completed=False)
    require(state['recovery_sha256']==seal['sha256'],'Different recovery ledger')
    lock=ROOT/'data/final_lab_v1/collection.lock';fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY);os.write(fd,str(os.getpid()).encode());os.close(fd)
    collector.docker=ResolutionBridge(ORIGINAL_DOCKER);done=0
    try:
        for unit in plan['planned_units']:
            previous=[a for a in state['attempts'] if a['unit_id']==unit['id']]
            if previous:
                require(len(previous)==1 and previous[0]['state']=='scored_all_cases','Failed/partial recovery unit requires explicit new review, not retry');continue
            if done>=limit:break
            attempt=dict(unit_id=unit['id'],entry=unit,state='started',start_utc=time.time());state['attempts'].append(attempt);write(ROOT/LEDGER,state)
            try:
                slot='lab_slow' if unit['kind']=='attack' else 'lab_benign'
                authorization=dict(authorizations[slot],reference_recovery_sha256=seal['sha256'])
                folder=collector.collect(ROOT/'data/final_lab_v1'/unit['id'],unit,authorization);evidence=qualify(folder)
                qdir=folder/'qualified_v1';record=read(qdir/'qualification.json')
                proof=qdir/'reference_recovery.json';write(proof,dict(plan_sha256=seal['sha256'],plan_path=PLAN,image_identity=plan['exact_image_identity'],
                    overlay_sha256=sha(folder/'image_resolution_overlay_v1.json'),original_qualification_sha256=sha(qdir/'qualification.json'),
                    preserved_pretraffic_failure=unit['id']=='final-b-014',models_or_truth_changed=False),new=True)
                record['qualification_evidence']['reference_recovery']=dict(path=proof.relative_to(ROOT).as_posix(),sha256=sha(proof))
                qpath=qdir/'qualification_recovery_v1.json';write(qpath,record,new=True)
                attempt.update(state='qualified',audit=evidence,qualification_sha256=sha(qpath));write(ROOT/LEDGER,state)
                score(qpath);result=ROOT/'results/final'/(unit['id']+'.json');completed=read(result)['all_cases_completed']
                attempt.update(state='scored_all_cases' if completed else 'scoring_failures_preserved',result_sha256=sha(result));write(ROOT/LEDGER,state)
                require(completed,'Scoring failures retained; do not rescore or tune')
                print(json.dumps(dict(unit=unit['id'],kind=unit['kind'],quality_pass=True,all117_cases_scored=True,frames=evidence['counts']['frames'])),flush=True);done+=1
            except BaseException as error:
                attempt.update(state='failed_preserved',error_type=type(error).__name__,error=str(error));write(ROOT/LEDGER,state);raise
        state['all_recovery_units_completed']=len(state['attempts'])==len(plan['planned_units']) and all(a['state']=='scored_all_cases' for a in state['attempts']);write(ROOT/LEDGER,state)
    finally:collector.docker=ORIGINAL_DOCKER;lock.unlink()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('stage',choices=['declare','run']);p.add_argument('--limit',type=int,default=1);a=p.parse_args();declare() if a.stage=='declare' else execute(a.limit)
