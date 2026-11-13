"""Sequential predeclared collection. Stops on a failed attempt; never retries it."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from packet_model_policy import ROOT,read,require
from frozen_suite import authorize_qualification
sys.path.insert(0,str(ROOT/'lab/final_v1'))
from collector import collect
from audit_final_lab_v1 import qualify


def save(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n')


def execute(preflight,limit=None):
    require(limit is None or limit>0,'Limit must be positive')
    authorizations={slot:authorize_qualification(slot) for slot in ('lab_benign','lab_slow')}
    plans={slot:read(ROOT/f'plan/final_lab_{slot}_acquisition_v1.json') for slot in authorizations}
    units=plans['lab_benign']['excluded_preflights'] if preflight else sorted([u for p in plans.values() for u in p['planned_units']],key=lambda u:u['run_order'])
    path=ROOT/f'results/qualification/final_lab_{"preflights" if preflight else "batch"}_v1.json'
    if not preflight:
        passed=read(ROOT/'results/qualification/final_lab_preflights_v1.json');require(passed.get('all_declared_units_passed'),'Final preflight gate incomplete')
        require(passed['acquisition_sha256']=={s:a['acquisition_sha256'] for s,a in authorizations.items()},'Preflights belong to different acquisition seal')
    state=read(path) if path.exists() else dict(acquisition_sha256={s:a['acquisition_sha256'] for s,a in authorizations.items()},preflight=preflight,attempts=[],all_declared_units_passed=False)
    require(state['acquisition_sha256']=={s:a['acquisition_sha256'] for s,a in authorizations.items()},'Existing attempts from another declaration')
    directory=ROOT/'data/final_lab_v1';directory.mkdir(parents=True,exist_ok=True);lock=directory/'collection.lock'
    descriptor=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY);os.write(descriptor,str(os.getpid()).encode());os.close(descriptor)
    done=0
    try:
        for unit in units:
            existing=[a for a in state['attempts'] if a['unit_id']==unit['id']]
            if existing:
                require(len(existing)==1 and existing[0]['state']=='quality_pass','Prior failed/interrupted unit needs explicit versioned recovery, not retry')
                continue
            if limit is not None and done>=limit:break
            attempt=dict(unit_id=unit['id'],entry=unit,state='started',start_utc=time.time());state['attempts'].append(attempt);save(path,state)
            try:
                folder=collect(directory/unit['id'],unit,authorizations['lab_slow' if unit['kind']=='attack' else 'lab_benign'])
                evidence=qualify(folder);attempt.update(state='quality_pass',audit=evidence)
            except BaseException as e:attempt.update(state='failed_preserved',error_type=type(e).__name__,error=str(e));save(path,state);raise
            save(path,state);done+=1;print(json.dumps(dict(unit=unit['id'],quality_pass=True,preflight=preflight,counts=evidence['counts'])),flush=True)
        state['all_declared_units_passed']=len(state['attempts'])==len(units) and all(a['state']=='quality_pass' for a in state['attempts']);save(path,state)
    finally:lock.unlink()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);mode=p.add_mutually_exclusive_group(required=True);mode.add_argument('--preflight',action='store_true');mode.add_argument('--final',action='store_true');p.add_argument('--limit',type=int);a=p.parse_args();execute(a.preflight,a.limit)
