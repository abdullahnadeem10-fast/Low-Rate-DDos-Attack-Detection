"""Sequential, hash-guarded, resumable benign stress collection; no silent reruns."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lab/stress_v2'))
from stress_runner_v2 import collect
from audit_stress_session_v2 import audit


def execute(plan_path, preflight=False, limit=None):
    raw=plan_path.read_bytes(); plan=json.loads(raw); digest=hashlib.sha256(raw).hexdigest()
    for relative,expected in plan['source_sha256'].items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()!=expected:
            raise ValueError('Declared source differs: '+relative)
    output=ROOT/'results/development'/('benign_stress_preflights_v2.json' if preflight else 'benign_stress_batch_v2.json')
    if output.exists():
        record=json.loads(output.read_text(encoding='utf-8'))
        if record['plan_sha256']!=digest: raise ValueError('Existing batch belongs to different plan')
    else:
        record=dict(plan_sha256=digest,scope='Excluded preflight' if preflight else 'Benign development only',attempts=[],study_training_ready=False)
    def save(): output.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8',newline='\n')
    selected=plan['excluded_preflights' if preflight else 'development_entries']
    completed=0
    for index,entry in enumerate(selected):
        previous=[a for a in record['attempts'] if a['entry_index']==index]
        if previous:
            if previous[-1]['state']=='quality_pass': continue
            raise RuntimeError('Prior attempt requires explicit recovery review, not automatic recollection')
        if limit is not None and completed>=limit: break
        attempt=dict(entry_index=index,entry=entry,state='started',start_utc=time.time()); record['attempts'].append(attempt); save()
        try:
            folder=collect(entry,plan['tools_image'],digest); attempt['session']=folder.name
            result=audit(folder); attempt.update(state='quality_pass',audit=result)
        except BaseException as error:
            attempt.update(state='failed_preserved',error_type=type(error).__name__,error=str(error)); save(); raise
        save(); completed+=1
        print(json.dumps({'entry':index,'session':folder.name,'quality_pass':True,'outcomes':result['client_outcomes']}),flush=True)
    record['all_declared_entries_passed']=len(record['attempts'])==len(selected) and all(a['state']=='quality_pass' for a in record['attempts'])
    save()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--plan',type=Path,default=ROOT/'plan/benign_stress_v2.json')
    p.add_argument('--preflight',action='store_true'); p.add_argument('--limit',type=int)
    a=p.parse_args(); execute(a.plan,a.preflight,a.limit)
