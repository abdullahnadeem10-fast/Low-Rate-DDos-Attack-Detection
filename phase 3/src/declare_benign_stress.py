"""Prespecify whole-session benign stress roles/seeds before any traffic."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
LAB=ROOT/'lab/stress_v1'
sys.path.insert(0,str(LAB))
from runner import PROFILES, PARENT_ID, WEB_IMAGE


def entries(preflight=False):
    output=[]
    for repeat in ([0] if preflight else [1,2,3]):
        for condition in PROFILES:
            for role in (['PREFLIGHT'] if preflight else ['T','C1','C2','V']):
                base=(50_000_000 if preflight else 5_000_000)+len(output)*100_000
                output.append(dict(role=role,condition=condition,repeat=repeat,clients=3,warmup=30,duration=60,
                                   client_seeds=[base+101,base+202,base+303],down_seed=base+5001,up_seed=base+5002))
    return output


def build(image):
    development,preflights=entries(),entries(True)
    all_new=[s for e in development+preflights for s in e['client_seeds']+[e['down_seed'],e['up_seed']]]
    old=json.loads((ROOT/'plan/benign_batch_v3.json').read_text(encoding='utf-8'))
    previous=old['expected_effective_client_seeds']
    if len(set(all_new))!=len(all_new) or set(all_new)&set(previous):
        raise ValueError('Effective seeds overlap')
    files=[*sorted(LAB.glob('*.py')),LAB/'Dockerfile',Path(__file__),ROOT/'src/audit_stress_session.py',ROOT/'src/run_benign_stress.py']
    hashes={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    return dict(version='benign_stress_v1',date='2026-11-12',state='declared_before_traffic',tools_image=image,
                verified_parent_image=PARENT_ID,web_image=WEB_IMAGE,profiles=PROFILES,source_sha256=hashes,
                development_entries=development,excluded_preflights=preflights,
                selection='Engineering quality only; retain legitimate request errors, timeouts, aborts and configured network loss.',
                observation='Known capture ready/stop wall bounds; replay full measurement interval, including observed idle tails. New wrapper required before registry integration.',
                scope='Benign development; no slow mechanisms, final tests, model fitting or held-out source access.',
                repetitions='Three fresh sessions per role/profile; same host and image, not independent environments.',
                study_training_ready=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--image',required=True); p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if a.out.exists(): raise FileExistsError('Do not overwrite a declared plan')
    result=build(a.image); a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'plan':a.out.name,'sha256':hashlib.sha256(a.out.read_bytes()).hexdigest(),'sessions':36,'excluded_preflights':3}))
