"""Compose v3 from eight unchanged v2 sessions plus four seed-disjoint replacements.

The correction is selected solely by generator-seed overlap before any detector
fitting/scoring. Roles/profiles/capture images are unchanged; all originals remain.
"""
import csv
import json
from pathlib import Path
import subprocess
import sys
import contextlib

from collect_benign_batch import ROOT, DATA, OUT, digest, select_windows, initial_partial_packets
from audit_benign_session import audit_session, frames
from replay_causal_features import extract


def require_disjoint_seeds(entries):
    seen=set()
    for entry in entries:
        for i in range(1,entry['clients']+1):
            seed=entry['seed']+1000*i
            if seed in seen: raise ValueError('Workload jitter substream reused across the declared component')
            seen.add(seed)
    return sorted(seen)


def main():
    source=json.loads((OUT/'benign_batch_v2.json').read_text())
    plan_path=ROOT/'plan/benign_batch_v3.json';progress_path=DATA/'batch_v3_progress.json'
    if plan_path.exists():
        plan=json.loads(plan_path.read_text())
    else:
        entries=[]
        for original in source['sessions']:
            entry={k:original[k] for k in ('role','condition','clients','warmup','duration','seed')}
            replace=entry['role'] in ('C1','C2') and entry['condition'] in ('bursts','flash')
            if replace:
                entry['seed']=(200000 if entry['role']=='C1' else 300000)+(2 if entry['condition']=='bursts' else 3)
                entry['reuse_session']=None
            else:
                entry['reuse_session']=original['session']
                entry['capture_sha256']=original['capture_sha256']
            entries.append(entry)
        seeds=require_disjoint_seeds(entries)
        plan={'date':'2026-11-11','batch':'benign_v3','scope':'Initial benign development component, not final testing.',
            'reason':'Correct additive per-client PRNG seed overlap across roles; no classifier outcomes were used.',
            'source_batch':'benign_v2','entries':entries,'expected_effective_client_seeds':seeds,
            'expected_tools_image':source['plan']['expected_tools_image'],
            'functional_source_sha256':source['plan']['functional_source_sha256'],
            'composition_source_sha256':digest(Path(__file__))}
        plan_path.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    if digest(Path(__file__))!=plan['composition_source_sha256'] or any(digest(ROOT/n)!=s for n,s in plan['functional_source_sha256'].items()):
        raise ValueError('Frozen collection/composition source changed')
    require_disjoint_seeds(plan['entries'])
    progress=json.loads(progress_path.read_text()) if progress_path.exists() else {
        'plan_sha256':digest(plan_path),'completed':[],'failed_attempts':[],'state':'collecting'}
    if progress['plan_sha256']!=digest(plan_path): raise ValueError('Composition plan changed')
    def save():progress_path.write_text(json.dumps(progress,indent=2)+'\n',encoding='utf-8')
    source_by_id={s['session']:s for s in source['sessions']}
    for i,entry in enumerate(plan['entries']):
        if any(r['plan_index']==i for r in progress['completed']): continue
        progress.update(active_plan_index=i,state='collecting');save()
        directory=None
        try:
            if entry['reuse_session']:
                result=dict(source_by_id[entry['reuse_session']]);directory=ROOT/result['relative_session_path']
                if digest(directory/'capture/traffic.pcap')!=entry['capture_sha256'] or digest(directory/'model_windows.csv')!=result['model_windows_sha256']:
                    raise ValueError('A reused original data file changed')
                print('Verified unchanged '+entry['reuse_session'],flush=True)
            else:
                prior=[f for f in progress['failed_attempts'] if f['plan_index']==i]
                if prior: raise ValueError('Inspect prior replacement failure explicitly; do not silently regenerate traffic')
                before={p.name for p in DATA.iterdir() if p.is_dir()}
                command=[sys.executable,str(ROOT/'lab/run_benign_session.py'),'--no-build','--expected-tools-image',plan['expected_tools_image']]
                for name in ('role','condition','clients','warmup','duration','seed'):command+=['--'+name,str(entry[name])]
                log=DATA/f'batch_v3_entry_{i:02d}.log'
                print(f'Collecting replacement {entry["role"]}/{entry["condition"]}, seed {entry["seed"]}',flush=True)
                with log.open('w',encoding='utf-8') as stream:subprocess.run(command,check=True,stdout=stream,stderr=subprocess.STDOUT)
                created=[p for p in DATA.iterdir() if p.is_dir() and p.name not in before]
                if len(created)!=1:raise ValueError('Unexpected replacement directory count')
                directory=created[0];audit=audit_session(directory)
                if not audit['passed']:raise ValueError('Replacement quality failed: '+str(audit['issues']))
                manifest=json.loads((directory/'session.json').read_text())
                with log.open('a',encoding='utf-8') as stream,contextlib.redirect_stdout(stream):
                    extract(directory/'capture/traffic.pcap',manifest['service'],directory/'features.csv')
                replay=json.loads((directory/'features.json').read_text())
                prefix=initial_partial_packets(frames(directory/'capture/traffic.pcap'))
                if replay['counts']['late_selected_dropped'] or replay['counts']['decode_errors'] or replay['counts']['selected_tcp']+prefix!=audit['counts']['frames']:
                    raise ValueError('Replacement replay does not reconcile')
                with (directory/'features.csv').open(newline='') as f:rows=select_windows(list(csv.DictReader(f)),*audit['measurement_utc_seconds_exclusive_end'])
                if len(rows)<entry['duration']-5:raise ValueError('Insufficient replacement measurement coverage')
                table=directory/'model_windows.csv'
                with table.open('w',newline='',encoding='utf-8') as f:
                    writer=csv.DictWriter(f,fieldnames=['session_id','role','condition','y',*rows[0]]);writer.writeheader()
                    writer.writerows({'session_id':audit['session'],'role':entry['role'],'condition':entry['condition'],'y':0,**r} for r in rows)
                result={k:entry[k] for k in ('role','condition','clients','warmup','duration','seed')}
                result.update(session=audit['session'],relative_session_path=str(directory.relative_to(ROOT)).replace('\\','/'),
                    web_container_id=manifest['web_container_id'],capture_sha256=audit['capture_sha256'],model_windows_sha256=digest(table),
                    model_windows=len(rows),frames=audit['counts']['frames'],http_requests=audit['logged_http_requests'],
                    kernel_reported_drops=audit['tcpdump']['dropped_by_kernel'],max_frame_bytes=audit['max_frame_bytes'],
                    late_selected_dropped=0,audit_passed=True,capture_initial_partial_packets_excluded_by_replay=prefix,
                    image_ids=audit['image_ids'],measurement_utc_seconds_exclusive_end=audit['measurement_utc_seconds_exclusive_end'])
            actual=[json.loads((directory/f'client{j}/client.json').read_text())['seed'] for j in range(1,entry['clients']+1)]
            if actual!=[entry['seed']+1000*j for j in range(1,entry['clients']+1)]:raise ValueError('Actual generator seeds differ from the plan')
            result.update(plan_index=i,effective_client_jitter_seeds=actual,reused_unchanged_from_v2=bool(entry['reuse_session']))
            progress['completed'].append(result);save()
            print(f'Accepted {result["session"]}: {result["model_windows"]} windows',flush=True)
        except Exception as error:
            progress['failed_attempts'].append({'plan_index':i,'error':str(error),'session':directory.name if directory else None})
            progress['state']='failed';save();raise
    records=progress['completed'];seeds=[seed for s in records for seed in s['effective_client_jitter_seeds']]
    if len(seeds)!=len(set(seeds)) or len({s['capture_sha256'] for s in records})!=12 or len({s['web_container_id'] for s in records})!=12:
        raise ValueError('Composition independence check failed')
    if any(s['image_ids']!=records[0]['image_ids'] for s in records):raise ValueError('Composition image content differs')
    progress['state']='completed';save()
    report={'date':'2026-11-11','plan':plan,'plan_sha256':digest(plan_path),'sessions':records,
        'totals':{'sessions':12,'new_replacement_sessions':4,'reused_unchanged_sessions':8,
            'measurement_windows':sum(s['model_windows'] for s in records),'http_requests':sum(s['http_requests'] for s in records),'frames':sum(s['frames'] for s in records)},
        'independence_checks':{'unique_capture_hashes':True,'fresh_web_container_each_session':True,'new_causal_feature_instance_each_session':True,
            'same_image_content_within_component':True,'all_28_client_jitter_substreams_disjoint':True},
        'superseded_calibration_sessions':[s['session'] for s in source['sessions'] if s['role'] in ('C1','C2') and s['condition'] in ('bursts','flash')],
        'failed_attempts':progress['failed_attempts'],'training_ready':False,
        'remaining':['Controlled congestion/benign diversity and more independent repetitions.',
            'Public candidate compatibility, session/destination partitions and full study integration.',
            'Calibration/freeze and untouched final tests.']}
    (OUT/'benign_batch_v3.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report['totals']),flush=True)


if __name__=='__main__':main()
