"""Collect the prespecified first benign development batch, sequentially.

Every role/condition/seed is declared before traffic; failed attempts are retained.
No final stress/attack or external holdout is opened. Small first-batch counts do
not establish final calibration precision or solve public/lab source confounding.
"""
import argparse
import contextlib
import csv
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

from audit_benign_session import audit_session, frames
from replay_causal_features import extract

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'results/development'
DATA = ROOT/'data/lab_development'


def select_windows(rows, first, last):
    selected = []
    for row in rows:
        second = int(row['utc_second'])
        if second < first or second+1 > last or int(row['history_complete']) != 1:
            continue
        if not all(math.isfinite(float(v)) for v in row.values()):
            raise ValueError('Non-finite causal feature')
        selected.append(row)
    return selected


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def initial_partial_packets(records):
    boundary = None; count = 0
    for ts, _, _ in records:
        if boundary is None: boundary = math.floor(ts)+1
        count += int(ts < boundary)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--batch-version',choices=['v1','v2'],default='v2')
    parser.add_argument('--analysis-revision-reason',help='Explicitly record an audit-only bug fix; never permits traffic/feature-source changes')
    args = parser.parse_args()
    version=args.batch_version
    plan_path = ROOT/f'plan/benign_batch_{version}.json'
    progress_path = DATA/f'batch_{version}_progress.json'
    if plan_path.exists():
        if not args.resume:
            raise ValueError('Batch plan exists; inspect its evidence and explicitly use --resume')
        plan = json.loads(plan_path.read_text())
    else:
        image = subprocess.run(['docker','image','inspect','cnet-benign-tools:development','--format','{{.Id}}'],
            check=True,capture_output=True,text=True).stdout.strip()
        entries = []
        for role, base in [('T',1000),('C1',2000),('C2',3000),('V',4000)]:
            for index, condition in enumerate(['ordinary','bursts','flash'],1):
                entries.append({'role':role,'condition':condition,'seed':base+index,
                                'clients':1 if condition=='ordinary' else 3,'warmup':30,'duration':60})
        plan = {'date':'2026-11-11','batch':'benign_'+version,'scope':'Initial benign development only; no final tests.',
            'expected_tools_image':image,'sequential_collection':True,'entries':entries,
            'functional_source_sha256':{str(p.relative_to(ROOT)).replace('\\','/'):digest(p) for p in
                [ROOT/'lab/run_benign_session.py',ROOT/'lab/client.py',ROOT/'lab/capture.py',ROOT/'lab/Dockerfile',
                 ROOT/'src/audit_benign_session.py',ROOT/'src/replay_causal_features.py',ROOT/'src/causal_features.py']},
            'limitations':['Only one initial session per role/condition; not final independent stress replicates.',
                'Controlled congestion and representative benign diversity are not established by these profiles.',
                'Public/lab source and service confounding remain unresolved; full study is not training-ready.']}
        plan_path.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    plan_hash = digest(plan_path)
    changed={name:{'declared_sha256':sha,'current_sha256':digest(ROOT/name)} for name,sha in
        plan['functional_source_sha256'].items() if digest(ROOT/name)!=sha}
    if changed and (set(changed)!={'src/audit_benign_session.py'} or not args.analysis_revision_reason):
        raise ValueError('Source changed; only an explicitly recorded audit-only correction may resume this collection plan')
    progress = json.loads(progress_path.read_text()) if progress_path.exists() else {
        'plan_sha256':plan_hash,'completed':[],'failed_attempts':[],'state':'collecting'}
    if progress['plan_sha256'] != plan_hash:
        raise ValueError('Prespecified plan changed')
    if changed:
        revision={'reason':args.analysis_revision_reason,'changed_analysis_sources':changed,'collection_plan_unchanged':True}
        if revision not in progress.setdefault('analysis_revisions',[]): progress['analysis_revisions'].append(revision)
    def save():
        progress_path.write_text(json.dumps(progress,indent=2)+'\n',encoding='utf-8')
    DATA.mkdir(parents=True,exist_ok=True)
    for i, entry in enumerate(plan['entries']):
        completed = [r for r in progress['completed'] if r['plan_index']==i]
        if completed:
            old = completed[0]
            if digest(ROOT/old['relative_session_path']/'capture/traffic.pcap') != old['capture_sha256']:
                raise ValueError('Previously completed session changed')
            if digest(ROOT/old['relative_session_path']/'model_windows.csv') != old['model_windows_sha256']:
                raise ValueError('Previously completed model table changed')
            continue
        progress['active_plan_index'] = i; progress['state']='collecting'; save()
        before = {p.name for p in DATA.iterdir() if p.is_dir()}
        log = DATA/f'batch_{version}_entry_{i:02d}.log'
        command = [sys.executable,str(ROOT/'lab/run_benign_session.py'),'--no-build',
            '--expected-tools-image',plan['expected_tools_image']]
        for name in ['role','condition','seed','clients','warmup','duration']:
            command += ['--'+name,str(entry[name])]
        print(f'Collecting {i+1}/{len(plan["entries"])}: {entry["role"]} / {entry["condition"]}, seed {entry["seed"]}',flush=True)
        directory = None
        try:
            prior = [f for f in progress['failed_attempts'] if f['plan_index']==i]
            if prior:
                names=prior[-1]['created_session_directories']
                if len(names)!=1: raise ValueError('Prior collection needs explicit investigation before resuming')
                directory=DATA/names[0]
                m=json.loads((directory/'session.json').read_text())
                if m['state']!='collected_audit_pending' or any(m[k]!=entry[k] for k in entry):
                    raise ValueError('Prior collection is not a complete matching session; do not silently rerun it')
                progress.setdefault('analysis_recoveries',[]).append({'plan_index':i,'session':directory.name,
                    'raw_capture_reused':True,'analysis_source_sha256':digest(Path(__file__))})
                print('Reusing preserved completed capture for analysis-only recovery.',flush=True)
            else:
                with log.open('w',encoding='utf-8') as stream:
                    subprocess.run(command,check=True,stdout=stream,stderr=subprocess.STDOUT)
                created = [p for p in DATA.iterdir() if p.is_dir() and p.name not in before]
                if len(created)!=1: raise ValueError('Unexpected session directory count')
                directory = created[0]
            audit = audit_session(directory)
            if not audit['passed']: raise ValueError('Session quality failed: '+str(audit['issues']))
            manifest = json.loads((directory/'session.json').read_text())
            if manifest.get('cleanup_exit_code')!=0: raise ValueError('Session cleanup did not succeed')
            with log.open('a',encoding='utf-8') as stream,contextlib.redirect_stdout(stream):
                extract(directory/'capture/traffic.pcap',manifest['service'],directory/'features.csv')
            replay = json.loads((directory/'features.json').read_text())
            if replay['counts']['late_selected_dropped'] or replay['counts']['decode_errors']:
                raise ValueError('Replay quality failure')
            prefix_excluded=initial_partial_packets(frames(directory/'capture/traffic.pcap'))
            if replay['counts']['frames']!=audit['counts']['frames'] or replay['counts']['selected_tcp']+prefix_excluded!=audit['counts']['frames']:
                raise ValueError('Replay selected packet count differs from the capture audit')
            with (directory/'features.csv').open(newline='') as f:
                rows = select_windows(list(csv.DictReader(f)),*audit['measurement_utc_seconds_exclusive_end'])
            if len(rows) < entry['duration']-5: raise ValueError('Insufficient complete measurement windows')
            model_path = directory/'model_windows.csv'
            with model_path.open('w',newline='',encoding='utf-8') as f:
                writer = csv.DictWriter(f,fieldnames=['session_id','role','condition','y',*rows[0]])
                writer.writeheader()
                writer.writerows({'session_id':audit['session'],'role':entry['role'],'condition':entry['condition'],'y':0,**r} for r in rows)
            result = {**entry,'plan_index':i,'session':audit['session'],'relative_session_path':str(directory.relative_to(ROOT)).replace('\\','/'),
                'web_container_id':manifest['web_container_id'],'capture_sha256':audit['capture_sha256'],
                'model_windows_sha256':digest(model_path),'model_windows':len(rows),
                'frames':audit['counts']['frames'],'http_requests':audit['logged_http_requests'],
                'kernel_reported_drops':audit['tcpdump']['dropped_by_kernel'],'max_frame_bytes':audit['max_frame_bytes'],
                'late_selected_dropped':replay['counts']['late_selected_dropped'],'audit_passed':True,
                'capture_initial_partial_packets_excluded_by_replay':prefix_excluded,
                'image_ids':audit['image_ids'],'measurement_utc_seconds_exclusive_end':audit['measurement_utc_seconds_exclusive_end']}
            progress['completed'].append(result); save()
            print(f'Accepted {audit["session"]}: {len(rows)} measurement windows, {result["http_requests"]} complete HTTP exchanges',flush=True)
        except Exception as error:
            progress['failed_attempts'].append({'plan_index':i,'entry':entry,'error':str(error),
                'created_session_directories':[directory.name] if directory else [p.name for p in DATA.iterdir() if p.is_dir() and p.name not in before]})
            progress['state']='failed'; save(); raise
    records = progress['completed']
    if len({r['capture_sha256'] for r in records}) != len(records) or len({r['web_container_id'] for r in records}) != len(records):
        raise ValueError('Duplicate captures or reused web containers across independent sessions')
    if any(r['image_ids'] != records[0]['image_ids'] for r in records):
        raise ValueError('Image content changed within the prespecified batch')
    progress['state']='completed'; save()
    summary = {'date':'2026-11-11','plan':plan,'plan_sha256':plan_hash,'sessions':records,
        'independence_checks':{'unique_capture_hashes':True,'fresh_web_container_each_session':True,
            'new_causal_feature_instance_each_session':True,'same_image_content_within_batch':True},
        'grouping_basis':'Whole independent lab sessions; connection identities are namespaced by session, not pooled across separate container lifetimes.',
        'totals':{'sessions':len(records),'measurement_windows':sum(r['model_windows'] for r in records),
            'http_requests':sum(r['http_requests'] for r in records),'frames':sum(r['frames'] for r in records)},
        'failed_attempts':progress['failed_attempts'],'analysis_recoveries':progress.get('analysis_recoveries',[]),
        'analysis_source_sha256':digest(Path(__file__)),'training_ready':False,
        'analysis_revisions':progress.get('analysis_revisions',[]),
        'remaining':['Controlled congestion, benign diversity and independent repetitions.',
            'Public attack/session split integration and a source/service-confounding audit.',
            'Full calibration/freeze and untouched final evaluations.']}
    (OUT/f'benign_batch_{version}.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary['totals']),flush=True)


if __name__=='__main__': main()
