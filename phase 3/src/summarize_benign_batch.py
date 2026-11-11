"""Verify the completed lab component and make its predictor/group manifest."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import argparse

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/development'
META=['session_id','role','condition','y','utc_second','history_complete']


def digest(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch-version',choices=['v2','v3'],default='v3')
    args=parser.parse_args()
    report=json.loads((OUT/f'benign_batch_{args.batch_version}.json').read_text())
    plan=report['plan']
    if digest(ROOT/f'plan/benign_batch_{args.batch_version}.json')!=report['plan_sha256']:
        raise ValueError('Plan checksum changed')
    if any(digest(ROOT/name)!=sha for name,sha in plan['functional_source_sha256'].items()):
        raise ValueError('Collection/feature source differs from the batch plan')
    partitions=defaultdict(lambda:{'sessions':[],'windows':0,'conditions':Counter()})
    conditions=defaultdict(lambda:{'requests':0,'measurement_requests':0,'windows':0,'response_seconds':[],'packet_counts':[]})
    predictor_schema=None; tuples=set(); measurement_total=0;client_seeds=[]
    for session in report['sessions']:
        directory=ROOT/session['relative_session_path']
        if digest(directory/'capture/traffic.pcap')!=session['capture_sha256'] or digest(directory/'model_windows.csv')!=session['model_windows_sha256']:
            raise ValueError('Session data checksum changed')
        m=json.loads((directory/'session.json').read_text())
        a=json.loads((directory/'audit.json').read_text())
        if not a['passed'] or m['cleanup_exit_code']!=0:
            raise ValueError('Collection/audit did not finish cleanly')
        identity=(session['role'],session['condition'])
        if identity in tuples: raise ValueError('Unexpected repeated role/condition in first batch')
        tuples.add(identity)
        with (directory/'model_windows.csv').open(newline='') as f:
            reader=csv.DictReader(f); names=[n for n in reader.fieldnames if n not in META]
            rows=list(reader)
        if len(names)!=30 or predictor_schema is not None and names!=predictor_schema:
            raise ValueError('Inconsistent predictor schema')
        predictor_schema=names
        first,last=session['measurement_utc_seconds_exclusive_end']
        if len(rows)!=session['model_windows'] or any(
                r['session_id']!=session['session'] or r['role']!=session['role'] or
                r['condition']!=session['condition'] or r['y']!='0' or r['history_complete']!='1' or
                not first<=int(r['utc_second'])<last or not all(math.isfinite(float(r[n])) for n in names)
                for r in rows):
            raise ValueError('Model row metadata, measurement interval or feature validity changed')
        p=partitions[session['role']];p['sessions'].append(session['session']);p['windows']+=len(rows);p['conditions'][session['condition']]+=1
        c=conditions[session['condition']];c['windows']+=len(rows)
        c['packet_counts'].extend(float(r['packets_in'])+float(r['packets_out']) for r in rows)
        for i in range(1,session['clients']+1):
            metadata=json.loads((directory/f'client{i}/client.json').read_text())
            client_seeds.append(metadata['seed'])
            records=[json.loads(line) for line in (directory/f'client{i}/requests.jsonl').read_text().splitlines()]
            c['requests']+=len(records)
            measured=[r for r in records if r['phase']=='measurement']
            c['measurement_requests']+=len(measured);measurement_total+=len(measured)
            c['response_seconds'].extend(r['seconds'] for r in measured)
    if tuples!={(role,c) for role in ('T','C1','C2','V') for c in ('ordinary','bursts','flash')}:
        raise ValueError('Incomplete declared role/condition matrix')
    disjoint=len(client_seeds)==len(set(client_seeds))
    if args.batch_version=='v3' and not disjoint: raise ValueError('Corrected component still reuses workload jitter seeds')
    workload={}
    for name,c in conditions.items():
        values=sorted(c['response_seconds'])
        workload[name]={'sessions':4,'all_logged_requests':c['requests'],'measurement_requests':c['measurement_requests'],
            'model_windows':c['windows'],'mean_captured_packets_per_measurement_second':statistics.mean(c['packet_counts']),
            'client_http_roundtrip_median_seconds':statistics.median(values),
            'client_http_roundtrip_p95_seconds':values[math.ceil(.95*len(values))-1]}
    result={'date':'2026-11-11','scope':'Audited initial benign lab development component; no fitted packet-window model/final research results.',
        'batch':'benign_'+args.batch_version,'plan_sha256':report['plan_sha256'],'group_unit':'Whole lab session with a fresh service container and feature instance.',
        'label_basis':'Predeclared controlled benign workload plus endpoint/route/packet/HTTP audits; labels are not inferred from idle windows.',
        'predictor_columns':predictor_schema,'metadata_columns_excluded_from_predictors':META,
        'ae_signed_predictor_columns':['packet_rate_change'],'ae_signed_column_indices':[predictor_schema.index('packet_rate_change')],
        'partitions':{role:{**p,'conditions':dict(p['conditions'])} for role,p in partitions.items()},
        'workload_characterization':workload,'measurement_request_count':measurement_total,
        'lab_component_quality_checks_passed':True,'workload_jitter_substreams_disjoint':disjoint,
        'client_jitter_substreams':len(client_seeds),'unique_client_jitter_seeds':len(set(client_seeds)),
        'study_training_ready':False,
        'remaining_gates':['Add controlled-congestion and more representative/independently repeated benign development traffic.',
            'Audit and partition public benign HTTP candidates plus the known-attack source; prevent source/service-label confounding.',
            'Complete split-safe public replay, full calibration and freeze before untouched final tests.'],
        'limits':['One initial session per role/condition is not sufficient independent evidence of generalization.',
            'HTTP roundtrip is a benign service measurement, not detector inference or attack-onset-to-alert delay.',
            'Final benign stress sessions and all lab attack episodes remain separate and uncollected.']}
    (OUT/'benign_development_manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'partitions':result['partitions'],'workload_characterization':workload,'study_training_ready':False},indent=2))


if __name__=='__main__': main()
