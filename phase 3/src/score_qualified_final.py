"""Frozen inference on an already qualified final feature/truth pair.

No discovery, acquisition, fitting, recalibration or silent overwrite. This entry
point remains unusable until both freeze and source qualification gates pass.
"""
import argparse
import csv
import json
import math
from pathlib import Path
import numpy as np
from threadpoolctl import threadpool_limits
from frozen_suite import FrozenSuite,authorize_scoring,contained
from packet_model_policy import ROOT,checked_table,read,require,sha
from blind_evaluation import decision_trace,window_metrics,alert_burden,episode_result,episode_summary


def qualified_inputs(root,record,features):
    rows,seconds,x=checked_table(contained(root,record['features']['path']),features,False)
    labels={}
    with contained(root,record['ground_truth']['path']).open(encoding='utf-8',newline='') as f:
        reader=csv.DictReader(f);require({'utc_second','y','family','condition'}<=set(reader.fieldnames),'Truth schema unsupported')
        for r in reader:
            t=int(r['utc_second']);require(t not in labels,'Repeated truth timestamp')
            y=int(r['y']);require(y in (-1,0,1) and (y!=1 or r['family']),'Unknown truth class/family')
            labels[t]=(y,r['family'],r['condition'])
    require(set(labels)<=set(seconds.tolist()),'Truth points outside feature clock; retain qualification exclusions separately')
    y=np.asarray([labels.get(int(t),(-1,'unknown','unknown'))[0] for t in seconds])
    families=[labels.get(int(t),(-1,'unknown','unknown'))[1] for t in seconds]
    complete=np.asarray([int(r['history_complete'])==1 for r in rows]);inside=np.zeros(len(seconds),dtype=bool)
    for s in record['scorable_clock_segments']:
        a,b=math.ceil(s['start']),math.floor(s['end']);mask=(seconds>=a)&(seconds<b)
        require(np.array_equal(seconds[mask],np.arange(a,b)),'Unreported observation gap inside qualified segment')
        inside|=mask;complete[mask]&=seconds[mask]>=a+s['boundary_guard_seconds']
    complete&=inside
    intervals=record['evaluation_intervals'];require(intervals and all(a<b for a,b in intervals),'Missing fixed evaluation intervals')
    evaluation=np.zeros(len(seconds),dtype=bool)
    for a,b in intervals:evaluation|=(seconds>=a)&(seconds+1<=b)
    require(np.all(~evaluation|inside),'Evaluation interval outside qualified observation')
    return seconds,x,y,families,complete,evaluation


def main(qualification):
    authorization=authorize_scoring(qualification);record=read(qualification);suite=FrozenSuite()
    directory=ROOT/'data/final_scoring_v1'/record['group_id']
    public=ROOT/'results/final';result_path=public/(record['group_id']+'.json')
    if directory.exists() or result_path.exists():raise FileExistsError('Never overwrite a final scoring attempt')
    directory.mkdir(parents=True);public.mkdir(parents=True,exist_ok=True)
    seconds,x,y,families,complete,evaluation=qualified_inputs(ROOT,record,suite.manifest['predictor_columns'])
    results=[];failures=[]
    with threadpool_limits(limits=2):
        for case_id,case in sorted(suite.manifest['cases'].items()):
            try:
                scores=suite.score(case_id,x,suite.manifest['predictor_columns'])
                trace=decision_trace(seconds,scores,case['k'],case['h'],case['threshold'],complete)
                common=window_metrics(trace,y,5,evaluation)
                per_family={}
                for family in sorted({family for family,label in zip(families,y) if label==1}):
                    local=y.copy();local[(y==1)&(np.asarray(families)!=family)]=-1
                    per_family[family]=window_metrics(trace,local,5,evaluation)
                episodes=[]
                for e in record.get('episodes',[]):
                    matching=[s for s in record['scorable_clock_segments'] if s['start']<=e['onset_low']<s['end']]
                    if len(matching)==1:
                        s=matching[0];value=episode_result(trace,e['onset_low'],e['onset_high'],e['end'],s['start'],s['end'])
                    else:value=dict(status='unobserved_episode_onset',episode_recall_eligible=False,binary_episode_hit=None,observed_detection=False)
                    episodes.append(dict(episode_id=e['id'],family=e['family'],impact_class=e.get('impact_class','not_measured'),**value))
                point=dict(case_id=case_id,method=case['method'],variant=case['variant'],seed=case['seed'],
                    window_common=common,window_own_history=window_metrics(trace,y,case['h'],evaluation),
                    alert_burden=alert_burden(trace,y,5,evaluation),per_family=per_family,episodes=episodes,episode_summary=episode_summary(episodes))
                results.append(point)
                np.savez_compressed(directory/(case_id.replace(':','_')+'.npz'),seconds=seconds,scores=scores,
                    alarms=np.asarray([-1 if t['alarm'] is None else int(t['alarm']) for t in trace]),
                    qualified_onsets=np.asarray([t['new_alert_onset'] for t in trace]),evaluation_mask=evaluation)
            except Exception as error:
                failures.append(dict(case_id=case_id,status='inference_or_evaluation_failed',error_type=type(error).__name__,error=str(error)))
    output=dict(freeze_sha256=authorization['freeze_sha256'],qualification_sha256=authorization['qualification_sha256'],
        group_id=record['group_id'],source_slot=record['source_slot'],parent_recording=record['parent_recording'],
        results=results,failures=failures,expected_cases=len(suite.manifest['cases']),all_cases_completed=not failures and len(results)==len(suite.manifest['cases']),
        qualification_exclusions=record.get('qualification_exclusions',{}),
        scope='Frozen qualified-source result; cohort/clock/label limits apply. No tuning from this output; report every planned failure/exclusion.')
    result_path.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'group':record['group_id'],'completed_cases':len(results),'failed_cases':len(failures),'result_sha256':sha(result_path)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--qualification',type=Path,required=True)
    main(parser.parse_args().qualification)
