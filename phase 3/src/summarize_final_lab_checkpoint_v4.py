"""Read-only partial frozen-result synthesis; no fitting, tuning or new cases.

Every completed catalog unit is included. Pooled windows are descriptive, not
independent replications. Frozen helpers supply eligibility and uncertainty.
"""
import csv
import json
from collections import Counter,defaultdict
import math
from pathlib import Path
import socket
import dpkt
import numpy as np
from packet_model_policy import ROOT,read,sha,require
from blind_evaluation import decision_trace,paired_cluster_bootstrap
from score_qualified_final import qualified_inputs
from audit_benign_session import frames


def observed_load_and_service(unit):
    directory=ROOT/'data/final_lab_v1'/unit['id']
    if not (directory/'session.json').exists():return dict(status='private_service_evidence_unavailable')
    session=read(directory/'session.json');schedule=session['schedule'];result=dict(status='observed_private_evidence',service_by_endpoint={})
    with (directory/'probe/requests.jsonl').open(encoding='utf-8') as f:requests=[json.loads(line) for line in f if line.strip()]
    for phase,a,b in [('warmup',schedule['warmup_start_utc'],schedule['measurement_start_utc']),('measurement',schedule['measurement_start_utc'],schedule['measurement_end_utc'])]:
        values={}
        phase_rows=[v for v in requests if a<=v['scheduled_utc']<b];require(len(phase_rows)==b-a,'Missing fixed probe slots')
        for parity,name in [(0,'complete_GET_small'),(1,'complete_POST_CGI')]:
            selected=[v for v in phase_rows if int(v['scheduled_utc']-schedule['warmup_start_utc'])%2==parity]
            good=[v for v in selected if v['success']];latencies=[v['seconds'] for v in good]
            values[name]=dict(scheduled_slots=len(selected),timely_successes=len(good),failed_or_skipped=len(selected)-len(good),
                skipped_slots=sum(v.get('scheduler_skip',False) for v in selected),
                timely_latency_median_seconds=float(np.median(latencies)) if latencies else None,
                timely_latency_p95_seconds=float(np.quantile(latencies,.95)) if latencies else None)
        result['service_by_endpoint'][phase]=values
    if unit['kind']=='attack':
        counts=defaultdict(Counter);per_second=Counter();a,b=schedule['measurement_start_utc'],schedule['measurement_end_utc']
        for timestamp,frame,wire in frames(directory/'capture/traffic.pcap'):
            if not a<=timestamp<b:continue
            ip=dpkt.ethernet.Ethernet(frame).data;tcp=ip.data;source=socket.inet_ntoa(ip.src)
            if source not in ('172.28.240.20','172.28.240.21','172.28.240.22') or socket.inet_ntoa(ip.dst)!='172.28.240.100' or tcp.dport!=80:continue
            counts[source]['inbound_frames']+=1;counts[source]['captured_Ethernet_bytes']+=wire;counts[source]['TCP_payload_bytes']+=len(tcp.data)
            per_second[math.floor(timestamp)]+=wire
        total_bytes=sum(v['captured_Ethernet_bytes'] for v in counts.values())
        result['attack_inbound_observed']=dict(per_source={s:dict(v) for s,v in counts.items()},measurement_seconds=b-a,
            mean_captured_Ethernet_bits_per_second=8*total_bytes/(b-a),peak_one_second_captured_Ethernet_bits=8*max(per_second.values(),default=0),
            scope='Client-to-service observed capture bytes including retransmissions/TCP overhead; excludes preamble/FCS/IFG. Not nominal configured rate or proven link saturation/worker occupancy.')
    return result


def active_before_measurement(unit,case_id,manifest,expected_qualification_sha):
    directory=ROOT/'data/final_lab_v1'/unit['id']/'qualified_v1'
    path=directory/('qualification_recovery_v1.json' if (directory/'qualification_recovery_v1.json').exists() else 'qualification.json')
    scorepath=ROOT/'data/final_scoring_v1'/unit['id']/(case_id.replace(':','_')+'.npz')
    if not path.exists() or not scorepath.exists():return dict(status='private_clock_or_scores_unavailable',alarm_active=None)
    require(sha(path)==expected_qualification_sha,'Qualification bytes differ from scored evidence')
    record=read(path)
    for item in (record['features'],record['ground_truth']):require(sha(ROOT/item['path'])==item['sha256'],'Qualified clock/truth bytes changed')
    clock,x,y,family,complete,evaluation=qualified_inputs(ROOT,record,manifest['predictor_columns'])
    with np.load(scorepath,allow_pickle=False) as data:
        require(np.array_equal(clock,data['seconds']),'Private score clock differs');scores=data['scores']
    c=manifest['cases'][case_id];trace=decision_trace(clock,scores,c['k'],c['h'],c['threshold'],complete)
    first=np.flatnonzero(evaluation)
    if not len(first) or first[0]==0:return dict(status='no_pre_measurement_decision',alarm_active=None)
    i=int(first[0]);return dict(status='frozen_trace_reproduced',alarm_active=trace[i-1]['alarm_episode_active'],
        qualified_starts_before_measurement=sum(r['new_alert_onset'] for r in trace[:i]),
        unqualified_starts_before_measurement=sum(r['unqualified_alert_start'] for r in trace[:i]))


def main():
    output=ROOT/'results/final/final_lab_checkpoint_v4.json';table=ROOT/'results/final/final_lab_case_summary_v4.csv'
    require(not output.exists() and not table.exists(),'Preserve completed checkpoint; use a new version')
    manifest=read(ROOT/'results/development/final_freeze_v1.json');gate=read(ROOT/'results/development/final_freeze_gate_v1.json')
    units=sorted([u for slot in ('lab_benign','lab_slow') for u in read(ROOT/f'plan/final_lab_{slot}_acquisition_v1.json')['planned_units']],key=lambda u:u['run_order'])
    complete=[];rows=[];pairs=[];seedpairs=[];proof={};aggregate={m:dict(TP=0,FN=0,FP=0,TN=0) for m in ('hybrid','AE')}
    for unit in units:
        path=ROOT/'results/final'/(unit['id']+'.json')
        if not path.exists():continue
        result=read(path);require(result['freeze_sha256']==gate['freeze_sha256'],'Mixed model freeze')
        require(result['all_cases_completed'] and {v['case_id'] for v in result['results']}==set(manifest['cases']),'Incomplete case results retained; not a complete unit')
        by_case={v['case_id']:v for v in result['results']};proof[path.relative_to(ROOT).as_posix()]=sha(path)
        item=dict(unit_id=unit['id'],kind=unit['kind'],condition=unit['condition'],run_order=unit['run_order'],factors={key:unit.get(key) for key in ('repeat','sources','connections','interval','warmup','duration')},qualification_exclusions=result.get('qualification_exclusions',{}),observed_load_and_service=observed_load_and_service(unit),main={})
        for caseid,value in by_case.items():
            w=value['window_common'];e=value['episode_summary'];a=value['alert_burden']
            rows.append(dict(unit_id=unit['id'],kind=unit['kind'],condition=unit['condition'],case_id=caseid,
                TP=w['TP'],FN=w['FN'],FP=w['FP'],TN=w['TN'],recall=w['recall'],fpr=w['fpr'],
                excluded_known_positive=w['excluded_known_positive'],excluded_known_benign=w['excluded_known_benign'],
                qualified_false_alert_starts=a['qualified_false_alert_starts'],eligible_benign_seconds=a['eligible_benign_seconds'],
                exact_scorable_episodes=e['scorable_exact_episodes'],episode_hits=e['hits'],episode_misses=e['misses'],
                mean_penalty_coded_restricted_delay_seconds=e['mean_penalty_coded_restricted_delay_seconds']))
        for method in ('hybrid','AE'):
            caseid=f'main:{method}:7';value=by_case[caseid];w=value['window_common'];episode=value['episode_summary']
            item['main'][method]=dict(window=w,episodes=value['episodes'],episode_summary=episode,alert_burden=value['alert_burden'],pre_measurement=active_before_measurement(unit,caseid,manifest,result['qualification_sha256']))
            for key in aggregate[method]:aggregate[method][key]+=w[key]
            pairs.append(dict(parent=unit['id'],stratum=unit['condition'],session=unit['id'],seed=7,method=method,**{k:w[k] for k in ('TP','FN','FP','TN')}))
            for seed in (7,19,42,73,101):
                ww=by_case[f'main:{method}:{seed}']['window_common']
                seedpairs.append(dict(parent=unit['id'],stratum=unit['condition'],session=unit['id'],seed=seed,method=method,**{k:ww[k] for k in ('TP','FN','FP','TN')}))
        complete.append(item)
    require(complete,'No complete catalog unit')
    completed_ids={u['unit_id'] for u in complete};next_unit=next((u for u in units if u['id'] not in completed_ids),None)
    for values in aggregate.values():
        values['observed_pooled_fpr']=values['FP']/(values['FP']+values['TN']) if values['FP']+values['TN'] else None
        values['observed_pooled_recall']=values['TP']/(values['TP']+values['FN']) if values['TP']+values['FN'] else None
    uncertainty={}
    for label,records,seeds in [('primary_fixed_seed7',pairs,{'hybrid':[7],'AE':[7]}),('secondary_seed_averaged',seedpairs,{'hybrid':[7,19,42,73,101],'AE':[7,19,42,73,101]})]:
        uncertainty[label]={metric:paired_cluster_bootstrap(records,metric=metric,expected_seeds=seeds) for metric in ('recall','fpr')}
    recovery=read(ROOT/'results/qualification/final_lab_resolution_batch_v1.json')
    unresolved=[a['unit_id'] for a in recovery['attempts'] if a['state']!='scored_all_cases']
    result=dict(version='final_lab_checkpoint_v4',freeze_sha256=gate['freeze_sha256'],completed_final_sessions=len(complete),
        final_benign_completed=sum(u['kind']=='benign' for u in complete),final_attack_completed=sum(u['kind']=='attack' for u in complete),
        remaining_catalog_sessions=60-len(complete),next_catalog_unit=next_unit,unresolved_attempts=unresolved,
        original_pretraffic_resolution_failure_retained=True,source_sha256=sha(Path(__file__)),result_sha256=proof,units=complete,
        primary_pooled_counts=aggregate,uncertainty=uncertainty,public_slow_K_external_payloads_opened=False,headline_generalization_readiness=False,
        scope='Partial same-host frozen evidence. Pooled windows are descriptive only; no model/variant promotion, retuning, population or zero-day/superiority claim.',
        limitations=['Source/service/path/load shift and sparse development V remain.',
            'Report preexisting alarm state and alarm-window occupancy alongside starts. Zero new starts does not imply alarm-free operation.',
            'Controlled campaign exposure is not packet maliciousness, proven worker occupancy or demonstrated denial. Service probes are separate impact evidence.',
            'Include no-payload/failed/unscorable planned episodes from qualification ledgers when reporting all planned trials.',
            'Unique reserved seed IDs and repeated same-host sessions are not independent environments. Unsupported paired-parent strata produce N/A.'])
    attacks=[u for u in complete if u['kind']=='attack']
    result['attack_trial_accounting']=dict(completed_planned_trials=len(attacks),
        trials_with_observed_payload_onset=sum(u['main']['hybrid']['episode_summary']['total_recorded_episodes']>0 for u in attacks),
        no_corroborated_payload_trials=sum(u['qualification_exclusions'].get('no_corroborated_initial_payload',0) for u in attacks),
        primary_exact_scorable_episodes=sum(u['main']['hybrid']['episode_summary']['scorable_exact_episodes'] for u in attacks),
        primary_censored_or_unscored_episodes=sum(u['main']['hybrid']['episode_summary']['unscored_or_censored_episodes'] for u in attacks),
        scope='Payload onset proves a controlled campaign, not successful denial. Include ineffective trials; no-payload trials remain unscorable, not benign/hit/miss.')
    result['benign_counts_by_condition']={}
    for condition in sorted({u['condition'] for u in complete if u['kind']=='benign'}):
        selected=[u for u in complete if u['kind']=='benign' and u['condition']==condition];cell={}
        for method in ('hybrid','AE'):
            fp=sum(u['main'][method]['window']['FP'] for u in selected);tn=sum(u['main'][method]['window']['TN'] for u in selected)
            cell[method]=dict(completed_trials=len(selected),FP=fp,TN=tn,observed_fpr=fp/(fp+tn) if fp+tn else None)
        result['benign_counts_by_condition'][condition]=cell
    result['partial_mix_warning']='Pooled rates change with the observed condition mix; a lower pooled rate after extra ordinary sessions is not model improvement. No settings changed.'
    cells=defaultdict(list);by_id={u['unit_id']:u for u in complete}
    for unit in units:
        if unit['kind']=='attack':cells[(unit['condition'],unit['sources'],unit['connections'],unit['interval'])].append(unit['id'])
    result['attack_factor_coverage']=[]
    for (family,sources,connections,interval),ids in sorted(cells.items()):
        scored=[by_id[i] for i in ids if i in by_id]
        result['attack_factor_coverage'].append(dict(family=family,sources=sources,connections_per_source=connections,interval_seconds=interval,
            planned_trials=len(ids),scored_trial_ids=[u['unit_id'] for u in scored],remaining_unscored_ids=[i for i in ids if i not in by_id],
            observed_payload_onset_trials=sum(u['main']['hybrid']['episode_summary']['total_recorded_episodes']>0 for u in scored),
            exact_primary_scorable_episodes=sum(u['main']['hybrid']['episode_summary']['scorable_exact_episodes'] for u in scored)))
    result['benign_condition_coverage']={condition:dict(planned_trials=sum(u['kind']=='benign' and u['condition']==condition for u in units),
        scored_trial_ids=[u['unit_id'] for u in complete if u['kind']=='benign' and u['condition']==condition]) for condition in sorted({u['condition'] for u in units if u['kind']=='benign'})}
    result['attack_mix_warning']='Pooled recall changes with the observed family/source/intensity mix; a higher rate after different trials is not model learning or improvement. Campaign exposure is not successful denial.'
    with table.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    result['case_summary_CSV']=dict(path=table.relative_to(ROOT).as_posix(),sha256=sha(table),rows=len(rows))
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(dict(completed=len(complete),benign=result['final_benign_completed'],attacks=result['final_attack_completed'],remaining=result['remaining_catalog_sessions'],summary_sha256=sha(output),CSV_sha256=sha(table))))


if __name__=='__main__':main()
