"""Append an exact declared, audited stress batch once to the v4 whitelist."""
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
from audit_stress_session_v5 import audit, read, require, sha
from replay_stress_session_v5 import replay
from summarize_study_development import timeline, distribution

ROOT=Path(__file__).resolve().parents[1]


def main():
    results=ROOT/'results/development'; plan_path=ROOT/'plan/benign_stress_v5.json'
    plan=read(plan_path); batch_path=results/'benign_stress_batch_v5.json'; batch=read(batch_path)
    preflight=read(results/'benign_stress_preflights_v5.json'); base_path=results/'study_development_manifest_v4.json'
    base=read(base_path); plan_hash=sha(plan_path)
    require(batch['plan_sha256']==preflight['plan_sha256']==plan_hash,'Batch/preflight plan differs')
    require(preflight.get('all_declared_entries_passed') and len(preflight['attempts'])==3,'Preflight gate incomplete')
    require(batch.get('all_declared_entries_passed') and len(batch['attempts'])==36,'Complete declared batch required')
    for relative,expected in plan['source_sha256'].items():
        require(sha(ROOT/relative)==expected,'Declared source changed: '+relative)
    groups=[dict(g) for g in base['groups']]; new=[]; sessions=set(); hashes=set(); container_ids=set()
    for index,entry in enumerate(plan['development_entries']):
        attempt=batch['attempts'][index]
        require(attempt['entry_index']==index and attempt['entry']==entry and attempt['state']=='quality_pass','Selection differs')
        folder=ROOT/'data/lab_stress_v5'/attempt['session']; m=read(folder/'session.json'); evidence=audit(folder)
        require(all(m[k]==v for k,v in entry.items()),'Actual session differs from declaration')
        require(m['plan_sha256']==plan_hash and m['tools_image']==plan['tools_image'],'Source/image provenance differs')
        require(m['session'] not in sessions and m['pcap_sha256'] not in hashes,'Repeated session/capture')
        sessions.add(m['session']); hashes.add(m['pcap_sha256'])
        for field in ('web_container_id','router_container_id'):
            require(m[field] not in container_ids,'Container state reused'); container_ids.add(m[field])
        directory=folder/'causal_observed_v5'; report_path=directory/'replay.json'
        if not directory.exists(): replay(folder)
        report=read(report_path)
        require(report['pcap_sha256']==m['pcap_sha256'] and report['plan_sha256']==plan_hash,'Replay input changed')
        require(report['replay_wrapper_sha256']==sha(ROOT/'src/replay_stress_session_v5.py'),'Replay wrapper changed')
        require(report['feature_core_sha256']==sha(ROOT/'src/causal_features.py'),'Core changed')
        features=directory/'features.csv'; require(sha(features)==report['features_sha256'],'Feature bytes changed')
        with features.open(encoding='utf-8',newline='') as f: rows=list(csv.DictReader(f))
        selected=[r for r in rows if m['schedule']['measurement_start_utc']<=int(r['utc_second'])<m['schedule']['measurement_end_utc']]
        require(len(selected)==entry['duration'] and all(r['history_complete']=='1' for r in selected),'Missing warmed measurement')
        table=directory/'model_windows.csv'
        names=base['metadata_columns_excluded_from_predictors']+base['predictor_columns']
        with table.open('w',encoding='utf-8',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=names); writer.writeheader()
            for r in selected:
                writer.writerow(dict(r,session_id=m['session'],role=m['role'],condition=m['condition'],y=0))
        group=dict(id=m['session'],role=m['role'],condition=m['condition'],source='Controlled_benign_stress_v5',
                   table=table.relative_to(ROOT).as_posix(),sha256=sha(table),expected_rows=len(selected),expected_y=0,
                   capture_sha256=m['pcap_sha256'],session_manifest_sha256=sha(folder/'session.json'),
                   replay_report_sha256=sha(report_path),plan_sha256=plan_hash,repeat=m['repeat'],
                   group_unit='whole_fresh_benign_session',parent_recording=m['session'],
                   packet_extraction_quality_accepted=True,client_outcomes=evidence['client_outcomes'],
                   kernel_capture_drops=evidence['kernel_capture_drops'],router_qdisc_drops=evidence['router_qdisc_drops'],
                   raw_start=m['schedule']['warmup_start_utc'],raw_end=evidence['observation_stop_signal_utc'])
        groups.append(group); new.append(dict(group,audit=evidence,replay=report))
    require(len(groups)==56 and len({g['id'] for g in groups})==56,'Whitelist duplicated')
    counts={r:{'0':0,'1':0} for r in ('T','C1','C2','V')}; descriptions=defaultdict(lambda:defaultdict(list))
    diagnostic=('packets_in','packets_out','inbound_iat_mean','packet_length_mean','active_connections','unknown_age_connections','packet_rate_change','uncompleted_fraction')
    for g in groups:
        path=ROOT/g['table']; require(sha(path)==g['sha256'],'Table bytes changed')
        with path.open(encoding='utf-8',newline='') as f:
            reader=csv.DictReader(f); require(set(reader.fieldnames)==set(names),'Schema differs'); rows=list(reader)
        require(len(rows)==g['expected_rows'],'Row count differs')
        for r in rows:
            require((r['session_id'],r['role'],r['condition'],int(r['y']),int(r['history_complete']))==(g['id'],g['role'],g['condition'],g['expected_y'],1),'Metadata/label differs')
            require(all(math.isfinite(float(r[p])) for p in base['predictor_columns']),'Nonfinite predictor')
            counts[g['role']][str(g['expected_y'])]+=1
            for p in diagnostic: descriptions[g['source']+'/'+g['condition']+'/y='+str(g['expected_y'])][p].append(float(r[p]))
        g['timeline_coverage']=timeline([int(r['utc_second']) for r in rows])
    summary=dict(base,date='2026-11-13',version='study_development_manifest_v5',groups=groups,windows_by_role_and_y=counts,
                 scope='Engineering whitelist plus declared repeated legitimate stress. No fitted/frozen main model or final efficacy results.',
                 source_code_sha256=sha(Path(__file__)),selected_lab_sessions=48,selected_stress_sessions=36,
                 descriptive_feature_distributions={g:{p:distribution(v) for p,v in d.items()} for g,d in descriptions.items()},
                 remaining_gates=['Review sparse known-V representativeness and source/service/path confounding.',
                                  'Define missing-label/gap-aware matched calibration before fitting.',
                                  'Fit/select matched branches/baselines, calibrate, freeze, then qualify reserved final sources.'])
    summary['negative_history_preserved']=[*base['negative_history_preserved'],
        'Stress v1 two-bridge connectivity failure, v2 HEAD/read1 defect and flooded non-service copies, v3 unrun supersession, and interrupted v4 clock interval remain excluded.']
    summary['source_evidence_sha256']={**base['source_evidence_sha256'],
         base_path.relative_to(ROOT).as_posix():sha(base_path),plan_path.relative_to(ROOT).as_posix():plan_hash,
         batch_path.relative_to(ROOT).as_posix():sha(batch_path)}
    component=dict(plan_sha256=plan_hash,selected_sessions=36,measurement_rows=sum(g['expected_rows'] for g in new),
                   groups=new,study_training_ready=False,scope='Benign development only; failed legitimate requests retained, no model results.')
    (results/'benign_stress_component_v5.json').write_text(json.dumps(component,indent=2)+'\n',encoding='utf-8',newline='\n')
    (results/'study_development_manifest_v5.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(counts,indent=2))


if __name__=='__main__': main()
