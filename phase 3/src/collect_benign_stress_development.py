"""Run the declared development batch only after all excluded preflights pass."""
from pathlib import Path
import json
from audit_stress_session_v5 import read, require, sha
from run_benign_stress_v5 import execute
from integrate_benign_stress import main as integrate

ROOT=Path(__file__).resolve().parents[1]


def gate():
    plan=ROOT/'plan/benign_stress_v5.json'
    path=ROOT/'results/development/benign_stress_preflights_v5.json'; preflight=read(path)
    require(preflight.get('all_declared_entries_passed') and len(preflight['attempts'])==3,'All three preflights required')
    require(preflight['plan_sha256']==sha(plan),'Preflight plan differs')
    reports=[]
    for index,entry in enumerate(read(plan)['excluded_preflights']):
        attempt=preflight['attempts'][index]
        require(attempt['entry_index']==index and attempt['entry']==entry and attempt['state']=='quality_pass','Preflight declaration differs')
        directory=ROOT/'data/lab_stress_v5'/attempt['session']
        report_path=directory/'causal_observed_v5/replay.json'; report=read(report_path)
        require(report['role']=='PREFLIGHT' and not report['eligible_for_development'],'Preflight entered model data')
        require(report['measurement_rows']==60 and report['late_packets']==0,'Preflight replay incomplete')
        require(report['plan_sha256']==sha(plan) and report['pcap_sha256']==attempt['audit']['pcap_sha256'],'Replay source differs')
        require(report['replay_wrapper_sha256']==sha(ROOT/'src/replay_stress_session_v5.py'),'Replay wrapper changed')
        require(report['features_sha256']==sha(directory/'causal_observed_v5/features.csv'),'Replay bytes changed')
        reports.append(dict(report_sha256=sha(report_path),audit=attempt['audit'],replay=report))
    evidence=dict(date='2026-11-13',engineering_preflight_gate_pass=True,plan_sha256=sha(plan),
                  preflight_batch_sha256=sha(path),preflights=reports,
                  all_preflights_excluded_from_model_data=True,study_training_ready=False,
                  scope='Only permission to collect declared legitimate development traffic; not model readiness or final test evidence.')
    output=ROOT/'results/development/benign_stress_development_gate_v5.json'
    raw=json.dumps(evidence,indent=2)+'\n'
    if output.exists(): require(output.read_text(encoding='utf-8')==raw,'Preserved development gate differs')
    else: output.write_text(raw,encoding='utf-8',newline='\n')
    return plan


if __name__=='__main__':
    execute(gate())
    integrate()
