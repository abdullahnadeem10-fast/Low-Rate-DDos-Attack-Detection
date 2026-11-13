"""Describe source/class ownership and conservative labelled persistence coverage.

This does not fit models, select a rule, label unknown seconds, or change any
eligibility table. Counts using only known-benign prior windows are a diagnostic
for the future calibration policy, not a retrospectively selected policy.
"""
from collections import defaultdict
import csv
import json
from pathlib import Path
from audit_stress_session_v5 import read, require, sha

ROOT=Path(__file__).resolve().parents[1]


def labelled_history_count(seconds,horizon):
    require(horizon in (1,3,5),'Unapproved diagnostic horizon')
    require(len(set(seconds))==len(seconds),'Repeated timestamp within group')
    known=set(seconds)
    return sum(all(t-i in known for i in range(horizon)) for t in seconds)


def main():
    path=ROOT/'results/development/study_development_manifest_v5.json'; manifest=read(path)
    coverage=defaultdict(lambda:dict(groups=0,windows=0,benign_labelled_history_1=0,benign_labelled_history_3=0,benign_labelled_history_5=0))
    for group in manifest['groups']:
        table=ROOT/group['table']; require(sha(table)==group['sha256'],'Input bytes changed')
        with table.open(encoding='utf-8',newline='') as f: rows=list(csv.DictReader(f))
        key=(group['source'],group['role'],group['condition'],group['expected_y']); item=coverage[key]
        item['groups']+=1; item['windows']+=len(rows)
        if group['expected_y']==0:
            seconds=[int(r['utc_second']) for r in rows]
            for horizon in (1,3,5): item[f'benign_labelled_history_{horizon}']+=labelled_history_count(seconds,horizon)
    records=[dict(source=k[0],role=k[1],condition=k[2],y=k[3],**v) for k,v in sorted(coverage.items())]
    out=ROOT/'results/development'; table=out/'development_coverage_v5.csv'
    with table.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
    result=dict(date='2026-11-13',registry_sha256=sha(path),table_sha256=sha(table),records=records,
                study_training_ready=False,main_model_trained=False,
                strict_known_benign_history_is_diagnostic_only=True,
                unknown_or_idle_public_windows_relabelled_benign=False,
                limitations=[
                    'One known-attack training recording and one sparse independent known-attack validation recording; window counts are not independent episodes.',
                    'Friday attack target has no corroborated benign-only seconds; public benign targets and lab workloads have different service/path/environment provenance.',
                    'CIC2019 V supplies 44 SYN-labelled TCP/443 seconds in 40 runs, maximum two seconds; no TLS-functionality/denial or within-source FPR evidence.',
                    'Stress repetitions use the same host/server/image. Distinct seeds and container resets do not establish independent environments.',
                    'Known-history counts omit the first horizon-1 measurement windows even for declared benign warm-up. They are conservative model-table diagnostics, not final calibration eligibility.',
                    'Persistence needs an explicit missing-label/clock-gap policy and adequate per-stratum sample sizes before rule selection; this report neither chooses it nor guarantees a 1% population FPR.'
                ],
                next_action='Declare the permitted validation-selection and source/path sensitivity controls plus missing-label/persistence calibration policy; then fit matched development models with all final holds preserved.')
    (out/'development_coverage_review_v5.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'coverage_rows':len(records),'registry_sha256':sha(path),'study_training_ready':False}))


if __name__=='__main__': main()
