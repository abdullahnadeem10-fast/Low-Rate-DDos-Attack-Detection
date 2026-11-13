"""Prepare/audit and then seal a fixed blind suite; development C1/C2 only.

Two explicit stages preserve a reviewable engineering gate. No reserved source
is discovered, opened or scored. Existing artifacts are never overwritten.
"""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import platform
import time
import joblib
import numpy as np
import sklearn
from threadpoolctl import threadpool_limits
from packet_model_policy import ROOT,read,sha,require,load_inputs,STRESS
from run_packet_model_development import native_score,labelled_matrix
from audit_packet_model_development import independent_stat
from frozen_suite import FrozenSuite,FREEZE,GATE

PRIVATE=ROOT/'data/final_freeze_v1'
AUDIT='results/development/final_ablations_audit_v1.json'
PROTOCOL='plan/blind_final_protocol_v1.json'
VALIDATION='results/development/validation_final_protocol_2026-11-13.json'


def write_new(path,value):
    if path.exists():raise FileExistsError('Preserve completed version: '+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n',encoding='utf-8',newline='\n')


def protocol():
    return dict(version='blind_final_protocol_v1',declared_before_reserved_access=True,
        claim='Frozen confirmatory comparison at qualified observed scope; hypothesis remains unproven. No population, live-latency, zero-day or fusion-superiority claim from development.',
        primary=dict(candidate='main:hybrid:7',comparator='main:AE:7',outcomes=['per-family window recall','eligible benign window FPR'],
            interpretation='Report both outcomes and trade-off; no outcome-based winner selection. Seed7 was prespecified, not selected for performance.'),
        secondary=dict(seeds=[7,19,42,73,101],methods=['HGB','AE','hybrid','RF','IF','LR','rate'],
            controls=['mapped_branch_control','drop_volume','lab_benign_T_only','no_rate_history','no_tcp_state_iat','no_hgb_class_weights','no_persistence'],
            selection='No promotion, refitting, new searches, C1 refit, threshold adjustment or epoch extension after final access.'),
        development_limits=['V is44 SYN-labelled seconds in40 runs from one recording, max2s; no observed TLS functionality or denial impact.',
            'No matched benign target/source coverage; class/service/path confounding persists.',
            'Main AE seeds reach100/100 epoch cap; convergence is unestablished.',
            'h5 public C2 eligibility13/246, public V1/155. C2 empirical1% is not final/population FPR guarantee.',
            'Hybrid recall varies20.45-88.64% across seeds; AE86.36-100%. Some AE/IF V FPR exceeds1%.'],
        features=dict(count=30,signed='packet_rate_change',metadata_excluded=True,core='src/causal_features.py',
            policy='Split/source first, core reset per group/observation segment, conservative50s start guard, omit partial tail, no cross-group state. Preserve full observed idle timeline; idle public truth stays unknown.'),
        decisions=dict(strict_threshold=True,persistence='Frozen kth-largest trailing-h, gaps/invalid feature history =>unknown, never compress clock.',
            onset='New alert only after five preceding valid nonalerts. Startup/gap alarm is unqualified. Short off gaps remain same alarm episode. Unknown truth never changes decision state.',
            availability='Offline proxy=window end+1s fixed reorder=t+2. Measured live latency is a separate experiment.'),
        windows=dict(primary_support='Common5 consecutive valid raw feature seconds; current positive label suffices; benign requires all5 truth labels benign. Own-h support is secondary.',
            unknown='y=-1 never a negative; report excluded known labels and all-known recall/FPR bounds.',
            AP_AUC='Trailing decision statistic on stated eligible support; undefined without both classes.',
            benign_burden='Qualified new-alert starts/hour on at least6 consecutive valid known-benign seconds; report startup and unattributed starts separately.'),
        episodes=dict(credit='Fresh qualified alert, originating window overlaps onset, availability<=onset+180s and<episode end; preexisting alarms get no immediate credit.',
            eligibility='Exact-onset primary denominator requires same common5 input support, recent pre-onset history and complete fixed min(180s,duration) observation, independent of detection outcome.',
            censoring='Incomplete/gapped episodes remain recorded, unscorable/censored, with bounds; fully observed misses remain misses, including ineffective attacks.',
            coarse_truth='Onset interval gets diagnostic possible/guaranteed bounds only, no invented point delay/binary primary hit.',
            delay='Penalty-coded restricted delay includes misses at min(180s,duration); detected-only median secondary. No inference of live speed from replay proxy.'),
        uncertainty=dict(bootstrap_draws=2000,seed=20261113,
            unit='Pair models by session; average algorithm seeds within session, pool within parent, resample whole parent recordings within prespecified source/family/condition stratum.',
            unsupported='N/A with<2 independent parents per stratum, missing pairs/seeds, absent metric denominator or parent spanning strata. Never treat windows, rotations or seeds as independent.',
            claims='Descriptive conditional intervals; primary fixed-seed and secondary seed-averaged results separate. No multiple-comparison superiority claim.'),
        reserved_sources=['CICIDS2017/Wednesday complete slow-family/context','CIC-DDoS2019/01-12 complete supplied day','CSE-CIC-IDS2018 entire source','fresh final lab attack/benign sessions'],
        qualification='After seal, predeclare source-specific acquisition/adapter hashes before payload access. Select endpoints/clock using provenance/count/label compatibility only, never scores. Record unsupported/failed units and outcome-independent exclusions. Shared all-week label archive envelope is not a blanket denial of unopened Wednesday member.',
        lab=dict(attack_episodes=40,mechanisms=['incomplete_header','slow_request_body'],sources=[1,3],
            connection_timing_profiles=[dict(connections_per_source=10,interval_seconds=20),dict(connections_per_source=60,interval_seconds=5)],repeats=5,
            minimum_benign_sessions=20,benign_conditions=['ordinary','bursts','flash','long_lived_or_congested'],minimum_repeats_each=5,
            session_policy='Fresh isolated private lab only; benign verification first.>=60s observed warmup, independent core reset, all legitimate failures remain benign. Retain ineffective attacks and planned failures; log actual rate/service impact/packet loss separately.',
            duration='Final acquisition addendum must fix durations/measurement intervals, seeds, order, image/collector/adapter hashes and impact probes before any final traffic. No outcome-driven duration/intensity tuning.'),
        scope='Detection/evaluation only; no mitigation/blocking. Costs of feature extraction/inference and actual live availability measured separately from fitting/task runtime.',
        final_acquisition_ready=False,final_tests_run=False)


def prepare():
    for p in (PRIVATE,ROOT/AUDIT,ROOT/PROTOCOL,ROOT/FREEZE,ROOT/GATE):
        if p.exists():raise FileExistsError('Preserve existing stage: '+str(p))
    old=read(ROOT/'results/development/packet_model_development_v1.json');new=read(ROOT/'results/development/final_ablations_v1.json')
    plan=read(ROOT/'plan/model_development_v1.json');aplan=read(ROOT/'plan/final_ablations_v1.json')
    require(sha(ROOT/new['plan'])==new['plan_sha256'],'Ablation declaration changed')
    require(sha(ROOT/'results/development/packet_model_development_v1.json')==new['development_results_sha256'],'Original results changed')
    for declaration in (plan,aplan):
        for path,expected in declaration['source_sha256'].items():require(sha(ROOT/path)==expected,'Declared source changed')
    artifacts={**old['private_artifacts'],**new['private_artifacts']}
    require(len(artifacts)==164,'Artifact inventory changed')
    for item in artifacts.values():require(sha(ROOT/item['path'])==item['sha256'],'Artifact checksum mismatch')
    features,allgroups=load_inputs(plan);groups=[g for g in allgroups if g['meta']['role'] in ('C1','C2')]
    PRIVATE.mkdir();(PRIVATE/'C1').mkdir();components={};cases={};expected={};native={};reloaded=0;imputers=0
    def component(method,item,scorefile):
        nonlocal reloaded,imputers
        if method=='rate':
            key='rate';components.setdefault(key,dict(method='rate',features=['packets_in']))
            if key not in native:
                with np.load(ROOT/scorefile['path'],allow_pickle=False) as z:native[key]={g['meta']['id']:z[g['meta']['id']] for g in groups}
            return key
        key=Path(item['path']).stem
        with np.load(ROOT/scorefile['path'],allow_pickle=False) as z:scores={g['meta']['id']:z[g['meta']['id']] for g in groups}
        if key in components:
            require(components[key]['weights']['sha256']==item['sha256'] and all(np.array_equal(scores[k],native[key][k]) for k in scores),'Inconsistent reused model/reference')
            return key
        payload=joblib.load(ROOT/item['path']);names=payload['features'];columns=[features.index(n) for n in names]
        for g in groups:require(np.allclose(native_score(method,payload['model'],g['x'],columns),scores[g['meta']['id']],rtol=0,atol=1e-12),'Reloaded C1/C2 prediction mismatch')
        reloaded+=1;native[key]=scores
        if method=='AE':
            # Audit only the already-permitted T source; no attack-V scores.
            x,y=labelled_matrix(allgroups,'T',True,key.startswith('lab_benign_T_only'))
            model=payload['model'];require(np.allclose(model.imputer.statistics_,np.nanmedian(model.clean(x[:,columns]),axis=0),rtol=0,atol=1e-12),'AE imputer not fitted on declared benign T')
            imputers+=1
        reference=np.sort(np.concatenate([scores[g['meta']['id']] for g in groups if g['meta']['role']=='C1']))
        require(reference.shape==(1209,),'C1 reference size changed')
        path=PRIVATE/'C1'/f'{key}.npy';np.save(path,reference,allow_pickle=False)
        components[key]=dict(method=method,features=names,weights=dict(path=item['path'],sha256=item['sha256']),
            C1_reference=dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path),n=1209,ecdf='right; no extrapolation'))
        return key
    with threadpool_limits(limits=2):
        for report,isnew in ((old,False),(new,True)):
            for point in report['operating_points']:
                v,m,s=point['variant'],point['method'],point['seed'];keys=[]
                for method in (('HGB','AE') if m=='hybrid' else (m,)):
                    if isnew:
                        item=point['components'][method];sf=report['private_artifacts'][f'{v}_{method}_{s}_calibration_scores.npz']
                    else:
                        vv='main' if v=='mapped_branch_control' else v
                        item=None if method=='rate' else report['private_artifacts'][f'{vv}_{method}_{s}.joblib']
                        sf=report['private_artifacts'][f'{vv}_{method}_{s}_scores.npz']
                    keys.append(component(method,item,sf))
                mode='max_c1_percentiles' if m=='hybrid' else 'c1_percentile' if v=='mapped_branch_control' else 'native'
                caseid=f'{v}:{m}:{s}';case=dict(variant=v,method=m,seed=s,k=point['k'],h=point['h'],threshold=point['threshold'],components=keys,score_mode=mode,C2=point['C2'])
                values={}
                for g in groups:
                    gid=g['meta']['id'];parts=[]
                    for key in keys:
                        z=native[key][gid]
                        if mode!='native':
                            r=np.load(ROOT/components[key]['C1_reference']['path'],allow_pickle=False);z=np.searchsorted(r,z,side='right')/len(r)
                        parts.append(z)
                    values[gid]=np.maximum.reduce(parts) if mode=='max_c1_percentiles' else parts[0]
                totals={}
                for g in groups:
                    if g['meta']['role']!='C2':continue
                    stat=independent_stat(g['seconds'],values[g['meta']['id']],case['k'],case['h']);good=np.isfinite(stat)
                    n=int(good.sum());fp=int((stat[good]>case['threshold']).sum());st='stress' if g['meta']['condition'] in STRESS else 'ordinary'
                    for label in ('overall','stratum:'+st,'condition:'+g['meta']['condition']):
                        counts=totals.setdefault(label,[0,0]);counts[0]+=n;counts[1]+=fp
                require(set(totals)==set(case['C2']),'C2 missing strata')
                for label,(n,fp) in totals.items():require(n==case['C2'][label]['eligible_windows'] and fp==case['C2'][label]['false_positive_windows'] and fp<=int(np.floor(.01*n+1e-12)),'Independent C2/budget mismatch')
                cases[caseid]=case;expected[caseid]=values
    require(len(cases)==117 and len(components)==67 and reloaded==66,'Frozen inventory size differs')
    write_new(ROOT/AUDIT,dict(date='2026-11-13',private_artifacts_verified=164,unique_weights_reloaded_C1_C2=66,AE_imputers_T_checked=imputers,
        independently_checked_operating_points=117,all_C2_budgets_pass=True,new_ablation_attack_V_scores_computed=False,final_sources_opened=False,
        source_sha256=sha(Path(__file__)),scope='Integrity, inference and development calibration audit only. No final efficacy evidence.'))
    write_new(ROOT/PROTOCOL,protocol())
    registry=read(ROOT/'results/development/study_development_manifest_v5.json')
    sources={p.relative_to(ROOT).as_posix():sha(p) for folder in ('src','lab') for p in (ROOT/folder).rglob('*')
             if p.is_file() and (p.suffix in ('.py','.ps1') or p.name.startswith('Dockerfile'))}
    for p in ROOT.glob('requirements*.txt'):sources[p.relative_to(ROOT).as_posix()]=sha(p)
    evidence=[PROTOCOL,AUDIT,VALIDATION,'plan/model_development_v1.json','plan/final_ablations_v1.json',
        'results/development/study_development_manifest_v5.json','results/development/packet_model_development_v1.json',
        'results/development/packet_model_development_audit_v1.json','results/development/final_ablations_v1.json']
    candidate=dict(frozen=False,final_tests_run_at_seal=False,final_acquisition_ready=False,predictor_columns=features,
        feature_core_sha256=sha(ROOT/'src/causal_features.py'),source_sha256=sources,evidence_sha256={p:sha(ROOT/p) for p in evidence},
        components=components,cases=cases,software=dict(python=platform.python_version(),numpy=np.__version__,sklearn=sklearn.__version__),
        denied_development_parents=sorted(set(['CICIDS2017/Monday','CICIDS2017/Friday','CIC-DDoS2019/03-11']+[g.get('parent_recording',g['id']) for g in registry['groups']])),
        denied_development_capture_hashes=sorted({g.get('capture_sha256',g.get('source_archive_sha256')) for g in registry['groups']}),
        source_slots={'public_slow':dict(source_id='CICIDS2017/Wednesday',role='U',kind='public'),
            'known_final':dict(source_id='CIC-DDoS2019/01-12',role='K',kind='public'),
            'external':dict(source_id='CSE-CIC-IDS2018',role='E',kind='public'),
            'lab_slow':dict(source_id='lab_final_slow',role='U',kind='lab'),
            'lab_benign':dict(source_id='lab_final_benign',role='K_BENIGN',kind='lab')},
        primary_case='main:hybrid:7',primary_comparator='main:AE:7',scope='Integrity/analysis freeze only. No proof of model adequacy or independent generalization. Source-specific acquisition addenda must precede payload access.')
    write_new(PRIVATE/'candidate.json',candidate)
    # Only C1/C2 expectations are retained for the post-seal adapter audit.
    for caseid,values in expected.items():np.savez_compressed(PRIVATE/(caseid.replace(':','_')+'_expected.npz'),**values)
    print(json.dumps(dict(prepared_cases=len(cases),weights=reloaded,final_payloads_accessed=False)))


def seal():
    require(not (ROOT/FREEZE).exists() and not (ROOT/GATE).exists(),'Never reseal completed freeze')
    candidate=read(PRIVATE/'candidate.json');validation=read(ROOT/VALIDATION)
    require(validation['all_tests_passed'] and validation['tests_run']>=193,'Offline engineering tests incomplete')
    for category in ('source_sha256','evidence_sha256'):
        for path,expected in candidate[category].items():require(sha(ROOT/path)==expected,'Prepared source/evidence changed')
    candidate.update(frozen=True,sealed_at_utc=time.time(),sealed_at_iso=datetime.now(timezone.utc).isoformat())
    write_new(ROOT/FREEZE,candidate)
    write_new(ROOT/GATE,dict(freeze_sha256=sha(ROOT/FREEZE),engineering_gate_pass=True,final_acquisition_ready=False,
        test_summary_sha256=sha(ROOT/VALIDATION),scope='Model/evaluation lock. Qualification, reserved experiments and research conclusions remain pending.'))
    verify()


def verify():
    output=ROOT/'results/development/frozen_suite_reproduction_v1.json'
    require(not output.exists(),'Never overwrite completed reproduction')
    suite=FrozenSuite();features,allgroups=load_inputs(read(ROOT/'plan/model_development_v1.json'))
    groups=[g for g in allgroups if g['meta']['role'] in ('C1','C2')];checked=0
    with threadpool_limits(limits=2):
        for caseid in suite.manifest['cases']:
            with np.load(PRIVATE/(caseid.replace(':','_')+'_expected.npz'),allow_pickle=False) as reference:
                for g in groups:
                    actual=suite.score(caseid,g['x'],features)
                    require(np.allclose(actual,reference[g['meta']['id']],rtol=0,atol=1e-12),'Frozen adapter differs from audited expectation')
                    checked+=1
    write_new(output,dict(freeze_sha256=suite.gate['freeze_sha256'],cases=117,group_score_arrays_reproduced=checked,
        C1_C2_only=True,all_scores_match=True,absolute_tolerance=1e-12,final_sources_opened=False,
        scope='Read-only native/mapped/fused inference equivalence. No final performance evidence.'))
    print(json.dumps(dict(frozen_cases=117,C1_C2_arrays=checked,all_scores_match=True,freeze_sha256=suite.gate['freeze_sha256'])))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('stage',choices=['prepare','seal','verify']);a=p.parse_args()
    {'prepare':prepare,'seal':seal,'verify':verify}[a.stage]()
