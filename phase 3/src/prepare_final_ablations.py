"""Fixed confirmatory ablations, T/benign-V/C1/C2 only; no final payloads.

This is not another configuration search. No attack-V scores are calculated,
and none of these controls can replace the prespecified primary hypothesis.
"""
import argparse
import json
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits
from benign_autoencoder import BenignAutoencoder,benign_percentiles
from packet_model_policy import ROOT,SEEDS,sha,read,require,load_inputs,calibrate
from run_packet_model_development import labelled_matrix,native_score,score_vector

VARIANTS={
    'no_rate_history':dict(remove=['packet_rate_change','packets_in_mean_5','packets_in_std_5','packets_in_mean_10','packets_in_std_10','packets_in_mean_20','packets_in_std_20'],methods=['HGB','AE','hybrid']),
    'no_tcp_state_iat':dict(remove=['syn_in','ack_in','rst_in','synack_out','handshakes_completed','new_connections','inbound_iat_mean','inbound_iat_std','active_connections','known_age_connections','unknown_age_connections','active_age_mean','active_age_max','uncompleted_fraction','handshake_to_syn_ratio'],methods=['HGB','AE','hybrid']),
    'no_hgb_class_weights':dict(remove=[],methods=['HGB','hybrid']),
    'no_persistence':dict(remove=[],methods=['AE','hybrid'])}


def ensure_new(paths):
    for path in paths:
        if path.exists():raise FileExistsError('Preserve completed artifacts; use a separately declared version: '+path.name)


def signed_indices(names):
    return (names.index('packet_rate_change'),) if 'packet_rate_change' in names else ()


def fit_control(method,variant,seed,names,columns,groups,selected):
    if method=='AE':
        x,y=labelled_matrix(groups,'T',True);v,vy=labelled_matrix(groups,'V',True)
        params=selected['AE']['parameters']
        return BenignAutoencoder(seed=seed,max_epochs=params['max_epochs'],patience=params['patience'],signed_columns=signed_indices(names)).fit(x[:,columns],y,v[:,columns],vy)
    x,y=labelled_matrix(groups,'T');model=HistGradientBoostingClassifier(**selected['HGB']['parameters'],random_state=seed)
    if variant=='no_hgb_class_weights':model.fit(x[:,columns],y)
    else:
        counts=np.bincount(y,minlength=2);model.fit(x[:,columns],y,sample_weight=len(y)/(2*counts[y]))
    return model


def calibration_scores(method,model,groups,columns):
    # Never call the old make_scores(), which would also score attack V.
    return {g['meta']['id']:native_score(method,model,g['x'],columns) for g in groups if g['meta']['role'] in ('C1','C2')}


def map_calibration(groups,scores):
    reference=score_vector(groups,scores,'C1');require(len(reference)==1209,'Changed C1')
    return {key:benign_percentiles(reference,value) for key,value in scores.items()}


def declare():
    target=ROOT/'plan/final_ablations_v1.json';ensure_new([target])
    previous=ROOT/'results/development/packet_model_development_v1.json'
    plan=dict(date='2026-11-13',version='final_ablations_v1',declared_before_fitting=True,
        development_policy_sha256=sha(ROOT/'plan/model_development_v1.json'),development_results_sha256=sha(previous),
        source_sha256={n:sha(ROOT/n) for n in ('src/prepare_final_ablations.py','src/test_final_ablations.py','src/packet_model_policy.py','src/run_packet_model_development.py','src/benign_autoencoder.py')},
        variants=VARIANTS,seeds=list(SEEDS),selection='No search, no variant/seed promotion, no attack-V scoring. Primary hybrid seed7 remains fixed despite mixed development performance.',
        hyperparameters='Inherit selected main HGB/AE settings; feature ablations refit on permitted T, AE early stopping benign V only. No epoch-budget extension.',
        rules='Fix main method k/h; no-persistence sets1/1. Recompute C1 maps and joint C2 threshold with unchanged empirical budget/eligibility.',
        nonchanges='Existing mapped-branch controls remove either hybrid branch. HGB already1/1, so no-persistence HGB is the existing main HGB, not another fit.',
        budget='The completed v1 selection search is closed. These prespecified nonselectable factor controls do not add hyperparameter searches; unique trained HGB configurations total8 and AE total5, each below original12.',
        scope='Development preparation for a frozen confirmatory suite, not final ablation results. All reserved sources remain unopened.',
        expected_new_weight_bundles=25,expected_new_operating_points=50,final_sources_opened=False)
    target.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'plan':target.name,'sha256':sha(target)}))


def run():
    plan_path=ROOT/'plan/final_ablations_v1.json';plan=read(plan_path)
    for name,expected in plan['source_sha256'].items():require(sha(ROOT/name)==expected,'Declared ablation source changed')
    development_path=ROOT/'results/development/packet_model_development_v1.json';require(sha(development_path)==plan['development_results_sha256'],'Development results changed')
    original=read(development_path);features,groups=load_inputs(read(ROOT/'plan/model_development_v1.json'))
    directory=ROOT/'data/final_ablations_v1';output=ROOT/'results/development/final_ablations_v1.json'
    ensure_new([directory,output]);directory.mkdir();artifacts={};operating=[];trace=[]
    def add(path):artifacts[path.name]=dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path))
    with threadpool_limits(limits=2):
        for variant,spec in plan['variants'].items():
            columns=[i for i,n in enumerate(features) if n not in spec['remove']];names=[features[i] for i in columns]
            for seed in SEEDS:
                scores={};components={}
                for method in ('HGB','AE'):
                    reuse=variant=='no_persistence' or variant=='no_hgb_class_weights' and method=='AE'
                    if reuse:
                        source=original['private_artifacts'][f'main_{method}_{seed}.joblib'];require(sha(ROOT/source['path'])==source['sha256'],'Reused model changed')
                        components[method]=dict(**source,features=features)
                        scorefile=original['private_artifacts'][f'main_{method}_{seed}_scores.npz'];require(sha(ROOT/scorefile['path'])==scorefile['sha256'],'Reused scores changed')
                        with np.load(ROOT/scorefile['path'],allow_pickle=False) as z:scores[method]={g['meta']['id']:z[g['meta']['id']] for g in groups if g['meta']['role'] in ('C1','C2')}
                    else:
                        model=fit_control(method,variant,seed,names,columns,groups,original['selected_configurations'])
                        path=directory/f'{variant}_{method}_{seed}.joblib'
                        joblib.dump(dict(model=model,features=names,plan_sha256=sha(plan_path),final_frozen=False),path);add(path)
                        components[method]=dict(**artifacts[path.name],features=names)
                        scores[method]=calibration_scores(method,model,groups,columns)
                        trace.append(dict(variant=variant,method=method,seed=seed,predictors=len(names),signed_indices=list(signed_indices(names)),
                            fit_role='T_benign' if method=='AE' else 'T_both_classes',early_stop_role='V_benign' if method=='AE' else None,
                            best_epoch=model.best_epoch if method=='AE' else None,sample_weights_used=method=='HGB' and variant!='no_hgb_class_weights'))
                    # Retain C1/C2 ONLY for new calibrations; no final or attack-V arrays.
                    path=directory/f'{variant}_{method}_{seed}_calibration_scores.npz';np.savez_compressed(path,**scores[method]);add(path)
                mapped={method:map_calibration(groups,values) for method,values in scores.items()}
                hybrid={key:np.maximum(mapped['HGB'][key],mapped['AE'][key]) for key in mapped['HGB']}
                for method in spec['methods']:
                    values=hybrid if method=='hybrid' else scores[method]
                    k,h=(1,1) if variant=='no_persistence' else original['selected_rules'][method]
                    items=[(g['meta'],g['seconds'],values[g['meta']['id']]) for g in groups if g['meta']['role']=='C2']
                    tau,cal=calibrate(items,k,h)
                    operating.append(dict(variant=variant,method=method,seed=seed,k=k,h=h,threshold=tau,C2=cal,components=components if method=='hybrid' else {method:components[method]}))
            print(json.dumps({'variant':variant,'prepared_seeds':5,'attack_V_evaluated':False}),flush=True)
    require(sum(n.endswith('.joblib') for n in artifacts)==25 and len(operating)==50,'Unexpected ablation suite size')
    report=dict(date='2026-11-13',plan='plan/final_ablations_v1.json',plan_sha256=sha(plan_path),
        development_results_sha256=sha(development_path),private_artifacts=artifacts,operating_points=operating,fit_trace=trace,
        new_weight_bundles=25,new_operating_points=50,attack_V_scores_computed=False,final_sources_opened=False,
        scope='Prepared/calibrated factor controls only; no final outcomes and no primary-model change.')
    output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'weights':25,'points':50,'report_sha256':sha(output)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--declare',action='store_true');args=parser.parse_args()
    declare() if args.declare else run()
