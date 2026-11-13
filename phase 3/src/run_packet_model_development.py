"""Bounded exploratory causal-window fit/calibration; NEVER opens final data."""
from collections import defaultdict
import csv
import json
from pathlib import Path
import platform
import time
import warnings
import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier,RandomForestClassifier,IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits
from benign_autoencoder import BenignAutoencoder,benign_percentiles
from packet_model_policy import ROOT,SEEDS,RULES,sha,read,require,load_inputs,rule_statistic,calibrate,confusion,PacketTransform


def labelled_matrix(groups,role,benign=False,lab_only=False):
    chosen=[g for g in groups if g['meta']['role']==role and (not benign or g['meta']['expected_y']==0)
            and (not lab_only or g['meta']['expected_y']==1 or g['meta']['source'] in ('lab_benign_v3','Controlled_benign_stress_v5'))]
    require(bool(chosen),'Empty permitted fitted partition')
    return np.concatenate([g['x'][g['known']] for g in chosen]),np.concatenate([g['y'][g['known']] for g in chosen])


def fit_model(name,params,seed,features,groups,columns,lab_only=False):
    anomaly=name in ('AE','IF')
    x,y=labelled_matrix(groups,'T',anomaly,lab_only);x=x[:,columns]
    signed=(list(features[i] for i in columns).index('packet_rate_change'),)
    if name=='AE':
        v,vy=labelled_matrix(groups,'V',True);v=v[:,columns]
        return BenignAutoencoder(seed=seed,max_epochs=params['max_epochs'],patience=params['patience'],signed_columns=signed).fit(x,y,v,vy)
    if name=='IF':
        require(np.all(y==0),'Anomaly branch saw attack fit rows')
        model=Pipeline([('transform',PacketTransform(signed)),('forest',IsolationForest(**params,random_state=seed))])
    elif name=='LR':
        model=Pipeline([('transform',PacketTransform(signed)),('classifier',LogisticRegression(**params))])
    elif name=='RF': model=RandomForestClassifier(**params,random_state=seed)
    elif name=='HGB': model=HistGradientBoostingClassifier(**params,random_state=seed)
    else: raise ValueError('Unknown fitted method')
    with warnings.catch_warnings():
        warnings.simplefilter('error',ConvergenceWarning)
        if name=='HGB':
            frequency=np.bincount(y,minlength=2);require(np.all(frequency>0),'Supervised T needs both classes')
            model.fit(x,y,sample_weight=len(y)/(2*frequency[y]))
        else: model.fit(x,y)
    return model


def native_score(name,model,x,columns):
    x=x[:,columns]
    if name=='AE': return model.score(x)
    if name=='IF': return -model.named_steps['forest'].score_samples(model.named_steps['transform'].transform(x))
    if name=='rate': return x[:,0]
    return model.predict_proba(x)[:,1]


def make_scores(name,model,groups,columns):
    result={}
    for g in groups:
        if g['meta']['role'] in ('C1','C2','V'):
            s=np.asarray(native_score(name,model,g['x'],columns),dtype=float)
            require(np.isfinite(s).all(),'Nonfinite native scores');result[g['meta']['id']]=s
    return result


def score_vector(groups,scores,role):
    return np.concatenate([scores[g['meta']['id']][g['known']] for g in groups if g['meta']['role']==role])


def mapped_scores(groups,scores):
    reference=score_vector(groups,scores,'C1');require(len(reference)==1209,'C1 reference changed')
    return {key:benign_percentiles(reference,value) for key,value in scores.items()}


def validation_metrics(groups,scores,k,h,tau):
    ys=[];ss=[];common_y=[];common_s=[];by_group=[]
    for g in groups:
        if g['meta']['role']!='V':continue
        s=rule_statistic(g['seconds'],scores[g['meta']['id']],k,h)
        valid=g['known']&np.isfinite(s)
        # Common 5-window clock support. For benign model tables all preceding
        # labels are benign; positive V uses unknown-labelled SCORES, not labels.
        support=np.isfinite(rule_statistic(g['seconds'],np.zeros(len(s)),1,5))
        common=valid&support
        ys.extend(g['y'][valid].tolist());ss.extend(s[valid].tolist())
        common_y.extend(g['y'][common].tolist());common_s.extend(s[common].tolist())
        m=confusion(g['y'][valid],s[valid],tau)
        by_group.append(dict(group=g['meta']['id'],source=g['meta']['source'],condition=g['meta']['condition'],
                             excluded_known_windows=int(np.sum(g['known']&~valid)),**m))
    full=confusion(ys,ss,tau);common=confusion(common_y,common_s,tau)
    require(full['positive_windows']==common['positive_windows']==44,'V proxy support lost; do not silently remove positives')
    return dict(all_supported=full,common_5_window_support=common,groups=by_group)


def evaluate_rules(groups,scores,forced=None):
    items=[(g['meta'],g['seconds'],scores[g['meta']['id']]) for g in groups if g['meta']['role']=='C2']
    result=[]
    for k,h in (RULES if forced is None else [tuple(forced)]):
        tau,cal=calibrate(items,k,h)
        result.append(dict(k=k,h=h,threshold=tau,C2=cal,V=validation_metrics(groups,scores,k,h,tau)))
    return result


def choose_rule(seed_results):
    n=len(seed_results[0]);require(all(len(r)==n for r in seed_results),'Candidate rule lists differ')
    ranking=[]
    for i in range(n):
        metrics=[r[i]['V']['common_5_window_support'] for r in seed_results]
        ranking.append((float(np.mean([m['recall'] for m in metrics])),-float(np.mean([m['fpr'] for m in metrics])),-i))
    index=max(range(n),key=lambda i:ranking[i])
    return index,[dict(candidate=i,mean_proxy_recall=r[0],mean_common_V_benign_fpr=-r[1]) for i,r in enumerate(ranking)]


def main():
    plan_path=ROOT/'plan/model_development_v1.json';plan=read(plan_path)
    for relative,expected in plan['source_sha256'].items(): require(sha(ROOT/relative)==expected,'Declared source changed: '+relative)
    require(plan['software']['python']==platform.python_version() and plan['software']['numpy']==np.__version__ and plan['software']['sklearn']==sklearn.__version__,'Runtime differs from declaration')
    features,groups=load_inputs(plan);base_columns=list(range(len(features)));vx,vy=labelled_matrix(groups,'V')
    require(len(vy)==915 and int(np.sum(vy==1))==44,'Known V denominator differs')
    out=ROOT/'data/packet_model_development_v1';out.mkdir(exist_ok=False)
    public=ROOT/'results/development';plan_hash=sha(plan_path)
    state=dict(plan_sha256=plan_hash,state='fitting',scope=plan['scope'],final_model_frozen=False)
    def save_state(): (out/'run_state.json').write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
    save_state();start=time.perf_counter();models={};selected={};candidates=[];artifacts={};all_rules=[];operating=[];by_group=[]
    def save_model(variant,name,seed,model,columns):
        path=out/f'{variant}_{name}_{seed}.joblib'
        joblib.dump(dict(model=model,features=[features[i] for i in columns],plan_sha256=plan_hash,final_frozen=False),path)
        artifacts[path.name]=dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path))
    try:
        with threadpool_limits(limits=2):
            for name in ('HGB','RF','LR','IF','AE'):
                seeds=[7] if name=='LR' else list(SEEDS);best=-float('inf')
                for index,params in enumerate(plan['configurations'][name]):
                    fitted={};aps=[];details=[]
                    for seed in seeds:
                        model=fit_model(name,params,seed,features,groups,base_columns)
                        score=native_score(name,model,vx,base_columns)
                        ap=float(average_precision_score(vy,score));fitted[seed]=model;aps.append(ap)
                        detail=dict(seed=seed,AP=ap)
                        if name=='AE': detail.update(best_epoch=model.best_epoch,epochs_run=len(model.history),kept_transform_columns=int(np.sum(model.keep)),history=model.history)
                        details.append(detail)
                    mean=float(np.mean(aps));candidates.append(dict(method=name,configuration_index=index,parameters=params,mean_V_AP=mean,seeds=details))
                    print(json.dumps({'stage':'configuration','method':name,'index':index,'mean_proxy_V_AP':mean}),flush=True)
                    if mean>best:
                        best=mean;models[name]=fitted;selected[name]=dict(configuration_index=index,parameters=params,mean_V_AP=mean)
                for seed,model in models[name].items(): save_model('main',name,seed,model,base_columns)
            selected['rate']=dict(configuration_index=0,parameters=dict(feature='packets_in'))
            variants=[('main',base_columns,False)]
            for spec in plan['sensitivity_controls']:
                cols=[i for i,p in enumerate(features) if p not in spec['removed_predictors']]
                variants.append((spec['id'],cols,spec['id']=='lab_benign_T_only'))
            selected_rules={};saturation=[]
            for variant,columns,lab_only in variants:
                names=('HGB','AE','hybrid') if variant!='main' else ('rate','LR','RF','IF','HGB','AE','hybrid')
                scores_by_method={}
                for name in names:
                    if name=='hybrid':
                        scores_by_method[name]={}
                        for seed in SEEDS:
                            hs=mapped_scores(groups,scores_by_method['HGB'][seed]);ae=mapped_scores(groups,scores_by_method['AE'][seed])
                            scores_by_method[name][seed]={key:np.maximum(hs[key],ae[key]) for key in hs}
                        continue
                    seeds=[7] if name in ('LR','rate') else list(SEEDS)
                    scores_by_method[name]={}
                    for seed in seeds:
                        if name=='rate':
                            rate_col=[features.index('packets_in')];model=None
                            scores=make_scores(name,model,groups,rate_col)
                        else:
                            model=models[name][seed] if variant=='main' else fit_model(name,selected[name]['parameters'],seed,features,groups,columns,lab_only)
                            if variant!='main':save_model(variant,name,seed,model,columns)
                            scores=make_scores(name,model,groups,columns)
                        scores_by_method[name][seed]=scores
                for name in names:
                    results=[];seed_order=list(scores_by_method[name])
                    for seed in seed_order:
                        forced=selected_rules[name] if variant!='main' else None
                        result=evaluate_rules(groups,scores_by_method[name][seed],forced)
                        results.append(result)
                        all_rules.append(dict(variant=variant,method=name,seed=seed,candidates=result))
                    if variant=='main':
                        index,ranking=choose_rule(results)
                        selected_rules[name]=(results[0][index]['k'],results[0][index]['h'])
                    else: index=0;ranking=[]
                    for seed,result in zip(seed_order,results):
                        point=dict(variant=variant,method=name,seed=seed,**result[index],rule_selection_ranking=ranking)
                        operating.append(point)
                        for row in point['V']['groups']: by_group.append(dict(variant=variant,method=name,seed=seed,**row))
                        scores=scores_by_method[name][seed]
                        path=out/f'{variant}_{name}_{seed}_scores.npz';np.savez_compressed(path,**scores)
                        artifacts[path.name]=dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path))
                        if name=='hybrid':
                            for role in ('C2','V'):
                                for y in (0,1):
                                    vals=np.concatenate([scores[g['meta']['id']][g['known']] for g in groups if g['meta']['role']==role and g['meta']['expected_y']==y]) if any(g['meta']['role']==role and g['meta']['expected_y']==y for g in groups) else np.array([])
                                    saturation.append(dict(variant=variant,seed=seed,role=role,y=y,known_windows=len(vals),at_one=int(np.sum(vals==1.))))
                    print(json.dumps({'stage':'operating_rule','variant':variant,'method':name,'k_h':selected_rules[name]}),flush=True)
                if variant=='main':
                    for branch in ('HGB','AE'):
                        for seed in SEEDS:
                            mapped=mapped_scores(groups,scores_by_method[branch][seed]);rule=evaluate_rules(groups,mapped,selected_rules['hybrid'])[0]
                            operating.append(dict(variant='mapped_branch_control',method=branch,seed=seed,**rule,rule_selection_ranking=[]))
            points_path=out/'operating_rules.json'
            points_path.write_text(json.dumps(dict(plan_sha256=plan_hash,selected_rules=selected_rules,operating=operating),indent=2)+'\n',encoding='utf-8')
            artifacts[points_path.name]=dict(path=points_path.relative_to(ROOT).as_posix(),sha256=sha(points_path))
        fit_trace={}
        for variant,columns,lab_only in variants:
            x,y=labelled_matrix(groups,'T',False,lab_only);ax,ay=labelled_matrix(groups,'T',True,lab_only)
            fit_trace[variant]=dict(supervised_T_benign=int(np.sum(y==0)),supervised_T_attack=int(np.sum(y==1)),anomaly_T_benign=len(ay),
                AE_early_stopping_V_benign=871,predictor_count=len(columns),signed_index=[features[i] for i in columns].index('packet_rate_change'),
                fitted_roles=['T'],AE_epoch_selection_role='V_benign',C1_used_for_fit=False,C2_used_for_fit=False)
        report=dict(date='2026-11-13',version='packet_model_development_v1',plan='plan/model_development_v1.json',plan_sha256=plan_hash,
            registry_sha256=plan['registry_sha256'],scope=plan['scope'],configuration_candidates=candidates,selected_configurations=selected,
            fitting_provenance=fit_trace,
            all_rule_candidates=all_rules,selected_rules=selected_rules,operating_points=operating,hybrid_mapped_score_saturation=saturation,
            private_artifacts=artifacts,elapsed_seconds=round(time.perf_counter()-start,3),
            main_packet_window_models_fitted=True,final_model_frozen=False,final_attack_tests_run=0,
            headline_generalization_readiness=False,source_path_confounding_resolved=False,
            limitations=['All V metrics participate in exploratory selection and are optimistically biased; no final-test or unseen-family efficacy claim.',
                '44 positive seconds are one sparse TCP/443 source, not 44 independent attacks; no onset/delay, TLS-functionality or denial impact measured.',
                'C2 target is empirical on eligible labelled histories; small strata may require zero FPs. Unknowns remain unknown; denominators differ by rule.',
                'Same-host benign repetitions and class/source/service/path confounding persist; sensitivity variants are diagnostic and never promoted.',
                'Five model seeds are repeated fits, not five independent traffic experiments. No window-wise significance test or population FPR guarantee.',
                'Weights, C1 references via private native scores, operating thresholds and score tables are provisional; no final freeze or final source opened.'])
        (public/'packet_model_development_v1.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
        table=public/'packet_model_development_v1.csv'
        with table.open('w',encoding='utf-8',newline='') as f:
            fields=['variant','method','seed','k','h','threshold','C2_n','C2_FP','C2_fpr','V_positive_n','V_benign_n','V_TP','V_FP','V_recall','V_fpr']
            writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
            for p in operating:
                c=p['C2']['overall'];v=p['V']['common_5_window_support']
                writer.writerow(dict(variant=p['variant'],method=p['method'],seed=p['seed'],k=p['k'],h=p['h'],threshold=p['threshold'],
                    C2_n=c['eligible_windows'],C2_FP=c['false_positive_windows'],C2_fpr=c['fpr'],V_positive_n=v['positive_windows'],V_benign_n=v['benign_windows'],
                    V_TP=v['TP'],V_FP=v['FP'],V_recall=v['recall'],V_fpr=v['fpr']))
        state.update(state='completed_exploratory_not_frozen',report_sha256=sha(public/'packet_model_development_v1.json'),summary_csv_sha256=sha(table),private_artifact_count=len(artifacts));save_state()
        print(json.dumps(state,indent=2),flush=True)
    except BaseException as error:
        state.update(state='failed_preserved',error_type=type(error).__name__,error=str(error));save_state();raise


if __name__=='__main__': main()
