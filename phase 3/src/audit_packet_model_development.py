"""Read-only artifact/role/calibration audit; does not refit or tune models."""
import json
import math
from pathlib import Path
import joblib
import numpy as np
from threadpoolctl import threadpool_limits
from packet_model_policy import ROOT,sha,read,require,load_inputs
from run_packet_model_development import labelled_matrix,native_score,mapped_scores


def independent_stat(clock,values,k,h):
    result=np.full(len(values),np.nan)
    for i in range(h-1,len(values)):
        if all(int(clock[i-j])==int(clock[i])-j for j in range(h)):
            result[i]=sorted(float(v) for v in values[i-h+1:i+1])[-k]
    return result


def main():
    report_path=ROOT/'results/development/packet_model_development_v1.json';report=read(report_path)
    plan=read(ROOT/report['plan']);require(sha(ROOT/report['plan'])==report['plan_sha256'],'Plan bytes changed')
    for p,h in plan['source_sha256'].items():require(sha(ROOT/p)==h,'Declared source changed')
    features,groups=load_inputs(plan);directory=ROOT/'data/packet_model_development_v1'
    state=read(directory/'run_state.json');require(state['state']=='completed_exploratory_not_frozen' and state['report_sha256']==sha(report_path),'Run incomplete/changed')
    for a in report['private_artifacts'].values():require(sha(ROOT/a['path'])==a['sha256'],'Private artifact bytes changed')
    scores={};reloads=0;transform_checks=0
    with threadpool_limits(limits=2):
        for p in report['operating_points']:
            key=(p['variant'],p['method'],p['seed'])
            if p['variant']=='mapped_branch_control' or key in scores:continue
            path=directory/f'{p["variant"]}_{p["method"]}_{p["seed"]}_scores.npz'
            with np.load(path,allow_pickle=False) as data: values={n:data[n] for n in data.files}
            scores[key]=values
            if p['method']=='hybrid':continue
            if p['method']=='rate':model=None;columns=[features.index('packets_in')]
            else:
                artifact=directory/f'{p["variant"]}_{p["method"]}_{p["seed"]}.joblib'
                payload=joblib.load(artifact);model=payload['model'];columns=[features.index(n) for n in payload['features']]
                require(payload['plan_sha256']==report['plan_sha256'] and not payload['final_frozen'],'Wrong model provenance')
                reloads+=1
                if p['method'] in ('AE','IF','LR'):
                    t,y=labelled_matrix(groups,'T',p['method'] in ('AE','IF'),p['variant']=='lab_benign_T_only')
                    t=t[:,columns]
                    transform=model if p['method']=='AE' else model.named_steps['transform']
                    imputer=transform.imputer if p['method']=='AE' else transform.imputer_
                    require(np.allclose(imputer.statistics_,np.nanmedian(transform.clean(t),axis=0),rtol=0,atol=1e-12),'Fitted imputation does not match permitted T')
                    transform_checks+=1
            for g in groups:
                if g['meta']['role'] not in ('C1','C2','V'):continue
                actual=native_score(p['method'],model,g['x'],columns)
                require(np.allclose(actual,values[g['meta']['id']],rtol=0,atol=1e-12),'Reloaded predictions differ')
        for key,values in scores.items():
            variant,method,seed=key
            if method!='hybrid':continue
            h=mapped_scores(groups,scores[(variant,'HGB',seed)]);a=mapped_scores(groups,scores[(variant,'AE',seed)])
            require(all(np.array_equal(values[n],np.maximum(h[n],a[n])) for n in values),'Fusion/reference replay differs')
    # Independent (non-vectorised) temporal calculation, not the fitted runner's
    # kth-statistic/calibration helper. C2 has only known-benign model rows.
    checked=0;coverage=[]
    for p in report['operating_points']:
        key=(p['variant'],p['method'],p['seed'])
        values=mapped_scores(groups,scores[('main',p['method'],p['seed'])]) if p['variant']=='mapped_branch_control' else scores[key]
        totals={}
        for g in groups:
            if g['meta']['role']!='C2':continue
            require(g['meta']['expected_y']==0,'Calibration label contamination')
            stat=independent_stat(g['seconds'],values[g['meta']['id']],p['k'],p['h'])
            valid=np.isfinite(stat);fp=int(np.sum(stat[valid]>p['threshold']));n=int(np.sum(valid))
            stratum='stress' if g['meta']['condition'] in plan['calibration']['stress'] else 'ordinary'
            for label in ('overall','stratum:'+stratum,'condition:'+g['meta']['condition']):
                count=totals.setdefault(label,[0,0]);count[0]+=n;count[1]+=fp
        for label,(n,fp) in totals.items():
            expected=p['C2'][label]
            require(n==expected['eligible_windows'] and fp==expected['false_positive_windows'],'Independent calibration counts differ')
            require(fp<=math.floor(.01*n+1e-12),'Empirical calibration budget violated')
        require(p['V']['common_5_window_support']['positive_windows']==44 and p['V']['common_5_window_support']['benign_windows']==669,'V comparison support differs')
        coverage.append(dict(variant=p['variant'],method=p['method'],seed=p['seed'],h=p['h'],C2_eligible=totals['overall'][0]))
        checked+=1
    result=dict(date='2026-11-13',report_sha256=sha(report_path),plan_sha256=report['plan_sha256'],source_code_sha256=sha(Path(__file__)),
                selected_weight_bundles_reloaded=reloads,imputer_role_provenance_checks=transform_checks,
                private_artifacts_hash_verified=len(report['private_artifacts']),operating_points_independently_recalculated=checked,
                all_reload_scores_match=True,all_fusion_scores_match=True,all_joint_C2_empirical_budgets_pass=True,
                known_V_comparison_support=dict(positive=44,benign=669),coverage=coverage,
                final_model_frozen=False,final_sources_opened=False,scope='Reproduction and engineering audit, not independent efficacy validation or final readiness.')
    output=ROOT/'results/development/packet_model_development_audit_v1.json'
    if output.exists():raise FileExistsError('Preserve completed audit')
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in result.items() if k!='coverage'},indent=2))


if __name__=='__main__':main()
