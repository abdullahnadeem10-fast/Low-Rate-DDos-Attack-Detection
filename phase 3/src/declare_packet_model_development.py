"""Seal bounded exploratory modelling policy before any main-data fitting."""
import json
import platform
from pathlib import Path
import sklearn
import numpy as np
from packet_model_policy import ROOT,REGISTRY_SHA,SEEDS,RULES,sha,read,require


def declare():
    registry_path=ROOT/'results/development/study_development_manifest_v5.json'
    require(sha(registry_path)==REGISTRY_SHA,'Registry differs from audited v5')
    registry=read(registry_path);cic=read(ROOT/'results/development/cic2019_causal_v1.json')
    bounds=read(ROOT/'plan/cic2019_features_v1.json')
    context=cic['files']['features.csv'];require(sha(ROOT/context['path'])==context['sha256'],'V context differs')
    source_names=['src/packet_model_policy.py','src/declare_packet_model_development.py','src/run_packet_model_development.py',
                  'src/test_packet_model_policy.py','src/benign_autoencoder.py']
    for g in registry['groups']: require(sha(ROOT/g['table'])==g['sha256'],'Changed selected model table')
    plan=dict(date='2026-11-13',version='model_development_v1',declared_before_main_fitting=True,
        scope='Exploratory causal packet-window DEVELOPMENT only. No final freeze, unseen-family result, live delay, denial-impact or broad-generalization claim.',
        registry='results/development/study_development_manifest_v5.json',registry_sha256=REGISTRY_SHA,
        source_sha256={n:sha(ROOT/n) for n in source_names},
        software=dict(python=platform.python_version(),numpy=np.__version__,sklearn=sklearn.__version__,threads=2),
        predictor_columns=registry['predictor_columns'],excluded_metadata=registry['metadata_columns_excluded_from_predictors'],
        ae_signed_predictor='packet_rate_change',ae_signed_index=23,
        group_ownership='Exact 56-group whitelist once; no packet/feature/fitted state crosses roles. Entire Friday target T and entire provided CIC2019 03-11 V.',
        validation_positive_context=dict(**context,eligible_start=bounds['eligible_start'],eligible_end=bounds['eligible_end'],
            use='Only scores from already permitted whole-V features for preceding decision history. Unknown labels remain -1; they never fit models/maps, enter negatives, or gain labels.'),
        seeds=list(SEEDS),primary_seed=7,primary_seed_not_selected_by_outcome=True,
        configurations=dict(HGB=[dict(max_iter=n,max_leaf_nodes=15,learning_rate=.1,l2_regularization=0.,early_stopping=False) for n in (50,100,200)],
            RF=[dict(n_estimators=100,max_depth=d,class_weight='balanced',n_jobs=2) for d in (6,12,None)],
            LR=[dict(C=c,class_weight='balanced',max_iter=2000,solver='lbfgs') for c in (.1,1.,10.)],
            IF=[dict(n_estimators=100,max_samples=s,contamination='auto',n_jobs=2) for s in (128,256)],
            AE=[dict(hidden_layers=[32,16,8,16,32],adam_learning_rate=.001,batch_size=256,max_epochs=100,patience=10)],
            rate=[dict(feature='packets_in')]),
        deterministic_methods=['LR','rate'],stochastic_methods=['HGB','RF','IF','AE'],
        fitting=dict(supervised='Only T known benign+known attack; inverse class frequency weights for HGB, balanced LR/RF.',
            anomaly='Only benign T fits IF/AE and their transforms; AE epochs selected on benign V only.',
            transforms='No fitted transforms from V/C1/C2. Supervised LR signed-log/median/robust fitted on T. IF signed-log/median/robust fitted on benign T. AE frozen BenignAutoencoder with dynamic signed index for reduced schema.'),
        configuration_selection=dict(metric='Mean raw-score AP on exactly 915 known V windows, no unknown windows or onset metrics.',
            seeds='Average five seeds for stochastic methods; LR one deterministic fit.',
            tie='Configuration order: lower HGB iterations, shallower RF, smaller LR C / IF max_samples.',
            qualification='Exploratory only: 44 positive seconds in one sparse source, source/class/path confounded. Not an independent estimate after selection; does not resolve representativeness.'),
        scoring=dict(single_methods='Raw native anomaly/positive-probability scores, high means attack. Rate packets_in; IF negative score_samples.',
            hybrid='HGB and AE right empirical percentiles on disjoint known benign C1, max fusion; preserve ties and saturation at 1; no tail extrapolation.',
            branch_controls='Mapped HGB-only and mapped AE-only at the chosen hybrid persistence, recalibrated C2; distinguish mapping effects from branch removal.'),
        persistence=dict(candidates=[dict(k=k,h=h) for k,h in RULES],comparison='Strict score > tau; kth-largest trailing h statistic > tau.',
            resets='Every group reset; nonconsecutive model-table times invalidate history, never compress/zero-fill gaps.',
            C2='Only trailing h consecutive known-benign model windows count. Initial h-1 and every incomplete history excluded; no warm-up labels inferred.',
            V_positive='Current corroborated positive only; prior complete-clock scores may have unknown labels in permitted full V source. Does not turn unknowns into ground truth.',
            V_negative='Trailing h known-benign windows. Rule-selection FPR tie-break uses common 5-window known-benign support for comparable denominators.',
            selection='Max mean V proxy positive-window recall, then min mean common-support benign V FPR, then candidate order 1/1,2/3,3/5. No episode/delay selection.'),
        calibration=dict(role='C2 only',alpha=.01,groups='All benign C2 whole groups; require nonempty overall, ordinary/stress and every condition stratum.',
            ordinary=['public_http','ordinary','mixed_keepalive'],stress=['bursts','flash','long_download','congested_mixed'],
            threshold='Max of each stratum order statistic at n-floor(alpha*n)-1, with strict comparison; retain ties. n<100 requires zero exceedances.',
            guarantee='Empirical eligible-window budget only. No population/final FPR guarantee; unsupported strata fail; zero attack recall/infinite-equivalent cutoff retained.'),
        sensitivity_controls=[dict(id='drop_volume',removed_predictors=['bytes_in','bytes_out','packet_length_mean','packet_length_std','in_out_byte_ratio'],
                fit='Same chosen HGB config, AE settings and permitted T; fixed primary method rule, fresh C1/C2 calibration; diagnostic only.'),
            dict(id='lab_benign_T_only',removed_predictors=[],fit='Remove public benign T only; retain whole positive T; no role reassignment. Same chosen config/rule, fresh benign transforms/C1/C2; diagnostic only.')],
        configuration_budget='At most 12 per learned family including score/rule controls: main HGB 3*3 +2 fixed-rule source controls +1 mapped branch; other families no larger. No sensitivity variant promoted by outcomes.',
        report='All candidates/seeds/thresholds/stratum denominators, source-condition FPR, V labelled-window metrics and mapped saturation. No episode CIs or independent-attack counts; five seeds are algorithm repeats, not traffic recordings.',
        artifact_policy='Ignored data/packet_model_development_v1 holds weights/references/scores and hashes; public small results/manifests only. Source/data changes fail; no silent overwrite/retraining.',
        reserved=['All Slowloris/Slowhttptest groups/context','Entire CSE-CIC-IDS2018 source including benign','Entire provided CIC2019 01-12 source/context/labels','All lab attack and final benign sessions'],
        exploratory_training_authorized=True,headline_generalization_readiness=False,final_model_frozen=False,final_attack_tests_run=0,
        references=['https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html',
            'https://scikit-learn.org/1.7/modules/generated/sklearn.neural_network.MLPRegressor.html',
            'https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.IsolationForest.html'])
    path=ROOT/'plan/model_development_v1.json'
    if path.exists(): raise FileExistsError('Never overwrite a declared modelling policy')
    path.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'plan':path.name,'sha256':sha(path),'known_V_rows':915,'final_sources_opened':False}))


if __name__=='__main__': declare()
