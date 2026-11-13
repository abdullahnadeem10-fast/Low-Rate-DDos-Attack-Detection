"""Small, qualified model-development summary; no refitting or test access."""
import csv
import json
from pathlib import Path
import numpy as np
from packet_model_policy import ROOT,read,sha,require


def main():
    out=ROOT/'results/development';path=out/'packet_model_development_v1.json';report=read(path)
    audit_path=out/'packet_model_development_audit_v1.json';audit=read(audit_path)
    require(audit['report_sha256']==sha(path) and audit['all_joint_C2_empirical_budgets_pass'],'Audited report changed')
    records=[]
    for variant in ('main','drop_volume','lab_benign_T_only','mapped_branch_control'):
        for method in sorted({p['method'] for p in report['operating_points'] if p['variant']==variant}):
            points=[p for p in report['operating_points'] if p['variant']==variant and p['method']==method]
            recalls=[p['V']['common_5_window_support']['recall'] for p in points]
            fprs=[p['V']['common_5_window_support']['fpr'] for p in points]
            records.append(dict(variant=variant,method=method,seeds=len(points),k=points[0]['k'],h=points[0]['h'],
                C2_eligible_windows=points[0]['C2']['overall']['eligible_windows'],V_positive_windows=44,V_benign_windows=669,
                V_proxy_recall_mean=float(np.mean(recalls)),V_proxy_recall_min=min(recalls),V_proxy_recall_max=max(recalls),
                V_benign_fpr_mean=float(np.mean(fprs)),V_benign_fpr_min=min(fprs),V_benign_fpr_max=max(fprs),
                V_seed_fits_exceeding_1percent=sum(f>.01 for f in fprs)))
    table=out/'packet_model_development_summary_v1.csv'
    with table.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    primary=[p for p in report['operating_points'] if p['variant']=='main' and p['seed']==7]
    hybrid=next(p for p in primary if p['method']=='hybrid');ae=next(p for p in primary if p['method']=='AE')
    candidates={n:a for n,a in report['private_artifacts'].items() if n in ('main_HGB_7.joblib','main_AE_7.joblib','main_HGB_7_scores.npz','main_AE_7_scores.npz','operating_rules.json')}
    candidate=dict(date='2026-11-13',primary_method='hybrid',primary_seed=7,seed_prespecified_not_selected_by_outcome=True,
        plan_sha256=report['plan_sha256'],report_sha256=sha(path),registry_sha256=report['registry_sha256'],
        components=candidates,decision=dict(k=hybrid['k'],h=hybrid['h'],strict_threshold=hybrid['threshold'],
            mapping='Right C1 empirical percentiles, max across HGB/AE. C1 references reconstruct from private native C1 score arrays.',
            state='Reset per whole group; insufficient/missing decision history is undefined, never benign.'),
        final_model_frozen=False,final_scoring_authorized_by_this_manifest=False,
        scope='Concrete provisional candidate for review; this manifest is not a final freeze or evidence of superiority.')
    (out/'packet_model_candidate_v1.json').write_text(json.dumps(candidate,indent=2)+'\n',encoding='utf-8',newline='\n')
    readiness=dict(date='2026-11-13',exploratory_model_policy_declared=True,packet_window_models_fitted=True,
        source_data_unchanged=True,source_path_confounding_resolved=False,final_model_frozen=False,final_attack_tests_run=0,
        headline_generalization_readiness=False,plan_sha256=report['plan_sha256'],report_sha256=sha(path),audit_sha256=sha(audit_path),
        summary_csv_sha256=sha(table),candidate_sha256=sha(out/'packet_model_candidate_v1.json'),source_code_sha256=sha(Path(__file__)),
        private_weight_bundles=41,private_artifacts=99,operating_points=67,offline_policy_tests=146,
        V_selection_known_rows=915,V_rule_comparison=dict(positive=44,benign=669),
        C2_eligible_by_h={'1':962,'3':734,'5':681},
        important_findings=[
            'No demonstrated hybrid superiority: lower proxy recall than AE, with lower observed V benign FPR; observed V rates differ despite the common C2 budget.',
            'HGB/RF/LR/IF/rate selected primary rules miss all 44 proxy positives; preserve this negative cross-source result.',
            'Hybrid proxy recall varies across seeds and the lab-only benign training sensitivity control; variants are diagnostic and not promoted.',
            'Every main AE seed selected epoch100 at the 100-epoch cap. This is not convergence evidence or permission to silently extend training.',
            'For 3-of-5, public C2 support is only 13/246 known benign windows and public V support 1/155. Do not generalize eligible-history FPR to excluded labelled windows.',
            'All V outcomes influenced model/rule selection; these are biased development estimates from one sparse attack source, not independent/final validation.'
        ],
        next_action='Review the provisional seed-7 hybrid versus the declared AE baseline and sensitivity results, qualify the claim/label-support limitations, then write a separate final-freeze and blind-evaluation protocol before opening reserved sources. Preserve v1; any revised training/selection needs a new bounded declaration.')
    (out/'packet_model_readiness_v1.json').write_text(json.dumps(readiness,indent=2)+'\n',encoding='utf-8',newline='\n')
    lines=['# Exploratory packet-window model review — 13 November 2026','',
        '**This is development evidence, not a final or unseen-attack result.** The policy was declared and hash-pinned before fitting. All 56 input groups/6,206 labelled windows remain unchanged. No slow-family, external, final-known payload, lab attack or final benign session was opened.','',
        'HGB, Random Forest, Logistic Regression, Isolation Forest, benign AE, a rate baseline and HGB+AE max fusion were fitted/scored as declared. Five algorithm seeds were used for stochastic methods; deterministic methods ran once. HGB internal random validation was disabled. AE/IF transforms and fits used only benign T; AE epoch selection used only benign V. C1 built fusion score maps; C2 calibrated the complete rule.','',
        '| Main method | Rule | Eligible C2 windows | Mean V proxy recall | Seed range | Mean V benign FPR | Seed range |',
        '| --- | --- | ---: | ---: | ---: | ---: | ---: |']
    for r in records:
        if r['variant']!='main':continue
        lines.append(f'| {r["method"]} | {r["k"]}-of-{r["h"]} | {r["C2_eligible_windows"]} | {100*r["V_proxy_recall_mean"]:.2f}% | {100*r["V_proxy_recall_min"]:.2f}–{100*r["V_proxy_recall_max"]:.2f}% | {100*r["V_benign_fpr_mean"]:.3f}% | {100*r["V_benign_fpr_min"]:.3f}–{100*r["V_benign_fpr_max"]:.3f}% |')
    lines += ['', 'Every V rule comparison uses the same 44 positive proxy seconds and 669 eligible benign seconds. Configuration AP used 915 known labelled V windows; unknown context was scored only for causal decision history and never became ground truth. V metrics were used for selection, so these are optimistic development estimates. Seed ranges describe algorithm variability on the same data, not confidence intervals or independent attack repetitions.','',
        f'The prespecified primary seed is **7**, not the best observed seed. Its hybrid uses **3-of-5, strict threshold {hybrid["threshold"]:.12f}**, detects **{hybrid["V"]["common_5_window_support"]["TP"]}/44** proxy windows and flags **{hybrid["V"]["common_5_window_support"]["FP"]}/669** eligible V benign windows. The declared AE baseline detects **{ae["V"]["common_5_window_support"]["TP"]}/44** with **{ae["V"]["common_5_window_support"]["FP"]}/669** benign alerts. Both have zero C2 FP windows on their 681 eligible histories for seed 7. This is a recall/false-positive trade-off, not demonstrated fusion superiority.','',
        'HGB, RF, LR, IF and rate miss all 44 validation proxy positives at their selected calibrated settings. These negative findings remain in every table. The lab-only benign T control and removal of volume/length predictors changed hybrid recall; neither variant is promoted. Mapped-only branch controls separate the fusion decision from native-score baselines. All AE main seeds reached and selected epoch 100/100; convergence has not been established.','',
        'All declared C2 budgets pass overall, in ordinary/stress strata and in every benign condition. These are empirical rates on eligible histories: horizons1/3/5 have 962/734/681 C2 windows respectively. For horizon 5 only 13 of 246 public C2 negatives and 1 of 155 public V negatives have complete known-benign label history. Excluded known negatives were not counted as correct decisions. Small strata require zero observed FPs and do not justify a population FPR guarantee. The observed V FPR exceeds 1% for some AE/IF seeds despite passing C2; final FPR can also exceed the target.','',
        'Audit reproduced all 41 saved weight bundles and 99 private artifact hashes, checked 21 fitted-imputer role traces and independently recalculated 67 operating points. All reload scores and hybrid score compositions matched. All 146 offline engineering/policy checks passed. The recorded roughly 36 seconds cover the fitting/scoring/calibration/artifact section, excluding initial input loading and final report writing. This is not an inference or live-latency benchmark.','',
        'Source/service/path confounding remains: Friday has one attacked T target with no matched benign-only seconds; known V has one sparse SYN-labelled TCP/443 source without observed TLS functionality, denial-impact or matched benign-target controls. Same-host synthetic repetitions are not independent environments. No episode recall, onset-to-alert delay, significance test or final generalization claim follows.','',
        '**No final freeze has occurred.** [The candidate manifest](../results/development/packet_model_candidate_v1.json) packages the preselected seed 7 hybrid for review, not permission to score held-out sources. '+readiness['next_action'],'',
        'Evidence: [declared policy](model_development_v1.json), [all development results](../results/development/packet_model_development_v1.json), [compact table](../results/development/packet_model_development_summary_v1.csv), [independent audit](../results/development/packet_model_development_audit_v1.json), [readiness](../results/development/packet_model_readiness_v1.json). Weights, native/fused scores and C1 references remain under ignored `data/packet_model_development_v1/`. Transfer these exact artifacts and original data for byte-exact continuation; do not overwrite v1 with a newly trained run.']
    (ROOT/'plan/PACKET_MODEL_DEVELOPMENT_REVIEW.md').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'summary_rows':len(records),'primary_seed 7_hybrid_TP':hybrid['V']['common_5_window_support']['TP'],
                      'primary_seed 7_AE_TP':ae['V']['common_5_window_support']['TP'],'final_frozen':False},indent=2))


if __name__=='__main__':main()
