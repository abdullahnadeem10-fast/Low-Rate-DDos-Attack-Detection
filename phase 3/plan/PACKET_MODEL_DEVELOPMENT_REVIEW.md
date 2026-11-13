# Exploratory packet-window model review — 13 November 2026

**This is development evidence, not a final or unseen-attack result.** The policy was declared and hash-pinned before fitting. All 56 input groups/6,206 labelled windows remain unchanged. No slow-family, external, final-known payload, lab attack or final benign session was opened.

HGB, Random Forest, Logistic Regression, Isolation Forest, benign AE, a rate baseline and HGB+AE max fusion were fitted/scored as declared. Five algorithm seeds were used for stochastic methods; deterministic methods ran once. HGB internal random validation was disabled. AE/IF transforms and fits used only benign T; AE epoch selection used only benign V. C1 built fusion score maps; C2 calibrated the complete rule.

| Main method | Rule | Eligible C2 windows | Mean V proxy recall | Seed range | Mean V benign FPR | Seed range |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| AE | 3-of-5 | 681 | 96.36% | 86.36–100.00% | 0.957% | 0.149–2.093% |
| HGB | 1-of-1 | 962 | 0.00% | 0.00–0.00% | 0.000% | 0.000–0.000% |
| IF | 1-of-1 | 962 | 0.00% | 0.00–0.00% | 1.315% | 1.046–1.644% |
| LR | 1-of-1 | 962 | 0.00% | 0.00–0.00% | 0.299% | 0.299–0.299% |
| RF | 1-of-1 | 962 | 0.00% | 0.00–0.00% | 0.000% | 0.000–0.000% |
| hybrid | 3-of-5 | 681 | 73.64% | 20.45–88.64% | 0.179% | 0.149–0.299% |
| rate | 2-of-3 | 734 | 0.00% | 0.00–0.00% | 0.299% | 0.299–0.299% |

Every V rule comparison uses the same 44 positive proxy seconds and 669 eligible benign seconds. Configuration AP used 915 known labelled V windows; unknown context was scored only for causal decision history and never became ground truth. V metrics were used for selection, so these are optimistic development estimates. Seed ranges describe algorithm variability on the same data, not confidence intervals or independent attack repetitions.

The prespecified primary seed is **7**, not the best observed seed. Its hybrid uses **3-of-5, strict threshold 0.986765922250**, detects **39/44** proxy windows and flags **1/669** eligible V benign windows. The declared AE baseline detects **43/44** with **3/669** benign alerts. Both have zero C2 FP windows on their 681 eligible histories for seed 7. This is a recall/false-positive trade-off, not demonstrated fusion superiority.

HGB, RF, LR, IF and rate miss all 44 validation proxy positives at their selected calibrated settings. These negative findings remain in every table. The lab-only benign T control and removal of volume/length predictors changed hybrid recall; neither variant is promoted. Mapped-only branch controls separate the fusion decision from native-score baselines. All AE main seeds reached and selected epoch 100/100; convergence has not been established.

All declared C2 budgets pass overall, in ordinary/stress strata and in every benign condition. These are empirical rates on eligible histories: horizons1/3/5 have 962/734/681 C2 windows respectively. For horizon 5 only 13 of 246 public C2 negatives and 1 of 155 public V negatives have complete known-benign label history. Excluded known negatives were not counted as correct decisions. Small strata require zero observed FPs and do not justify a population FPR guarantee. The observed V FPR exceeds 1% for some AE/IF seeds despite passing C2; final FPR can also exceed the target.

Audit reproduced all 41 saved weight bundles and 99 private artifact hashes, checked 21 fitted-imputer role traces and independently recalculated 67 operating points. All reload scores and hybrid score compositions matched. All 146 offline engineering/policy checks passed. The recorded roughly 36 seconds cover the fitting/scoring/calibration/artifact section, excluding initial input loading and final report writing. This is not an inference or live-latency benchmark.

Source/service/path confounding remains: Friday has one attacked T target with no matched benign-only seconds; known V has one sparse SYN-labelled TCP/443 source without observed TLS functionality, denial-impact or matched benign-target controls. Same-host synthetic repetitions are not independent environments. No episode recall, onset-to-alert delay, significance test or final generalization claim follows.

**No final freeze has occurred.** [The candidate manifest](../results/development/packet_model_candidate_v1.json) packages the preselected seed 7 hybrid for review, not permission to score held-out sources. Review the provisional seed-7 hybrid versus the declared AE baseline and sensitivity results, qualify the claim/label-support limitations, then write a separate final-freeze and blind-evaluation protocol before opening reserved sources. Preserve v1; any revised training/selection needs a new bounded declaration.

Evidence: [declared policy](model_development_v1.json), [all development results](../results/development/packet_model_development_v1.json), [compact table](../results/development/packet_model_development_summary_v1.csv), [independent audit](../results/development/packet_model_development_audit_v1.json), [readiness](../results/development/packet_model_readiness_v1.json). Weights, native/fused scores and C1 references remain under ignored `data/packet_model_development_v1/`. Transfer these exact artifacts and original data for byte-exact continuation; do not overwrite v1 with a newly trained run.
