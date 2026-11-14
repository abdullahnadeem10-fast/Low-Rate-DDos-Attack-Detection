# Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks

A Computer Networks research project by M Abdullah Nadeem and Ayaan Faisal. It asks whether a hybrid supervised and anomaly detector can recognize withheld slow denial-of-service attacks while keeping false alarms and detection delay low.

For continuation on another machine or harness, start with [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md). It records the complete handoff, protocol, data hashes, limitations, commands and exact next action; [AGENTS.md](AGENTS.md) points compatible coding tools to it. For the next computer/Claude Code session, follow the [dedicated friend handoff](phase%203/plan/CLAUDE_CODE_FRIEND_HANDOFF.md); original model weights and calibration arrays must be transferred privately.

| Stage | Work available |
| --- | --- |
| Phase 2: research design | [Reviewed IEEE-format proposal](phase%202/CNET_Phase2_IEEE.pdf), [LaTeX source](phase%202/CNET_Phase2_IEEE.tex), [methodology diagram](phase%202/CNET_Phase2_Methodology_Diagram.pdf), [source and methodology review](phase%202/FINAL_REVIEW.md) |
| Phase 3: testing | [Checklist](phase%203/plan/CHECKLIST.md), [progress and next step](phase%203/plan/PROGRESS.md), [pilot code and setup](phase%203/README.md), [development evidence](phase%203/results/development/) |

## Completed frozen lab evaluation — 14 November 2026

**All 60 declared lab trials are complete and audited:** 20 benign sessions and 40 controlled campaigns, 117 frozen configurations each (7,020 case/session evaluations). All 8 campaign cells and 4 benign conditions have 5 repetitions. These are same-host recordings, not independent environments. No model, threshold, seed or trial order was tuned from final outcomes.

| Prespecified seed 7 | Window recall | Benign window FPR | Exact episode hits |
| --- | ---: | ---: | ---: |
| Hybrid | 7476/9560 (78.20%) | 2129/3600 (59.14%) | 40/40 |
| AE | 9509/9560 (99.47%) | 1581/3600 (43.92%) | 40/40 |

The hybrid has severe false alarms and weak one-source low-connection detection. Episode hits do not erase window misses, late alerts or preexisting false alarms. All matched baselines/controls/seeds remain visible; these results do not establish a hybrid advantage, production FPR or independent-domain generalization. Detector delays are offline proxies, not measured live latency. A separately sealed pre-schedule-interruption continuation retained every earlier scientific outcome and the old setup/ledger; no measured trial was replaced.

Read the [complete lab report](phase%203/plan/FINAL_LAB_RESULTS_V2.md), [v8 checkpoint/audit](phase%203/results/final/final_lab_checkpoint_v8_audit.json), [all-case/stratum manifest](phase%203/results/final/final_lab_results_v2.json), [current readiness](phase%203/results/final/final_lab_readiness_v1.json) and [next gate](phase%203/plan/NEXT_STEPS.md). Public slow/K/external qualification/transfer and separate feature/inference/live-latency evaluation remain pending before full-study/paper claims. Final raw/context/warmup remains excluded from development/calibration. Keep exact raw/model/score/image/interruption bundles separate from this public repository.

## Historical development snapshot — superseded by the completed lab evaluation above

The [v5 input whitelist](phase%203/results/development/study_development_manifest_v5.json) contains **56 groups/6,206 known labelled windows**, including 36 new legitimate stress sessions/2,160 benign windows. Initial lab sessions, public-source audits, failed splits and engineering attempts remain preserved; only selected whole groups enter modelling. Raw data, weights and environments stay outside Git.

**Exploratory causal packet-window models are now fitted:** HGB, benign AE, hybrid, rate, LR, RF and IF, under a [policy declared before fitting](phase%203/plan/model_development_v1.json). All 146 offline engineering/policy checks pass. Audit reloaded 41 weight bundles and independently recalculated 67 operating points; C2 empirical budgets pass jointly across conditions. The [model review](phase%203/plan/PACKET_MODEL_DEVELOPMENT_REVIEW.md) records the actual trade-off: the hybrid has lower proxy recall and lower observed validation false-positive counts than AE, with no demonstrated superiority. Other calibrated main baselines miss the 44 proxy-positive seconds. These selected, source-confounded development estimates are not final/unseen-family results or independent attack replications.

At that historical pre-freeze checkpoint, no final freeze or final attack test had occurred. Sparse known V, limited labelled persistence support, the AE epoch ceiling and same-host/source/path limitations remain. Read the [candidate/readiness](phase%203/results/development/packet_model_readiness_v1.json), [next actions](phase%203/plan/NEXT_STEPS.md), [progress](phase%203/plan/PROGRESS.md) and [roadmap](phase%203/plan/FIVE_STEP_ROADMAP.md). Next: document the candidate review and blind final-freeze/evaluation protocol before reserved scoring. All slow-family context, lab attack/final benign sessions, CSE-CIC-IDS2018 and unopened/unqualified CIC2019 01-12 remain unused. Friday target is T-only; provided CIC2019 03-11 is V-only. No training/audit job is active.

The repository contains the public version of the coursework, without student roll numbers. Raw captures and label archives are kept outside Git. Use the linked publisher and pinned mirror records in the pilot evidence to reproduce data acquisition.
