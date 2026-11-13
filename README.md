# Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks

A Computer Networks research project by M Abdullah Nadeem and Ayaan Faisal. It asks whether a hybrid supervised and anomaly detector can recognize withheld slow denial-of-service attacks while keeping false alarms and detection delay low.

For continuation on another machine or harness, start with [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md). It records the complete handoff, protocol, data hashes, limitations, commands and exact next action; [AGENTS.md](AGENTS.md) points compatible coding tools to it.

| Stage | Work available |
| --- | --- |
| Phase 2: research design | [Reviewed IEEE-format proposal](phase%202/CNET_Phase2_IEEE.pdf), [LaTeX source](phase%202/CNET_Phase2_IEEE.tex), [methodology diagram](phase%202/CNET_Phase2_Methodology_Diagram.pdf), [source and methodology review](phase%202/FINAL_REVIEW.md) |
| Phase 3: testing | [Checklist](phase%203/plan/CHECKLIST.md), [progress and next step](phase%203/plan/PROGRESS.md), [pilot code and setup](phase%203/README.md), [development evidence](phase%203/results/development/) |

The [v5 input whitelist](phase%203/results/development/study_development_manifest_v5.json) contains **56 groups/6,206 known labelled windows**, including 36 new legitimate stress sessions/2,160 benign windows. Initial lab sessions, public-source audits, failed splits and engineering attempts remain preserved; only selected whole groups enter modelling. Raw data, weights and environments stay outside Git.

**Exploratory causal packet-window models are now fitted:** HGB, benign AE, hybrid, rate, LR, RF and IF, under a [policy declared before fitting](phase%203/plan/model_development_v1.json). All 146 offline engineering/policy checks pass. Audit reloaded 41 weight bundles and independently recalculated 67 operating points; C2 empirical budgets pass jointly across conditions. The [model review](phase%203/plan/PACKET_MODEL_DEVELOPMENT_REVIEW.md) records the actual trade-off: the hybrid has lower proxy recall and lower observed validation false-positive counts than AE, with no demonstrated superiority. Other calibrated main baselines miss the 44 proxy-positive seconds. These selected, source-confounded development estimates are not final/unseen-family results or independent attack replications.

**No final freeze or final attack test has occurred.** Sparse known V, limited labelled persistence support, the AE epoch ceiling and same-host/source/path limitations remain. Read the [candidate/readiness](phase%203/results/development/packet_model_readiness_v1.json), [next actions](phase%203/plan/NEXT_STEPS.md), [progress](phase%203/plan/PROGRESS.md) and [roadmap](phase%203/plan/FIVE_STEP_ROADMAP.md). Next: document the candidate review and blind final-freeze/evaluation protocol before reserved scoring. All slow-family context, lab attack/final benign sessions, CSE-CIC-IDS2018 and unopened/unqualified CIC2019 01-12 remain unused. Friday target is T-only; provided CIC2019 03-11 is V-only. No training/audit job is active.

The repository contains the public version of the coursework, without student roll numbers. Raw captures and label archives are kept outside Git. Use the linked publisher and pinned mirror records in the pilot evidence to reproduce data acquisition.
