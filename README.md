# Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks

A Computer Networks research project by M Abdullah Nadeem and Ayaan Faisal. It asks whether a hybrid supervised and anomaly detector can recognize withheld slow denial-of-service attacks while keeping false alarms and detection delay low.

For continuation on another machine or harness, start with [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md). It records the complete handoff, protocol, data hashes, limitations, commands and exact next action; [AGENTS.md](AGENTS.md) points compatible coding tools to it.

| Stage | Work available |
| --- | --- |
| Phase 2: research design | [Reviewed IEEE-format proposal](phase%202/CNET_Phase2_IEEE.pdf), [LaTeX source](phase%202/CNET_Phase2_IEEE.tex), [methodology diagram](phase%202/CNET_Phase2_Methodology_Diagram.pdf), [source and methodology review](phase%202/FINAL_REVIEW.md) |
| Phase 3: testing | [Checklist](phase%203/plan/CHECKLIST.md), [progress and next step](phase%203/plan/PROGRESS.md), [pilot code and setup](phase%203/README.md), [development evidence](phase%203/results/development/) |

The selected initial benign component contains **12 sessions and 702 measurement windows**, with all 28 client jitter seeds distinct and zero kernel-reported capture drops. It retains eight unchanged pilot sessions plus four seed-separated calibration replacements; superseded data are not pooled. All **81 offline engineering checks pass**. See the [canonical selection](phase%203/results/development/benign_batch_v3.json) and [predictor/group manifest](phase%203/results/development/benign_development_manifest.json).

The current [v4 registry](phase%203/results/development/study_development_manifest_v4.json) contains **2,926 candidate benign rows, 1,076 attack-present T rows and 44 preliminary independent attack-present V rows**. Friday's complete target stream remains T-only. The new CIC-DDoS2019 03-11 source is V-only: 61,407,884 frames were inventoried, with an empirical +3-hour clock/count join before fresh TCP/443 features. This sparse, SYN-labelled slice has no observed TLS prefix or corroborated benign target seconds; it does not establish HTTPS functionality, denial impact, within-source FPR or broad validation. Read the [source review](phase%203/plan/CIC2019_VALIDATION_REVIEW.md). Entire unopened 01-12 is reserved as an unqualified final-known candidate; all slow-family/external reservations remain. Failed v1/v2 temporal splits are preserved. Broader benign congestion/diversity/repetitions, source/path controls, sparse-V review and gap-aware calibration remain before matched model fitting/freezing. Earlier auxiliary completed-flow fusion did not improve recall over HGB; no main detector or final attack test has run.

WSL/Docker and the controlled benign capture path are operational. The [progress log](phase%203/plan/PROGRESS.md), [readiness evidence](phase%203/results/development/development_readiness_cic2019_2026-11-12.json) and [five-step roadmap](phase%203/plan/FIVE_STEP_ROADMAP.md) record the remaining work. Study training readiness is false. Results here are engineering/development evidence, not claimed detector superiority.

The repository contains the public version of the coursework, without student roll numbers. Raw captures and label archives are kept outside Git. Use the linked publisher and pinned mirror records in the pilot evidence to reproduce data acquisition.
