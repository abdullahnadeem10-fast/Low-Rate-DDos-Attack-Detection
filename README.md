# Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks

A Computer Networks research project by M Abdullah Nadeem and Ayaan Faisal. It asks whether a hybrid supervised and anomaly detector can recognize withheld slow denial-of-service attacks while keeping false alarms and detection delay low.

| Stage | Work available |
| --- | --- |
| Phase 2: research design | [Reviewed IEEE-format proposal](phase%202/CNET_Phase2_IEEE.pdf), [LaTeX source](phase%202/CNET_Phase2_IEEE.tex), [methodology diagram](phase%202/CNET_Phase2_Methodology_Diagram.pdf), [source and methodology review](phase%202/FINAL_REVIEW.md) |
| Phase 3: testing | [Checklist](phase%203/plan/CHECKLIST.md), [progress and next step](phase%203/plan/PROGRESS.md), [pilot code and setup](phase%203/README.md), [saved pilot evidence](phase%203/results/pilot/) |

The full Friday capture passed its pinned checksum, and replay/clock/count audits and 18 engineering fixture tests have completed. Separate auxiliary known-flood flow models were compared; fusion showed no recall advantage over HGB. The target-service packet audit found no fully corroborated benign-only seconds, so compatible benign packet coverage and split-safe feature integration are required before the main detector can be trained. The final hybrid, withheld-family evaluation, distributed lab tests and external transfer remain incomplete. See the [development evidence](phase%203/results/development/) and [next development gate](phase%203/plan/NEXT_STEPS.md). These are engineering/development outcomes, not final research performance results.

The repository contains the public version of the coursework, without student roll numbers. Raw captures and label archives are kept outside Git. Use the linked publisher and pinned mirror records in the pilot evidence to reproduce data acquisition.
