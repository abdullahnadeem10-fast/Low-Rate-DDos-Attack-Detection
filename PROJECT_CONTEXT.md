# Project handoff — 9 November 2026

Read `phase 3/plan/PROGRESS.md`, `phase 3/plan/CHECKLIST.md` and `phase 3/plan/NEXT_STEPS.md` for the current state. Phase 2 is a reviewed research proposal, not an experimental paper.

The full Friday capture is checksum-verified. Causal replay produced 18,894 one-second target-service windows. The full clock/count audit supports a +15-hour CSV-to-packet correction for this capture only. Label evidence is uncertain and lacks fully corroborated benign-only target-service seconds. Do not infer benign from unlabelled idle time. The continuous replay is not split-safe training data. Compatible benign service traffic, explicit partitions, resets/purging and group-overlap checks come next.

Eighteen engineering fixture tests pass. Auxiliary completed-flow development models ran on the allowed Friday CSV; score fusion did not improve recall over HGB. These finished-flow outcomes are not evidence about early/live detection, unseen slow attacks or distributed low-rate traffic. All slow-family holdout groups and the entire external CSE-CIC-IDS2018 source remain excluded from development. No final model freeze, live attack lab session or final research evaluation has occurred.

Preserve detection/evaluation-only scope. Use benign training only for the anomaly branch and all its fitted transforms. Keep T, C1, C2 and V disjoint; fit score maps on C1 and calibrate the complete threshold/persistence rule on C2 overall and per benign ordinary/stress stratum. Freeze all settings before final tests. Do not use model seeds or correlated windows as independent traffic replications.

Raw datasets, environments and private coursework identifiers are excluded from this public checkout. Reproduction commands and pinned sources/hashes are in the Phase 3 README and evidence. Update the checklist only when its own evidence exists; record failed tests, uncertain labels and negative findings.
