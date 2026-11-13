# Five steps before writing the results-based research paper

Updated 13 November 2026. Phase 2 is already the proposal; these steps produce the missing experimental evidence.

1. **Complete the model-development policy — in progress.** The v5 registry has 56 groups/6,206 windows after 36 accepted benign stress sessions added 2,160 windows. Benign collection is complete; sparse known-V representativeness, class/service/path controls and missing-label/persistence calibration policy remain. Read `BENIGN_STRESS_REVIEW.md` and write `model_development_v1.json` before fitting. No reserved source has been used.
2. **Fit, calibrate and freeze the real detector.** Train packet-window HGB, benign-only AE and matched baselines; configure signed-feature preprocessing; use independent C1 score maps and C2 full-rule/persistence calibration overall and per benign stratum. Select on V and freeze settings/provenance before final tests.
3. **Run the reserved primary tests.** Evaluate withheld slow families and known tests; run at least 20 independent final benign ordinary/stress sessions and 40 planned isolated attack episodes. Record traffic rates, service impact, false alarms, recall, delay, misses and ineffective attack attempts. Development lab traffic remains benign only.
4. **Complete comparisons and uncertainty.** Run matched ablations, five stochastic seeds, paired session-level uncertainty and frozen external transfer when compatible data permit it. Keep optional adaptation separate; disclose incompatible/insufficient data instead of silently changing the claim.
5. **Audit and package paper evidence.** Reconcile manifests, split independence, metrics and limitations; produce final tables/figures/failure cases and a reproducibility package. Then write the research paper around the measured findings, including negative results.

Use `CHECKLIST.md` for evidence-backed ticks, `PROGRESS.md` for history, and the maintained root `PROJECT_CONTEXT.md` for a new harness. Offline fixture checks and installer downloads are not final research tests.
