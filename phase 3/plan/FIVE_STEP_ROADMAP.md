# Five steps before writing the results-based research paper

Updated 12 November 2026. Phase 2 is already the proposal; these steps produce the missing experimental evidence.

1. **Complete data readiness — in progress.** Infrastructure, 12 selected benign sessions (702 windows), public benign extraction and full TCP boundary auditing are complete. The current v3 registry supplies 2,926 candidate benign rows and 1,076 attack-present T rows by assigning the whole Friday target stream to T. Failed v1/v2 temporal splits remain preserved. Obtain independent known-attack V data, allocate final K separately, and finish source/path controls, gap-aware calibration, congestion/diversity/repetitions. See `TCP_BOUNDARY_REVIEW.md`.
2. **Fit, calibrate and freeze the real detector.** Train packet-window HGB, benign-only AE and matched baselines; configure signed-feature preprocessing; use independent C1 score maps and C2 full-rule/persistence calibration overall and per benign stratum. Select on V and freeze settings/provenance before final tests.
3. **Run the reserved primary tests.** Evaluate withheld slow families and known tests; run at least 20 independent final benign ordinary/stress sessions and 40 planned isolated attack episodes. Record traffic rates, service impact, false alarms, recall, delay, misses and ineffective attack attempts. Development lab traffic remains benign only.
4. **Complete comparisons and uncertainty.** Run matched ablations, five stochastic seeds, paired session-level uncertainty and frozen external transfer when compatible data permit it. Keep optional adaptation separate; disclose incompatible/insufficient data instead of silently changing the claim.
5. **Audit and package paper evidence.** Reconcile manifests, split independence, metrics and limitations; produce final tables/figures/failure cases and a reproducibility package. Then write the research paper around the measured findings, including negative results.

Use `CHECKLIST.md` for evidence-backed ticks, `PROGRESS.md` for history, and the maintained root `PROJECT_CONTEXT.md` for a new harness. Offline fixture checks and installer downloads are not final research tests.
