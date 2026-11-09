# Phase 3 — Testing checklist

Start with a small, real packet-capture test. A checked box means there is evidence in `../results/` or a linked local file. Pilot results are engineering checks, not paper results.

## 1. Start-up and pilot

- [x] Create the Phase 3 workspace and this checklist.
- [x] Check local hardware and tools: the PC has a four-core i7-8650U, about 16 GB RAM and approximately 106 GiB free at the start. WSL is not currently installed; the offline pilot can run natively on Windows.
- [x] Verify data provenance and publisher schedule. [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) identifies Monday as benign and Wednesday as containing the reserved slow families. The official download form returned a server error; use a revision-pinned public mirror for the pilot and record its provenance.
- [x] Set up a project-local Python environment with the [pinned pilot dependencies](../requirements-pilot.txt).
- [x] Acquire and hash a bounded Monday capture prefix; leave Wednesday and all external captures untouched. [Range and SHA-256](../results/pilot/monday_pilot.json).
- [x] Validate directional packet counts and causal one-second windows with a controlled fixture. [Passing fixture](../src/check_packet_pilot.py).
- [x] Run a real Monday feature extraction and a benign-only baseline smoke test; record counts and wall time. [Pilot evidence](../results/pilot/monday_pilot.json).
- [x] Audit the allowlisted Friday DDoS flow-label CSV for timestamp precision and repeated connection keys. [Audit evidence](../results/pilot/friday_label_audit.json).
- [x] Download the full Friday-only capture with resumable ranges and verify its pinned SHA-256: 8,839,309,056 bytes. [Provenance manifest](../results/development/development_manifest.json).
- [x] Corroborate the Friday clock on a bounded tail sample using unambiguous benign keys: the current canonical-key audit supports a +15-hour combined CSV-to-packet shift. [Interim clock evidence](../results/development/friday_bounded_clock_audit.json).
- [x] Quarantine impossible negative-duration label keys and record the exclusions. [Exclusion evidence](../results/development/friday_label_exclusions.json).
- [x] Complete the full Friday clock/directional-count join audit. The +15-hour shift is supported by 22,768 benign keys; matching uses the observed private endpoints with no inferred NAT substitution. Quantify conflicts, count mismatches and missing keys; retain uncertainty. [Full audit](../results/development/friday_packet_audit.json). Count corroboration is not exact packet ground truth.
- [x] Replay all 9,997,874 Friday frames into 18,894 causal service windows; reconcile every overlapping labelled second's packet total. No selected late packets or decoding errors occurred. [Replay](../results/development/friday_causal_windows.json), [readiness/coverage](../results/development/friday_packet_readiness.json).
- [x] Pass all 18 protocol/preprocessing/split/replay/join-consistency fixture tests. [Validation](../results/development/validation_summary.json).

## 2. Prepare the experiments

- [x] Implement and fixture-test the causal feature core and bounded-lateness replay; exercise it on the Monday prefix and full Friday capture. [Monday replay](../results/development/monday_causal_windows.json). Grouped-split integration remains pending.
- [x] Run separate **auxiliary completed-flow development** baselines and a benign-trained AE/score-fusion check on disjoint Friday connection groups. [Evidence and limitations](../results/development/completed_flow_development.json). These are not the final packet-window experiments.
- [ ] Build the full capture/session manifest, including capture hashes, label provenance, direction/NAT notes, actual group counts and split boundaries. Quarantine all Slowloris/Slowhttptest groups, associated context, and all CSE-CIC-IDS2018 data.
- [ ] Obtain and audit compatible benign target-service packet traffic. Friday `.50:80` has zero fully corroborated benign-only seconds; the Monday LDAP prefix and unlabelled idle time cannot supply matched HTTP calibration. Quantify uncertain-label selection bias before fitting.
- [ ] Implement the complete causal feature schema, session resets, purging and group-overlap checks. Keep identifiers out of the predictors.
- [ ] Prepare benign-only lab development/calibration sessions and keep final stress sessions separate.
- [ ] Fit the supervised and benign-only anomaly branches and matched baselines. Map scores with C1; calibrate the full alert rule on C2 against the 1% development FPR budget overall and per ordinary/stressed stratum. Freeze all settings before opening final tests.

## 3. Final tests and reporting

- [ ] Score the known-attack and withheld slow-family sessions; report per-family recall, missed episodes, false alarms and delay with an explicit measurement basis.
- [ ] Run final benign stress sessions (at least five per condition) and isolated distributed sessions (40 planned attack episodes); log service impact, capture quality and misses. Verify isolation with benign traffic first.
- [ ] Run matched ablations and paired session-level comparisons. Keep repeats/seeds distinct from independent traffic sessions.
- [ ] Run frozen CSE-CIC-IDS2018 transfer on compatible packet data or record the precise limitation.
- [ ] Produce paper-ready tables, figures, reproducibility notes and the results section.
