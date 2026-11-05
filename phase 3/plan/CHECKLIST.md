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
- [ ] Validate the Friday raw-packet-to-label join. Confirm time-zone/AM-PM and NAT/direction mappings against the capture; quantify ambiguous and unmatched records. Do not infer packet labels from minute timestamps alone.

## 2. Prepare the experiments

- [ ] Build the full capture/session manifest, including capture hashes, label provenance, direction/NAT notes, actual group counts and split boundaries. Quarantine all Slowloris/Slowhttptest groups, associated context, and all CSE-CIC-IDS2018 data.
- [ ] Implement the complete causal feature schema, session resets, purging and group-overlap checks. Keep identifiers out of the predictors.
- [ ] Prepare benign-only lab development/calibration sessions and keep final stress sessions separate.
- [ ] Fit the supervised and benign-only anomaly branches and matched baselines. Map scores with C1; calibrate the full alert rule on C2 against the 1% development FPR budget overall and per ordinary/stressed stratum. Freeze all settings before opening final tests.

## 3. Final tests and reporting

- [ ] Score the known-attack and withheld slow-family sessions; report per-family recall, missed episodes, false alarms and delay with an explicit measurement basis.
- [ ] Run final benign stress sessions (at least five per condition) and isolated distributed sessions (40 planned attack episodes); log service impact, capture quality and misses. Verify isolation with benign traffic first.
- [ ] Run matched ablations and paired session-level comparisons. Keep repeats/seeds distinct from independent traffic sessions.
- [ ] Run frozen CSE-CIC-IDS2018 transfer on compatible packet data or record the precise limitation.
- [ ] Produce paper-ready tables, figures, reproducibility notes and the results section.
