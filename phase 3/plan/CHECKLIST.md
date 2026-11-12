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
- [x] Audit the allowlisted Monday CSV for compatible benign target-service coverage; record its 529,918 benign rows, 15 negative-duration rows and absent target-host HTTP/HTTPS occurrences. [Evidence](../results/development/monday_service_label_audit.json). This inventory does not prove absence of all raw packets or establish calibration readiness.
- [x] Add explicit signed-column AE preprocessing and guards so negative packet-rate changes can be preserved. Existing flow defaults remain unchanged. [25 passing offline checks](../results/development/validation_summary_2026-11-11.json).
- [x] Download and verify official WSL 3.0.5 / Docker Desktop 4.98.0 installer hashes and signatures; prepare an administrator setup script that does not reboot. [Setup record](../results/development/lab_prerequisite_status.json).
- [x] Prepare a bounded benign-only Apache/client/capture lab with an internal network and no published ports; validate its offline scope guards. [Lab preparation](../lab/README.md). Actual Docker validation and collection remain pending.
- [x] Install WSL 3.0.5 through the user-approved UAC relaunch and enable both required Windows features. MSI exit 0; feature exits 3010; version check succeeds. A Windows restart is required before runtime readiness can be checked.
- [x] Complete the user-controlled restart and install Docker Desktop 4.98.0 (exit 0). Verify client/server 29.9.2, Linux WSL2 engine, Compose 5.6.1, prepared Compose schema and creation/removal of an empty internal network. [Runtime evidence](../results/development/docker_runtime_verification.json).
- [x] Build digest-pinned lab images and validate the controlled benign scope/capture path: private service resolution, no client IPv4 default routes, internal bridge/no published web ports, reconstructed HTTP exchanges and drop/truncation checks. Fix aggregation offloads and capture buffering before accepting data. [Preflight evidence](../results/development/lab_preflight_review.json).
- [x] Collect and audit the selected **v3** benign component: 12 whole sessions, 702 measurement windows, 28 distinct client jitter seeds, zero kernel-reported capture drops. T/C1/C2/V have 175/175/176/176 windows. Preserve earlier pilots/replacements without pooling them. [Canonical selection](../results/development/benign_batch_v3.json), [predictor/group manifest](../results/development/benign_development_manifest.json).
- [x] Pass 35 offline regression checks, including TCP connection incarnations, reassembly, partial-window accounting, jitter-seed separation and conservative HTTP label guards. [Validation](../results/development/validation_summary_lab_collection.json).
- [x] Audit all nine pre-inventoried Friday TCP/80 candidates against the pinned raw capture: count/direction/HTTP-prefix evidence yields 2,243 nonempty benign service-seconds across eight services; retain 1,743 uncertain service-seconds. [Audit](../results/development/friday_public_http_audit.json). These are candidate labels, not final split-safe training windows.
- [x] Declare v1 public development groups before extraction; replay eight fresh-state streams with guards and observed-connection quarantine. Verify capture hash and label/feature packet totals. Preserve the negative finding: 2,224 candidate benign rows and zero retained attack rows. [Plan](public_partitions_v1.json), [review](PUBLIC_SPLIT_REVIEW.md), [replay](../results/development/public_partitioned_v1.json).
- [x] Pass 47 offline checks, including complete split-first PCAPNG replay, unknown-start/cross-role influence, boundary resets and sparse-label gaps. [Validation](../results/development/validation_summary_public_partitions_2026-11-12.json).
- [ ] Resolve v1 unknown/ambiguous-start exclusions using full TCP-incarnation/boundary evidence and a new declared rule or an independent known-attack source. Zero retained positives is insufficient supervised-development coverage.
- [ ] Complete the full-study manifest, including independent final K/U sources/groups, label provenance, direction/NAT notes and boundaries. The v1 development allocation/registry is not final-test allocation. Keep all Slowloris/Slowhttptest groups/context and CSE-CIC-IDS2018 quarantined.
- [ ] Confirm public/lab service and network-path compatibility and uncertain-label selection coverage before fitting. The original `.50:80` target still has no fully corroborated benign-only seconds; different-server HTTP candidates and the lab require explicit grouping/controls.
- [ ] Complete full-study split-safe feature integration with sufficient accepted class/session coverage. v1 public reset/purge checks exist, but its attack component has zero retained rows. Exclude identifiers from predictors and preserve missing seconds in persistence evaluation.
- [ ] Extend the initial benign development/calibration coverage with controlled congestion, legitimate long-lived/diverse traffic and independent repetitions. Retain failed legitimate requests under stress; keep all final stress sessions separate.
- [ ] Fit the supervised and benign-only anomaly branches and matched baselines. Map scores with C1; calibrate the full alert rule on C2 against the 1% development FPR budget overall and per ordinary/stressed stratum. Freeze all settings before opening final tests.

## 3. Final tests and reporting

- [ ] Score the known-attack and withheld slow-family sessions; report per-family recall, missed episodes, false alarms and delay with an explicit measurement basis.
- [ ] Run final benign stress sessions (at least five per condition) and isolated distributed sessions (40 planned attack episodes); log service impact, capture quality and misses. Verify isolation with benign traffic first.
- [ ] Run matched ablations and paired session-level comparisons. Keep repeats/seeds distinct from independent traffic sessions.
- [ ] Run frozen CSE-CIC-IDS2018 transfer on compatible packet data or record the precise limitation.
- [ ] Produce paper-ready tables, figures, reproducibility notes and the results section.
