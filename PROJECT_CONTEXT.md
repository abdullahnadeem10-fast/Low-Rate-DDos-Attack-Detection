# CNET project history and handoff context

Phase 3 began on 4 November 2026 and now includes the full TCP-incarnation audit and whole-stream positive training component on 12 November. For the current experiment checklist, evidence and exact next action, start with `phase 3/plan/CHECKLIST.md` and `phase 3/plan/PROGRESS.md`. The full 8,839,309,056-byte Friday capture passed its pinned SHA-256, causal replay produced 18,894 one-second windows, and the clock/count audit and label-coverage checks are recorded in `phase 3/results/development/`. Separate auxiliary completed-flow models were run on known-family development data; fusion did not improve recall over HGB. No final attack tests or paper-grade results exist yet. The Phase 2 history below remains the protocol record.

The key 9 November finding is inadequate matched benign coverage: the Friday target `.50:80` has 1,076 attack-present seconds, 20 uncertain seconds and no fully corroborated benign-only seconds. Another 17,798 replay seconds are unlabelled; do not call them benign. That finding prompted the lab component and broader HTTP-service audits described below; v1/v2 temporal splits retained zero positives; v3 now assigns the complete Friday target stream only to T and retains 1,076 attack-present rows. Independent attack V, compatibility and broader benign coverage remain next. The current offline suite has 65 passing checks, but full-study training readiness remains false. See `phase 3/plan/NEXT_STEPS.md`. The slow-family holdout and entire external source remain unused; no lab attack sessions or final freeze have occurred.

On 5 November 2026 the user asked to publish completed work to GitHub. The verified initial commit is `7dd0559e41df54a3d1d865c25b12043176e44e7c` on `main` in `abdullahnadeem10-fast/Low-Rate-DDos-Attack-Detection`. The local Git checkout is `github-repo/` inside this workspace. The original folders remain the private working copies; the checkout contains the public Phase 2 proposal/source/diagrams/review and Phase 3 checklist/code/pilot outputs. The public report was rebuilt without student roll numbers. Raw datasets, virtual environments, prior report archives and build tools were excluded. For future pushes, copy only reviewed public changes into `github-repo/` and preserve its exclusions.

On 9 November 2026 the reviewed Phase 3 source, plans, portable public context and small development evidence were pushed to `main`; remote verification returned `eafb7650981ea2cb1644c5737fe48f2030c94c5a`. The preceding implementation commit is `92e7d90`; the final commit preserves exact CSV evidence bytes so recorded checksums survive Git checkout. No raw captures/archives, environments or private coursework identifiers were included. The local full replay feature CSV remains under ignored `phase 3/data/development/`; its checksum and schema are recorded in the public readiness evidence. No background download/audit/replay process remains running at this checkpoint.

Last updated: 12 November 2026 (Asia/Karachi). The Phase 2 historical sections below describe the October proposal; their statements about no implementation refer to that stage. Current implementation status is in Phase 3. On 11 November, the user requested a fresh push and a complete portable handoff; documentation was consolidated without running new scientific experiments.

This file records the work completed in this chat and the context needed to continue in another chat or agent environment. It is a handoff record, not evidence that the proposed research experiments have been performed.

## Latest implementation update — 12 November 2026 (TCP audit and whole-stream T)

**Current engineering registry: `phase 3/results/development/study_development_manifest_v3.json`.** It has 19 groups and 4,002 candidate labelled rows: **2,926 benign plus 1,076 corroborated attack-present T rows**. All observed Friday target-service traffic/context now belongs to T only. No old Friday block becomes V or an untouched final set. Other six public benign destination groups and 12 canonical lab sessions retain their roles. Combined T has 1,504 benign/1,076 attack rows; C1 669 benign, C2 422 benign and V 331 benign with **no attack validation**.

The new hash-verified private TCP index contains all 1,282,861 target packets. Its audit reproduced both v1 feature CSV hashes and exactly 6,745/7,940 unknown packets. It found 96,010 observed initiating-SYN identities across 45,532 keys; 554 packets/546 keys remain unresolved. Most v1 unknown observations were attributable to identities wholly inside the raw block (6,504/6,754); only 5/7 followed an observed close. No conflicting server-handshake identities or supported identity shared between the old blocks appeared. These are observed sequence/ACK consistency results, not OS socket ground truth.

Preserve the failed **v2** refinement: whole-key unresolved quarantine, complete-identity boundary checks and unsafe influence propagated until actual frozen-core close/reset/expiry still left zero attack rows. Feature bytes matched v1. Rather than weaken masks, **v3 was declared before fresh whole-stream extraction**, assigning complete Friday target groups/context to one role. A raw-packet overlap audit found zero target packets shared with other assigned destination roles. The frozen core processed all packets before label selection. Of 28,981 complete target seconds, 1,076 are attack-present, 20 uncertain and 27,885 unlabelled; idle/unlabelled time remains unknown. Unknown observed ages are valid within this wholly assigned group, but the endpoint-key tracker remains approximate.

Read `phase 3/plan/TCP_BOUNDARY_REVIEW.md`, `NEXT_STEPS.md` and `results/development/development_readiness_tcp_2026-11-12.json`. All **65 offline checks pass**. **Exact next action:** find/audit a distinct permitted known TCP-denial capture for attack V, verify compatible packet/label provenance, and declare independent V and final K groups before feature creation. Then broaden benign congestion/diversity/repetitions, constrain class/service/path/source confounding and use gap-aware C2 calibration before matched model fitting/freeze. The source/path confounding and maximum six-second public C2 labelled run remain unresolved. This is one attack training episode, not 1,076 independent experiments. Study training readiness stays false; no main model or final attack test exists. Entire slow-family groups/context and all CSE-CIC-IDS2018 remain excluded from development.

The ignored cache is `phase 3/data/development/friday_tcp_boundary_v1/` (packets, assignments, incarnation evidence and unresolved keys); v3 feature/eligibility/model tables are under `data/development/public_partitioned_v3/`. Keep the canonical v3 lab whitelist and six reused public benign groups, without pooling old attack blocks or preflights. The index elapsed counter jumped between checkpoints; its 47,062.551 seconds is bookkeeping, not a performance benchmark. For another harness, transfer original raw/cache data or create new versioned rebuild evidence; do not overwrite timed/hash-pinned checkpoint manifests. No processing/training/research collection job is running.

Publication: reviewed source/plans/small evidence and sanitized full handoff are published without raw caches/captures, environments or private student identifiers. Use `git log -1` for the current published commit. Prior verified checkpoint: `0959479b21be37832c543116ac3bd06a9df1c9f1`.

## Prior v1 public replay checkpoint — 12 November 2026

**The v1 split-first public engineering milestone is complete, but its attack component is unusable for supervised development.** A plan saved before feature creation assigns six whole benign destinations to roles and splits one inspected Friday attack episode into guarded T/V blocks. Eight fresh feature/connection instances produced 36,240 raw windows; all 9,997,874 frames and 8,839,309,056 bytes passed full SHA-256 verification, with no selected late drops/decoder errors. Raw packets were never filtered by labels. The frozen lab feature core was preserved.

There are **2,224 candidate public benign windows** (T/C1/C2/V **1329/494/246/155**) and **zero retained public attack windows**. The blocks contain 418/547 raw attack-present seconds, 363/452 after boundary/history guards, but all are masked by the conservative unknown/ambiguous-start influence policy (6,745/7,940 packets). No observed initiating-SYN fingerprints overlap roles. This is a negative result for the allocation/purge policy, not proof every masked connection crosses roles or any detector failure. The endpoint-key core lacks TCP sequence numbers; full-incarnation audit is next before a more precise v2 rule.

The original fragment flag conservatively counted eight service-IP fragments of any protocol. Independent full-hash attribution proved all eight UDP (protocol 17), with zero TCP fragments. Preserve both reports; the combined registry accepts packet extraction quality while retaining all connection exclusions. An initial PCAP/PCAPNG filename assumption was corrected before successful outputs and regression-tested.

Use `phase 3/results/development/study_development_manifest_v1.json` for the exact engineering-table registry, input/source/table hashes, 30 predictors, six excluded metadata columns and timeline coverage. It references only the 12 canonical v3 lab sessions and these eight public streams; zero-row attack tables remain explicit. Combined candidate benign rows total **2,926** (T/C1/C2/V **1504/669/422/331**), not independent replications. Public C2 has 137 labelled runs, longest six seconds: preserve full timelines; never compress unknown gaps into consecutive persistence evidence. Service/path/source remain confounded with class. Engineering quality is not study training readiness.

All **47 offline checks pass**. Read `phase 3/plan/PUBLIC_SPLIT_REVIEW.md`, `NEXT_STEPS.md` and `results/development/development_readiness_2026-11-12.json`. **Exact next action:** trace unknown-start events using full Friday TCP-incarnation metadata and boundary provenance. If evidence supports safe recovery, declare v2 before replay; otherwise obtain independently grouped permitted known-attack development data. Independent final K is unallocated: inspected Friday is development-only. Then broaden controlled congestion/long-lived benign diversity/repetitions, constrain source/path confounding, and fit/calibrate/freeze matched models. No main detector is trained/frozen; no final attack tests occurred; entire slow-family groups/context and CSE-CIC-IDS2018 remain unused. No research job remains running.

Publication: reviewed source/plans/small evidence preserve raw JSON evidence bytes for pinned hashes. Raw captures, label/feature tables, environments and private identifiers remain excluded. Resolve the current published commit using `git log -1`; the prior verified checkpoint is `976d208e6eae856677cf00ec028ecf2f2baa0eaa`.

## Prior implementation update — 11 November 2026

**Current selected lab component: benign_v3.** It contains 12 whole-session groups and **702** complete one-second measurement windows: T 175, C1 175, C2 176 and V 176. The controlled complete-GET workloads are ordinary (one client), bursts (three clients) and concurrent/flash (three clients), each with a 30-second benign warm-up and 60-second scheduled measurement. There is one initial session per role/condition. All **11,798** logged HTTP exchanges were reconstructed from **376,961** captured frames, with zero kernel-reported capture drops/truncations and zero selected late-packet drops. Fresh service containers, unique capture hashes and a fresh causal feature instance separate sessions. All 28 effective client jitter seeds are distinct; these are provenance controls, not proof of IID samples or independent environments.

Use `phase 3/results/development/benign_batch_v3.json` as the canonical session whitelist and `benign_development_manifest.json` for its predictor/partition schema. It selects eight unchanged v2 sessions and four new C1/C2 burst/concurrent replacements. Do not add v2/v3 counts together or glob all local model tables: the raw directory also contains preflights, an interrupted first batch and superseded calibration sessions. The 30 predictors exclude `session_id`, `role`, `condition`, `y`, `utc_second` and `history_complete`. Explicit signed AE preprocessing is required for `packet_rate_change`; its index is recorded in the manifest. Lab labels come from the predeclared controlled scenario plus scope/HTTP/packet audits, not from silence.

The retained engineering history matters. The first ordinary preflight exposed aggregation frames up to 7,306 bytes; web-namespace TSO/GSO/GRO were disabled. The first concurrent batch then lost 476 kernel-reported packets while using per-packet Windows bind-mount writes. Capture now writes on the Linux container filesystem with a 32 MiB buffer and copies only after flush. A corrected concurrent preflight reconstructed all 984 exchanges with zero reported drops and a 1,514-byte maximum frame. Audits also gained explicit first-partial-second accounting and separate TCP handshake incarnations for reused ports. Finally, the initial additive seed matrix reused jitter streams across roles (28 clients, 16 unique seeds); four calibration sessions were replaced using disjoint seed ranges before any model fitting/scoring. `lab_preflight_review.json`, `benign_batch_v1_interrupted.json`, `benign_batch_v2_seed_diagnostic.json` and both original plans preserve the findings. No classifier outcome selected replacements.

The allowed Friday public HTTP audit is also complete. A fixed metadata rule selected all nine TCP/80 candidates before the packet scan. Directional-count agreement, unanimous BENIGN keys and HTTP payload prefixes corroborated **2,243 nonempty service-seconds across eight services**; **1,743** remain uncertain. These are service-time cells, not independent session replicates or exact packet ground truth. Idle/uncertain cells were not assigned benign labels. The original attacked `.50:80` service still has no fully corroborated benign-only seconds. Different benign servers create a source/path comparability question, not permission to ignore it. See `friday_benign_http_candidates.json` and `friday_public_http_audit.json`. Their public IPs are archival identifiers: do not contact them live.

All **35 offline checks pass**. WSL 3.0.5, Docker Desktop 4.98.0, its Linux engine 29.9.2 and Compose 5.6.1 work. Pinned image content IDs and image-config version declarations are in `lab_software_manifest.json` (tool image declares Python 3.12.16; Apache declares HTTPD 2.4.70, distinct from the host analysis Python 3.12.14). Debian package availability can still affect a fresh rebuild. All task-owned temporary lab containers/networks are removed; Docker Desktop remains available and no research collection/training/scoring job is active.

**Next:** build the full public destination/session/known-attack block manifest before reset/purged public feature replay; audit source/path/label-selection coverage; add controlled-congestion, long-lived/diverse legitimate workloads and independent repetitions. Under stress, failed legitimate requests remain benign and need appropriate logging/quality rules rather than exclusion merely for not returning 200. The current complete-success audit applies to the initial profiles only. Then fit matched packet-window branches/baselines, calibrate and freeze before final tests. `development_readiness_2026-11-11.json` deliberately keeps `study_training_ready` false. No main packet-window detector is fitted/frozen; all slow-family and external final sources remain untouched.

Publication checkpoint: on 11 November the completed v3 component/code, public HTTP audits, immutable plans and sanitized handoff were pushed and remote-verified at `976d208e6eae856677cf00ec028ecf2f2baa0eaa` on `main`. The public checkout was clean afterward. Raw captures, generated model tables, environments and private identifiers were excluded.

## Read first: continuation checkpoint

This is the maintained project knowledge entry point. `AGENTS.md` directs compatible coding harnesses here. The local root copy includes historical private-workspace details; the Git checkout contains a sanitized full copy. Update both deliberately after substantive work. `phase 2/PROJECT_CONTEXT.md`, where present locally, is an October proposal snapshot and is not the current implementation handoff.

The next research-data task is **independent known-attack validation data**. The TCP audit and failed v2 refinement are preserved; current v3 allocates the complete Friday target only to T and retains 1,076 positive rows. Audit a different permitted TCP-denial capture and declare V and independent final K groups before feature creation. No inspected Friday block is an untouched final set. Do not borrow reserved slow/external data or infer idle labels.

Use `phase 3/results/development/study_development_manifest_v3.json` as the current exact registry and read `TCP_BOUNDARY_REVIEW.md` / `NEXT_STEPS.md`. Broader benign repetitions/diversity, source/path controls and gap-aware calibration remain before actual matched fitting/freezing. Study training readiness remains false.

No background acquisition, audit or training process is running at this handoff. No final model has been frozen or serialized as a deployable detector. The full packet-window experiment, five-seed matched runs, withheld slow-family tests, ordinary/stress lab calibration, 40 planned distributed attack episodes, ablations, frozen external transfer and final research paper/results remain unfinished. Phase 2 remains the proposal; do not relabel it as an experimental paper.

## Local workspace versus a fresh clone

- Public repository: https://github.com/abdullahnadeem10-fast/Low-Rate-DDos-Attack-Detection ; branch `main`. The latest 12 November checkpoint adds the TCP audit and whole-stream T component; earlier v3 lab/public HTTP evidence remains unchanged. Use `git log -1` for its current commit; this file cannot contain its own eventual commit hash. Earlier verified pilot/runtime pushes are recorded in the history above.
- This machine's parent workspace has private `phase 2/`, `phase 3/` and this history. Its Git checkout is the nested `github-repo/`. Work in the parent folders, then copy reviewed public changes into that checkout before committing. In a fresh clone, work directly at the repository root; do not create another nested checkout.
- The public checkout contains the reviewed Phase 2 LaTeX/PDF/diagram/source/review and Phase 3 source, plans and small evidence. Raw data, `.venv`, credentials, student roll numbers, scratch/build files and old report archives are not publication artifacts. Some older local aliases/source archives mentioned in the history are absent from a clone; `phase 2/CNET_Phase2_IEEE.pdf` and `.tex` are the portable proposal files.
- Do not overwrite the public Phase 2 source/report with the private student-identifier version. Do not force-push or add raw captures. CSV evidence uses `.gitattributes` to preserve exact bytes for SHA-256 records.
- Current evidence paths in the following sections are relative to the project/clone root unless explicitly stated otherwise. If raw inputs are absent on a new machine, reacquire them with the pinned source records and verify checksums rather than inventing substitute inputs. Local resumable chunks can save downloads but are not required Git content.

## Data ledger and quarantine

The allowlisted mirror is `bencorn/CICIDS2017` at immutable revision `811c007f08d693a8a8b4226c197c138391806ce6`. This is a public mirror, not an official publisher download; provenance is recorded explicitly. Use `https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/` plus the suffix below. Publisher context is https://www.unb.ca/cic/datasets/ids-2017.html .

| Local path under `phase 3/` | Pinned source / scope | Bytes / SHA-256 |
| --- | --- | --- |
| `data/development/Friday-WorkingHours.pcap` | `pcaps/Friday-WorkingHours.pcap?download=true`; full capture | 8,839,309,056; `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0` |
| `data/quarantine/CICIDS2017-GeneratedLabelledFlows.zip` | `csvs/GeneratedLabelledFlows.zip`; Friday DDoS and Monday members only | 283,876,488; `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a` |
| `data/pilot/monday-first-32MiB.partial` | `pcaps/Monday-WorkingHours.pcap`; inclusive byte range 0–33,554,431 only | 33,554,432; `138e288cf10a0f8934feccccbda9f9789c34bc771e6e65b0c7d021da157a1815` |
| `data/development/friday_causal_windows.csv` | Generated engineering feature table; continuous, not split-safe | 18,894 rows; `aef18b026aa26c013b0171295078c7b888191959f440b0eb36fb1afa67cbe773` |

The exact archive member is `TrafficLabelling /Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (including the space before `/` and `DDos` spelling). It has 97,718 BENIGN and 128,027 DDoS rows. The additional permitted Monday member `TrafficLabelling /Monday-WorkingHours.pcap_ISCX.csv` was opened on 11 November and contains 529,918 BENIGN rows; no matched target HTTP/HTTPS rows were found. All remaining label members, particularly Wednesday slow-family data, remain unopened for development. Wednesday raw data and the entire CSE-CIC-IDS2018 source, including benign data, remain unfetched/unused. CIC-DDoS2019 is a proposed separate known/flooding benchmark, not a completed experiment.

CSV starts have minute precision. The empirically corroborated **+54,000-second (+15-hour)** shift applies to this Friday join only; it does not establish exact flow starts/onsets or a general timezone correction. Two negative-duration benign rows cause complete quarantine of their two canonical connection keys, including two other valid rows. Canonical grouping combines both directions. Conflicting labels and count mismatches remain uncertain; no NAT substitution is inferred.

## Implemented code and engineering evidence

All following source names are under `phase 3/src/`.

| Code | What it does / current limit |
| --- | --- |
| `packet_pilot.py`, `check_packet_pilot.py`, `audit_friday_labels.py`, `audit_monday_labels.py` | Original benign pilot/fixture, Friday inventory and the newly allowlisted Monday service-coverage audit |
| `download_friday.py` | Friday-only resumable 8 MiB ranges, 12 workers, final full-file checksum gate; importing it starts acquisition, so run it as a script and do not import it casually |
| `friday_packet_audit.py` | Hash guards, label-key quarantine, benign-key clock votes, directional-count join and conservative per-second label evidence |
| `bounded_friday_clock.py` | Historical tail-range clock corroboration; superseded for confirmation by the full audit; depends on retained local range parts |
| `causal_features.py`, `replay_causal_features.py` | Thirty causal predictors, one-second event-time windows, one-second reorder budget, 30-second observed-connection expiry and 5/10/20-second histories; instantiate fresh state per session |
| `benign_autoencoder.py` | CPU dense AE, benign-only preprocessing, external benign-V early stopping and benign ECDF score maps |
| `train_flow_development.py` | Separate completed-flow auxiliary LR/RF/HGB/AE/fusion experiment; not the final packet-window detector |
| `assess_packet_development.py` | Reconciles overlapping per-second packet totals, checks finite schema/contiguous seconds, records coverage and deliberately false training readiness |
| `test_*.py` | Thirty-five offline protocol/preprocessing/split/replay/member-audit/lab-scope/TCP-incarnation/seed/HTTP-label fixtures as last run on 11 November; these are not attack efficacy tests |

Predictors describe packet/byte directions, TCP flags/handshake observations, inbound timing, length moments, source counts, connection counts/known and unknown ages, ratios, rate changes and rolling counts. They exclude IPs, ports, absolute time, labels and future CSV totals. Connection state is an observation-based approximation, not a server OS socket count. Captured frame lengths include link-layer bytes. A continuous replay must not silently carry state across future partition boundaries. Unknown/late-data policies must be fixed before final evaluation; never filter raw packets by label confidence before feature extraction.

Preprocessing integration detail: the AE's default `clean()` retains its nonnegative completed-flow policy. Since 11 November, explicit `signed_columns=(index, ...)` applies sign(x)*log1p(abs(x)) to those columns and preserves valid negative changes; non-finite inputs remain missing. `packet_rate_change` must be mapped to its frozen schema index by the future packet-model caller. Fit imputation/scaling on benign T only. Signed preprocessing is fixture-tested, but the packet-window pipeline itself is not fitted.

`phase 3/results/development/` contains `development_manifest.json`, `friday_packet_audit.json`, `friday_clock_audit.json`, `friday_label_exclusions.json`, `friday_causal_windows.json`, `friday_packet_readiness.json`, the two per-second join CSVs, Monday replay evidence, `completed_flow_development.json` and the validation summary/log. The manifest describes **one known-family development capture**, not the complete study/session manifest.

Full Friday replay: 9,997,874 frames, 1,282,861 selected service TCP packets, 18,894 windows, 18,875 fully warmed windows, zero selected late drops and zero decode errors; 261.434 seconds of replay on the current PC, excluding startup/download. Clock pass found 7,094 adjacent timestamp regressions; its winning +15-hour shift had 22,768 benign-key votes versus at most 40 for another shift. All 1,096 overlapping labelled seconds reconciled exactly to feature packet totals. Count agreement corroborates labels; it is not independent packet ground truth.

At the target service, the label envelope contains 488,376 corroborated attack packets, 1,160 corroborated benign packets and 791,066 uncorroborated packets. Window statuses: **1,076 attack-present; 20 uncertain; 17,798 unlabelled; zero fully corroborated benign-only**. There are 17,470 empty windows overall. The 20,055 conflicting BENIGN/DDoS canonical groups and other mismatches are retained in the audit. Do not convert these exclusions into inflated accuracy or exact delay claims.

## Current data/collection code and continuation rules

- `phase 3/src/audit_benign_session.py`: controlled request/response reconstruction, TCP incarnations, packet/drop/route/scope checks; applies to the declared complete-success workloads, not arbitrary future stress failures.
- `collect_benign_batch.py`: immutable historical v1/v2 collection plans and partial-second measurement accounting. `collect_benign_repair.py`: canonical v3 selection and four seed-separated replacements. The current client formula is master seed + 1000 * client index; check the **whole matrix** with `require_disjoint_seeds`, not just distinct master seeds.
- `summarize_benign_batch.py --batch-version v3`: verifies selected raw/model hashes and generates the canonical predictor/group/workload manifest. Each raw selected folder has its own PCAP, request/network/capture logs, session/audit metadata, causal features and measurement-only `model_windows.csv`.
- `inventory_friday_http.py` and `audit_friday_http_services.py`: offline candidate metadata, HTTP-prefix and packet-count evidence. Labels live locally under `phase 3/data/development/public_http_candidates/`; no candidate public server was contacted.
- Collection plans under `phase 3/plan/benign_batch_v1.json`, `phase 3/plan/benign_batch_v2.json` and `phase 3/plan/benign_batch_v3.json` are immutable hashed evidence. Git attributes preserve their exact bytes; frozen source hashes were checked against staged repository blobs. A new collection needs a separate recorded plan/version, not edits that pretend an old hash was regenerated.
- A fresh clone contains code/plans/small evidence, not raw datasets or the selected lab folders. Transfer those byte-for-byte for exact replay. Repeating a network workload seed creates new timestamps/TCP state and new hashes; it does not recreate an old PCAP exactly.

## Auxiliary results: development only

The separate Friday completed-flow run uses 14 finished-flow predictors, one seed (7) and disjoint canonical connection groups. T has 27,691 rows (17,044 benign / 10,647 known DDoS), benign C1 1,712, benign C2 1,023, and V 44,741 (10,041 benign / 34,700 DDoS). It drops 12,515 cross-partition-key candidate rows and two negative durations. Printed-minute T intervals are [210,220) and [231,240), C1 [221,225), C2 [226,230), V [241,248); latest possible flow end must remain inside its block. These are development blocks from one known flooding episode, not independent final attack sessions.

| Model | V TP / FN | V FP / TN |
| --- | --- | --- |
| Logistic Regression | 34,664 / 36 | 58 / 9,983 |
| Random Forest | 34,685 / 15 | 13 / 10,028 |
| HGB | 34,685 / 15 | 10 / 10,031 |
| Benign AE | 21,808 / 12,892 | 17 / 10,024 |
| HGB/AE score fusion | 34,685 / 15 | 11 / 10,030 |

There is **no demonstrated fusion advantage**. Thresholds used the higher 99th percentile of benign C2 with strict `score > threshold`; the flow experiment does not implement one-second persistence or stress-stratum calibration. The AE reached its 100-epoch cap and selected epoch 100. Completed-flow features include future/end-of-flow information, negatives span services, and service/environment confounding remains possible. These outcomes do not establish unseen slow-family recall, live delay, distributed low-rate detection or final FPR. Full settings, metrics and limitations are in the saved JSON. Do not use them as paper headline results.

## Environment and reproducible entry points

The local offline environment is `phase 3/.venv/Scripts/python.exe`, Python 3.12.14 with CPU-only dependencies pinned in `phase 3/requirements-pilot.txt`: dpkt 1.9.8, NumPy 2.3.5, SciPy 1.18.1, scikit-learn 1.7.2, joblib 1.6.0, threadpoolctl 3.7.0 and cloudpickle 3.1.2. The local environment was built using available system packages; a fresh clone has no environment. On a new machine, create a Python 3.12 virtual environment and install the requirements, then run the fixtures before parsing large inputs. Do not assume this PC's bundled runtime path exists elsewhere.

From `phase 3/` on Windows, use the following commands as needed, not as a request to repeat large downloads:

```powershell
python -m venv .venv
& '.venv/Scripts/python.exe' -m pip install -r requirements-pilot.txt
& '.venv/Scripts/python.exe' -m unittest discover -s src -p 'test_*.py' -v
& '.venv/Scripts/python.exe' src/friday_packet_audit.py
& '.venv/Scripts/python.exe' src/replay_causal_features.py --pcap data/development/Friday-WorkingHours.pcap --service 192.168.10.50:80 --out data/development/friday_causal_windows.csv
& '.venv/Scripts/python.exe' src/assess_packet_development.py
```

Use `.venv/bin/python` on POSIX. `src/download_friday.py` is the explicit Friday acquisition entry point if that capture is absent; the label archive and Monday prefix must also be acquired with their pinned source/range records before their respective scripts run. The downloader retains ranges and intermediate files, so allow several tens of GB of working space. Do not delete/move raw/quarantine inputs merely to tidy a fresh continuation.

The benign lab uses the Apache `httpd:2.4` development image plus a Python/tcpdump tool image, with image IDs/source hashes recorded on actual collection. Tags are developmental, not a final freeze; runtime isolation, packet quality, service compatibility and real benign diversity remain to be checked. WSL 3.0.5 installer SHA-256 is `2313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa`; Docker Desktop 4.98.0 build 245422 installer SHA-256 is `cd6273d9eaa4f07fa7593fc6813d37e1004381cebc3f26047a2554fa5db24388`. Verified signers are Microsoft Corporation and Docker Inc respectively. Binaries and private logs stay under ignored `phase 3/data/setup/`.

The checked machine is an i7-8650U with four reported cores/logical processors and about 16 GB RAM; no GPU is needed for these offline models. Approximately 81 GiB was free after acquisition on 9 November, not a current guaranteed capacity. After the user-controlled restart on 11 November, WSL 3.0.5 and Docker Desktop 4.98.0 are installed and the Linux engine/Compose work. Initial controlled-profile capture/scope audits passed; controlled congestion, broader benign diversity and full public integration remain pending. No live attack generation has been completed. Only an isolated, authorized local lab is in scope.

The harness sandbox redirects LocalAppData and denies WSL/Docker IPC. Successful runtime checks used its authorized unsandboxed execution route; sandboxed `Wsl/E_ACCESSDENIED` is not evidence that the installed engine is broken. A running pre-install harness may lack the updated PATH: resolve the CLI from the real Windows `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe`. Docker Desktop is running, but no research acquisition/training job or final test is active.

## Resume prompt for another harness

> Read `AGENTS.md` and `PROJECT_CONTEXT.md`, then `phase 3/plan/PROGRESS.md`, `CHECKLIST.md`, `NEXT_STEPS.md` and `phase 3/results/development/friday_packet_readiness.json`. Preserve the untouched slow-family/external holdouts. Use the v3 whitelist and current readiness evidence; declare public group/block splits, extend benign congestion/diversity, then perform split-safe replay and calibration; do not present auxiliary flow results as final research. Maintain the context and checklist with evidence, and preserve the reviewed public/private file boundary.

An arbitrary Markdown file is not automatically read by every harness. `AGENTS.md` helps tools that support that convention; otherwise explicitly provide the prompt above. A Git clone restores code, plans and small evidence, **not raw data or environments**. To resume without downloading again, separately transfer the approved local data files and verify their hashes.

## Historical Phase 2 version: IEEE-format LaTeX paper

The preferred report is the **nine-page LaTeX paper, finally reviewed and corrected on 17 October 2026**. The user explicitly requested a professional research-paper format found online and asked to use LaTeX. The official IEEE conference template was selected from the IEEE Author Center: https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/authoring-tools-and-templates/ . Its standard `IEEEtran` conference class provides the two-column typography and section/citation styles. Page numbers are added for course review. The assignment specifies content and comparison-table fields but does not mandate a template; this is an editorial format choice, not a claim of IEEE publication.

The paper has a title and student author blocks, abstract, index terms, seven numbered sections, full-width literature/gap tables, numbered equations, a native TikZ vector methodology diagram, eighteen numbered references and twelve methodology subsections. All four required deliverables and the detection-only proposal scope are retained. No project experiments had been performed as of that October proposal review.

Current editable source: `phase 2/CNET_Phase2_IEEE.tex`. The compiled `phase 2/CNET_Phase2_IEEE.pdf` and submission alias `phase 2/CNET_Phase2_Report.pdf` are identical. `phase 2/CNET_Phase2_LaTeX.zip` contains the standalone source and instructions for Overleaf. There are no external image, bibliography or project-file dependencies. The earlier Word/PDF report is preserved under `phase 2/archive/academic_layout_2026-10-17/`; the original 19-page layout remains under `phase 2/archive/original_layout_2026-10-14/`.

Current generator: `phase 2/source/build_ieee_paper.py`; content snapshot: `phase 2/source/report_content.json`; verification: `phase 2/source/verify_ieee_paper.py`; page renders and structural checks: `tmp/phase2/ieee_render/`. Regenerating replaces direct edits to the `.tex` file. Do not run the old Word generators to replace the current PDF.

This handoff file is maintained at the project root. The earlier `phase 2/PROJECT_CONTEXT.md` is an archived October snapshot; use this root file for Phase 3 continuation.

The final factual/methodological review is documented in `phase 2/FINAL_REVIEW.md`, including primary-source links, corrections and limits. Read it before relying on older summaries. The user asked to check that information is perfect; the review does not claim independent replication of published findings or guarantee grading. The remaining course interpretation is that SJR Q1–Q2 meets the unspecified ranking-system requirement; CMC is SJR Q2 but JCR Q3.

## Workspace and project

- Workspace: `<original private workspace>`
- User-facing deliverables folder: `phase 2` inside the workspace.
- Course: Computer Networks.
- Project title: Machine Learning-Based Detection of Previously Unseen Low-Rate DDoS Attacks.
- Students: M Abdullah Nadeem and Ayaan Faisal.

If this project is copied to another machine, resolve the relative paths below against the new project root instead of relying on the original Windows paths.

## User requests and completed history

### 14 October 2026 — Prepare Phase 2

The user said Phase 1 was complete and asked for careful completion of the assignment PDF in the project folder. Required deliverables were:

1. Extended literature review.
2. Refined research gap.
3. Proposed research methodology.
4. Research methodology diagram.

The assistant read the assignment PDF and both supplied Word documents, researched additional papers and dataset documentation, and created a 19-page report in Word and PDF plus a standalone methodology diagram in PDF, PNG and SVG formats.

### 17 October 2026 — Save in a separate folder

The user requested another folder named exactly `phase 2` inside `Cnet_Proj`. The assistant created it and copied all five final deliverables from `output/phase2`. SHA-256 hashes were compared between each source and destination to verify the copies. The original files were preserved.

### 17 October 2026 — Save context for future chats

The user requested a Markdown history file so a new chat or harness can recover context. This file fulfills that request.

### 17 October 2026 — Revise the report presentation

The user said the report looked unprofessional. The assistant rechecked the assignment and created a 23-page formal academic Word report with a separate cover, abstract, contents page and numbered sections. Word updated the contents field and exported the PDF. All 23 pages were rendered and visually inspected; the final small wrapping correction changed only page 10, which was inspected again. Checks retained all twelve methodology subsections and references [1]-[18]. This version is now archived. The standalone diagram files were unchanged.

### 17 October 2026 — Use an internet-sourced LaTeX research-paper format

The user then requested an established research-paper format from the internet and explicitly asked for LaTeX. Official IEEE Author Center and IEEE's official Overleaf conference example were consulted. The content was rebuilt in `IEEEtran` conference mode with standard column dimensions, full-width booktabs comparison tables, native equations and a TikZ architecture diagram. Long methodological tables were converted to labeled prose to keep the two-column paper readable. Small punctuation, bibliography author-boundary and table-rule issues were corrected during QA; no experimental findings were added.

The built-in compiler failed because it could not download its TeX bundle. A portable official Tectonic 0.17.0 Windows binary was downloaded to `tmp/latex-runtime/`; its ZIP SHA-256 was `f61ce51f0b0ade1015b7de7ef368541c5424e9756ecbd0d7af97d6d48030845f`. With approved network access it fetched the TeX packages and compiled the source. Later builds used its cache. Nothing was installed system-wide. The portable binary is a temporary local build aid, not a submission dependency.

The final PDF has nine pages, all twelve steps, all eighteen references and 78 link annotations. No overfull boxes or unresolved references remain. TeX still reports ordinary underfull spacing notices; the compiler's Fontconfig notice did not prevent embedded TeX fonts from rendering. Every page was rendered and visually reviewed, including the final comparison tables, diagram and balanced reference columns. The old 23-page files were archived before replacing the main PDF. The source and final PDF were queued for opening in the app; successful compilation is established by the portable compiler and saved PDF, not by the editor-opening response.

### 17 October 2026 — Final factual and methodological review

At the user's request, the original brief and Phase 1 scope were reread, the eight new articles' identities and reported results were checked against accessible primary/author-linked evidence, and the final methodology was audited. `phase 2/FINAL_REVIEW.md` records the evidence and limits. The prior LaTeX files and content snapshot were archived under `phase 2/archive/before_final_review_2026-10-17/`.

Corrections qualify F-OSFA's proposed resource-analysis component, remove unnecessary A2 shared-representation wording, explicitly exclude all slow-attack lab data from development, reserve all CSE-CIC-IDS2018 records for external testing, restrict AE fitted preprocessing to benign training data, and disable HGB internal random early-stopping splits. The complete rule's development FPR target applies overall and to ordinary/stress strata. The lab plan is now 40 attack episodes (2 mechanisms × 2 source counts × 2 concurrency/timing profiles × 5 independent repeats), plus at least 5 final sessions per benign condition. Pre-onset alarms do not count as immediate detections. AP, session-stratified bootstrap and seed averaging are specified. These are proposed protocols, not experimental outcomes.

The final paper remains nine pages with twelve steps, eighteen unique resolved bibliography entries and 78 link annotations. Every page was visually checked. The generator now rejects duplicate/missing bibliography identifiers and unresolved citation keys; the PDF verifier also rejects `[?]`. Natural bibliography flow replaces the earlier manual `IEEEtriggeratref{6}` balancing point. Both PDF aliases, the ZIP, README and context copies are synchronized. The older Word reports are historical and do not contain these final refinements.

## Original inputs and their authority

- `Phase 02 - Extended Literature - Research Methdology.pdf`: the three-page Phase 2 assignment brief. Preserve the filename's original spelling.
- `CNET_Phase1_Literature_Review.docx`: the completed Phase 1 report. This is the authoritative source for the accepted project scope.
- `cnet-research.docx`: earlier brainstorming notes. These contain an older direction involving mitigation and are superseded on scope by the completed Phase 1 report.

The Phase 2 brief requires **8–10 additional original research papers from 2025–2026**, eligible Q1–Q2 journal/conference/book-chapter venues, a comparison table, at least three potential gaps, a justified methodology and a diagram. Its example tables still refer to three studies, but the extended-selection requirement explicitly asks for 8–10 additions; the report uses eight additions.

The methodology must cover all 12 steps: research input, collection, preprocessing, feature engineering, proposed method, baselines, experimental design, metrics, statistical comparison, ablation, failure analysis and final output.

## Final deliverables

The following are the copies requested by the user:

| Relative path | Purpose |
| --- | --- |
| `phase 2/CNET_Phase2_Report.pdf` | Preferred nine-page compiled LaTeX submission paper |
| `phase 2/CNET_Phase2_IEEE.pdf` | Identical PDF under the source basename |
| `phase 2/CNET_Phase2_IEEE.tex` | Editable standalone LaTeX source |
| `phase 2/CNET_Phase2_LaTeX.zip` | LaTeX source and README for Overleaf |
| `phase 2/README.md` | Submission-file guide, template provenance and build instructions |
| `phase 2/FINAL_REVIEW.md` | Final compliance/source audit, corrections and remaining qualifications |
| `phase 2/PROJECT_CONTEXT.md` | Portable copy of this handoff file |
| `phase 2/archive/academic_layout_2026-10-17/CNET_Phase2_Report.docx` | Earlier editable Word report, superseded by LaTeX |
| `phase 2/CNET_Phase2_Methodology_Diagram.pdf` | Standalone vector diagram |
| `phase 2/CNET_Phase2_Methodology_Diagram.png` | High-resolution diagram for insertion |
| `phase 2/CNET_Phase2_Methodology_Diagram.svg` | Editable vector diagram |

The PDF alias under `output/phase2/` is synchronized to the LaTeX PDF. The Word file there is historical. Future edits should keep the user-facing `phase 2` PDF aliases current and avoid unexplained conflicting versions.

## Key scope decisions

- Preserve **detection and evaluation only**. Automatic blocking, rate limiting, traffic redirection and mitigation-effectiveness experiments are outside the accepted implementation scope.
- The original three Phase 1 papers are retained as the foundation; they do not count toward the eight additional Phase 2 papers.
- Previously unseen or experimental zero-day means an attack family excluded from training, validation, early stopping, calibration and augmentation. It does not mean a new software vulnerability unknown to the security community.
- Slow application-layer DoS and distributed low-rate DDoS are distinct. Public Slowloris/Slowhttptest results alone do not prove distributed low-rate DDoS detection. The proposed isolated multi-client lab provides the additional distributed evidence.
- Do not describe completed-flow CSV classification as proof of early/live detection latency.
- At the October Phase 2 stage, no dataset collection, model implementation, training, attack experiment or measured research result had been completed. The report is a literature review and **proposed** methodology. Literature performance numbers are author-reported, not project results. The November engineering/development work is recorded separately above.

## Literature review and refined gap

The report adds these eight articles, numbered A1–A8 and references [4]–[11]:

| ID | Study | DOI |
| --- | --- | --- |
| A1 | Minhas et al., F-OSFA, IEEE Access, 2025 | `10.1109/ACCESS.2025.3557822` |
| A2 | Ullah et al., Hybrid dual-head IDS, Results in Engineering, 2026 | `10.1016/j.rineng.2026.111498` |
| A3 | Han et al., Adapting Convolutional Autoencoder for DDoS Attack Detection via Joint Reconstruction Learning and Refined Anomaly Scoring, CMC, 2025 | `10.32604/cmc.2025.067211` |
| A4 | Nawaz et al., Lightweight machine learning framework for efficient DDoS attack detection in IoT networks, Scientific Reports, 2025 | `10.1038/s41598-025-10092-0` |
| A5 | Anandhi and Srikanth, Federated sparse-learning framework for detecting low-rate stealth attacks in resource-constrained IoT devices, Scientific Reports, 2026 | `10.1038/s41598-026-46531-9` |
| A6 | Raza et al., Liquid neural networks for adaptive DDoS detection in IoT and SDN environments, Scientific Reports, 2026 | `10.1038/s41598-026-67535-5` |
| A7 | Ebrahem et al., A lightweight machine learning approach for DDoS detection and classification, Scientific Reports, 2026 | `10.1038/s41598-026-48535-x` |
| A8 | Kalafy et al., Dynamic graph neural network-based framework to increase detection accuracy in SDN under DDOS, Scientific Reports, 2026 | `10.1038/s41598-025-32102-x` |

A8 was first online on 29 December 2025, with the publisher's volume citation/version of record in 2026. Both are within the assignment period.

The retained Phase 1 references are Bocu and Iavich (`10.1016/j.jnca.2026.104441`), Rullo et al. (`10.1016/j.asoc.2026.115796`) and Nakıp (`10.1016/j.knosys.2026.115995`).

Important correction to the earlier gap: A2 already explicitly provides a strict zero-day holdout and hybrid detection. Do not claim this project invents either or that no recent work evaluates unseen attacks. The refined gap concerns **unseen slow-family recall, a fixed low false-positive operating point, stressed legitimate traffic, temporal delay and frozen environment transfer together**.

Four gap themes are documented: joint novelty and benign stress; temporal evidence versus delay; provenance and transfer; and complexity versus measured value.

Venue eligibility uses **SCImago SJR**, explicitly distinguished from JCR. The report documents the audited 2024 ranking edition and supporting 2025 institutional records where checked. CMC is SJR Q2 but JCR Q3; do not silently call it JCR Q2. Rankings are historical evidence recorded in the report, not a guarantee of their latest status. Some publisher pages were inaccessible; accessible publisher records and author manuscripts/repositories supported the review. Recheck full texts and venue records if deeper source verification is requested.

## Proposed methodology to preserve

- Inputs: timestamped PCAP-derived, causal one-second destination-service windows, with rolling temporal context. Metadata identifiers support grouping and labels, not prediction.
- Sources: CIC-IDS2017 for the primary public study; CSE-CIC-IDS2018 for external testing; CIC-DDoS2019 as a separate flooding/known-family benchmark; isolated local sessions for benign stress and multi-source slow traffic.
- Final-review clarification: reserve the entire external CSE-CIC-IDS2018 source, including benign data, from development. Lab development/pilots are benign only; all slow-attack lab runs are final-only. A lab environment already used for benign calibration is not an unseen transfer environment.
- Primary novelty test: quarantine the **entire Slowloris/Slowhttptest group** from every development stage. Secondary Hulk/GoldenEye exclusions test broader novelty, not extra slow-family diversity.
- Split before window creation or fitted transformations. Keep captures/sessions or purged contiguous blocks separate; prevent duplicated observations and future-flow features from leaking across splits. Proposed eligible-group allocations are 50% T, 15% V, 10% benign C1, 10% benign C2 and 15% final K, subordinate to holdout and benign-only eligibility. These are planning proportions, not allocated packet-window groups. For contiguous blocks purge at least maximum history plus tracker timeout and separately handle continuing/crossing connections.
- Proposed supervised branch: HistGradientBoosting with inverse-frequency sample weights on benign and permitted known attacks.
- Disable HGB internal random early stopping; tune iteration count on grouped V. AE initial Adam learning rate is 0.001, batch size 256, maximum 100 epochs and patience 10 on benign V. All AE fitted transforms, including imputation, use benign training only.
- Proposed anomaly branch: benign-trained dense autoencoder, initially `d-32-16-8-16-32-d`, with reconstruction error as its score.
- Use disjoint benign C1 data to build empirical score-percentile maps. Combine branches by the maximum mapped score. Calibrate the **whole** threshold-plus-persistence rule on separate benign C2 data to empirical development FPR at most 1%, overall and in ordinary/stress strata.
- Do not independently allocate each branch 1% FPR and assume their OR also has 1% FPR. Final test FPR can exceed the development target and must be reported honestly.
- Candidate persistence rules: 1-of-1, 2-of-3 and 3-of-5. Select using development data and freeze features, transformations, weights, mappings and decision settings before final tests.
- Baselines: rate threshold, Logistic Regression, Random Forest, supervised branch alone, AE alone and benign-trained Isolation Forest. Use matched splits and calibration procedures.
- Main outcomes: per-family unseen recall, ordinary/stress FPR, episode recall, onset-to-alert delay, alert burden and computational cost; supplement with accuracy, precision, F1 and ranking curves.
- Count newly starting eligible alerts within 180 seconds of onset and before episode end; do not credit a pre-existing alarm as immediate detection. Define alert episodes after five preceding non-alert windows, show misses/censoring and undefined metrics as N/A. Use AP for the precision–recall summary.
- Lab target: two mechanisms (incomplete-header and slow-request-body connection holding), one/three clients, profiles of 10 connections/20-second spacing or 60 connections/5-second spacing per client, with five independent session repeats each: 40 planned attack episodes. Benign conditions are ordinary requests, bursts, flash-crowd-like concurrency and controlled congestion, with at least five independent final sessions per condition (at least 20 total), separate from benign development/calibration sessions. Reset service/client state and vary background seeds; actual rates and denial-of-service impact remain to be measured.
- Proposed model-comparison budget: at most 12 prespecified configurations per learned method, chosen on development data only; stochastic seeds 7, 19, 42, 73 and 101, with one run for deterministic methods. Only the auxiliary seed-7 run is complete. Proposed statistical work includes paired session/block bootstrap intervals, effect sizes and appropriately qualified paired tests. Seeds and correlated windows are not independent traffic replications.
- Average seeds within each session before paired cluster resampling; stratify by family/benign condition and recompute pooled confusion-count metrics. Use 2,000 resamples and 95% intervals.
- Ablations: remove either branch, temporal history, persistence, timing/connection features or class weights; recalibrate variants to the same development FPR target.
- Frozen external transfer is separate from optional target-benign recalibration. Never use final-test outcomes to tune the headline model.
- The final scientific result may be negative. Preserve missed episodes, false positives, uncertain labels and failed attack attempts rather than hiding them with aggregate accuracy.

## Generation and verification details

The following first three items are the current LaTeX workflow. Word-related details below document previous layouts and should not be treated as current build instructions.

- `phase 2/source/build_ieee_paper.py`: current standalone LaTeX generator.
- `phase 2/source/verify_ieee_paper.py`: current structural checks and page renderer.
- `phase 2/README.md`: current build/edit instructions. Use pdfLaTeX twice, XeLaTeX twice, or Tectonic; IEEEtran and TikZ are standard TeX packages. The distributed source includes all bibliography entries and the diagram inline.
- `phase 2/source/format_phase2_report.py`: previous 23-page Word formatter.
- `phase 2/source/report_content.json`: portable content snapshot shared by the formatters.
- `phase 2/source/verify_academic_report.py`: previous Word-report renderer.
- `build_phase2.py`: original report/diagram source using `python-docx`, ReportLab and `pypdfium2`; generates the superseded 19-page report layout.
- `tmp/phase2/report_structure.json`: structured report content generated by the builder.
- `tmp/phase2/verify_report.py`: structural checks and page rendering.
- `tmp/phase2/render/page-1.png` through `page-19.png`: internal visual QA images; `overview.png` is a contact sheet.
- The original builder writes to **`output/phase2`**; the current formatter writes to **`phase 2`**. After verification, synchronize the report copies deliberately.
- The builder does not itself export the full Word report to PDF. The report PDF was exported with installed Microsoft Word through a hidden COM instance.
- The document skill's `render_docx.py` was attempted but could not find LibreOffice. Word export followed by `pypdfium2` rendering provided visual verification instead. Word automation required an escalated command in this environment.
- Every final report page was visually inspected. A final reference-link repair changed only page 19; rendered PNG hashes confirmed pages 1–18 were unchanged, and page 19 was inspected again.
- Final checks confirmed 19 pages, all 12 methodology steps, references [1]–[18], 18 Word hyperlinks and 18 PDF link annotations. No tool citation tokens or placeholder markers remained.
- A default blue border under the Word title was removed. Headings are black Arial; body text is Times New Roman; comparison tables use landscape pages.

Bundled Python used during creation:

`<bundled Python runtime; rediscover on a new machine>`

If continuing on another machine or runtime, rediscover dependencies and available document tools rather than assuming that path exists. Read applicable skills and repository instructions before editing.

## Suggested continuation

The requested Phase 2 content, LaTeX paper, source package and handoff documentation are complete.

For revisions, read the current LaTeX paper, final review and this history first. Preserve the accepted scope, edit the standalone source or regenerate deliberately, compile, render and visually inspect the pages. The current bibliography uses natural column flow; recheck it after length changes. Synchronize the PDF aliases, source ZIP and context copies. Word export is not part of the current workflow.

The November implementation has completed the initial audit/replay engineering gate. Continue from the current benign-coverage and split-safety checkpoint above, not from the start of the October proposal. Refine proposed settings using permitted development data while preserving genuinely untouched final sets.

## How to use this context in a new chat

Ask the new assistant to read `PROJECT_CONTEXT.md`, `phase 2/README.md` and `phase 2/CNET_Phase2_IEEE.tex` before continuing. An arbitrary Markdown file is not guaranteed to be loaded automatically by every harness. If moving the work elsewhere, include the original assignment, authoritative Phase 1 report, final Phase 2 deliverables, this file and `phase 2/source/` for regeneration. Include the original `build_phase2.py` only if the original diagram or layout generator is also needed.
