# Instructions for the next Claude Code session

Copy the short launch prompt at the end into Claude Code after cloning the repository. This document is the detailed task specification. It adds no new completed experiment or permission to change the original freeze.

## Decision: evaluate the existing approach first; separate any new approach

First reproduce the frozen model setup, analyze the existing ablations, qualify independent data, and complete compatible frozen transfer and performance measurements. Do not start by training another model or changing thresholds to make the numbers look better.

A new approach is optional and must be a separately declared V2 development study with new development/calibration/validation data and untouched final recordings. It must not replace the existing results. The current 60 final lab recordings, their warmup/context and the reserved complete slow families/external source must never become training/calibration data. A useful evaluation/negative-results paper remains possible without claiming a better detector.

## 1. Establish the correct project state

Repository: https://github.com/abdullahnadeem10-fast/Low-Rate-DDos-Attack-Detection

The complete-lab baseline is commit `96b51c7d7af4d2c90b2c91343429c2b4c5def600`; later handoff-only commits may follow. Preserve that baseline and work on a new branch, for example `friend-evaluation-v1`.

Read these before substantive work:

1. `AGENTS.md` and `PROJECT_CONTEXT.md`.
2. `phase 3/plan/PROGRESS.md`, `CHECKLIST.md`, `NEXT_STEPS.md`.
3. `phase 3/results/final/final_lab_readiness_v1.json`.
4. `phase 3/plan/FINAL_LAB_RESULTS_V2.md`, `FINAL_FREEZE_REVIEW.md`, `blind_final_protocol_v1.json`.
5. `phase 3/results/development/final_freeze_v1.json` and its gate.

All 60 original lab trials are finished: 20 benign, 40 controlled campaigns, 117 configurations each, 7,020 case/session evaluations. Do not run their collectors again. Prepared v7/report-v1 sources were superseded; v8 and report-v2 contain the completed results. The preserved setup interruption and old rolling ledger are engineering history, not another trial or a reason to recollect.

Primary seed 7 results are hybrid recall 78.20% / benign FPR 59.14%, versus AE 99.47% / 43.92%. Both hit 40/40 episodes, but this does not erase window misses or severe false alarms. The current results do not demonstrate a hybrid advantage. Other matched baselines, ablations and all prescribed seeds must remain visible; do not promote the best final-performing case.

## 2. Obtain and verify the original model artifacts

Git contains code and small evidence, not trained weights, C1 references, raw captures, score arrays or environments. Ask the project owner for the private bundle if absent; **do not retrain substitutes**.

Prepared private bundle: `PRIVATE_FROZEN_MODELS_v1.zip`, approximately 6.15 MiB.

Expected ZIP SHA-256:

```text
caea26e3d073e5c309734ee26c9b3d1f67c55575fe22f994d8ede23677cef15c
```

Extract it at the repository root, not inside `phase 3`. Entries already start with `phase 3/`. It contains 66 original weight files, 66 C1 arrays, and `phase 3/data/friend_transfer_v1/PRIVATE_TRANSFER_MANIFEST.json`. Keep the ZIP and extracted assets private under ignored data directories. Verify every artifact against the public freeze and the private manifest. The model bundle does not contain the original raw/features/scores/interruption archive needed to reproduce the complete historical packet audit; record that limitation if those are not transferred separately.

Original frozen software: Python **3.12.14**, NumPy **2.3.5**, scikit-learn **1.7.2**; other pinned packages are in `phase 3/requirements-pilot.txt`. Inventory OS, CPU, RAM, Python, package/BLAS versions and thread settings. Recreate an environment; do not copy another computer's virtual environment. Do not edit version/hash assertions or the freeze to accommodate a mismatch.

Using that environment's Python, from `phase 3`:

```text
python -c "import sys; sys.path.insert(0, 'src'); from frozen_suite import verify_freeze; f,g=verify_freeze(); print(g['freeze_sha256'], len(f['cases']))"
python -m unittest discover -s src -p "test_*.py" -v
```

Expected freeze SHA-256 is `063a838d5fe45b1d38e536ca589959214871961dcb944a868203e98e15712bfe`, with 117 cases. Record actual test passes, skips and failures on this machine; do not mistake saved historical test counts for a new run. Fix environment/setup problems without changing sealed scientific code. If exact artifacts/runtime cannot be obtained, report a reproduction blocker rather than claiming frozen-model testing.

## 3. Audit the friend's data before deciding what it can establish

Start with owner-provided descriptions and file metadata. Record source/version, provenance, format, capture/session/day boundaries, services, family labels, whether the friend already used it for training/tuning, and overlap with our sources. Do not assume it is new or unseen because it is on another PC.

Before semantic payload inspection, feature extraction or scoring, write and hash a versioned qualification plan. Fix the intended role, permitted files/groups, compatibility/label/clock rules, exclusions and failure accounting independently of model scores. Then inspect under that declaration, calculate fingerprints, and document actual compatibility. No fitting or score-based inclusion during qualification.

Use this decision rule:

| Available data | Permitted next action |
| --- | --- |
| Raw PCAP/PCAPNG with defensible labels, full observation clocks, service/direction/context evidence | Assess compatibility with the frozen causal 30-feature packet-window contract. If qualified, evaluate unchanged models. |
| Precomputed causal packet-window tables | Accept only if feature definitions, units, clocks, resets, provenance and label support are demonstrably equivalent; matching column names alone is insufficient. |
| Completed-flow CSVs, including ordinary CICFlowMeter exports | Do not feed them into the packet-window models or invent missing packet history. Record frozen packet evaluation as unsupported; a separate completed-flow development study can be considered, with its own claims and splits. |
| Unlabelled traffic | Do not infer benign labels from silence/idle time or calculate detection recall/FPR. It may support a declared engineering throughput test; manually qualified known-legitimate traffic needs independent provenance. |
| Duplicates of our Friday T, 03-11 V, or original final lab recordings | Not independent final evidence. Same recordings on a new computer support reproduction/cost measurements only. |
| Data already used to select a proposed V2 model | Development evidence for that V2, not a new untouched final test. |

Check whole-parent/connection/time/family overlap, not just duplicate rows. Never call a sample a genuine slow attack merely because its packet rate is low. Family novelty requires the whole relevant family and aliases to be excluded from all development/augmentation/model selection/calibration; later traffic or a new machine alone is not unseen-family evidence.

The original reserved slots are `public_slow` = complete CICIDS2017 Wednesday (U), `known_final` = supplied CIC-DDoS2019 01-12 (K), and `external` = CSE-CIC-IDS2018 (E). Friday remains T and provided 03-11 remains V. Entire public slow-family context and the entire reserved external source stay excluded from development.

If the friend's data is a different source, do not rename it to an existing source ID or edit/bypass the gate. Declare a separate versioned external-extension protocol anchored to the original freeze, with unchanged models and evaluation, before accessing its payloads. Any new adapter must pass equivalence fixtures and provenance/ownership checks. Clearly distinguish that extension from the original preregistered source slots. If compatibility cannot be established, report N/A and explain why.

## 4. Perform these tasks in order

### A. Diagnose existing results without recollecting or tuning

Analyze the existing 117-case totals and 1,404 stratum rows. Compare HGB, AE, fusion, rate/history/state feature controls and persistence/instantaneous controls using their declared calibrations. Report per-family/profile recall, per-condition FPR, alert starts and alarm occupancy, episode hits/misses and miss-inclusive delay. Explain which component changes are associated with failures; do not call an uncontrolled difference causal or select a winning variant for a fresh-performance claim.

### B. Compatible frozen public/friend-data evaluation

For original source slots, implement and fixture-test a separate source-specific acquisition/qualification adapter and seal it through the existing gate before payload access. Preserve source/parent ownership, raw hashes, full clocks, unknown labels, strict state resets and at least the frozen 50-second boundary guard. Corroborate clock/labels; do not simply trust advertised attack times. No cross-partition feature state or final-context reuse.

Score each accepted new recording once with all 117 frozen cases, not only hybrid/AE. The existing entry point, from `phase 3`, is:

```text
python src/score_qualified_final.py --qualification <new_qualified_record.json>
```

This is not an arbitrary CSV scoring command: the acquisition seal and full qualified-input contract must pass first. Retain every declared failure, unsupported source, uncertain label and ineffective/no-payload episode. Do not refit scalers, score maps, models, thresholds or persistence rules on external/final data. Do not recreate original final artifacts or reuse their group IDs/output paths.

### C. Processing-cost benchmarks on the friend's hardware

Declare workload, fixture roles, warmup, repetitions, thread settings and measurements before timing. Measure feature extraction, warm inference per window, cold model loading and end-to-end processing separately. Report median/p95 processing time, CPU, peak RAM, windows/second and any drops/backlog. Use matched inputs/hardware/settings for compared methods. Engineering repetitions and synthetic vectors are not independent attack trials.

### D. Actual online latency and new-host stress evidence

Use only an isolated, bounded local lab or controlled replay. Implement a versioned streaming wrapper around the unchanged causal core and prove score/state equivalence to offline processing before reporting performance. At original timing (1x), record verified attack onset, packet arrival/window availability, processing completion and alert emission with appropriate wall/monotonic clocks. Report misses/censoring and preexisting alarm state, as well as delay. Accelerated offline replay is a throughput test, not live detection latency; preserve event-time semantics.

A new-host lab can provide additional traffic/environment evidence only through fresh, separately declared captures, not by merely replaying the same original 60 files. If that claim is pursued, predeclare a fresh matrix: two mechanisms × one/three sources × the original two paired connection/timing profiles × five repeats = 40 campaigns, plus five ordinary/burst/flash/shaped-long benign sessions each = 20. Use globally new IDs/seeds, fixed order, warmup/measurement intervals, independently logged source clients, complete probe denominators and exact image/resource/network settings. Compare all declared methods on the same fresh sessions. Do not launch old completed collectors, modify sealed sources, expose ports, change host NICs, or send attack traffic to public/third-party services.

Keep network loss/service impairment distinct from capture loss. A broken observation clock or missing capture is not licence to fabricate history or report fully observed metrics; retain the failure and use the declared unsupported/unknown/censored handling.

## 5. Optional V2 approach: a separate study, not a repaired result

Do not silently substitute another model into V1. First document a specific failure mechanism using development evidence and the completed evaluation's stated limitations. Propose a small, testable change and a measurable recall/FPR trade-off; a larger neural network or a model search until high accuracy appears is not a contribution by itself.

If V2 is pursued, declare its hypothesis, data allocation, features, preprocessing, candidate settings, seeds, baselines, threshold policy and stopping criteria before fitting. Split by whole parent capture/session/day and connection ownership before preprocessing/window construction. Fit transformations on T only; fit an anomaly model on permitted benign T; use separate permitted validation and benign C1/C2 calibration. Keep full slow-family groups/aliases, the reserved external source and all original final data out of development.

Reserve genuinely untouched final recordings before inspecting model outcomes. If all the friend's data has already influenced design, no fresh final set exists: obtain new independent recordings or call the work exploratory. A development calibration budget of at most 1% FPR is a target to calibrate and test, not a guaranteed final FPR.

For an architectural improvement claim, refit appropriate AE/HGB/RF/simple baselines and the new candidate on the same newly declared development roles and compare them on the same fresh final inputs. Keep unchanged V1 transfer results as a separate reference; different training data must not be mistaken for architectural improvement. Freeze V2 before final access and report every prescribed seed, false alarm, miss and failure. Never train or recalibrate on the original 60 trials or recycle them as new unseen validation.

## 6. Required records and deliverables

Create a versioned continuation folder such as `phase 3/friend_continuation_v1/` for plans/results/reports. Put raw data, weights, score vectors, secrets and environments only in ignored private locations; verify Git ignore rules before storing or staging them. Preserve every old source/JSON/CSV checksum and the sanitized Phase 2 proposal. Version new adapters/experiments; never overwrite a completed result.

Deliver: environment/artifact reproduction report; data qualification/usage-history/role/overlap manifest; ablation findings; supported frozen external results plus all N/A/failures; cost benchmark; measured live-latency report or a specific remaining blocker; and a decision report separating V1 conclusions from any optional V2 study. Report confusion counts and eligible denominators, per-family/profile recall, per-condition FPR, precision/F1 where supported, qualified false starts/hour plus alarm occupancy, exact/coarse/censored episode outcomes, miss-inclusive restricted delay and group-level uncertainty only where justified. Do not infer performance from accuracy alone or pool windows/model seeds as independent traffic recordings.

Maintain a checked progress file and update `PROJECT_CONTEXT.md` plus Phase 3 progress/checklist/next steps after substantive work. Record exact commands, source/data/artifact hashes, timing scope, limitations and the next action. Commit only reviewed code/plans/small sanitized evidence on the new branch. Resolve ordinary implementation choices independently; ask only for genuinely missing data/provenance/artifacts or access. Never invent labels/results, weaken a guard, hide a negative finding or claim full-study readiness while transfer/cost/live-latency work is unsupported.

## Short launch prompt to paste into Claude Code

```text
Continue our low-rate DoS/DDoS research from this repository:
https://github.com/abdullahnadeem10-fast/Low-Rate-DDos-Attack-Detection

Read AGENTS.md and PROJECT_CONTEXT.md, then follow
"phase 3/plan/CLAUDE_CODE_FRIEND_HANDOFF.md" in order.
The original 60 lab trials are complete; do not rerun, overwrite or retune them.

I will provide the private frozen-model ZIP and a folder containing my own data.
First verify the original artifacts/runtime and inventory my data's provenance,
format, prior use and overlap. Do not assume it is compatible or unseen.
Declare the qualification/split roles before payload inspection or model scoring.

Start with existing ablation analysis, compatible unchanged-model external tests,
processing-cost benchmarks and genuinely measured online latency.
A new approach must be a separate V2 study with permitted new development data,
matched baselines and untouched final recordings; preserve all V1 findings.

Use versioned files and a new branch, keep raw data/models/secrets out of Git,
maintain the project handoff/progress, and record unsupported tests honestly.
Do not replace missing models by retraining or bypass a failing qualification gate.
```

Methodological reference: scikit-learn's guidance on separating training/test data and training-only preprocessing: https://scikit-learn.org/stable/common_pitfalls.html
