# Phase 3 — Experiment workspace

Track completed work in [plan/CHECKLIST.md](plan/CHECKLIST.md) and resume from [plan/PROGRESS.md](plan/PROGRESS.md). Phase 2 defines the study protocol. Files under `results/pilot` are engineering evidence, not paper results.

For a different harness or machine, read the maintained root [PROJECT_CONTEXT.md](../PROJECT_CONTEXT.md) first. It includes the full handoff, source hashes, commands and exact next action; [AGENTS.md](../AGENTS.md) is the compatible-harness entry point. A clone includes code and small evidence, while raw datasets and the local environment must be transferred separately or recreated.

Development evidence is in `results/development/`: full Friday capture replay, clock/count audits, readiness checks and separate completed-flow baseline comparisons. The latter deliberately use finished-flow features and a development partition; they do **not** establish unseen-family recall or early/live detection performance.

12 November current checkpoint: [split-first public replay](results/development/public_partitioned_v1.json) is complete: 2,224 candidate benign rows and **zero retained attack rows** under its declared conservative connection policy. The independent [fragment audit](results/development/public_fragment_attribution_v1.json) attributes eight flags to UDP while preserving the original flag. All 47 offline checks pass. Study training readiness remains false. Read the [split review](plan/PUBLIC_SPLIT_REVIEW.md), [engineering registry](results/development/study_development_manifest_v1.json) and [current readiness](results/development/development_readiness_2026-11-12.json). Next: full TCP-incarnation/boundary audit or independent permitted known-attack data; final K is unallocated.

Prior 11 November component checkpoint follows:

11 November: WSL/Docker and the initial benign data component work. The selected **v3** component contains 12 sessions, 702 measurement windows and 28 distinct client jitter seeds; every selected capture passed HTTP/packet checks with zero kernel-reported drops. The public HTTP-candidate audit yielded 2,243 corroborated nonempty service-seconds and retained 1,743 uncertain cells. All 35 offline checks pass. See [current readiness](results/development/development_readiness_2026-11-11.json), [canonical lab selection](results/development/benign_batch_v3.json), [predictor/group manifest](results/development/benign_development_manifest.json) and the [roadmap](plan/FIVE_STEP_ROADMAP.md). No main detector/final attack test has run.

From this folder, with Python 3.12 and the pilot dependencies installed in `.venv`:

```powershell
& '.venv/Scripts/python.exe' 'src/check_packet_pilot.py'
& '.venv/Scripts/python.exe' 'src/packet_pilot.py' --service '192.168.10.3:389'
& '.venv/Scripts/python.exe' 'src/audit_friday_labels.py'
```

`requirements-pilot.txt` lists the versions used. The packet pilot reads `data/pilot/monday-first-32MiB.partial`, an intentional byte range; its exact URL, range and slice hash are in `results/pilot/monday_pilot.json`. Do not use the slice hash as the full-file hash. The label audit reads `data/quarantine/CICIDS2017-GeneratedLabelledFlows.zip`, verifies the archive hash and opens only the named Friday member. Its URL and expected hash are in `results/pilot/friday_label_audit.json`. The raw data and environment are excluded from version control.

## Development commands

Run these from `phase 3` using the existing `.venv` (on another machine create a Python 3.12 environment and install `requirements-pilot.txt`). The downloader needs network access and up to several tens of GB of working space for resumable ranges and the assembled file.

```powershell
& '.venv/Scripts/python.exe' -m unittest discover -s src -p 'test_*.py' -v
& '.venv/Scripts/python.exe' 'src/replay_causal_features.py' --pcap 'data/pilot/monday-first-32MiB.partial' --service '192.168.10.3:389' --out 'results/development/monday_causal_windows.csv' --prefix
& '.venv/Scripts/python.exe' 'src/train_flow_development.py'
& '.venv/Scripts/python.exe' 'src/download_friday.py'
& '.venv/Scripts/python.exe' 'src/friday_packet_audit.py'
& '.venv/Scripts/python.exe' 'src/replay_causal_features.py' --pcap 'data/development/Friday-WorkingHours.pcap' --service '192.168.10.50:80' --out 'data/development/friday_causal_windows.csv'
& '.venv/Scripts/python.exe' 'src/assess_packet_development.py'
& '.venv/Scripts/python.exe' 'src/audit_monday_labels.py'
& '.venv/Scripts/python.exe' 'lab/run_benign_session.py' --role T --condition ordinary --clients 1 --prepare-only
& '.venv/Scripts/python.exe' 'src/summarize_benign_batch.py' --batch-version v3
```

`download_friday.py` fetches only the pinned Friday source, preserves resumable chunks and verifies the full SHA-256 before publishing the final capture filename. `friday_packet_audit.py` opens only the Friday DDoS label member, excludes impossible-duration keys, infers the clock offset from benign keys and compares canonical directional packet counts. The join outputs distinguish corroborated labels from possible or uncertain matches; they are not a blanket declaration of exact ground truth.

The entry points above are not a request to rerun downloads/collections blindly. For existing lab data, use only the v3 whitelist and verify hashes. The raw directory contains interrupted pilots, preflights and superseded calibration sessions; globbing all tables would duplicate/contaminate the dataset. v3 retains eight original sessions and four seed-separated replacements. Transfer the selected raw session folders for exact replay on a new harness; new network acquisitions produce new timestamps/hashes and require a separately recorded plan.

`inventory_friday_http.py` and `audit_friday_http_services.py` inspect archived Friday data only; candidate public IPs are not live traffic targets. Public candidate labels still need destination/session partitioning and reset/purged feature replay before model use. Broaden benign calibration with controlled congestion/diversity and repetitions; keep failed legitimate stress requests benign rather than selecting only successful easy cases. The study is deliberately not yet marked training-ready.

Do not score the slow-family holdout or CSE-CIC-IDS2018 while developing these tools. The causal extractor's proposed one-second lateness budget and 30-second connection timeout require full-capture and split-boundary validation before final use. The dense AE uses CPU scikit-learn `partial_fit` to retain Adam state, with benign-only fitted preprocessing and separate benign development early stopping; no GPU dependency is required.

The continuous Friday replay is **not a split-safe training table**. Start from the readiness report and development manifest, reset feature state at declared partition boundaries, and audit connection overlap before fitting the packet-window models. Missing/uncertain labels, including unlabelled idle seconds, are not benign by default. Do not filter packets by label confidence before extracting features; that would change the traffic the detector sees. Any later exclusion of uncertain windows must be quantified as coverage and possible selection bias.

When integrating the AE with the packet schema, explicitly pass `signed_columns=(feature_names.index('packet_rate_change'),)` so valid negative changes use signed-log preprocessing. Other features keep the nonnegative default; all fitted transforms still use benign training only. The packet-window model and its final schema are not yet fitted/frozen.

## Public split-first development commands

The v1 plan exists; do not change its boundaries under that name. From this folder, with pinned raw capture and saved audited label tables:

```powershell
& '.venv/Scripts/python.exe' 'src/declare_public_partitions.py'
& '.venv/Scripts/python.exe' 'src/replay_public_partitions.py'
& '.venv/Scripts/python.exe' 'src/audit_public_fragments.py'
& '.venv/Scripts/python.exe' 'src/summarize_study_development.py'
```

The conservative fragment flag covers all IPv4 protocols touching selected service IPs. Independent attribution preserves that report and establishes zero TCP fragments. The registry records supplemented packet quality, sparse timelines and zero positive rows. Raw features/eligibility/model tables stay ignored under `data/development/public_partitioned_v1/`. A clone must reacquire/recreate pinned raw evidence; never substitute guessed labels. v1 is a negative data-readiness checkpoint, not trained or final detection evidence.
