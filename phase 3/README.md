# Phase 3 — Experiment workspace

Track completed work in [plan/CHECKLIST.md](plan/CHECKLIST.md) and resume from [plan/PROGRESS.md](plan/PROGRESS.md). Phase 2 defines the study protocol. Files under `results/pilot` are engineering evidence, not paper results.

For a different harness or machine, read the maintained root [PROJECT_CONTEXT.md](../PROJECT_CONTEXT.md) first. It includes the full handoff, source hashes, commands and exact next action; [AGENTS.md](../AGENTS.md) is the compatible-harness entry point. A clone includes code and small evidence, while raw datasets and the local environment must be transferred separately or recreated.

Development evidence is in `results/development/`: full Friday capture replay, clock/count audits, readiness checks and separate completed-flow baseline comparisons. The latter deliberately use finished-flow features and a development partition; they do **not** establish unseen-family recall or early/live detection performance.

11 November: the additional Monday label audit did not establish matched benign HTTP coverage. The AE supports explicit signed feature columns; 25 offline checks pass. WSL 3.0.5 is installed and both Windows features succeeded; **restart Windows next**, then finish Docker installation and engine verification. Docker's first per-user attempt failed because VirtualMachinePlatform was absent. See [setup](setup/README.md), the prepared [benign-only lab](lab/README.md), and the [five-step roadmap](plan/FIVE_STEP_ROADMAP.md). No lab collection/final attack test has run.

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
```

`download_friday.py` fetches only the pinned Friday source, preserves resumable chunks and verifies the full SHA-256 before publishing the final capture filename. `friday_packet_audit.py` opens only the Friday DDoS label member, excludes impossible-duration keys, infers the clock offset from benign keys and compares canonical directional packet counts. The join outputs distinguish corroborated labels from possible or uncertain matches; they are not a blanket declaration of exact ground truth.

Do not score the slow-family holdout or CSE-CIC-IDS2018 while developing these tools. The causal extractor's proposed one-second lateness budget and 30-second connection timeout require full-capture and split-boundary validation before final use. The dense AE uses CPU scikit-learn `partial_fit` to retain Adam state, with benign-only fitted preprocessing and separate benign development early stopping; no GPU dependency is required.

The continuous Friday replay is **not a split-safe training table**. Start from the readiness report and development manifest, reset feature state at declared partition boundaries, and audit connection overlap before fitting the packet-window models. Missing/uncertain labels, including unlabelled idle seconds, are not benign by default. Do not filter packets by label confidence before extracting features; that would change the traffic the detector sees. Any later exclusion of uncertain windows must be quantified as coverage and possible selection bias.

When integrating the AE with the packet schema, explicitly pass `signed_columns=(feature_names.index('packet_rate_change'),)` so valid negative changes use signed-log preprocessing. Other features keep the nonnegative default; all fitted transforms still use benign training only. The packet-window model and its final schema are not yet fitted/frozen.
