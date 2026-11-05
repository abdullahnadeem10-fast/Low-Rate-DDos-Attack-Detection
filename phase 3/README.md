# Phase 3 — Experiment workspace

Track completed work in [plan/CHECKLIST.md](plan/CHECKLIST.md) and resume from [plan/PROGRESS.md](plan/PROGRESS.md). Phase 2 defines the study protocol. Files under `results/pilot` are engineering evidence, not paper results.

From this folder, with Python 3.12 and the pilot dependencies installed in `.venv`:

```powershell
& '.venv/Scripts/python.exe' 'src/check_packet_pilot.py'
& '.venv/Scripts/python.exe' 'src/packet_pilot.py' --service '192.168.10.3:389'
& '.venv/Scripts/python.exe' 'src/audit_friday_labels.py'
```

`requirements-pilot.txt` lists the versions used. The packet pilot reads `data/pilot/monday-first-32MiB.partial`, an intentional byte range; its exact URL, range and slice hash are in `results/pilot/monday_pilot.json`. Do not use the slice hash as the full-file hash. The label audit reads `data/quarantine/CICIDS2017-GeneratedLabelledFlows.zip`, verifies the archive hash and opens only the named Friday member. Its URL and expected hash are in `results/pilot/friday_label_audit.json`. The raw data and environment are excluded from version control.
