# Final lab acquisition v1

This new directory leaves all frozen development/model/evaluation sources unchanged. The scripts run only against the fixed private service `172.28.240.100:80`, on one internal Docker bridge with forced router host routes. No published ports, NAT, host networking, host NIC changes, arbitrary target arguments, image builds or downloads are supported.

The immutable source-slot declarations are `../../plan/final_lab_lab_benign_acquisition_v1.json` and `../../plan/final_lab_lab_slow_acquisition_v1.json`. Their anchors are under `../../results/qualification/`. They bind all new scripts, the original model/evaluation freeze, image content IDs, validation and the exact collection catalog before traffic. The existing tool image supplies its hash-verified network helper; new scripts are mounted read-only. Apache's default request-read timeout module stays enabled. A bounded shell CGI body reader provides the POST target, with complete POST probes checking functionality before attacks. No timeouts are weakened to make attacks effective.

The fixed final catalog has 60 fresh sessions in a prespecified shuffled global order:

- 40 attacks: incomplete headers / incomplete request bodies × one / three sources × 10 connections per source with 20-second keep intervals / 60 connections with 5-second intervals × five repetitions. Every attack has 60 seconds of complete legitimate warmup, 240 seconds of campaign exposure and a bounded drain. All sources are private containers; at most 180 slow connections across three sources.
- 20 benign sessions: ordinary, bursts, flash and long-lived/congested, five repetitions each, with 60-second warmup and 180-second measurement. Complete legitimate failures remain benign. Long downloads use the fixed 512 kbit/s, 40 ms router profile.
- Three excluded benign-only preflights: ordinary, flash and shaped long downloads; 60-second warmup and 30-second measurement. No preflight is used for fitting, calibration or final scoring. All must pass before final traffic starts.

Three complete-request clients and a separate probe are present in every session. Probe slots occur at fixed 1 Hz, alternating complete GET/POST, with at most three workers and a two-second request budget. Late/failing/skipped slots are retained. Warmup/measurement availability and timely response latency are service-impact measurements, separate from detector delay. Headers are sent complete in benign traffic; request bodies are never deliberately withheld by benign agents.

Attack exposure labels mean an operating controlled campaign after its first unique-token/log/PCAP-corroborated incomplete request. They do not assert that every packet is malicious, that a socket is occupying an Apache worker, or that denial occurred. The first partial second is unknown. A campaign that emits no corroborated initial payload keeps measurement truth unknown and is recorded as an unscorable planned episode. Ineffective attacks, service crashes and legitimate failures are outcomes, never replacement criteria. Warmup/benign labels derive from controlled agents, not public silence. Observation tails remain unknown.

The auditor verifies route/MAC/clock/capture/HTTP evidence and resets the unchanged causal core per session. It reuses the already frozen full-observation replay extractor, including known observed idle tails; no feature code or decision mathematics is changed. A qualification record binds full feature/truth clocks and all hashes. No collector/auditor loads or fits models. Frozen scoring is a separate explicit step.

From the project root, after the two acquisition seals exist and using the existing project Python/Docker runtime:

```powershell
$env:CNET_DOCKER_EXE = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'
& '.\phase 3\.venv\Scripts\python.exe' -X utf8 'phase 3/src/run_final_lab_v1.py' --preflight
# After all three preflights pass, process the next single catalog unit:
& '.\phase 3\.venv\Scripts\python.exe' -X utf8 'phase 3/src/run_final_lab_v1.py' --final --limit 1
# Qualified final units only; excluded preflights have no qualification.json:
& '.\phase 3\.venv\Scripts\python.exe' -X utf8 'phase 3/src/score_qualified_final.py' --qualification 'phase 3/data/final_lab_v1/<unit>/qualified_v1/qualification.json'
```

`--final` without a limit runs all remaining catalog units sequentially. The planned measurement/warmup time alone is 280 minutes, plus 4.5 minutes for the excluded preflights; startup, drain, qualification and capture copying increase the total, roughly five to six hours on this PC if uninterrupted. This is an estimate, not measured completion time. Do not run two collections simultaneously. The runner records each start before collection, uses an exclusive lock, resumes only after completed successes, and refuses failed/interrupted attempts rather than recollecting them. A failure requires explicit reviewed versioned recovery preserving the original attempt and seal. Never edit a sealed source or overwrite any v1 artifact. Process-scoped sleep inhibition restores on exit; manual sleep or pauses can still invalidate a capture.

Raw PCAPs, full request/probe/slow logs, route metadata, features, truth and score arrays stay in ignored `data/final_lab_v1/` and `data/final_scoring_v1/`. Public evidence consists of reviewed plans, code and compact qualification/result summaries. Transfer exact images/weights/C1 arrays separately. These same-host repetitions do not establish independent environments or production-wide false-alarm/zero-day claims. Public slow/K/external sources remain under separate, still unopened acquisition gates.
