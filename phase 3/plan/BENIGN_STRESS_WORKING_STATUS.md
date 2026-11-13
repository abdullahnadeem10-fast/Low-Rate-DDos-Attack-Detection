# Benign stress work completed — 13 November 2026

All 36 declared v5 development sessions passed and were integrated into the v5 whitelist. All three successful preflights and superseded attempts remain excluded. No project collection/replay job is active. Continue from `BENIGN_STRESS_REVIEW.md`, `NEXT_STEPS.md` and current readiness. The notes below are the preserved mid-run audit trail, not current instructions to start another collection.

## Historical working notes

# Benign stress work in progress — 13 November 2026

Current accepted model-input registry remains `../results/development/study_development_manifest_v4.json` (20 groups, 4,046 rows). No main model trained/frozen; no final tests. Never pool preflights or superseded profiles.

A broader development matrix is declared in `benign_stress_v5.json`: 36 sessions, T/C1/C2/V × mixed keep-alive / bandwidth-limited long downloads / delayed-lossy mixed × three fresh repetitions; three clients, 30-second warm-up and 60-second measurement each. All exact client and impairment seeds are disjoint from the original selected lab v3 and all superseded stress plans. The separate `lab/stress_v5/` uses one internal Docker bridge with forced /32 routes through a private router, disabled ICMP redirects, no NAT/published ports/host network or host NIC changes. Router peer MACs and exact web MAC capture filtering are audited. Capture and configured network drops are separate.

All three excluded v5 preflights passed capture/routing/clock and 60-window causal replay checks. They remain excluded. `src/collect_benign_stress_development.py` is now collecting the declared 36 sessions sequentially, then auditing/replaying them and building the v5 registry only if every declared entry passes. Check `../results/development/benign_stress_batch_v5.json` and `../data/benign_stress_collection_v5.log`; inspect actual Docker state before starting anything. Do not launch another collection on the fixed subnet. Accepted model inputs remain v4 until integration succeeds.

Preserved engineering history:

- stress v1: two internal bridges and router did not deliver traffic; all 108 client attempts failed, zero service frames. Rejected and cleaned up. Do not treat this as functioning congestion.
- stress v2: one-bridge routing worked. Mixed preflight exposed the CPython HEAD/read1 keep-alive state bug (362 completed / 69 local failures); these failures are engineering defects, not legitimate stress outcomes. Long preflight audit caught two router-forwarded packets flooded to the promiscuous service interface after client shutdown. Rejected; no congestion preflight collected. The old audit's quality-pass flag on mixed does not approve generator correctness.
- stress v3: HEAD handling corrected and progress logging bounded; declared but no traffic collected. Superseded before traffic to fix the capture scope.
- stress v4: complete HEAD responses use read(), regression-tested with HEAD followed by GET on one HTTPConnection. Capture explicitly matches the actual web MAC and disables promiscuity. Root/child qdisc drops are not double-counted. Preflights and development remain separate.

The preflight gate is saved in `../results/development/benign_stress_development_gate_v5.json`. Completed preflights were replayed with `src/replay_stress_session_v5.py` to confirm complete warmed 60-second intervals and observed idle-tail handling. Then collect the prespecified 36 sessions with `src/run_benign_stress_v5.py` (same plan, no --preflight). It resumes only successful entries and refuses silent replacement of a failed attempt. Review any failure before a separately declared replacement. Finally run `src/integrate_benign_stress.py` to audit/replay and create the v5 registry; that file does not yet exist. Sparse known-V representativeness and source/service/path confounding still require review before fitting.

Preserve the frozen causal core, old replay, selected original lab sources and every prior negative finding. Keep all Slowloris/Slowhttptest context, every lab attack, final benign stress, CSE-CIC-IDS2018 and CIC2019 01-12 unopened. Packet arrays, raw captures, environments and credentials remain private.

The v4 mixed preflight passed (481 complete, zero failed), but its long preflight was interrupted: capture stop timestamp preceded the measurement end, while clients later logged a large UTC jump. All v4 attempts remain excluded; congestion was not reached. v5 preserves identical embedded image sources/content ID and adds process-scoped Windows idle-sleep inhibition plus 15-second host/container time probes, a five-second host-loop pause guard and audit rejection of observation gaps. No global power settings/display/lid behavior is changed. v5 uses fresh seeds. No development traffic has run yet.
