# Isolated benign development lab

Requires an operational Docker Linux engine. Runtime services use an **internal Docker network**, no published ports and no host networking. One Apache web container, one capture sidecar sharing its network namespace and one/three clients produce complete benign HTTP requests only. Images/build packages need downloads during preparation; runtime clients target only `web:80` and do not follow redirects or use internet targets. The runner cleans up only its uniquely named Compose project and retains session data.

The initial capture/scope preflight and selected **v3** component are complete: 12 sessions, 702 complete measurement windows and 28 distinct client jitter seeds. All selected sessions reconciled request logs to captured complete HTTP exchanges, with zero kernel-reported capture drops. Public/lab compatibility, broader benign diversity and final research evaluation remain open.

From `phase 3/`:

```powershell
& '.venv/Scripts/python.exe' lab/run_benign_session.py --role T --condition ordinary --clients 1 --prepare-only
# Omit --prepare-only only for a declared new bounded development session.
```

The default session is a 30-second benign warm-up and 60-second measurement. Roles are preassigned T, C1, C2 or V; PREFLIGHT is engineering-only. Do not relabel sessions based on scores. Sessions reset all containers and causal state. Raw PCAP, outcomes, image/source hashes and diagnostics stay under ignored `data/lab_development/`. `collected_audit_pending` is not training-ready by itself.

Use `results/development/benign_batch_v3.json` as the selection whitelist. It retains eight unchanged v2 sessions and four C1/C2 replacements selected only to remove additive jitter-seed overlap. The raw directory also contains preflights, an interrupted v1 and superseded v2 calibration sessions: **never glob all model_windows.csv files into one dataset**. v2 is a preserved pilot, not an additional independent 12-session dataset to pool with v3.

The current client derives its effective jitter seed as `master_seed + 1000 * client_index`. Unique master seeds alone do not guarantee distinct client seeds. Check the entire declared matrix with `require_disjoint_seeds` and verify actual client metadata before accepting new partitions.

Capture disables TSO/GSO/GRO only in the web container network namespace. It uses a 32 MiB packet buffer and Linux-side file writes, copying to the Windows host after flushing. The earlier Windows per-packet path lost 476 reported packets under concurrency; that capture is retained but excluded. `audit_benign_session.py` reconstructs separate TCP handshake incarnations, validates overlaps/gaps and compares complete controlled responses to logs. Source/destination groups, missingness and uncertain public labels remain separate issues.

The tool image is locally built, not a published Docker Hub release. `lab_software_manifest.json` records its actual content ID and the pinned public base/Apache digests. Preserve/export that local image separately if its exact generator environment is needed elsewhere; a new apt-based rebuild may get different packages and must record its own content ID.

`benign_development_manifest.json` specifies the 30 predictors and six excluded metadata columns. Measurement windows exclude warm-up and incomplete endpoint seconds. For current selected rows, T/C1/C2/V contain 175/175/176/176 windows. `collect_benign_batch.py` records historical v1/v2 collection; `collect_benign_repair.py` records the canonical v3 selection. Their existing plans/data are immutable evidence, not instructions to recreate identical packet hashes from a random seed. Transfer selected raw folders for exact replay; new acquisitions require a separately recorded plan and new hashes.

Ordinary, short bursts and concurrent complete-request profiles are **synthetic development** workloads. They do not implement controlled congestion, prove realistic benign diversity or replace the reserved final stress sessions. Apache defaults have not been changed to support slow attacks; there is no slow-attack generator here. Public/lab service-environment confounding remains to be audited. Development image tags are not a final freeze; capture resolved image provenance before final tests.

For future congestion/diversity profiles, do not reject legitimate timeouts or server errors merely because they fail the current complete-success workload check. Define the new profile's logging/quality criteria before collection and retain legitimate failures as benign; avoid selecting only easy successful stress traffic. Distinct seeds/fresh containers are provenance controls, not proof of IID samples or independent environments. See [the next gate](../plan/NEXT_STEPS.md).
