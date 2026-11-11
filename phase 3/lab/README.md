# Isolated benign development lab — prepared, not yet validated

Requires an operational Docker Linux engine. Runtime services use an **internal Docker network**, no published ports and no host networking. One Apache web container, one capture sidecar sharing its network namespace and one/three clients produce complete benign HTTP requests only. Images/build packages need downloads during preparation; runtime clients target only `web:80` and do not follow redirects or use internet targets. The runner cleans up only its uniquely named Compose project and retains session data.

From `phase 3/`:

```powershell
& '.venv/Scripts/python.exe' lab/run_benign_session.py --role T --condition ordinary --clients 1 --prepare-only
# Once Docker/WSL is operational, omit --prepare-only for a bounded collection.
```

The default session is a 30-second benign warm-up and 60-second measurement. Roles are preassigned T, C1, C2 or V; do not relabel sessions based on scores. Independent sessions reset all containers. Save raw PCAP, request outcomes, actual service address, image IDs, source hashes and capture diagnostics under ignored `data/lab_development/`. `collected_audit_pending` is not training-ready: check packet drops/truncation, successful request counts, timing, observed HTTP/TCP direction, history coverage and split/group independence first.

Ordinary, short bursts and concurrent complete-request profiles are **synthetic development** workloads. They do not implement controlled congestion, prove realistic benign diversity or replace the reserved final stress sessions. Apache defaults have not been changed to support slow attacks; there is no slow-attack generator here. Public/lab service-environment confounding remains to be audited. Development image tags are not a final freeze; capture resolved image provenance before final tests.

Prepared files can be structurally checked without running traffic. Actual network isolation and PCAP quality must be verified on the installed engine before counting any sessions as completed. See [prerequisite setup](../setup/README.md) and [the next gate](../plan/NEXT_STEPS.md).
