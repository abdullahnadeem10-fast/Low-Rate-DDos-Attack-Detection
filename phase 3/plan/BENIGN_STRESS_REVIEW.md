# Benign development stress review — 13 November 2026

The declared stress v5 batch passed: **36 fresh sessions and 2,160 additional benign measurement windows**. Three separately seeded preflights and every superseded attempt stay excluded. The current v5 registry contains **56 groups and 6,206 candidate labelled windows**. Main model fitting/freezing and final attack tests have not run.

| Role | Benign windows | Attack-present windows |
| --- | ---: | ---: |
| T | 2,044 | 1,076 |
| C1 | 1,209 | 0 |
| C2 | 962 | 0 |
| V | 871 | 44 |

| Condition | Sessions | Measurement windows | Complete requests | Failed requests retained | Kernel capture drops | Router leaf drops |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| congested_mixed | 12 | 720 | 515 | 412 | 0 | 1,401 |
| long_download | 12 | 720 | 47 | 39 | 0 | 3,410 |
| mixed_keepalive | 12 | 720 | 5,759 | 0 | 0 | 0 |

Request counts cover the entire legitimate session, including warm-up and inflight drain. Model inputs contain only the 60 declared measurement seconds per session. Configured network loss/queue drops are legitimate outcomes, distinct from kernel capture loss. Successes require matching server request IDs and validated body size/SHA-256 (or HEAD length); legitimate timeouts/aborts/errors remain benign. The endpoint-key connection tracker is approximate, so observed ages are not OS socket ground truth.

All **129 public-checkout offline engineering checks passed**. The count includes preserved-version regression guards, not independent traffic experiments. Capture, scope, router-MAC path, clock probes, immutable source/image checks and fresh whole-session replay were verified. The unchanged causal core advances known observed idle tails; public unknown/idle traffic is not relabelled benign. No role shares feature state.

Preserved engineering failures are documented in [the history evidence](../results/development/benign_stress_engineering_history.json): the two-bridge connectivity failure, HEAD/read1 state defect, flooded non-service bridge copies and interrupted clock interval. The version 3 plan was superseded without traffic. The v5 host guard inhibits idle sleep only during collection and rejects clock/observation gaps; it does not alter global power settings or override manual sleep.

The original selected lab v3 component remains byte-for-byte separate and unchanged: 12 sessions/702 windows. Together there are 48 selected lab sessions/2,862 lab windows, plus the existing public inputs. Use the exact v5 whitelist once; never glob all raw/model files or pool earlier registries.

Three repeats per role/profile use the same host, image, service and fixed-order matrix. They are fresh traffic sessions, not independent environments or proof of realistic production diversity. The independent attack V component remains only 44 SYN-labelled TCP/443 seconds in 40 short runs, without observed TLS functionality, measured denial or matched target benign controls. New benign stress does not solve class/service/path/source confounding. Study training readiness remains false.

Read the [coverage diagnostic](../results/development/development_coverage_review_v5.json) and [current readiness](../results/development/development_readiness_benign_stress_2026-11-13.json). Known-benign history counts are conservative diagnostics, not a chosen calibration policy. Specify missing-label handling and per-stratum sample support before selecting the whole threshold/persistence rule. Empirical development FPR at most 1% is not a guaranteed population or final-test FPR.

**Exact next action:** Write plan/model_development_v1.json: qualify the sparse V selection criterion, prespecify source/path sensitivity controls and missing-label/persistence calibration policy, then fit matched development branches/baselines without opening final sources.

Raw captures, complete request/server logs, environments and packet/model tables stay outside Git. The public package includes exact byte hashes, selected-group metadata, small summaries and source. [The runtime README](../lab/stress_v5/README.md) records topology, limits, provenance and continuation commands.
