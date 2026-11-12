# Public split review — 12 November 2026

The first split-safe public development extraction is complete, but **this allocation/purge policy supplies no usable attack training/validation rows**. This is a data-readiness finding, not detector performance or proof that every excluded connection crossed a boundary.

## Allocation and extraction

`public_partitions_v1.json` was saved before feature creation, using previously inspected label-quality coverage rather than detector scores. Six benign destinations with at least 50 corroborated nonempty seconds were ranked by coverage and assigned T/C1/C2/T/V/V. Three sparse candidates remain excluded. Each destination belongs wholly to one role. These public IPs are archival grouping identifiers, not live targets.

The known target has T raw 18:56–19:04 and V raw 19:06–19:16 UTC on 7 July 2017. Both are **development blocks from one already-inspected episode**. Friday is not untouched final K. An independent final known-attack source remains unallocated. Entire slow-family groups/context and CSE-CIC-IDS2018 remain reserved.

Eight fresh feature/connection instances processed all allocated raw service packets with a one-second reorder budget, full-second boundaries, 20-second history and explicit guards. Labels and connection masks were applied afterward. All 9,997,874 frames and 8,839,309,056 bytes were read; the pinned SHA-256 matched. There are 36,240 raw feature windows, with no selected late drops or decode errors. The immutable lab feature core was not changed.

## Retained coverage

| Role | Public benign windows | Public attack windows | Selected v3 lab benign windows |
| --- | ---: | ---: | ---: |
| T | 1,329 | 0 | 175 |
| C1 | 494 | 0 | 175 |
| C2 | 246 | 0 | 176 |
| V | 155 | 0 | 176 |

There are 2,224 candidate public benign rows. Of the previous 2,243 corroborated candidate seconds, four belong to excluded sparse services and 15 fall outside eligible boundaries. Uncertain and idle/unlabelled seconds are not benign.

The attack blocks have 418 and 547 raw attack-present seconds. After boundary/history guards, 363 and 452 candidates remain, but every one falls under the conservative unknown/ambiguous-start influence mask. T and V contain 6,745 and 7,940 such packets. Each excludes its second and 50 following seconds (timeout plus history). Zero observed initiating-SYN fingerprints are shared across roles before or after quarantine; that alone does not establish independence of unknown-start traffic.

The frozen core tracks endpoint keys without TCP sequence numbers. Missing SYNs, post-close retransmissions and incomplete tuple reuse can yield unknown/ambiguous observations. The v1 mask is deliberately conservative and **does not prove every masked packet leaked**. Preserve this negative result and audit full TCP incarnations before proposing a more precise v2 rule.

## Calibration and interpretation limits

Public C1 has 348 labelled runs, longest 12 seconds. Public C2 has 137 runs, longest six seconds. Public benign V destinations have longest runs of three and five seconds. Full chronological features and eligibility tables remain local. Do not compress sparse rows into consecutive windows for 2-of-3/3-of-5 persistence or infer missing labels from silence. Lab v3 provides scheduled benign measurement but only one initial session per role/condition.

All public attack labels are on the local target; public benign labels are on external services, and development lab traffic is benign-only. Source, path and service are confounded with class. Descriptive feature summaries do not establish transfer or remove that confounding. The original target still has no fully corroborated benign-only seconds.

The initial replay startup assumed `.pcap` identified the container format and stopped before outputs. Magic-based PCAP/PCAPNG detection and full-stream hash fixtures corrected that error. A conservative fragment flag and its independent protocol-attribution evidence are preserved in `public_partitioned_v1.json` and `public_fragment_attribution_v1.json`. Use the combined registry's explicit quality fields without discarding the original flag.

## Exact next action

Trace unknown-start events against full Friday TCP-incarnation metadata: initiating sequence, SYN/SYN-ACK/ACK relationships, closes, retransmissions and boundary spans. Distinguish within-role post-close observations from actual/unresolved crossing connections. If evidence permits a more precise safe rule, declare **v2 before replay**; never overwrite v1 or relax a purge based on classifier outcomes. Otherwise acquire a separately allowlisted known-attack development source and allocate independent final K episodes. Do not fill the gap from reserved slow/external data.

Then broaden benign development with controlled congestion, diverse/long-lived legitimate requests and independent repetitions, retaining legitimate failures. Resolve or constrain source/path confounding and define gap-aware calibration before fitting/freezing matched models. No main packet-window detector or final attack test was run here.
