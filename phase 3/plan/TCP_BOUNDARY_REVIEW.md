# TCP boundary audit and whole-stream T — 12 November 2026

**Current registry:** `../results/development/study_development_manifest_v3.json`. It supplies 1,076 corroborated attack-present training windows by assigning the complete Friday target stream to T. Attack validation V and independent final K still require separate permitted captures. No main model has been fitted, selected or frozen.

## What the audit established

The new private index contains all 1,282,861 target TCP packets, including timestamps, original frame indices, direction, lengths, flags, sequence/ACK values and segment hashes. All 9,997,874 frames and 8,839,309,056 input bytes passed the pinned SHA-256. There were no service-IP TCP fragments or decode errors. The largest selected adjacent timestamp regression was 13.83 microseconds, below the fixed one-second reorder budget. Grouping identifiers and sequence/hash fields never become predictors.

Index replay reproduced the v1 T/V feature CSV SHA-256 values and exactly 6,745/7,940 unknown/ambiguous-start packets. Full-capture attribution identified 96,010 initiating-SYN identities across 45,532 endpoint keys. Of 1,282,861 packets, 1,282,307 had supported attribution and 554 remained unresolved; 546 canonical keys had some unresolved evidence. No conflicting server-handshake identities or supported identity shared by both old blocks were found. These are observational TCP consistency results, not OS socket or exact packet ground truth.

| v1 unknown-packet attribution | T | V |
| --- | ---: | ---: |
| Supported identity wholly inside its raw block; fully attributed key | 6,504 | 6,754 |
| Assigned identity, but canonical key has unresolved observations | 161 | 277 |
| Packet unresolved | 3 | 9 |
| Assigned identity crossing a raw edge or otherwise unsafe | 77 | 900 |

Only five T and seven V attributed unknown packets occurred after an observed close. The original issue is therefore not explained mainly by post-close retransmissions. Unknown sets include 497/526 initiating SYNs and the same numbers of matching SYN-ACKs. The frozen endpoint tracker can retain unknown/ambiguous state around tuple reuse; that state is not proof of connection overlap between partitions.

## Preserve the failed v2 refinement

The v2 rule was declared before selection. It accepted only fully attributed identities inside their block, quarantined every key with any unresolved full-capture evidence, and propagated unsafe influence through the actual frozen-core state until close/reset/expiry. A supported packet could not silently clear contaminated state. Every direct or propagated unsafe event masked its second and 50 following seconds.

This left **zero attack windows again**. T had 16,372 direct unsafe packets; V had 20,937. Their influence masks covered every eligible attack-labelled window. Feature CSV bytes remained identical to v1. Do not relax these masks further to obtain a desired row count. `public_partitions_v2.json` and its report preserve the negative result.

## Current v3 allocation

All observed Friday target-service groups/context now belong to **T only**, from the first complete capture second to the last complete capture second. Old T/V target blocks are superseded, never pooled or promoted to final tests. A raw-packet overlap audit found zero target packets shared with another assigned destination role. Six public benign destination groups and the 12 canonical v3 lab sessions keep their previous roles.

The v3 plan preceded fresh whole-stream feature creation. The frozen core processed every target packet regardless of labels. Unknown observed connection ages are retained because the complete observed destination stream has one owner. This avoids splitting connections between roles; it does not invent complete handshakes or upgrade the approximate tracker to OS socket counts. Corroborated labels were applied afterward. Of 28,981 full target seconds, 1,076 are attack-present, 20 uncertain and 27,885 unlabelled. Idle/unlabelled time remains unknown.

| Role | Candidate benign windows, public + selected lab | Attack-present windows |
| --- | ---: | ---: |
| T | 1,504 | 1,076 |
| C1 | 669 | 0 |
| C2 | 422 | 0 |
| V | 331 | 0 |

The authoritative registry has 19 groups: six public benign destinations, one whole public attack-training stream and 12 lab sessions. There are 4,002 candidate labelled rows, including 2,926 benign. This is **one attack training episode**, not 1,076 independent experiments. All 65 offline checks pass. Source, plan, input and table hashes are recorded. The index's elapsed counter jumped between checkpoints; its recorded 47,062.551 seconds is execution bookkeeping and is not a throughput/runtime benchmark.

## Exact next action and limitations

Find and audit a **different permitted known TCP-denial capture for attack V**. Verify packet/label provenance, compatible service/features, and independent capture/session groups before feature creation. Allocate independent final K separately. Do not borrow the reserved slow-family groups/context or any CSE-CIC-IDS2018 data; do not reuse inspected Friday as an untouched final set.

Then broaden legitimate development with controlled congestion, varied/long-lived requests and independent repetitions, retaining legitimate failures. Constrain the class/service/path/source confounding: public attack labels are on the local target, benign public labels on external destinations, and lab development is benign-only. Sparse public C2 still has a maximum six-second labelled run; persistence must use complete timelines and an explicit missing-label policy. These gates remain before matched model fitting, calibration and freeze. No final attack or transfer test ran.
