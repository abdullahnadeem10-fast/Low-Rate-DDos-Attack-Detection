# Independent validation-source checkpoint — 12 November 2026

**Current exact registry:** `../results/development/study_development_manifest_v4.json`. It adds one preliminary independent SYN-labelled TCP/443 validation stream with **44 attack-present windows**. The main detector remains untrained, study training readiness is false, and no final attack test has run.

## Source ownership and provenance

Before payload acquisition, `cic2019_validation_v1.json` assigned the complete provided `03-11` source to development V and reserved the entire `01-12` source, including labels/context, as an **unopened, unqualified final known-attack candidate**. Reserved Slowloris/Slowhttptest groups/context and all CSE-CIC-IDS2018 data remain unused. Do not reassign the reserved day to enlarge validation.

The [publisher description](https://www.unb.ca/cic/datasets/ddos-2019.html) provides raw PCAP/flow-label context and a SYN scenario. Its [download portal](https://cicresearch.ca/CICDataset/CICDDoS2019/) returned a server-error form; no personal information was submitted. Acquisition used a declared public mirror, [bencorn/CICDDoS2019 at immutable revision](https://huggingface.co/datasets/bencorn/CICDDoS2019/tree/88b5d61acbcd41a4bb96221a6a64990a506804b8), without claiming publisher-authenticated file bytes.

Dataset citation: Sharafaldin et al., *Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy*, [CCST 2019](https://ieeexplore.ieee.org/abstract/document/8888419).

| Allowed development artifact | Verified bytes | SHA-256 |
| --- | ---: | --- |
| `PCAP-03-11.zip` | 2,000,948,331 | `cdc8935296cab7a2354d4fd32939f7d5e6c592371e5fb89d6a3094cc05dc38c5` |
| `CSV-03-11.zip` | 918,815,761 | `a81d8ce59a819d13e6bfea4e4812d6d144d0572b6d2c42d8e0c0a8cf1c26c263` |
| Only opened label member, `03-11/Syn.csv` | 1,877,372,065 | `603648e7c56e9232b6d647470dc01b6451502c594a4ebf235b45103edb5e545a` |

The uncompressed Syn member also matches the separately pinned [baalajimaestro mirror](https://huggingface.co/datasets/baalajimaestro/CICDDoS2019/tree/1b3677ee26ba69caa5a9c1ba91cc75cec7ad976e). This corroborates byte identity between mirrors, not semantic label correctness. Other CSV payloads were not opened.

## Inventory, clock and labels

The packet ZIP contains 146 extensionless rotations totalling 29,069,824,713 uncompressed bytes. All **61,407,884 frames** were streamed and each member was hashed/CRC-checked; the full archive was not expanded to disk. An initial extension-only discovery guard stopped before outputs; exact rotation-name support and fixtures corrected it. Rotations are one recorded source, not 146 independent sessions.

Candidate TCP input had no observed decoding, truncation or fragment issues. Plainly unrelated IPv4 payloads were not fully decoded, so this is not a blanket claim of loss-free packet capture. Every member was timestamp-monotonic; natural rotation order had no overlap and a maximum 0.4511 ms inter-rotation gap. This proves the selected chronological cache cannot suffer a late-packet drop under the fixed one-second reorder budget. A regression fixture verifies byte-identical cache and direct bounded-raw feature output under that condition.

The Syn CSV contains **4,284,751 Syn-labelled and 35,790 BENIGN rows**. Only 30 Syn rows touch the declared web server's port 80 and 70 touch port 443. There are 64 candidate canonical keys; the alternate published server address has no candidate rows. Most SYN traffic is at other ports and was not silently pooled into a web-service stream.

Empirical interval/directional-count joining found **+10,800 seconds (+3 hours)**: 55 nonempty canonical groups matched exactly, while every other tested hour offset matched zero groups. This is development metadata alignment, not a detector score, a presumed timezone, or proof of exact attack onset. Actual capture/CSV dates are in 2018 despite the dataset's publication name.

Metadata ranking, declared before feature creation, selected `192.168.50.4:443`: 278 raw TCP packets, 132 corroborated attack-labelled packets and 44 attack-present service-seconds. Port 80 has only nine such seconds and was not substituted later based on classifier outcomes. Port 80 also has HTTP prefixes; **no TLS payload prefix was observed at port 443**. TCP/443 and SYN labels do not prove a functioning HTTPS application or service-denial impact.

## Fresh features and current registry

`cic2019_features_v1.json` preceded fresh feature creation. The unchanged core processed all selected raw service packets, with fresh state, complete capture seconds, history warm-up and boundary guards. Labels followed extraction. The full stream contains 29,919 windows: **44 attack-present, 32 uncertain and 29,843 unlabelled**. No idle/uncertain second was labelled benign. No BENIGN-labelled target seconds were available from this member.

All 44 positive windows survive the declared guards. They occupy **40 labelled runs, longest two seconds**; do not compress their gaps into consecutive persistence evidence. Full features and eligibility timelines remain in ignored data. Closed-window features are causal in event time; live inference throughput/delay was not measured.

| Role | Candidate benign rows | Attack-present rows |
| --- | ---: | ---: |
| T | 1,504 | 1,076 |
| C1 | 669 | 0 |
| C2 | 422 | 0 |
| V | 331 | 44 |

The v4 whitelist has 20 groups and **4,046 candidate labelled rows**. It retains every v3 group once, plus the one new V recording. Neither windows nor rotations are independent attack replications. The V negative rows still come from the earlier public/lab groups, so within-source FPR and class/service/path/source confounding remain unresolved. All **81 offline engineering checks pass**; these are not classifier efficacy tests.

## Next action and limits

Declare a new benign development matrix with controlled congestion, complete legitimate long-lived/varied workloads and independent repetitions across T/C1/C2/V. Preserve unique seed sets, fresh sessions, pinned software and capture quality. Retain failed legitimate requests as benign; the original complete-200-only audit is not appropriate for difficult stress traffic. Do not change frozen lab-v3 sources or use reserved slow-attack mechanisms for development.

Also review/expand validation representativeness before claiming generalization: this sparse, transport-level slice does not establish whole-host DDoS impact, HTTPS availability, low-rate attack efficacy, or broad known-family validation. Public C2 remains sparse (maximum six-second labelled run); use full timelines and an explicit missing-label policy. Then fit matched branches/baselines, calibrate and freeze before touching reserved final payloads. Keep the `01-12` candidate unopened and unqualified until the appropriate frozen final-stage audit.
