# Complete frozen lab results — v2

All 60 declared same-host lab trials are qualified and scored: 20 benign sessions and 40 controlled campaigns, 117 configurations per session (7,020 case/session evaluations). All eight campaign cells and four benign conditions have five repetitions. This completes the lab catalog; public-source transfer and separate feature/inference/live-latency measurements remain pending.

These are descriptive measurements on this host and acquisition design. Windows and algorithm seeds are not independent recordings or environments. No thresholds, models, seeds or trial order were changed from final outcomes. Campaign exposure does not prove denial or resource exhaustion. Detector delays are offline window-end plus one-second reorder proxies. Failed service probes include HTTP/socket/read errors and skips, not only elapsed-deadline overruns; latency quantiles condition on success.

An interrupted setup was archived before schedule release; seven agents failed at the schedule gate with no research logs or HTTP records. A separately sealed continuation retained every prior result and ran the original remaining entries without changing settings or seeds. The preserved setup is engineering history, not an additional independent trial. The host/engine restart is disclosed.

## Prespecified primary seed and matched baselines

| Method (seed 7) | TP / eligible positive | FP / eligible benign | Recall | FPR | Eligible episodes hit | Miss-inclusive restricted delay |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rate | 81/9560 | 642/3600 | 0.85% | 17.83% | 9/40 | 150.12s |
| LR | 912/9560 | 0/3600 | 9.54% | 0.00% | 20/40 | 97.22s |
| RF | 6962/9560 | 0/3600 | 72.82% | 0.00% | 30/40 | 46.45s |
| IF | 4773/9560 | 1190/3600 | 49.93% | 33.06% | 40/40 | 3.32s |
| HGB | 3750/9560 | 901/3600 | 39.23% | 25.03% | 30/40 | 50.15s |
| AE | 9509/9560 | 1581/3600 | 99.47% | 43.92% | 40/40 | 4.02s |
| hybrid | 7476/9560 | 2129/3600 | 78.20% | 59.14% | 40/40 | 10.49s |

Miss-inclusive restricted delays retain fully observed misses at the frozen 180-second limit; they are not detected-only medians or measured live latency. Preserve all unscorable/censored episodes and known-label exclusions in the source evidence. An episode hit does not erase missed positive windows, preexisting alarms or false-positive occupancy.

## Primary hybrid and AE by declared stratum

| Condition / profile (five trials each) | Hybrid TP or FP / support | AE TP or FP / support |
| --- | ---: | ---: |
| incomplete_header, 1 source(s), 10 connections/source, 20s | TP 176/1195 | TP 1184/1195 |
| incomplete_header, 1 source(s), 60 connections/source, 5s | TP 1190/1195 | TP 1190/1195 |
| incomplete_header, 3 source(s), 10 connections/source, 20s | TP 1190/1195 | TP 1190/1195 |
| incomplete_header, 3 source(s), 60 connections/source, 5s | TP 1190/1195 | TP 1190/1195 |
| slow_request_body, 1 source(s), 10 connections/source, 20s | TP 160/1195 | TP 1185/1195 |
| slow_request_body, 1 source(s), 60 connections/source, 5s | TP 1190/1195 | TP 1190/1195 |
| slow_request_body, 3 source(s), 10 connections/source, 20s | TP 1190/1195 | TP 1190/1195 |
| slow_request_body, 3 source(s), 60 connections/source, 5s | TP 1190/1195 | TP 1190/1195 |
| bursts | FP 758/900 | FP 772/900 |
| flash | FP 900/900 | FP 0/900 |
| long_lived_or_congested | FP 471/900 | FP 809/900 |
| ordinary | FP 0/900 | FP 0/900 |

## Evidence and interpretation

All 117 configurations, controls, ablations and prescribed seeds remain in `../results/final/final_lab_case_totals_v2.csv` and `final_lab_case_strata_v2.csv`; no best-performing variant was selected. Totals are sums of eligible counts; pooled rates reflect the declared mixture. False-alert starts/hour remain distinct from false-positive window rates. Every stratum total reconciles with the all-session total. See `final_lab_results_v2.json` for source hashes and the exact frozen paired-parent uncertainty output.

Any available paired-parent intervals resample observed recordings within declared strata and average algorithm seeds inside sessions. They describe conditional same-host session variability; they do not establish independent-domain transfer, a population FPR guarantee or hybrid superiority. Preserve negative findings, healthy-service/ineffective campaigns and any missing/censored outcomes.

Complete public Wednesday slow/context, supplied CIC2019 01-12 and CSE-CIC-IDS2018 remain unopened/unqualified. Friday stays development T and 03-11 V. Final lab raw/context/warmup remains excluded from development/calibration. Later model redesign requires separate development and new independent final evidence.
