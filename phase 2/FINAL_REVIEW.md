# Final Phase 2 review

This is the public copy of the review log. Its archive and export references describe the local course workspace. The public report was rebuilt without student roll numbers.

Reviewed: 17 October 2026. Status: **review complete; corrected paper compiled and visually checked**.

This is an assignment-compliance, source-consistency and methodological review. It does not independently reproduce published experiments or guarantee a grading outcome. The project remains a proposal, with no completed model/data experiments.

## Assignment and scope

The original three-page Phase 2 assignment and accepted Phase 1 report were reread.

| Requirement | Final evidence |
| --- | --- |
| 8–10 additional original research articles, 2025–2026 | Eight distinct additions A1–A8, references 4–11; Phase 1 papers are separate |
| Eligible Q1–Q2 venues | Documented SJR basis; explicitly distinguished from JCR |
| Nine comparison fields | Tables I–II contain all nine requested columns for every addition |
| At least three potential gaps supported by three studies | Four gaps in Table III, triangulated against A1, A2 and A5 |
| Refined and justified central gap | Section III acknowledges existing hybrids/holdouts and defines the remaining operating question |
| Twelve methodology steps | Section IV, Steps 1–12, all retained |
| Research methodology diagram | Figure 1 and the separate diagram exports |
| Consistency with accepted project | Detection and evaluation only; no mitigation implementation |
| No invented experiments | Abstract, hypotheses, settings and final output remain explicitly proposed |

The assignment does not prescribe IEEE formatting, a page limit or a specific ranking system. The IEEE format was selected at the user's request. CMC's eligibility is based on **SJR Q2**; its JCR ranking is Q3. If the instructor separately requires JCR rather than SJR, that paper would need replacement. No such JCR-only requirement appears in the supplied brief. See the [institutional ranking record](https://www.iit.comillas.edu/publicacion/info_revista/en/655/Computer%2C_Materials_%26_Continua).

## Literature verification

Article identities, years, venues and the principal reported numbers were checked against accessible publisher records/full-text sections, author-deposited material or institutional publication records. Search-indexed publisher text was used where direct retrieval failed. Numbers remain author-reported and should not be interpreted as independently verified experimental results or compared as a common leaderboard.

| Study | Claims checked | Primary or author-linked evidence |
| --- | --- | --- |
| A1 F-OSFA | IEEE Access 13, 75153–75166, 2025; 96.77%/95.98% zero-day accuracy; CNN/decision tree and benign-trained contractive AE; abstract/method terminology; resource-analyser future work | [IEEE record](https://ieeexplore.ieee.org/abstract/document/10949135), [author institution's published PDF](https://cris.fbk.eu/retrieve/828c9e00-6659-437c-954a-cb78518cd039/F-OSFA_A_Fog_Level_Generalizable_Solution_for_Zero-Day_DDOS_Attacks_Detection.pdf) |
| A2 Hybrid dual-head IDS | Results in Engineering 31, 111498, 2026; three IoT datasets; adaptive WGAN-GP augmentation; existing true holdout, ablation and five-seed evaluation; >99.5% accuracy/F1 and about 0.5 MB | [author institutional publication record and abstract](https://research.universityofgalway.ie/en/publications/hybrid-dual-head-ids-a-lightweight-and-explainable-deep-learning-/), [author-posted article text](https://www.researchgate.net/publication/406914103_Hybrid_Dual-Head_IDS_A_Lightweight_and_Explainable_Deep_Learning_DDOSDOS_Framework_for_Zero-Day_and_Imbalanced_Attack_Detection_in_IoT_Networks) |
| A3 CA-CAE | CMC 85(2), 2893–2912, 2025; consecutive asymmetric CAEs; differencing/standardization/windows; 190,817 normal and 78 anomalous instances; F1 0.515 to 0.934 | [publisher full text](https://www.techscience.com/cmc/v85n2/63815/html) |
| A4 Lightweight classifiers | Scientific Reports 15, 24961, 2025; NSL-KDD; 18 ExtraTrees-selected features; 80:20 split and tenfold validation; RF 99.88% accuracy/99.87% F1 | [publisher article](https://www.nature.com/articles/s41598-025-10092-0), [full-text archive](https://pmc.ncbi.nlm.nih.gov/articles/PMC12246053/) |
| A5 FSL-IDS | Scientific Reports 16, 21298, 2026; reported IoTID20-based stealth labels and training-only augmentation; cloud ROC-AUC 0.992/F1 0.965; provenance limitation retained | [publisher article](https://www.nature.com/articles/s41598-026-46531-9) |
| A6 LNN | Scientific Reports 16, 26053, 2026; three independently fitted datasets; chronological split before ten-flow windows; maximum accuracy 99.96% and FPR 0.07% | [publisher article](https://www.nature.com/articles/s41598-026-67535-5) |
| A7 Compact classification | Scientific Reports 16, 16895, 2026; CIC-DDoS2019 flooding subset, NearMiss, 70:30 split; Table 23 RF 99.32% accuracy/99.40% F1; balancing-before-split workflow warrants audit | [publisher article](https://www.nature.com/articles/s41598-026-48535-x) |
| A8 GCTNetwork | Scientific Reports 16, 2305, 2026; online 29 December 2025, version of record 19 January 2026; SDN data; 94.08% accuracy/93.27% F1; ten-versus-100-epoch discrepancy | [publisher article](https://www.nature.com/articles/s41598-025-32102-x) |

The original three Phase 1 bibliographic records were also checked: [Bocu and Iavich's institutional publication list](https://cu.edu.ge/en/cybersecurity-members/maksim-iavich-bio/publications-maksim-iavich), [Rullo et al.'s publisher record](https://www.sciencedirect.com/science/article/pii/S1568494626012445), and [Nakıp's publisher record](https://www.sciencedirect.com/science/article/abs/pii/S0950705126007215). Detailed Phase 1 experimental summaries are not reprinted as new Phase 2 findings.

Dataset roles were checked against [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) and [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html). Public slow DoS evidence is not presented as sufficient evidence of distributed low-rate DDoS; the proposed multi-client lab addresses that distinction.

Venue evidence was rechecked against the [2024 SJR IEEE Access listing](https://www.scimagojr.com/journalrank.php?country=&min=3&min_type=cd&ord=desc&order=titem&year=2024), [SCImago's 2024 Scientific Reports entry in its journal contribution table](https://www.scimagojr.com/diamond/journalsjr.php?sid=21100832688), and the institutional records for [Results in Engineering](https://www.iit.comillas.edu/publicacion/info_revista/en/675/Results_in_Engineering) and [CMC](https://www.iit.comillas.edu/publicacion/info_revista/en/655/Computer%2C_Materials_%26_Continua). The Scientific Reports bibliography URL now explicitly fixes `year=2024`; these are historical ranking claims, not claims about an unspecified latest edition.

The CA-CAE anomaly-percentage discrepancy was recalculated: `100 * 78 / (190817 + 78) = 0.04086%`, about 0.041%, rather than the article's printed 0.0004%. Its F1 numbers were retained as author-reported results. Other article limitations are distinguished from proven failures.

## Corrections and clarifications made

1. Qualified F-OSFA's resource analyser as proposed: its own future-work section still calls for a suitable dataset to implement it. The headline results are not attributed to validation of all three proposed components.
2. Removed unnecessary shared-representation wording from A2's comparison cells, retaining the directly supported dual heads, hybrid loss and SHAP.
3. Required benign-only lab development pilots. All slow-attack family examples and corresponding lab attack runs remain final-only, including their associated session context.
4. Reserved the complete CSE-CIC-IDS2018 source, including benign records, for external transfer. Lab sessions from an environment seen during calibration are explicitly stress/distribution tests, not unseen-environment transfer.
5. Made label matching and causal state handling explicit: schedule time alone is insufficient; audit five-tuples, time zones, direction and NAT, and reset state between sessions.
6. Restricted AE imputation and other fitted transforms to benign training data. Disabled HGB's internal random early-stopping split in favour of grouped development selection.
7. Required the complete decision rule's empirical development FPR to satisfy the 1% ceiling overall and within ordinary/stressed benign strata. This remains a development constraint, not a guaranteed final-test result.
8. Made the lab sample plan concrete: two mechanisms × two source counts × two concurrency/timing profiles × five independent session replicates = 40 planned attack episodes; at least five final sessions for each of four benign conditions. These are proposed sample targets, not collected data.
9. Excluded pre-onset active alarms from immediate attack-detection credit; specified new alert episodes, the 180-second/episode-end horizon, censoring and undefined metrics. Used packet/byte rate as the baseline so it needs no extra request-log telemetry.
10. Specified AP as the precision–recall summary and paired stratified session resampling after seed averaging, preventing model seeds from being counted as independent traffic replications.
11. Enforced exact, unique bibliography identifiers and resolved citation checks in the generator and PDF verifier. Restored natural bibliography flow after the content-length changes.

## Final artifact checks

- Nine pages; all four deliverables, twelve methodology steps and eighteen unique bibliography entries.
- Eight additional articles appear in both the critical review and the required comparison tables.
- All in-text citation keys resolve; no duplicate bibliography destinations, `[?]` placeholders or overfull text boxes.
- All nine pages rendered and visually inspected; changed pages reinspected after the final wording edits.
- The methodology diagram and decision equations are consistent with the body. Separate diagram exports remain a higher-level version of the same workflow.
- PDF fonts embedded; source and packaged `.tex` identical; both user-facing PDF aliases and the `output/phase2` PDF copy synchronized.
- Earlier artifacts archived under `archive/before_final_review_2026-10-17/`. Project context and editable source package updated.

Remaining limits are explicit in the paper: venue eligibility assumes SJR, public-data provenance/counts and feature compatibility need auditing during implementation, and proposed recall/FPR/delay outcomes have not been measured. The reviewed draft contains no known unresolved factual discrepancy from the accessible evidence; that is not a claim that every published experiment has been reproduced.
