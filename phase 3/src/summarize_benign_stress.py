"""Publish small engineering evidence without raw captures or fitted models."""
from collections import Counter,defaultdict
import csv
import json
from pathlib import Path
from audit_stress_session_v5 import read,require,sha

ROOT=Path(__file__).resolve().parents[1]


def main():
    out=ROOT/'results/development'; component_path=out/'benign_stress_component_v5.json'
    registry_path=out/'study_development_manifest_v5.json'; component=read(component_path); registry=read(registry_path)
    require(component['selected_sessions']==36 and component['measurement_rows']==2160,'Complete accepted batch required')
    require(len(registry['groups'])==56 and sum(sum(c.values()) for c in registry['windows_by_role_and_y'].values())==6206,'Unexpected complete-study candidate totals')
    summaries=defaultdict(Counter); evidence={}; maximum_ages=defaultdict(float); maximum_seconds=defaultdict(float)
    for group in component['groups']:
        audit=group['audit']; name=group['condition']; folder=ROOT/'data/lab_stress_v5'/group['id']
        item=summaries[name]; item['sessions']+=1; item['measurement_windows']+=group['expected_rows']
        item['complete_requests']+=audit['client_outcomes'].get('complete',0); item['failed_requests']+=audit['client_outcomes'].get('failed',0)
        item['frames']+=audit['counts']['frames']; item['kernel_capture_drops']+=audit['kernel_capture_drops']; item['router_qdisc_drops']+=audit['router_qdisc_drops']
        maximum_seconds[name]=max(maximum_seconds[name],audit['max_request_seconds'])
        table=ROOT/group['table']; require(sha(table)==group['sha256'],'Model table bytes changed')
        with table.open(encoding='utf-8',newline='') as f:
            maximum_ages[name]=max(maximum_ages[name],max(float(r['active_age_max']) for r in csv.DictReader(f)))
        paths=[folder/'session.json',folder/'compose.json',folder/'stress.conf',folder/'control/schedule.json',folder/'control/payloads.json',
               folder/'router/ready.json',folder/'router/final.json',folder/'capture/ready.json',folder/'capture/capture.json',
               folder/'capture/tcpdump.log',folder/'capture/traffic.pcap',folder/'server/access.tsv',
               folder/'causal_observed_v5/features.csv',folder/'causal_observed_v5/replay.json',table]
        for i in (1,2,3): paths.extend(folder/f'client{i}'/n for n in ('ready.json','requests.jsonl','client.json'))
        evidence[group['id']]={p.relative_to(ROOT).as_posix():sha(p) for p in paths}
    records=[]
    for name,counts in sorted(summaries.items()):
        records.append(dict(condition=name,**dict(counts),requests_whole_session=counts['complete_requests']+counts['failed_requests'],
                            max_request_seconds=round(maximum_seconds[name],6),max_observed_active_age_seconds=round(maximum_ages[name],6)))
    table=out/'benign_stress_summary_v5.csv'
    with table.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records)
    hashes=out/'benign_stress_raw_evidence_hashes_v5.json'
    hashes.write_text(json.dumps(dict(scope='Hashes only; raw evidence stays private/ignored.',groups=evidence),indent=2)+'\n',encoding='utf-8',newline='\n')
    validation=out/'validation_summary_benign_stress_public_2026-11-13.json'; tests=read(validation)
    require(tests['successful'],'Public engineering checks failed')
    readiness=dict(date='2026-11-13',registry=registry_path.relative_to(ROOT).as_posix(),registry_sha256=sha(registry_path),
                   component_sha256=sha(component_path),summary_csv_sha256=sha(table),raw_evidence_hashes_sha256=sha(hashes),
                   validation_summary_sha256=sha(validation),source_code_sha256=sha(Path(__file__)),
                   selected_stress_sessions=36,additional_benign_measurement_windows=2160,
                   total_candidate_labelled_windows=sum(sum(c.values()) for c in registry['windows_by_role_and_y'].values()),
                   total_groups=len(registry['groups']),windows_by_role_and_y=registry['windows_by_role_and_y'],conditions=records,
                   excluded_successful_preflights=3,all_superseded_stress_sessions_excluded=True,
                   study_training_ready=False,main_packet_window_model_trained=False,final_attack_tests_run=0,
                   sparse_attack_validation_and_source_path_confounding_resolved=False,
                   reserved_slow_family_entire_external_source_and_cic2019_final_candidate_unused=True,
                   request_count_scope='All warm-up/measurement/drain request outcomes; model windows are measurement only.',
                   scope='Controlled legitimate engineering/development coverage, not independent environments, population FPR, denial impact or classifier efficacy.',
                   exact_next_action='Write plan/model_development_v1.json: qualify the sparse V selection criterion, prespecify source/path sensitivity controls and missing-label/persistence calibration policy, then fit matched development branches/baselines without opening final sources.')
    (out/'development_readiness_benign_stress_2026-11-13.json').write_text(json.dumps(readiness,indent=2)+'\n',encoding='utf-8',newline='\n')
    lines=['# Benign development stress review — 13 November 2026','',
           'The declared stress v5 batch passed: **36 fresh sessions and 2,160 additional benign measurement windows**. Three separately seeded preflights and every superseded attempt stay excluded. The current v5 registry contains **56 groups and 6,206 candidate labelled windows**. Main model fitting/freezing and final attack tests have not run.','',
           '| Role | Benign windows | Attack-present windows |','| --- | ---: | ---: |']
    for role,c in registry['windows_by_role_and_y'].items(): lines.append(f'| {role} | {c["0"]:,} | {c["1"]:,} |')
    lines += ['', '| Condition | Sessions | Measurement windows | Complete requests | Failed requests retained | Kernel capture drops | Router leaf drops |',
              '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for r in records: lines.append(f'| {r["condition"]} | {r["sessions"]} | {r["measurement_windows"]} | {r["complete_requests"]:,} | {r["failed_requests"]:,} | {r["kernel_capture_drops"]} | {r["router_qdisc_drops"]:,} |')
    lines += ['', 'Request counts cover the entire legitimate session, including warm-up and inflight drain. Model inputs contain only the 60 declared measurement seconds per session. Configured network loss/queue drops are legitimate outcomes, distinct from kernel capture loss. Successes require matching server request IDs and validated body size/SHA-256 (or HEAD length); legitimate timeouts/aborts/errors remain benign. The endpoint-key connection tracker is approximate, so observed ages are not OS socket ground truth.','',
              f'All **{tests["tests_run"]} public-checkout offline engineering checks passed**. The count includes preserved-version regression guards, not independent traffic experiments. Capture, scope, router-MAC path, clock probes, immutable source/image checks and fresh whole-session replay were verified. The unchanged causal core advances known observed idle tails; public unknown/idle traffic is not relabelled benign. No role shares feature state.','',
              'Preserved engineering failures are documented in [the history evidence](../results/development/benign_stress_engineering_history.json): the two-bridge connectivity failure, HEAD/read1 state defect, flooded non-service bridge copies and interrupted clock interval. The version 3 plan was superseded without traffic. The v5 host guard inhibits idle sleep only during collection and rejects clock/observation gaps; it does not alter global power settings or override manual sleep.','',
              'The original selected lab v3 component remains byte-for-byte separate and unchanged: 12 sessions/702 windows. Together there are 48 selected lab sessions/2,862 lab windows, plus the existing public inputs. Use the exact v5 whitelist once; never glob all raw/model files or pool earlier registries.','',
              'Three repeats per role/profile use the same host, image, service and fixed-order matrix. They are fresh traffic sessions, not independent environments or proof of realistic production diversity. The independent attack V component remains only 44 SYN-labelled TCP/443 seconds in 40 short runs, without observed TLS functionality, measured denial or matched target benign controls. New benign stress does not solve class/service/path/source confounding. Study training readiness remains false.','',
              'Read the [coverage diagnostic](../results/development/development_coverage_review_v5.json) and [current readiness](../results/development/development_readiness_benign_stress_2026-11-13.json). Known-benign history counts are conservative diagnostics, not a chosen calibration policy. Specify missing-label handling and per-stratum sample support before selecting the whole threshold/persistence rule. Empirical development FPR at most 1% is not a guaranteed population or final-test FPR.','',
              '**Exact next action:** '+readiness['exact_next_action'],'',
              'Raw captures, complete request/server logs, environments and packet/model tables stay outside Git. The public package includes exact byte hashes, selected-group metadata, small summaries and source. [The runtime README](../lab/stress_v5/README.md) records topology, limits, provenance and continuation commands.']
    (ROOT/'plan/BENIGN_STRESS_REVIEW.md').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'sessions':36,'added_windows':2160,'total_windows':readiness['total_candidate_labelled_windows'],'conditions':records},indent=2))


if __name__=='__main__': main()
