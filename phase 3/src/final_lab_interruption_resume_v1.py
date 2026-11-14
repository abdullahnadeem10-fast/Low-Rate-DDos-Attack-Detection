"""Separately sealed restart of one demonstrably unscheduled setup attempt.

Never restarts a released/partially measured trial. Old sources/ledgers and
the complete interrupted setup stay immutable. No fitting or policy tuning.
"""
import argparse
import json
import os
from pathlib import Path
import time

from packet_model_policy import ROOT, read, sha, require
from frozen_suite import verify_freeze, authorize_qualification
import final_lab_resolution_recovery_v1 as reference

PLAN = 'plan/final_lab_interruption_resume_v1.json'
SEAL = 'results/qualification/final_lab_interruption_resume_seal_v1.json'
LEDGER = 'results/qualification/final_lab_interruption_batch_v1.json'
PRIVATE = 'data/final_lab_interruption_v1'
SOURCES = ('src/final_lab_interruption_resume_v1.py', 'src/test_final_lab_interruption_resume_v1.py')
AGENTS = ('benign1', 'benign2', 'benign3', 'probe', 'slow1', 'slow2', 'slow3')


def unscheduled_setup(directory, entry):
    record = read(directory / 'session.json')
    require(record['entry'] == entry and record['state'] == 'prepared', 'Only the preserved prepared entry is eligible')
    require('schedule' not in record and not (directory / 'control/schedule.json').exists(), 'Schedule was released; never restart')
    require((directory / 'server/access.tsv').exists() and (directory / 'server/access.tsv').stat().st_size == 0, 'HTTP outcome exists; never restart')
    require(not (directory / 'qualified_v1').exists() and not (directory / 'capture/traffic.pcap').exists() and not (directory / 'capture/capture.json').exists(), 'Final capture/qualification exists')
    for agent in AGENTS:
        require((directory / agent / 'ready.json').exists(), 'Missing setup readiness proof')
        require(not any((directory / agent / name).exists() for name in ('events.jsonl', 'requests.jsonl', 'final.json')), 'Agent research output exists; never restart')
    return dict(schedule_released=False, server_HTTP_bytes=0, agent_research_outputs=False, qualification_exists=False)


def verify_plan(root=ROOT):
    frozen, gate = verify_freeze(root)
    seal = read(root / SEAL)
    require(sha(root / PLAN) == seal['sha256'], 'Interruption declaration changed')
    plan = read(root / PLAN)
    require(plan['freeze_sha256'] == gate['freeze_sha256'], 'Mixed freeze')
    for name, expected in plan['source_sha256'].items():
        require(sha(root / name) == expected, 'Resume source changed')
    for item in plan['evidence'].values():
        require(sha(root / item['path']) == item['sha256'], 'Preserved interruption evidence changed')
    inventory = read(root / PRIVATE / 'prepared_file_inventory.json')
    archive = root / PRIVATE / 'preserved_setup'
    require({p.relative_to(archive).as_posix() for p in archive.rglob('*') if p.is_file()} == set(inventory), 'Preserved setup file set changed')
    for name, item in inventory.items():
        require(sha(archive / name) == item['sha256'] and (archive / name).stat().st_size == item['bytes'], 'Preserved setup bytes changed')
    unscheduled_setup(archive, plan['interrupted_entry'])
    require(sha(root / reference.LEDGER) == plan['legacy_ledger_sha256'], 'Original rolling ledger must remain byte-exact')
    old_seal = read(root / reference.SEAL)
    require(sha(root / reference.PLAN) == old_seal['sha256'] == plan['image_recovery_sha256'], 'Image recovery seal changed')
    old_plan = read(root / reference.PLAN)
    for name, expected in old_plan['source_sha256'].items():
        require(sha(root / name) == expected, 'Original image-recovery source changed')
    for key in ('original_ledger_snapshot', 'failure_evidence', 'validation'):
        item = old_plan[key]
        require(sha(root / item['path']) == item['sha256'], 'Original image-recovery evidence changed')
    return plan, seal


def effective_ledger(root=ROOT):
    plan, seal = verify_plan(root)
    legacy = read(root / reference.LEDGER)
    require(legacy['attempts'][-1]['unit_id'] == plan['interrupted_entry']['id'] and legacy['attempts'][-1]['state'] == 'started', 'Different legacy interruption')
    require(all(a['state'] == 'scored_all_cases' for a in legacy['attempts'][:-1]), 'Unexpected earlier legacy failure')
    current = read(root / LEDGER)
    require(current['resume_sha256'] == seal['sha256'], 'Mixed continuation ledger')
    require([a['entry'] for a in current['attempts']] == plan['planned_units'][:len(current['attempts'])], 'Continuation order/parameters changed')
    return dict(attempts=legacy['attempts'][:-1] + current['attempts'], preserved_unscheduled_setup=legacy['attempts'][-1], resume_sha256=seal['sha256'])


def declare():
    require(not (ROOT / PLAN).exists() and not (ROOT / SEAL).exists(), 'Never redeclare interruption recovery')
    frozen, gate = verify_freeze()
    for slot in ('lab_benign', 'lab_slow'):
        authorize_qualification(slot)
    directory = ROOT / PRIVATE
    legacy_path = ROOT / reference.LEDGER
    require(sha(legacy_path) == sha(directory / 'interrupted_legacy_ledger.json'), 'Interrupted ledger snapshot changed')
    legacy = read(legacy_path)
    require(len(legacy['attempts']) == 36 and all(a['state'] == 'scored_all_cases' for a in legacy['attempts'][:-1]), 'Expected 35 recovery successes and one interrupted setup')
    attempt = legacy['attempts'][-1]
    require(attempt['state'] == 'started' and attempt['unit_id'] == 'final-a-015', 'Different setup requires new review')
    entry = attempt['entry']
    proof = unscheduled_setup(directory / 'preserved_setup', entry)
    require(not (ROOT / 'data/final_lab_v1/collection.lock').exists() and not (ROOT / 'data/final_lab_v1/final-a-015').exists(), 'Old live/canonical setup still present')
    require(not (ROOT / 'results/final/final-a-015.json').exists() and not (ROOT / 'data/final_scoring_v1/final-a-015').exists(), 'No rescore/reselection allowed')
    require("while not Path('/control/schedule.json').exists():" in (ROOT / 'lab/final_v1/agent.py').read_text().splitlines()[153], 'Pinned schedule gate line differs')
    logs = read(directory / 'container_logs.json')
    for agent in AGENTS:
        item = logs[f'cnet-final-a-015-{agent}-1']
        text = item['stdout'] + item['stderr']
        require('line 154, in main' in text and 'OSError:' in text and "'/control/schedule.json'" in text, 'Agent did not fail at unreleased schedule gate')
    runtime = read(directory / 'runtime_inspect.json')
    require(len(runtime) == 10 and all(not item['State']['Running'] for item in runtime), 'Archived runtime was not stopped')
    remaining = sorted([u for slot in ('lab_benign', 'lab_slow') for u in read(ROOT / f'plan/final_lab_{slot}_acquisition_v1.json')['planned_units']], key=lambda u: u['run_order'])[36:]
    require(len(remaining) == 24 and remaining[0] == entry and remaining[-1]['id'] == 'final-a-008', 'Remaining original catalog changed')
    validation = ROOT / 'results/development/validation_final_lab_interruption_v1.json'
    require(read(validation)['all_tests_passed'] and read(validation)['tests_run'] >= 8, 'Interruption fixtures incomplete')
    evidence_names = ['interrupted_legacy_ledger.json', 'prepared_file_inventory.json', 'container_logs.json', 'runtime_inspect.json', 'original_collection.lock', 'unflushed_container_capture.pcap']
    evidence = {name: dict(path=f'{PRIVATE}/{name}', sha256=sha(directory / name)) for name in evidence_names}
    evidence['validation'] = dict(path=validation.relative_to(ROOT).as_posix(), sha256=sha(validation))
    old_seal = read(ROOT / reference.SEAL)
    value = dict(version='final_lab_interruption_resume_v1', sealed_at_utc=time.time(), freeze_sha256=gate['freeze_sha256'], source_sha256={name: sha(ROOT / name) for name in SOURCES}, legacy_ledger_sha256=sha(legacy_path), image_recovery_sha256=old_seal['sha256'], interrupted_entry=entry, proof=proof, evidence=evidence, planned_units=remaining, declared_before_resumed_schedule=True, allowed_change='Archive only the dead pre-schedule setup and stale lock; collect original remaining entries once in original order with the identical frozen collector, qualifier, scorer, images, resources, seeds and settings.', failure_policy='Any released schedule, agent research output, HTTP outcome, capture qualification or score disqualifies restart. Any new failure stops; no automatic recollection.', history='Old legacy started record, full setup files, logs, stopped-container metadata and unflushed zero-byte capture preserved. This is not an observed research trial, a negative outcome exclusion or an extra independent sample. Runtime interruption/restart is disclosed; all prior scientific results retained.')
    reference.write(ROOT / PLAN, value, new=True)
    reference.write(ROOT / SEAL, dict(path=PLAN, sha256=sha(ROOT / PLAN), sealed_at_utc=value['sealed_at_utc']), new=True)
    verify_plan()
    print(json.dumps(dict(declared=True, remaining=24, no_new_traffic=True, preserved_unscheduled_attempt=True)))


def execute(limit):
    require(limit > 0, 'Positive explicit limit required')
    plan, seal = verify_plan()
    authorizations = {slot: authorize_qualification(slot) for slot in ('lab_benign', 'lab_slow')}
    old_plan = read(ROOT / reference.PLAN)
    actual = reference.identity(json.loads(reference.ORIGINAL_DOCKER('image', 'inspect', reference.IMAGE, capture_output=True, text=True).stdout)[0])
    require(actual == old_plan['exact_image_identity'], 'Image content changed')
    state = read(ROOT / LEDGER) if (ROOT / LEDGER).exists() else dict(resume_sha256=seal['sha256'], attempts=[], all_remaining_units_completed=False)
    require(state['resume_sha256'] == seal['sha256'], 'Different resume ledger')
    lock = ROOT / 'data/final_lab_v1/collection.lock'
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.write(fd, str(os.getpid()).encode()); os.close(fd)
    reference.collector.docker = reference.ResolutionBridge(reference.ORIGINAL_DOCKER)
    done = 0
    try:
        for unit in plan['planned_units']:
            previous = [a for a in state['attempts'] if a['unit_id'] == unit['id']]
            if previous:
                require(len(previous) == 1 and previous[0]['state'] == 'scored_all_cases', 'New failed/partial attempt requires review, not retry')
                continue
            if done >= limit:
                break
            attempt = dict(unit_id=unit['id'], entry=unit, state='started', start_utc=time.time())
            state['attempts'].append(attempt); reference.write(ROOT / LEDGER, state)
            try:
                slot = 'lab_slow' if unit['kind'] == 'attack' else 'lab_benign'
                auth = dict(authorizations[slot], reference_recovery_sha256=plan['image_recovery_sha256'], interruption_resume_sha256=seal['sha256'])
                folder = reference.collector.collect(ROOT / 'data/final_lab_v1' / unit['id'], unit, auth)
                audit = reference.qualify(folder)
                qdir = folder / 'qualified_v1'; record = read(qdir / 'qualification.json')
                proof_path = qdir / 'reference_recovery.json'
                reference.write(proof_path, dict(plan_path=reference.PLAN, plan_sha256=plan['image_recovery_sha256'], image_identity=actual, overlay_sha256=sha(folder / 'image_resolution_overlay_v1.json'), original_qualification_sha256=sha(qdir / 'qualification.json'), models_or_truth_changed=False), new=True)
                resume_proof = qdir / 'interruption_resume.json'
                reference.write(resume_proof, dict(plan_path=PLAN, plan_sha256=seal['sha256'], original_setup_preserved=True, restarted_unscheduled_canonical_entry=unit['id'] == plan['interrupted_entry']['id'], settings_models_labels_or_seeds_changed=False), new=True)
                for key, path in [('reference_recovery', proof_path), ('interruption_resume', resume_proof)]:
                    record['qualification_evidence'][key] = dict(path=path.relative_to(ROOT).as_posix(), sha256=sha(path))
                qpath = qdir / 'qualification_recovery_v1.json'; reference.write(qpath, record, new=True)
                attempt.update(state='qualified', audit=audit, qualification_sha256=sha(qpath)); reference.write(ROOT / LEDGER, state)
                reference.score(qpath)
                result = ROOT / 'results/final' / (unit['id'] + '.json')
                completed = read(result)['all_cases_completed']
                attempt.update(state='scored_all_cases' if completed else 'scoring_failures_preserved', result_sha256=sha(result)); reference.write(ROOT / LEDGER, state)
                require(completed, 'Scoring failures retained; do not rescore')
                print(json.dumps(dict(unit=unit['id'], all117_cases_scored=True, quality_pass=True, frames=audit['counts']['frames'])), flush=True)
                done += 1
            except BaseException as error:
                attempt.update(state='failed_preserved', error_type=type(error).__name__, error=str(error)); reference.write(ROOT / LEDGER, state)
                raise
        state['all_remaining_units_completed'] = len(state['attempts']) == len(plan['planned_units']) and all(a['state'] == 'scored_all_cases' for a in state['attempts'])
        reference.write(ROOT / LEDGER, state)
    finally:
        reference.collector.docker = reference.ORIGINAL_DOCKER
        require(lock.read_text() == str(os.getpid()), 'Collector lock owner changed')
        lock.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['declare', 'run'])
    parser.add_argument('--limit', type=int, default=1)
    args = parser.parse_args()
    declare() if args.stage == 'declare' else execute(args.limit)
