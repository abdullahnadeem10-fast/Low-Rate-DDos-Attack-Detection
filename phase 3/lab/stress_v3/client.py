"""Bounded legitimate GET/HEAD traffic: complete headers, no slow request bodies."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import time

from network import CLIENT_SUBNET, SERVER_SUBNET, ROUTER_CLIENT, WEB, command, device_for, no_default_route, offloads


def outcome_is_failure(result):
    return not result.get('complete', False) or result.get('status') != 200


def read_response_chunk(response, method):
    # CPython read1(HEAD) returns empty without closing its response file.
    # read(HEAD) closes it, allowing HTTPConnection's next getresponse().
    return response.read() if method=='HEAD' else response.read1(16384)


def run():
    index, seed = int(os.environ['CLIENT_INDEX']), int(os.environ['CLIENT_SEED'])
    profile = json.loads(os.environ['PROFILE_JSON'])
    if index not in (1, 2, 3) or profile['workload'] not in ('mixed', 'bulk'):
        raise ValueError('Unapproved bounded benign client')
    own = f'172.28.240.{9+index}'
    device = device_for(own)
    command('ip', 'route', 'replace', SERVER_SUBNET, 'via', ROUTER_CLIENT, 'dev', device)
    settings = offloads(device)
    routes = no_default_route()
    addresses = {x[4][0] for x in socket.getaddrinfo('web', 80, socket.AF_INET)}
    if addresses != {WEB} or not ipaddress.ip_address(WEB) in ipaddress.ip_network(SERVER_SUBNET):
        raise ValueError('Fixed private web resolution changed')
    directory = Path('/output')
    (directory/'ready.json').write_text(json.dumps({'ready_utc': time.time(), 'client_index': index, 'effective_seed': seed,
        'client_addresses': [own], 'service_addresses': sorted(addresses), 'routes': routes, 'offloads': settings,
        'ipv4_default_routes': 0}, indent=2) + '\n')
    before = time.monotonic()
    while not Path('/control/schedule.json').exists():
        if time.monotonic() - before > 60:
            raise RuntimeError('No bounded collection schedule')
        time.sleep(.1)
    schedule = json.loads(Path('/control/schedule.json').read_text())
    warmup, boundary, end = (float(schedule[k]) for k in ('warmup_start_utc', 'measurement_start_utc', 'measurement_end_utc'))
    if not 20 <= boundary - warmup <= 120 or not 1 <= end - boundary <= 180 or end - time.time() > 310:
        raise ValueError('Unbounded or invalid session schedule')
    payloads = json.loads(Path('/control/payloads.json').read_text())
    generator = random.Random(seed)
    connection, used = None, 0
    totals = {'attempts': 0, 'complete': 0, 'failed': 0, 'bytes': 0}
    last_progress = 0.
    def progress(extra=None):
        nonlocal last_progress
        now = time.time()
        if now - last_progress < 5 and not (extra or {}).get('finished'):
            return
        temp = directory/'progress.writing.json'
        temp.write_text(json.dumps({**totals, 'utc': now, **(extra or {})}) + '\n')
        temp.replace(directory/'progress.json')
        last_progress = now
    while time.time() < warmup:
        time.sleep(max(0., min(.1, warmup - time.time())))
    with (directory/'requests.jsonl').open('w', encoding='utf-8') as stream:
        while time.time() < end and totals['attempts'] < 600:
            name = '/bulk.bin' if profile['workload'] == 'bulk' else generator.choices(['/small.bin', '/medium.bin', '/large.bin'], [.55, .30, .15])[0]
            method = 'GET' if profile['workload'] == 'bulk' or generator.random() < .8 else 'HEAD'
            rid = f'c{index}-s{seed}-r{totals["attempts"]:04d}'
            start = time.time()
            tick = time.monotonic()
            record = {'request_id': rid, 'client_index': index, 'method': method, 'path': name, 'start_utc': start,
                      'phase_at_start': 'measurement' if start >= boundary else 'warmup', 'complete': False, 'bytes': 0}
            expected = payloads[name]
            digest = hashlib.sha256()
            try:
                if connection is None:
                    connection = http.client.HTTPConnection('web', 80, timeout=10 if profile['workload'] == 'bulk' else 2)
                    used = 0
                close = used >= 7
                connection.request(method, name, headers={'Connection': 'close' if close else 'keep-alive', 'X-Request-Id': rid})
                # http.client sends complete headers immediately; no application
                # pacing/partial header or request-body withholding is implemented.
                response = connection.getresponse()
                record['status'] = response.status
                record['content_length'] = response.getheader('Content-Length')
                deadline = min(start + (90 if profile['workload'] == 'bulk' else 10), end + 20)
                while True:
                    if time.time() >= deadline:
                        raise TimeoutError('Legitimate response exceeded application budget')
                    block = read_response_chunk(response, method)
                    if not block:
                        break
                    digest.update(block)
                    record['bytes'] += len(block)
                    progress({'inflight_request': rid, 'inflight_bytes': record['bytes']})
                expected_bytes = expected['bytes'] if method == 'GET' else 0
                record['complete'] = record['bytes'] == expected_bytes
                if method == 'GET' and record['complete']:
                    record['body_sha256'] = digest.hexdigest()
                    record['body_integrity_ok'] = digest.hexdigest() == expected['sha256']
                used += 1
                if close or response.will_close:
                    connection.close()
                    connection = None
            except (OSError, http.client.HTTPException) as error:
                record['error'] = type(error).__name__
                if connection:
                    connection.close()
                connection = None
            record['end_utc'] = time.time()
            record['seconds'] = time.monotonic() - tick
            totals['attempts'] += 1
            totals['bytes'] += record['bytes']
            totals['failed' if outcome_is_failure(record) else 'complete'] += 1
            stream.write(json.dumps(record) + '\n')
            stream.flush()
            progress()
            if time.time() >= end:
                break
            time.sleep(generator.uniform(.3, .8))
    if connection:
        connection.close()
    progress({'finished': True})
    (directory/'client.json').write_text(json.dumps({'client_index': index, 'effective_seed': seed, 'profile': profile,
        'schedule': schedule, 'end_utc': time.time(), 'totals': totals,
        'scope': 'Benign development only; complete GET/HEAD headers, no request body or attack mechanism.'}, indent=2) + '\n')


if __name__ == '__main__':
    run()
