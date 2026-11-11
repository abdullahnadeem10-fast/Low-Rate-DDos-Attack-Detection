"""Complete benign HTTP requests to the fixed internal lab service only."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import time


def run():
    duration = int(os.environ.get('LAB_DURATION', '60'))
    warmup = int(os.environ.get('LAB_WARMUP', '30'))
    seed = int(os.environ.get('LAB_SEED', '7')) + int(os.environ.get('CLIENT_INDEX', '1')) * 1000
    condition = os.environ.get('LAB_CONDITION', 'ordinary')
    if condition not in ('ordinary', 'bursts', 'flash') or not 1 <= duration <= 300 or not 20 <= warmup <= 120:
        raise ValueError('Invalid bounded benign development configuration')
    addresses = {entry[4][0] for entry in socket.getaddrinfo('web', 80, socket.AF_INET)}
    if not addresses or any(not ipaddress.ip_address(a).is_private for a in addresses):
        raise ValueError('The fixed lab service must resolve only to private network addresses')
    routes=Path('/proc/net/route').read_text().splitlines()
    default_routes=[line for line in routes[1:] if line.split()[1]=='00000000']
    if default_routes:
        raise ValueError('The isolated client unexpectedly has an IPv4 default route')
    own_addresses={entry[4][0] for entry in socket.getaddrinfo(socket.gethostname(),None,socket.AF_INET)}
    network_evidence={'service_addresses':sorted(addresses),'client_addresses':sorted(own_addresses),
        'ipv4_default_routes':len(default_routes)}
    Path('/output/network.json').write_text(json.dumps(network_evidence,indent=2)+'\n')
    started = time.time(); deadline = time.monotonic() + duration + warmup
    boundary = time.monotonic() + warmup
    generator = random.Random(seed)
    output = Path('/output/requests.jsonl')

    def request():
        before = time.time(); tick = time.perf_counter(); connection = None
        result = {'start_utc': before}
        try:
            connection = http.client.HTTPConnection('web', 80, timeout=5)
            connection.request('GET', '/payload.txt', headers={'Connection': 'close'})
            response = connection.getresponse(); body = response.read()
            result.update(status=response.status, bytes=len(body), complete=True)
        except (OSError, http.client.HTTPException) as error:
            result.update(complete=False, error=type(error).__name__)
        finally:
            if connection: connection.close()
        result['seconds'] = time.perf_counter() - tick
        return result

    with output.open('w', encoding='utf-8') as stream, ThreadPoolExecutor(max_workers=4) as pool:
        while time.monotonic() < deadline:
            now = time.monotonic()
            active = now >= boundary
            batch = 1 if not active or condition == 'ordinary' else (4 if condition == 'flash' or int(now-boundary) % 10 < 2 else 1)
            for result in pool.map(lambda _: request(), range(batch)):
                stream.write(json.dumps({**result, 'phase': 'measurement' if active else 'warmup'}) + '\n')
            stream.flush()
            time.sleep(generator.uniform(.25, .5) if active else 1.)
    Path('/output/client.json').write_text(json.dumps({'condition': condition, 'seed': seed,
        'start_utc': started, 'measurement_start_utc':started+warmup,'end_utc': time.time(), 'duration': duration, 'warmup': warmup,
        'scope': 'Benign development only; complete GETs, no slow/attack traffic.'}, indent=2) + '\n')


if __name__ == '__main__':
    run()
