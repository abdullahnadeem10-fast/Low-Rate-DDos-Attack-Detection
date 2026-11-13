"""Configure only the declared container interfaces and private lab routes."""
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import time

CLIENT_SUBNET = '172.28.240.0/24'
SERVER_SUBNET = '172.28.241.0/24'
ROUTER_CLIENT = '172.28.240.2'
ROUTER_SERVER = '172.28.241.2'
WEB = '172.28.241.10'


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def interfaces():
    return json.loads(command('ip', '-j', 'address', 'show'))


def device_for(address):
    matches = [i['ifname'] for i in interfaces() if any(a.get('local') == address for a in i.get('addr_info', []))]
    if len(matches) != 1 or matches[0] == 'lo':
        raise ValueError('Declared private container interface missing/ambiguous')
    return matches[0]


def offloads(device):
    if device not in {i['ifname'] for i in interfaces()} or device == 'lo':
        raise ValueError('Unknown container device')
    command('ethtool', '-K', device, 'tso', 'off', 'gso', 'off', 'gro', 'off')
    text = command('ethtool', '-k', device)
    for name in ('tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload'):
        if not any(line.startswith(name + ': off') for line in text.splitlines()):
            raise RuntimeError('Container offload policy failed')
    return text


def no_default_route():
    routes = json.loads(command('ip', '-j', 'route', 'show'))
    if any(r.get('dst') == 'default' for r in routes):
        raise RuntimeError('Unexpected IPv4 default route in isolated lab')
    return routes


def qdisc(device, config, seed):
    args = ['tc', 'qdisc', 'replace', 'dev', device, 'root', 'netem', 'limit', str(config['limit'])]
    if config['delay_ms']:
        args += ['delay', str(config['delay_ms']) + 'ms']
        if config['jitter_ms']:
            args += [str(config['jitter_ms']) + 'ms']
    if config['loss_percent']:
        args += ['loss', 'random', str(config['loss_percent']) + '%']
    if config['rate_kbit']:
        args += ['rate', str(config['rate_kbit']) + 'kbit']
    args += ['seed', str(seed)]
    command(*args)


def stats():
    return {device: json.loads(command('tc', '-j', '-s', 'qdisc', 'show', 'dev', device))
            for device in (device_for(ROUTER_CLIENT), device_for(ROUTER_SERVER))}


def router():
    profile = json.loads(os.environ['PROFILE_JSON'])
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
        raise RuntimeError('Private router forwarding is not enabled')
    devices = {ROUTER_CLIENT: device_for(ROUTER_CLIENT), ROUTER_SERVER: device_for(ROUTER_SERVER)}
    settings = {ip: offloads(dev) for ip, dev in devices.items()}
    routes = no_default_route()
    if profile['shaping']:
        qdisc(devices[ROUTER_CLIENT], profile['downlink'], int(os.environ['DOWN_SEED']))
        qdisc(devices[ROUTER_SERVER], profile['uplink'], int(os.environ['UP_SEED']))
    directory = Path('/output')
    before = stats()
    (directory/'ready.json').write_text(json.dumps({'ready_utc': time.time(), 'devices': devices, 'routes': routes,
        'offloads': settings, 'tc_before': before, 'profile': profile,
        'scope': 'Private intermediate router only; no host NIC/routes modified.'}, indent=2) + '\n')
    started = time.monotonic()
    while not stopping and time.monotonic() - started < 600:
        time.sleep(.2)
    (directory/'final.json').write_text(json.dumps({'end_utc': time.time(), 'tc_after': stats(),
        'network_impairment_drops_are_not_capture_kernel_drops': True}, indent=2) + '\n')


if __name__ == '__main__':
    router()
