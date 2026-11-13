"""Configure only the declared container interfaces and private lab routes."""
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import time

CLIENT_SUBNET = '172.28.240.0/24'
SERVER_SUBNET = '172.28.240.100/32'
ROUTER_CLIENT = '172.28.240.2'
ROUTER_SERVER = ROUTER_CLIENT
WEB = '172.28.240.100'


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


def qdisc(device, config, seed, band):
    args = ['tc', 'qdisc', 'replace', 'dev', device, 'parent', f'1:{band}', 'handle', f'{band}0:', 'netem', 'limit', str(config['limit'])]
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
    device=device_for(ROUTER_CLIENT)
    return {device: json.loads(command('tc', '-j', '-s', 'qdisc', 'show', 'dev', device))}


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
    device=device_for(ROUTER_CLIENT)
    devices = {ROUTER_CLIENT: device}
    if Path(f'/proc/sys/net/ipv4/conf/{device}/send_redirects').read_text().strip()!='0':
        raise RuntimeError('Router ICMP redirects must be disabled')
    settings = {ip: offloads(dev) for ip, dev in devices.items()}
    routes = no_default_route()
    if profile['shaping']:
        command('tc','qdisc','replace','dev',device,'root','handle','1:','prio','bands','3','priomap',*(['2']*16))
        command('tc','filter','add','dev',device,'protocol','ip','parent','1:','prio','1','u32','match','ip','dst',WEB+'/32','flowid','1:1')
        command('tc','filter','add','dev',device,'protocol','ip','parent','1:','prio','2','u32','match','ip','dst',CLIENT_SUBNET,'flowid','1:2')
        qdisc(device, profile['uplink'], int(os.environ['UP_SEED']),1)
        qdisc(device, profile['downlink'], int(os.environ['DOWN_SEED']),2)
    directory = Path('/output')
    before = stats()
    (directory/'ready.json').write_text(json.dumps({'ready_utc': time.time(), 'devices': devices, 'routes': routes,
        'offloads': settings, 'tc_before': before, 'profile': profile,
        'router_mac':next(i['address'] for i in interfaces() if i['ifname']==device),
        'icmp_redirects_disabled':True,
        'scope': 'Private intermediate router only; no host NIC/routes modified.'}, indent=2) + '\n')
    started = time.monotonic()
    while not stopping and time.monotonic() - started < 600:
        time.sleep(.2)
    (directory/'final.json').write_text(json.dumps({'end_utc': time.time(), 'tc_after': stats(),
        'network_impairment_drops_are_not_capture_kernel_drops': True}, indent=2) + '\n')


if __name__ == '__main__':
    router()
