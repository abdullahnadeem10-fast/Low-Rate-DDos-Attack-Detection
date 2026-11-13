"""One fresh benign session: internal bridge, forced router routes, no NAT."""
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import shutil
import subprocess
import time
import uuid

LAB = Path(__file__).resolve().parent
ROOT = LAB.parents[1]
PARENT_ID = 'sha256:78168ae6e29ac8739ef00b6d99939c9ea94a15a64bc77b8631dc0cebb9d27b60'
WEB_IMAGE = 'httpd:2.4@sha256:ce3b1e5ab31c4b1b6aba298b935cb88bc6ca1d643446b69d396406db5550bf68'
CLIENT_SUBNET, SERVER_SUBNET = '172.28.240.0/24', '172.28.240.0/24'
WEB = '172.28.240.100'


def impairment(rate=0, delay=0, jitter=0, loss=0., limit=512):
    return {'rate_kbit': rate, 'delay_ms': delay, 'jitter_ms': jitter, 'loss_percent': loss, 'limit': limit}


PROFILES = {
    'mixed_keepalive': {'workload': 'mixed', 'shaping': False, 'downlink': impairment(), 'uplink': impairment()},
    'long_download': {'workload': 'bulk', 'shaping': True,
                      'downlink': impairment(rate=512, delay=40), 'uplink': impairment(delay=40)},
    'congested_mixed': {'workload': 'mixed', 'shaping': True,
                        'downlink': impairment(rate=256, delay=120, jitter=20, loss=1., limit=64),
                        'uplink': impairment(delay=60, jitter=10, loss=.5, limit=64)},
}


def configuration(output, entry, image):
    if entry['condition'] not in PROFILES or entry['clients'] != 3:
        raise ValueError('Unapproved benign profile/client count')
    profile = json.dumps(PROFILES[entry['condition']])
    common = {'image': image, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
              'mem_limit': '192m', 'cpus': .5, 'pids_limit': 64}
    services = {
        'router': {**common, 'cap_add': ['NET_ADMIN'], 'command': ['python', '/stress/network.py'],
            'sysctls': {'net.ipv4.ip_forward': '1','net.ipv4.conf.all.send_redirects':'0','net.ipv4.conf.default.send_redirects':'0'},
            'networks': {'client_net': {'ipv4_address': '172.28.240.2'}},
            'environment': {'PROFILE_JSON': profile, 'DOWN_SEED': str(entry['down_seed']), 'UP_SEED': str(entry['up_seed'])},
            'volumes': [{'type': 'bind', 'source': str(output/'router'), 'target': '/output'}]},
        'web': {'image': WEB_IMAGE, 'networks': {'client_net': {'ipv4_address': WEB}}, 'cap_drop': ['ALL'],
            'cap_add': ['NET_BIND_SERVICE', 'SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE'],
            'security_opt': ['no-new-privileges:true'], 'mem_limit': '256m', 'cpus': 1., 'pids_limit': 128,
            'command': ['httpd-foreground', '-c', 'Include /stress.conf'],
            'volumes': [{'type': 'bind', 'source': str(output/'htdocs'), 'target': '/usr/local/apache2/htdocs', 'read_only': True},
                        {'type': 'bind', 'source': str(output/'server'), 'target': '/evidence'},
                        {'type': 'bind', 'source': str(output/'stress.conf'), 'target': '/stress.conf', 'read_only': True}]},
        'capture': {**common, 'cap_add': ['NET_RAW', 'NET_ADMIN'], 'network_mode': 'service:web',
            'depends_on': ['web'], 'command': ['python', '/stress/capture.py'],
            'volumes': [{'type': 'bind', 'source': str(output/'capture'), 'target': '/output'}]},
    }
    for i, seed in enumerate(entry['client_seeds'], 1):
        services[f'client{i}'] = {**common, 'cap_add': ['NET_ADMIN'], 'command': ['python', '/stress/client.py'],
            'networks': {'client_net': {'ipv4_address': f'172.28.240.{9+i}'}}, 'extra_hosts': {'web': WEB},
            'environment': {'PROFILE_JSON': profile, 'CLIENT_INDEX': str(i), 'CLIENT_SEED': str(seed)},
            'volumes': [{'type': 'bind', 'source': str(output/f'client{i}'), 'target': '/output'},
                        {'type': 'bind', 'source': str(output/'control'), 'target': '/control', 'read_only': True}]}
    networks = {name: {'internal': True, 'enable_ipv6': False, 'ipam': {'config': [{'subnet': subnet}]}}
                for name, subnet in [('client_net', CLIENT_SUBNET)]}
    return {'services': services, 'networks': networks}


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def prepare(output, entry, image, plan_sha):
    for name in ('htdocs', 'server', 'router', 'capture', 'control', 'client1', 'client2', 'client3'):
        (output/name).mkdir(parents=True, exist_ok=False)
    payloads = {}
    for name, size in [('small.bin', 4096), ('medium.bin', 65536), ('large.bin', 262144), ('bulk.bin', 1048576)]:
        pattern = b'CNET complete legitimate response body.\n'
        body = (pattern * math.ceil(size/len(pattern)))[:size]
        p = output/'htdocs'/name
        p.write_bytes(body)
        payloads['/'+name] = {'bytes': len(body), 'sha256': sha(p)}
    (output/'control/payloads.json').write_text(json.dumps(payloads, indent=2)+'\n', encoding='utf-8')
    (output/'stress.conf').write_text('''KeepAlive On
KeepAliveTimeout 10
MaxKeepAliveRequests 8
Timeout 60
LogFormat "%{%s}t\\t%D\\t%a\\t%m\\t%U\\t%>s\\t%B\\t%{X-Request-Id}i" benign_stress
CustomLog "/evidence/access.tsv" benign_stress
''', encoding='utf-8')
    (output/'compose.json').write_text(json.dumps(configuration(output, entry, image), indent=2)+'\n', encoding='utf-8')
    manifest = {'session': output.name, **entry, 'profile': PROFILES[entry['condition']], 'label': 'BENIGN',
                'state': 'prepared_not_run', 'plan_sha256': plan_sha, 'tools_image': image,
                'web_image': WEB_IMAGE, 'service': WEB+':80', 'training_ready': False,
                'scope': 'Excluded engineering preflight.' if entry['role']=='PREFLIGHT' else 'Benign development only; not a final stress/attack test.',
                'payloads': payloads, 'server_config_sha256': sha(output/'stress.conf')}
    return manifest


def collect(entry, image, plan_sha):
    if entry['role'] not in ('PREFLIGHT', 'T', 'C1', 'C2', 'V') or not 20 <= entry['warmup'] <= 120 or not 1 <= entry['duration'] <= 180:
        raise ValueError('Unapproved role or duration')
    if len(entry['client_seeds']) != 3 or len(set(entry['client_seeds'])) != 3:
        raise ValueError('Client seeds overlap within session')
    if shutil.disk_usage(ROOT).free < 10 * 1024**3:
        raise ValueError('Required 10 GiB free-space reserve missing')
    # Refuse conflicting private subnets rather than modifying another network.
    network_ids = subprocess.run(['docker','network','ls','-q'], check=True,capture_output=True,text=True).stdout.split()
    networks = json.loads(subprocess.run(['docker','network','inspect',*network_ids],check=True,capture_output=True,text=True).stdout)
    for n in networks:
        for c in n.get('IPAM',{}).get('Config',[]) or []:
            if c.get('Subnet') and ':' not in c['Subnet'] and any(ipaddress.ip_network(c['Subnet']).overlaps(ipaddress.ip_network(s)) for s in (CLIENT_SUBNET,SERVER_SUBNET)):
                raise RuntimeError('Existing Docker subnet conflicts with this declared private lab')
    actual = subprocess.run(['docker','image','inspect',image,'--format','{{.Id}}'],check=True,capture_output=True,text=True).stdout.strip()
    if actual != image:
        raise ValueError('Content-pinned stress image differs')
    name = f'benign-stress-{entry["role"].lower()}-{entry["condition"]}-{uuid.uuid4().hex[:10]}'
    output = ROOT/'data/lab_stress_v3'/name
    manifest = prepare(output, entry, image, plan_sha)
    path = output/'session.json'
    def save():
        path.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    save()
    command = ['docker','compose','-p',name,'-f',str(output/'compose.json')]
    def run(*args, **kwargs):
        return subprocess.run([*command,*args],check=True,**kwargs)
    def wait_files(files, timeout):
        before = time.monotonic()
        while not all(p.exists() for p in files):
            if time.monotonic()-before > timeout:
                raise RuntimeError('Container readiness timed out')
            time.sleep(.2)
    started = False
    try:
        run('config','--quiet')
        started = True
        run('up','-d','--no-build','router','web','capture')
        wait_files([output/'router/ready.json',output/'capture/ready.json'],40)
        web_id = run('ps','-q','web',capture_output=True,text=True).stdout.strip()
        router_id = run('ps','-q','router',capture_output=True,text=True).stdout.strip()
        info = json.loads(subprocess.run(['docker','inspect',web_id,router_id],check=True,capture_output=True,text=True).stdout)
        net_ids = set()
        for item in info:
            if item['HostConfig'].get('Privileged') or item['HostConfig'].get('PortBindings'):
                raise RuntimeError('Unexpected privileged/published runtime service')
            net_ids.update(n['NetworkID'] for n in item['NetworkSettings']['Networks'].values())
        inspected = json.loads(subprocess.run(['docker','network','inspect',*sorted(net_ids)],check=True,capture_output=True,text=True).stdout)
        if len(inspected)!=1 or any(not n['Internal'] or n['EnableIPv6'] or n['Driver']!='bridge' for n in inspected):
            raise RuntimeError('Runtime network isolation differs')
        manifest.update(state='collecting', web_container_id=web_id, router_container_id=router_id,
                        isolation={'one_internal_bridge_forced_router_host_routes':True,'published_ports':False,'host_network':False,'host_nic_modified':False},
                        collection_start_utc=time.time())
        save()
        run('up','-d','--no-build','client1','client2','client3')
        wait_files([output/f'client{i}/ready.json' for i in (1,2,3)],40)
        start = math.ceil(time.time())+3
        schedule = {'warmup_start_utc':start,'measurement_start_utc':start+entry['warmup'],
                    'measurement_end_utc':start+entry['warmup']+entry['duration']}
        manifest['schedule'] = schedule
        (output/'control/schedule.json').write_text(json.dumps(schedule)+'\n',encoding='utf-8')
        save()
        deadline = time.monotonic()+entry['warmup']+entry['duration']+45
        last_tick = 0.
        while not all((output/f'client{i}/client.json').exists() for i in (1,2,3)):
            if time.monotonic()>deadline:
                raise RuntimeError('Bounded benign clients did not finish')
            if time.monotonic()-last_tick>30:
                totals = {'attempts':0,'complete':0,'failed':0,'bytes':0}
                for i in (1,2,3):
                    p=output/f'client{i}/progress.json'
                    if p.exists():
                        try:
                            d=json.loads(p.read_text())
                            for k in totals: totals[k]+=d[k]
                        except (ValueError,OSError): pass
                print(json.dumps({'session':name,'role':entry['role'],'condition':entry['condition'],'progress':totals}),flush=True)
                last_tick=time.monotonic()
            time.sleep(.3)
        # Cover the complete declared interval and allow ordinary closes/queued
        # packets to drain. No successful-response-only selection is made.
        while time.time() < schedule['measurement_end_utc']+6:
            time.sleep(.2)
        run('stop','-t','20','capture')
        run('stop','-t','15','router')
        web_state = json.loads(subprocess.run(['docker','inspect',web_id],check=True,capture_output=True,text=True).stdout)[0]
        if not web_state['State']['Running']:
            raise RuntimeError('The declared legitimate web service unexpectedly exited')
        manifest.update(state='collected_audit_pending',pcap_sha256=sha(output/'capture/traffic.pcap'),
                        collection_end_utc=time.time(),web_alive_after_measurement=True)
    except BaseException as error:
        manifest.update(state='failed',error_type=type(error).__name__,error=str(error))
        raise
    finally:
        if started:
            logs = subprocess.run([*command,'logs','--no-color'],capture_output=True,text=True)
            (output/'containers.log').write_text(logs.stdout+logs.stderr,encoding='utf-8')
            cleanup = subprocess.run([*command,'down','--timeout','15','--remove-orphans'],capture_output=True,text=True)
            manifest['cleanup_exit_code']=cleanup.returncode
            (output/'cleanup.log').write_text(cleanup.stdout+cleanup.stderr,encoding='utf-8')
        save()
    return output


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--entry-json',required=True)
    p.add_argument('--image',required=True)
    p.add_argument('--plan-sha',required=True)
    args=p.parse_args()
    print(collect(json.loads(args.entry_json),args.image,args.plan_sha),flush=True)
