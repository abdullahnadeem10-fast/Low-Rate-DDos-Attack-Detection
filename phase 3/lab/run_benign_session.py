"""Prepare/run one independent isolated benign session; never generates attacks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent
WEB_IMAGE = 'httpd:2.4@sha256:ce3b1e5ab31c4b1b6aba298b935cb88bc6ca1d643446b69d396406db5550bf68'


def configuration(output, clients, condition, duration, warmup, seed):
    common = {'image': 'cnet-benign-tools:development', 'networks': ['isolated'],
              'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
              'mem_limit': '192m', 'cpus': .5, 'pids_limit': 64}
    services = {
        'web': {'image': WEB_IMAGE, 'networks': ['isolated'], 'cap_drop': ['ALL'],
                'cap_add': ['NET_BIND_SERVICE', 'SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE'],
                'security_opt': ['no-new-privileges:true'], 'mem_limit': '256m', 'cpus': 1., 'pids_limit': 128,
                'volumes': [{'type': 'bind', 'source': str(output/'htdocs'),
                             'target': '/usr/local/apache2/htdocs', 'read_only': True}]},
        'capture': {'image': 'cnet-benign-tools:development', 'build': {'context': str(LAB)},
                    'network_mode': 'service:web', 'depends_on': ['web'], 'cap_drop': ['ALL'],
                    'cap_add': ['NET_RAW', 'NET_ADMIN'], 'security_opt': ['no-new-privileges:true'],
                    'command': ['python', '/lab/capture.py'], 'mem_limit': '192m', 'cpus': .5,
                    'volumes': [{'type': 'bind', 'source': str(output/'capture'), 'target': '/output'}]}
    }
    for i in range(1, clients+1):
        services[f'client{i}'] = {**common, 'command': ['python', '/lab/client.py'],
            'environment': {'LAB_DURATION': str(duration), 'LAB_WARMUP': str(warmup),
                'LAB_SEED': str(seed), 'CLIENT_INDEX': str(i), 'LAB_CONDITION': condition},
            'volumes': [{'type': 'bind', 'source': str(output/f'client{i}'), 'target': '/output'}]}
    return {'services': services, 'networks': {'isolated': {'internal': True}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['PREFLIGHT','T','C1','C2','V'], required=True)
    parser.add_argument('--condition', choices=['ordinary','bursts','flash'], default='ordinary')
    parser.add_argument('--clients', type=int, choices=[1,3], default=1)
    parser.add_argument('--duration', type=int, default=60)
    parser.add_argument('--warmup', type=int, default=30)
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--no-build', action='store_true', help='Use the already verified tool image without rebuilding')
    parser.add_argument('--expected-tools-image', help='Fail before traffic if the local tool image content ID differs')
    args = parser.parse_args()
    if not 1 <= args.duration <= 300 or not 20 <= args.warmup <= 120:
        parser.error('Duration must be 1–300s; warm-up 20–120s')
    session = f'benign-{args.role.lower()}-{args.condition}-{uuid.uuid4().hex[:12]}'
    output = ROOT/'data/lab_development'/session
    for name in ['htdocs','capture',*[f'client{i}' for i in range(1,args.clients+1)]]:
        (output/name).mkdir(parents=True)
    (output/'htdocs/payload.txt').write_bytes(b'CNET benign local HTTP payload.\n'*512)
    compose = output/'compose.json'
    compose.write_text(json.dumps(configuration(output,args.clients,args.condition,args.duration,args.warmup,args.seed),indent=2)+'\n')
    manifest = {'session': session, 'label': 'BENIGN', 'role': args.role, 'condition': args.condition,
        'clients': args.clients, 'duration': args.duration, 'warmup': args.warmup, 'seed': args.seed,
        'state': 'prepared_not_run', 'training_ready': False,
        'scope': 'Engineering preflight; exclude from model partitions.' if args.role=='PREFLIGHT' else 'Benign development only; not a final research test.',
        'source_hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in LAB.iterdir() if p.is_file()},
        'limitations': ['Synthetic complete-request development workloads, not final stress sessions.',
            'Controlled network congestion is not implemented by these request patterns.',
            'Apache/container environment compatibility with public attack traces still requires audit.',
            'Base/Apache digests and built tool-image IDs are recorded; apt package availability can still affect a rebuild.']}
    manifest_path = output/'session.json'
    def save(): manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    save(); print(str(output), flush=True)
    if args.prepare_only:
        return
    command = ['docker','compose','-p',session,'-f',str(compose)]
    def run(*arguments, **kwargs):
        return subprocess.run([*command,*arguments],check=True,**kwargs)
    started = False; clients = []
    try:
        subprocess.run(['docker','version'],check=True,capture_output=True)
        run('config','--quiet')
        if not args.no_build: run('build','capture')
        if args.expected_tools_image:
            actual=subprocess.run(['docker','image','inspect','cnet-benign-tools:development','--format','{{.Id}}'],check=True,capture_output=True,text=True).stdout.strip()
            if actual!=args.expected_tools_image: raise RuntimeError('Tool image changed from the declared batch image')
        started = True
        run('up','-d','--no-build','web','capture')
        before = time.monotonic()
        while not (output/'capture/ready.json').exists():
            if time.monotonic()-before > 30:
                raise RuntimeError('Capture did not become ready')
            time.sleep(.2)
        web_id = run('ps','-q','web',capture_output=True,text=True).stdout.strip()
        inspection = json.loads(subprocess.run(['docker','inspect',web_id],check=True,capture_output=True,text=True).stdout)[0]
        networks=inspection['NetworkSettings']['Networks']
        if len(networks)!=1 or inspection['HostConfig'].get('Privileged') or inspection['HostConfig'].get('PortBindings'):
            raise RuntimeError('Unexpected web network/privilege/port configuration')
        network_id=next(iter(networks.values()))['NetworkID']
        network=json.loads(subprocess.run(['docker','network','inspect',network_id],check=True,capture_output=True,text=True).stdout)[0]
        if not network['Internal'] or network['Driver']!='bridge':
            raise RuntimeError('The lab network must be an internal bridge')
        addresses = [n['IPAddress'] for n in inspection['NetworkSettings']['Networks'].values()]
        manifest.update(state='collecting',start_utc=time.time(),service=f'{addresses[0]}:80',
            isolation={'single_internal_bridge':True,'published_web_ports':False,'privileged_web_container':False},
            web_container_id=web_id)
        manifest['image_ids'] = {name: subprocess.run(['docker','image','inspect',name,'--format','{{.Id}}'],
            check=True,capture_output=True,text=True).stdout.strip() for name in [WEB_IMAGE,'cnet-benign-tools:development']}
        manifest['apache_repo_digests']=json.loads(subprocess.run(['docker','image','inspect',WEB_IMAGE,'--format','{{json .RepoDigests}}'],
            check=True,capture_output=True,text=True).stdout)
        save()
        for i in range(1,args.clients+1):
            clients.append(subprocess.Popen([*command,'run','--rm','-T',f'client{i}']))
        codes = [p.wait(timeout=args.duration+args.warmup+30) for p in clients]
        if any(codes): raise RuntimeError(f'Benign client failure: {codes}')
        time.sleep(2)
        run('stop','-t','15','capture')
        capture = json.loads((output/'capture/capture.json').read_text())
        if capture['tcpdump_exit_code'] != 0: raise RuntimeError('Capture shutdown failed')
        manifest.update(state='collected_audit_pending',end_utc=time.time(),
            pcap_sha256=hashlib.sha256((output/'capture/traffic.pcap').read_bytes()).hexdigest())
    except Exception as error:
        manifest.update(state='failed',error=str(error))
        raise
    finally:
        for process in clients:
            if process.poll() is None:
                process.terminate(); process.wait(timeout=10)
        if started:
            logs = subprocess.run([*command,'logs','--no-color'],check=False,capture_output=True,text=True)
            (output/'containers.log').write_text(logs.stdout+logs.stderr,encoding='utf-8')
            cleanup=subprocess.run([*command,'down','--timeout','10','--remove-orphans'],check=False)
            manifest['cleanup_exit_code']=cleanup.returncode
        save()


if __name__ == '__main__':
    main()
