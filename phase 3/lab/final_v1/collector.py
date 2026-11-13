"""One declared final/preflight lab session, with capture/clock/failure evidence.

No target options, image builds/pulls, published ports, NAT or host NIC changes.
All new scripts are mounted read-only into existing content-pinned images.
"""
import ipaddress
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
LAB=Path(__file__).resolve().parent;ROOT=LAB.parents[1]
sys.path.insert(0,str(ROOT/'lab/stress_v5'))
from stress_runner_v5 import awake_during_collection,PROFILES,sha

TOOLS='sha256:bcd95e916f898bfad243bd3d4e8ccaf542cbe9d870e782ee62c45e5473f8112b'
WEB_IMAGE='httpd:2.4@sha256:ce3b1e5ab31c4b1b6aba298b935cb88bc6ca1d643446b69d396406db5550bf68'
SUBNET='172.28.240.0/24';WEB='172.28.240.100'
SERVER_CONFIG='''KeepAlive On
KeepAliveTimeout 10
MaxKeepAliveRequests 8
Timeout 60
LoadModule cgid_module modules/mod_cgid.so
ScriptAlias /sink/ /tmp/final-sink.sh
<Directory /tmp>
    Options +ExecCGI
    Require all granted
</Directory>
LogFormat "%{%s}t\\t%D\\t%a\\t%m\\t%U\\t%>s\\t%B\\t%{X-Request-Id}i" final_lab
CustomLog "/evidence/access.tsv" final_lab
'''


def docker(*args,**kwargs):
    binary=os.environ.get('CNET_DOCKER_EXE','docker')
    return subprocess.run([binary,*args],check=True,**kwargs)


def agents(entry):
    values={f'benign{i}':dict(role='benign',own=f'172.28.240.{9+i}',seed=entry['agent_seeds'][i-1],condition=entry['condition'] if entry['kind']=='benign' else 'ordinary',unit_id=entry['id']) for i in (1,2,3)}
    values['probe']=dict(role='probe',own='172.28.240.30',seed=entry['agent_seeds'][3],condition='ordinary',unit_id=entry['id'])
    if entry['kind']=='attack':
        for i in range(entry['sources']):values[f'slow{i+1}']=dict(role='slow',own=f'172.28.240.{20+i}',seed=entry['agent_seeds'][4+i],mechanism=entry['mechanism'],connections=entry['connections'],interval=entry['interval'],unit_id=entry['id'])
    return values


def configuration(out,entry):
    profile=PROFILES['long_download' if entry['condition']=='long_lived_or_congested' else 'mixed_keepalive']
    common=dict(image=TOOLS,cap_drop=['ALL'],security_opt=['no-new-privileges:true'],mem_limit='192m',cpus=.5,pids_limit=64)
    mount=dict(type='bind',source=str(LAB),target='/final',read_only=True)
    def volume(name,target='/output',readonly=False):return dict(type='bind',source=str(out/name),target=target,read_only=readonly)
    services={
        'router':dict(**common,cap_add=['NET_ADMIN'],command=['python','/stress/network.py'],
            sysctls={'net.ipv4.ip_forward':'1','net.ipv4.conf.all.send_redirects':'0','net.ipv4.conf.default.send_redirects':'0'},
            networks={'private':{'ipv4_address':'172.28.240.2'}},environment=dict(PROFILE_JSON=json.dumps(profile),DOWN_SEED=str(entry['net_seeds'][0]),UP_SEED=str(entry['net_seeds'][1])),volumes=[volume('router')]),
        'web':dict(image=WEB_IMAGE,networks={'private':{'ipv4_address':WEB}},cap_drop=['ALL'],cap_add=['NET_BIND_SERVICE','SETUID','SETGID','CHOWN','DAC_OVERRIDE'],
            security_opt=['no-new-privileges:true'],mem_limit='256m',cpus=1,pids_limit=256,
            command=['sh','-c','cp /final/sink.sh /tmp/final-sink.sh && chmod 755 /tmp/final-sink.sh && exec httpd-foreground -c "Include /final.conf"'],
            volumes=[mount,volume('htdocs','/usr/local/apache2/htdocs',True),volume('server','/evidence'),volume('final.conf','/final.conf',True)]),
        'capture':dict(**common,cap_add=['NET_RAW','NET_ADMIN'],network_mode='service:web',depends_on=['web'],command=['python','/final/capture_final.py'],volumes=[mount,volume('capture')])}
    for name,spec in agents(entry).items():
        services[name]=dict(**common,cap_add=['NET_ADMIN'],command=['python','/final/agent.py'],networks={'private':{'ipv4_address':spec['own']}},
            environment={'AGENT_JSON':json.dumps(spec)},volumes=[mount,volume(name),volume('control','/control',True)])
    return dict(services=services,networks={'private':dict(internal=True,enable_ipv6=False,ipam={'config':[{'subnet':SUBNET}]})})


def prepare(out,entry,authorization):
    out.mkdir(parents=True,exist_ok=False)
    for name in ('htdocs','server','router','capture','control',*agents(entry)):(out/name).mkdir()
    payloads={}
    for name,size in [('small.bin',4096),('medium.bin',65536),('large.bin',262144),('bulk.bin',1048576)]:
        pattern=b'CNET complete legitimate response body.\n';data=(pattern*math.ceil(size/len(pattern)))[:size];(out/'htdocs'/name).write_bytes(data)
        payloads['/'+name]=dict(bytes=size,sha256=sha(out/'htdocs'/name))
    import hashlib
    payloads['/sink/']=dict(bytes=3,sha256=hashlib.sha256(b'ok\n').hexdigest())
    (out/'control/payloads.json').write_text(json.dumps(payloads)+'\n',encoding='utf-8')
    (out/'final.conf').write_text(SERVER_CONFIG,encoding='utf-8',newline='\n')
    (out/'compose.json').write_text(json.dumps(configuration(out,entry),indent=2)+'\n',encoding='utf-8')
    return dict(entry=entry,session=out.name,state='prepared',payloads=payloads,authorization=authorization,tools_image=TOOLS,web_image=WEB_IMAGE,
        server_config_sha256=sha(out/'final.conf'),payload_access_started_utc=time.time(),all_planned_outcomes_retained=True,model_scores_used_for_selection=False)


@awake_during_collection
def collect(out,entry,authorization):
    if out.exists():raise FileExistsError('Never overwrite/recollect an attempted unit')
    if shutil.disk_usage(ROOT).free<10*1024**3:raise RuntimeError('10GiB free-space reserve required')
    require_entry(entry)
    ids=docker('network','ls','-q',capture_output=True,text=True).stdout.split()
    for network in json.loads(docker('network','inspect',*ids,capture_output=True,text=True).stdout) if ids else []:
        for cfg in network.get('IPAM',{}).get('Config',[]) or []:
            if cfg.get('Subnet') and ':' not in cfg['Subnet'] and ipaddress.ip_network(cfg['Subnet']).overlaps(ipaddress.ip_network(SUBNET)):raise RuntimeError('Conflicting lab subnet')
    if docker('image','inspect',TOOLS,'--format','{{.Id}}',capture_output=True,text=True).stdout.strip()!=TOOLS:raise RuntimeError('Wrong pinned tool image')
    # --pull never is also passed to every compose up. No image installation.
    docker('image','inspect',WEB_IMAGE,capture_output=True,text=True)
    manifest=prepare(out,entry,authorization);path=out/'session.json';started=False;project='cnet-'+entry['id'].lower()
    def save():path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    def compose(*args,**kwargs):return docker('compose','-p',project,'-f',str(out/'compose.json'),*args,**kwargs)
    def wait(files,seconds=45):
        tick=time.monotonic()
        while not all(p.exists() for p in files):
            if time.monotonic()-tick>seconds:raise RuntimeError('Readiness timeout')
            time.sleep(.2)
    save()
    try:
        compose('config','--quiet');started=True;compose('up','-d','--no-build','--pull','never','router','web','capture')
        wait([out/'router/ready.json',out/'capture/ready.json'])
        containers={name:compose('ps','-q',name,capture_output=True,text=True).stdout.strip() for name in ('router','web','capture')}
        runtime=json.loads(docker('inspect',*containers.values(),capture_output=True,text=True).stdout);network_ids=set()
        for item in runtime:
            if item['HostConfig'].get('Privileged') or item['HostConfig'].get('PortBindings') or item['HostConfig']['NetworkMode']=='host':raise RuntimeError('Runtime privilege/port escape')
            network_ids.update(n['NetworkID'] for n in item['NetworkSettings']['Networks'].values())
        networks=json.loads(docker('network','inspect',*network_ids,capture_output=True,text=True).stdout)
        if len(networks)!=1 or not networks[0]['Internal'] or networks[0]['EnableIPv6'] or networks[0]['Driver']!='bridge':raise RuntimeError('Unexpected runtime network')
        manifest.update(state='collecting',capture_started_utc=json.loads((out/'capture/ready.json').read_text())['ready_utc'],containers=containers,
            isolation=dict(internal_bridge=True,no_published_ports=True,no_host_network=True,no_host_nic_changes=True),clock_probes=[])
        def probe():
            before=time.time();vm=float(docker('exec',containers['router'],'python','-c','import time;print(time.time())',capture_output=True,text=True,timeout=5).stdout);after=time.time()
            manifest['clock_probes'].append(dict(host_before_utc=before,container_utc=vm,host_after_utc=after))
            if after-before>3 or not before-.5<=vm<=after+.5:raise RuntimeError('Clock probe outside fixed bounds')
        probe();names=list(agents(entry));compose('up','-d','--no-build','--pull','never',*names);wait([out/name/'ready.json' for name in names])
        # Inspect every agent before releasing the schedule, not just web/router.
        agent_ids=[compose('ps','-q',name,capture_output=True,text=True).stdout.strip() for name in names]
        info=json.loads(docker('inspect',*agent_ids,capture_output=True,text=True).stdout)
        for item in info:
            if item['HostConfig'].get('Privileged') or item['HostConfig'].get('PortBindings') or item['HostConfig']['NetworkMode']=='host' or {v['NetworkID'] for v in item['NetworkSettings']['Networks'].values()}!=network_ids:raise RuntimeError('Agent escaped declared internal network')
        probe();a=math.ceil(time.time())+3;schedule=dict(warmup_start_utc=a,measurement_start_utc=a+60,measurement_end_utc=a+60+entry['duration'])
        manifest['schedule']=schedule;(out/'control/schedule.json').write_text(json.dumps(schedule)+'\n',encoding='utf-8');save()
        last_loop=last_probe=time.monotonic();deadline=last_loop+60+entry['duration']+45
        while not all((out/name/'final.json').exists() for name in names) or time.time()<schedule['measurement_end_utc']+6:
            now=time.monotonic()
            if now-last_loop>5:raise RuntimeError('Host pause exceeds5s; preserve attempt')
            if now>deadline:raise RuntimeError('Bounded agent completion timeout')
            last_loop=now
            if now-last_probe>=15:probe();last_probe=time.monotonic();save()
            time.sleep(.2)
        probe();compose('stop','-t','25','capture');compose('stop','-t','15','router')
        # A service crash is an impact outcome, not grounds to replace an attack.
        web=json.loads(docker('inspect',containers['web'],capture_output=True,text=True).stdout)[0]
        manifest.update(state='collected_audit_pending',web_alive_after_measurement=web['State']['Running'],pcap_sha256=sha(out/'capture/traffic.pcap'),collection_end_utc=time.time())
    except BaseException as e:manifest.update(state='failed_preserved',error_type=type(e).__name__,error=str(e));raise
    finally:
        if started:
            try:
                log=compose('logs','--no-color',capture_output=True,text=True);(out/'containers.log').write_text(log.stdout+log.stderr,encoding='utf-8')
            except Exception as e:manifest['log_error']=str(e)
            try:compose('down','--timeout','15','--remove-orphans',capture_output=True,text=True);manifest['cleanup_exit_code']=0
            except Exception as e:manifest['cleanup_exit_code']=1;manifest['cleanup_error']=str(e)
        save()
    return out


def require_entry(entry):
    if entry['kind'] not in ('attack','benign') or entry['warmup']!=60 or not 30<=entry['duration']<=240:raise ValueError('Undeclared kind/duration')
    if entry['kind']=='attack' and (entry['sources'] not in (1,3) or (entry['connections'],entry['interval']) not in ((10,20),(60,5))):raise ValueError('Undeclared attack intensity')
    if entry['kind']=='attack' and (entry['preflight'] or entry['mechanism'] not in ('incomplete_header','slow_request_body')):raise ValueError('Unapproved mechanism/preflight')
    if entry['kind']=='benign' and entry['condition'] not in ('ordinary','bursts','flash','long_lived_or_congested'):raise ValueError('Unapproved benign condition')
    if len(entry['agent_seeds'])!=7 or len(set(entry['agent_seeds']+entry['net_seeds']))!=9:raise ValueError('Repeated/missing effective seed')
