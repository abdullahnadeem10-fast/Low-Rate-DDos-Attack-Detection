"""MAC-scoped full capture in the fixed web namespace, with explicit clocks."""
import json
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time
sys.path.insert(0,'/stress')
from network import WEB,ROUTER_SERVER,command,device_for,no_default_route,offloads,interfaces


def main():
    stop=False
    def stopping(*_):
        nonlocal stop
        stop=True
    signal.signal(signal.SIGTERM,stopping);signal.signal(signal.SIGINT,stopping)
    device=device_for(WEB)
    for i in (10,11,12,20,21,22,30):command('ip','route','replace',f'172.28.240.{i}/32','via',ROUTER_SERVER,'dev',device)
    settings=offloads(device);routes=no_default_route();mac=next(i['address'] for i in interfaces() if i['ifname']==device)
    expression=f'tcp port 80 and ether host {mac}';out=Path('/output');started=time.time()
    with (out/'tcpdump.log').open('w') as log:
        p=subprocess.Popen(['tcpdump','-p','-i',device,'-B','32768','-s','0','-n','-Z','root','-w','/tmp/traffic.pcap',expression],stdout=subprocess.DEVNULL,stderr=log)
        time.sleep(1)
        if p.poll() is not None:raise RuntimeError('Capture failed to start')
        ready=time.time();(out/'ready.json').write_text(json.dumps(dict(ready_utc=ready,routes=routes,offloads=settings,web_mac=mac,filter=expression))+'\n')
        tick=time.monotonic()
        while not stop and p.poll() is None and time.monotonic()-tick<480:time.sleep(.2)
        premature=p.poll() is not None;signal_utc=time.time()
        if not premature:p.send_signal(signal.SIGINT)
        code=p.wait(timeout=20)
    shutil.copyfile('/tmp/traffic.pcap',out/'traffic.pcap')
    (out/'capture.json').write_text(json.dumps(dict(start_utc=started,ready_utc=ready,stop_signal_utc=signal_utc,copy_finished_utc=time.time(),premature_exit=premature,tcpdump_exit_code=code,web_mac=mac,filter=expression))+'\n')
    if code:raise RuntimeError('Capture did not flush')


if __name__=='__main__':main()
