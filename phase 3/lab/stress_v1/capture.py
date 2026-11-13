"""Observe the isolated web namespace and bulk-copy a flushed Linux PCAP."""
import json
from pathlib import Path
import signal
import shutil
import subprocess
import time

from network import CLIENT_SUBNET, ROUTER_SERVER, WEB, command, device_for, no_default_route, offloads


def run():
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    device = device_for(WEB)
    command('ip', 'route', 'replace', CLIENT_SUBNET, 'via', ROUTER_SERVER, 'dev', device)
    settings = offloads(device)
    routes = no_default_route()
    directory = Path('/output')
    started = time.time()
    with (directory/'tcpdump.log').open('w') as log:
        process = subprocess.Popen(['tcpdump', '-i', device, '-B', '32768', '-s', '0', '-n', '-Z', 'root',
                                    '-w', '/tmp/traffic.pcap', 'tcp', 'port', '80'], stdout=subprocess.DEVNULL, stderr=log)
        time.sleep(1)
        if process.poll() is not None:
            raise RuntimeError('Capture failed to start')
        ready = time.time()
        (directory/'ready.json').write_text(json.dumps({'ready_utc': ready, 'routes': routes,
            'offloads': settings, 'interface': device, 'host_nic_modified': False}, indent=2) + '\n')
        tick = time.monotonic()
        while not stopping and process.poll() is None and time.monotonic() - tick < 600:
            time.sleep(.2)
        premature = process.poll() is not None
        stop_signal_utc = time.time()
        if not premature:
            process.send_signal(signal.SIGINT)
        code = process.wait(timeout=15)
    shutil.copyfile('/tmp/traffic.pcap', directory/'traffic.pcap')
    (directory/'capture.json').write_text(json.dumps({'start_utc': started, 'ready_utc': ready,
        'stop_signal_utc': stop_signal_utc, 'copy_finished_utc': time.time(), 'premature_exit': premature,
        'tcpdump_exit_code': code, 'interface': device, 'filter': 'tcp port 80',
        'packet_buffer_kib': 32768, 'linux_write_then_bulk_copy': True}, indent=2) + '\n')
    if code:
        raise RuntimeError('Capture did not flush successfully')


if __name__ == '__main__':
    run()
