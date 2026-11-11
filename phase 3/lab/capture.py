"""Capture only the web container's interface; flush on controlled termination."""
import json
from pathlib import Path
import signal
import shutil
import subprocess
import time


def run():
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    started = time.time()
    # This sidecar shares only the isolated web network namespace. Disable
    # aggregation/segmentation offloads before capture, never on the host NIC.
    subprocess.run(['ethtool','-K','eth0','tso','off','gso','off','gro','off'],check=True)
    offloads=subprocess.run(['ethtool','-k','eth0'],check=True,capture_output=True,text=True).stdout
    for name in ('tcp-segmentation-offload','generic-segmentation-offload','generic-receive-offload'):
        if not any(line.startswith(name+': off') for line in offloads.splitlines()):
            raise RuntimeError('Requested web-interface offload policy did not take effect')
    Path('/output/offloads.json').write_text(json.dumps({'policy':'tso/gso/gro off on the isolated web eth0',
        'settings':offloads,'host_nic_modified':False},indent=2)+'\n')
    with Path('/output/tcpdump.log').open('w') as log:
        process = subprocess.Popen(['tcpdump', '-i', 'eth0', '-B', '32768', '-s', '0', '-n', '-Z', 'root',
            '-w', '/tmp/traffic.pcap', 'tcp', 'port', '80'], stdout=subprocess.DEVNULL, stderr=log)
        time.sleep(1)
        if process.poll() is not None:
            raise RuntimeError('Packet capture failed to start; inspect tcpdump.log')
        Path('/output/ready.json').write_text(json.dumps({'started_utc': started}))
        # Hard upper bound; normal host runner stops capture after clients complete.
        while not stopping and process.poll() is None and time.time()-started < 600:
            time.sleep(.2)
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        code = process.wait(timeout=10)
    # Keep packet writes in the Linux filesystem; bulk-copy only after flush.
    # Per-packet writes to the Windows bind mount lost packets under concurrency.
    shutil.copyfile('/tmp/traffic.pcap','/output/traffic.pcap')
    Path('/output/capture.json').write_text(json.dumps({'start_utc': started, 'end_utc': time.time(),
        'tcpdump_exit_code': code, 'interface': 'eth0', 'filter': 'tcp port 80',
        'packet_buffer_kib':32768,'capture_write_location':'container Linux /tmp; post-flush copy to host',
        'scope': 'Benign development capture; packet completeness/drop counts require audit.'}, indent=2) + '\n')
    if code != 0:
        raise RuntimeError('tcpdump did not close cleanly')


if __name__ == '__main__':
    run()
