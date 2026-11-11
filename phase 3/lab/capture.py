"""Capture only the web container's interface; flush on controlled termination."""
import json
from pathlib import Path
import signal
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
    with Path('/output/tcpdump.log').open('w') as log:
        process = subprocess.Popen(['tcpdump', '-i', 'eth0', '-U', '-s', '0', '-n', '-Z', 'root',
            '-w', '/output/traffic.pcap', 'tcp', 'port', '80'], stdout=subprocess.DEVNULL, stderr=log)
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
    Path('/output/capture.json').write_text(json.dumps({'start_utc': started, 'end_utc': time.time(),
        'tcpdump_exit_code': code, 'interface': 'eth0', 'filter': 'tcp port 80',
        'scope': 'Benign development capture; packet completeness/drop counts require audit.'}, indent=2) + '\n')
    if code != 0:
        raise RuntimeError('tcpdump did not close cleanly')


if __name__ == '__main__':
    run()
