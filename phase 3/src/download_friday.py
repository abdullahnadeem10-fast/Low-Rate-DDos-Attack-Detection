"""Resumable bounded parallel acquisition of the allowlisted Friday capture only."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

from friday_packet_audit import DATA, PCAP_SHA, PCAP_SIZE, REV

URL=f'https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/{REV}/pcaps/Friday-WorkingHours.pcap?download=true'
SIZE=8*1024*1024
parts=DATA/'friday_ranges_8MiB'
parts.mkdir(parents=True,exist_ok=True)
old=DATA/'Friday-WorkingHours.pcap.partial'

# Reuse complete subranges from the stopped downloader, including partial bodies.
seeds=[(0,old)] if old.exists() else []
seeds += [(int(p.stem)*128*1024*1024,p) for p in (DATA/'friday_parts').glob('*') if p.suffix in ('.part','.downloading') and p.stem.isdigit()]
for offset,seed in seeds:
    with seed.open('rb') as stream:
        i=offset//SIZE
        while i*SIZE < PCAP_SIZE:
            want=min(SIZE,PCAP_SIZE-i*SIZE)
            data=stream.read(want)
            if len(data)!=want: break
            p=parts/f'{i:03d}.part'
            if not p.exists(): p.write_bytes(data)
            i+=1


def acquire(i):
    start=i*SIZE; end=min(PCAP_SIZE,start+SIZE)-1
    p=parts/f'{i:03d}.part'
    expected=end-start+1
    if p.exists() and p.stat().st_size==expected: return i,expected,'cached'
    # Retain truncated range bodies across retries rather than restarting from zero.
    work=parts/f'{i:03d}.partial'
    for attempt in range(6):
        have=work.stat().st_size if work.exists() else 0
        if have==expected: work.replace(p); return i,expected,'downloaded'
        if have>expected: raise ValueError('Invalid partial range size')
        temp=parts/f'{i:03d}.response'
        cmd=['curl.exe','--fail','--location','--silent','--show-error',
             '--connect-timeout','20','--max-time','100','--range',f'{start+have}-{end}',
             '--max-filesize',str(expected-have),'--output',str(temp),'--write-out','%{http_code}',URL]
        r=subprocess.run(cmd,capture_output=True,text=True)
        received=temp.stat().st_size if temp.exists() else 0
        if r.stdout.strip()=='206' and 0<received<=expected-have:
            with work.open('ab') as out,temp.open('rb') as source: shutil.copyfileobj(source,out)
        if temp.exists(): temp.unlink()
        if work.exists() and work.stat().st_size==expected: work.replace(p); return i,expected,'downloaded'
        time.sleep(min(2+attempt,6))
    raise RuntimeError(f'Range {i} incomplete; partial bytes retained for restart')


started=time.perf_counter(); total=0
with ThreadPoolExecutor(max_workers=12) as pool:
    futures=[pool.submit(acquire,i) for i in reversed(range((PCAP_SIZE+SIZE-1)//SIZE))]
    for task in as_completed(futures):
        i,n,status=task.result(); total+=n
        if i%16==0 or total==PCAP_SIZE: print(f'{total/1e9:.2f}/{PCAP_SIZE/1e9:.2f} GB verified-length ranges ({i}: {status})',flush=True)
        status_path=DATA/'friday_acquisition_status.json'
        temp_status=status_path.with_suffix('.writing.json')
        temp_status.write_text(json.dumps({'state':'downloading','completed_range_bytes':total,'expected_bytes':PCAP_SIZE,'elapsed_seconds':round(time.perf_counter()-started,2)},indent=2),encoding='utf-8')
        temp_status.replace(status_path)

target=DATA/'Friday-WorkingHours.pcap'
temp=DATA/'Friday-WorkingHours.assembled.partial'
sha=hashlib.sha256()
with temp.open('wb') as out:
    for i in range((PCAP_SIZE+SIZE-1)//SIZE):
        with (parts/f'{i:03d}.part').open('rb') as src:
            while block:=src.read(4*1024*1024): out.write(block); sha.update(block)
if temp.stat().st_size!=PCAP_SIZE or sha.hexdigest()!=PCAP_SHA:
    raise ValueError('Assembled capture failed SHA-256 verification; no final file published')
temp.replace(target)
(DATA/'Friday-WorkingHours.source.json').write_text(json.dumps({'url':URL,'revision':REV,
    'bytes':PCAP_SIZE,'sha256':PCAP_SHA,'seconds':round(time.perf_counter()-started,2)},indent=2)+'\n',encoding='utf-8')
(DATA/'friday_acquisition_status.json').write_text(json.dumps({
    'state':'complete_verified','completed_range_bytes':PCAP_SIZE,'expected_bytes':PCAP_SIZE,
    'sha256':PCAP_SHA,'elapsed_seconds':round(time.perf_counter()-started,2)},indent=2)+'\n',encoding='utf-8')
print(f'COMPLETE: {PCAP_SIZE} bytes, SHA-256 {PCAP_SHA}',flush=True)
