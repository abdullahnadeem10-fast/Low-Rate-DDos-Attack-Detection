"""Bounded resumable ranges for exactly two pinned, declared development archives."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import re
import shutil
import subprocess
import time

from declare_cic2019_validation import ROOT, REV

CHUNK = 8 * 1024 * 1024


def approved(item):
    expected = {
        'pcaps/03-11/PCAP-03-11.zip': (2000948331, 'cdc8935296cab7a2354d4fd32939f7d5e6c592371e5fb89d6a3094cc05dc38c5'),
        'csvs/CSV-03-11.zip': (918815761, 'a81d8ce59a819d13e6bfea4e4812d6d144d0572b6d2c42d8e0c0a8cf1c26c263'),
    }
    if expected.get(item['path']) != (item['bytes'], item['sha256']):
        raise ValueError('Not an allowlisted development archive')
    target = (ROOT/item['local']).resolve()
    allowed = (ROOT/'data/development/cic2019_v').resolve()
    if not target.is_relative_to(allowed) or target.suffix != '.zip':
        raise ValueError('Destination outside private development cache')
    return target


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def valid_range(headers, start, end, total):
    # Redirect headers can contain several blocks; use the final Content-Range.
    found = re.findall(r'(?im)^content-range:\s*bytes\s+(\d+)-(\d+)/(\d+)\s*$', headers)
    return bool(found and tuple(map(int, found[-1])) == (start, end, total))


def acquire(item, index):
    target = approved(item)
    parts = target.parent/(target.stem + '_ranges')
    parts.mkdir(parents=True, exist_ok=True)
    start, end = index * CHUNK, min(item['bytes'], (index + 1) * CHUNK) - 1
    part = parts/f'{index:05d}.part'
    want = end - start + 1
    if part.exists() and part.stat().st_size == want:
        return want
    work = part.with_suffix('.partial')
    url = f'https://huggingface.co/datasets/bencorn/CICDDoS2019/resolve/{REV}/{item["path"]}?download=true'
    for attempt in range(5):
        have = work.stat().st_size if work.exists() else 0
        if have > want:
            raise ValueError('Range cache larger than allocated interval')
        if have == want:
            work.replace(part)
            return want
        body, header = part.with_suffix('.response'), part.with_suffix('.headers')
        command = ['curl.exe', '--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20',
                   '--max-time', '90', '--range', f'{start + have}-{end}', '--max-filesize', str(want - have),
                   '--dump-header', str(header), '--output', str(body), '--write-out', '%{http_code}', url]
        r = subprocess.run(command, capture_output=True, text=True)
        size = body.stat().st_size if body.exists() else 0
        text = header.read_text(encoding='iso-8859-1') if header.exists() else ''
        if r.stdout.strip() == '206' and valid_range(text, start + have, end, item['bytes']) and 0 < size <= want - have:
            with work.open('ab') as out, body.open('rb') as incoming:
                shutil.copyfileobj(incoming, out)
        body.unlink(missing_ok=True)
        header.unlink(missing_ok=True)
        if work.exists() and work.stat().st_size == want:
            work.replace(part)
            return want
        time.sleep(min(2 + attempt, 6))
    raise RuntimeError(f'Range {item["id"]}/{index} incomplete; private resumable cache retained')


def main():
    started = time.perf_counter()
    plan_path = ROOT/'plan/cic2019_validation_v1.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    if plan['revision'] != REV:
        raise ValueError('Declared mirror revision changed')
    if shutil.disk_usage(ROOT).free < 10 * 1024**3 + 2 * sum(x['bytes'] for x in plan['allowed_downloads']):
        raise ValueError('Insufficient declared disk reserve')
    reports = []
    for item in plan['allowed_downloads']:
        target = approved(item)
        if target.exists() and target.stat().st_size == item['bytes'] and sha(target) == item['sha256']:
            reports.append({**item, 'verified': True, 'cached': True})
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        n = (item['bytes'] + CHUNK - 1) // CHUNK
        received = 0
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(acquire, item, i) for i in range(n)]
            for future in as_completed(futures):
                received += future.result()
                if received // CHUNK % 16 == 0 or received == item['bytes']:
                    print(f'{item["id"]}: {received/1e9:.2f}/{item["bytes"]/1e9:.2f} GB ranges', flush=True)
        temporary = target.with_suffix('.assembling')
        parts = target.parent/(target.stem + '_ranges')
        digest = hashlib.sha256()
        with temporary.open('wb') as out:
            for i in range(n):
                with (parts/f'{i:05d}.part').open('rb') as f:
                    while block := f.read(1024 * 1024):
                        out.write(block)
                        digest.update(block)
        if temporary.stat().st_size != item['bytes'] or digest.hexdigest() != item['sha256']:
            raise ValueError('Full archive checksum gate failed')
        temporary.replace(target)
        reports.append({**item, 'verified': True, 'cached': False})
        print(f'Full archive verified: {item["id"]}', flush=True)
    result = {'date': '2026-11-12', 'scope': 'Allowlisted 03-11 acquisition only; no 01-12/final/slow/external payload opened.',
              'plan_sha256': sha(plan_path), 'revision': REV, 'archives': reports,
              'source_sha256': sha(ROOT/'src/download_cic2019_validation.py'),
              'elapsed_seconds': round(time.perf_counter() - started, 3), 'study_training_ready': False}
    (ROOT/'results/development/cic2019_acquisition_v1.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('Both development archives verified; reserved sources remain unopened.', flush=True)


if __name__ == '__main__':
    main()
