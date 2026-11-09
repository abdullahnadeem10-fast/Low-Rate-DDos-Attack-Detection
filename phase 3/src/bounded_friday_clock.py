"""Corroborate clock alignment from completed tail ranges while full acquisition runs.

This is an interim range audit, not full-file verification or a final label join.
Original PCAPNG interface metadata is retained; only complete blocks are replayed.
"""
import hashlib
import json
from pathlib import Path
import struct

from friday_packet_audit import DATA, OUT, PCAP_SIZE, REV, load_labels, pass_one

SIZE=8*1024*1024
parts=DATA/'friday_ranges_8MiB'
last=(PCAP_SIZE-1)//SIZE
first=last
while first>max(0,last-31) and (parts/f'{first-1:03d}.part').exists(): first-=1
if last-first<1: raise ValueError('Need at least two contiguous completed tail ranges')

header_source=(parts/'000.part').read_bytes()[:1024*1024]
if header_source[:12]!=bytes.fromhex('0a0d0d0a480000004d3c2b1a'):
    raise ValueError('Unrecognised section metadata; inspect instead of guessing byte order')
pos=0; interfaces=0
while pos+12<len(header_source):
    kind,length=struct.unpack_from('<II',header_source,pos)
    if kind==6: break
    if kind==1: interfaces+=1
    if length<12 or struct.unpack_from('<I',header_source,pos+length-4)[0]!=length: raise ValueError('Invalid header metadata')
    pos+=length
prefix=header_source[:pos]
raw=b''.join((parts/f'{i:03d}.part').read_bytes() for i in range(first,last+1))
sha=hashlib.sha256(raw).hexdigest()

def valid_packet(position):
    if position+32>len(raw): return False
    kind,length,interface,hi,lo,caplen,wirelen=struct.unpack_from('<7I',raw,position)
    return (kind==6 and 32<=length<=1048576 and length%4==0 and position+length<=len(raw)
            and interface<interfaces and caplen<=wirelen and length>=32+(caplen+3)//4*4
            and struct.unpack_from('<I',raw,position+length-4)[0]==length
            and 1499385600 <= ((hi<<32)|lo)/1e6 <= 1499472000)

candidate=raw.find(b'\x06\x00\x00\x00')
while candidate>=0:
    if valid_packet(candidate):
        length=struct.unpack_from('<I',raw,candidate+4)[0]
        if valid_packet(candidate+length): break
    candidate=raw.find(b'\x06\x00\x00\x00',candidate+1)
if candidate<0: raise ValueError('Could not find two validated consecutive packet blocks')
position=candidate
while position+12<=len(raw):
    kind,length=struct.unpack_from('<II',raw,position)
    if length<12 or length%4 or position+length>len(raw): break
    if struct.unpack_from('<I',raw,position+length-4)[0]!=length: raise ValueError('Broken body block')
    position+=length
target=DATA/'friday_tail_clock_sample.pcapng'
target.write_bytes(prefix+raw[candidate:position])
groups,counts=load_labels()
offset,report=pass_one(target,groups)
result={'scope':'INTERIM: bounded tail clock corroboration only; full capture hash and label join pending.',
        'revision':REV,'source_byte_range':[first*SIZE,PCAP_SIZE-1],'range_sha256':sha,
        'discarded_initial_partial_bytes':candidate,'discarded_tail_bytes':len(raw)-position,
        'retained_interface_metadata_sha256':hashlib.sha256(prefix).hexdigest(),
        'clock_offset_seconds':offset,'csv_counts':counts,'clock_audit':report}
OUT.mkdir(parents=True,exist_ok=True)
(OUT/'friday_bounded_clock_audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2),flush=True)
