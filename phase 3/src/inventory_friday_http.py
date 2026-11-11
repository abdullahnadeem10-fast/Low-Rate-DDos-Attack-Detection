"""Inventory allowed Friday HTTP-service label candidates; assign no packet labels."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import socket

from friday_packet_audit import load_labels, ZIP_SHA, MEMBER


def main():
    groups, rows = load_labels()
    endpoints = defaultdict(Counter)
    for key, group in groups.items():
        if key[4] != 6:
            continue
        for address, port in ((key[0],key[1]),(key[2],key[3])):
            if port != 80:
                continue
            c = endpoints[socket.inet_ntoa(address)]
            if group['labels'] == {'BENIGN'}:
                c['unambiguous_benign_canonical_groups'] += 1
                c['rows_in_unambiguous_benign_groups'] += group['rows']
                c['expected_packets_in_unambiguous_benign_groups'] += group['fwd']+group['bwd']
            elif group['labels'] == {'DDoS'}:
                c['known_DDoS_canonical_groups'] += 1
            else:
                c['conflicting_label_canonical_groups'] += 1
    candidates = []
    for address, counts in endpoints.items():
        eligible = counts['unambiguous_benign_canonical_groups'] >= 100 and not (
            counts['known_DDoS_canonical_groups'] or counts['conflicting_label_canonical_groups'])
        candidates.append({'service':address+':80',**dict(counts),
            'metadata_inventory_eligible':eligible})
    candidates.sort(key=lambda c:(-c.get('unambiguous_benign_canonical_groups',0),c['service']))
    result = {'date':'2026-11-11','scope':'Metadata inventory only; no raw packet join or benign window labels assigned.',
        'archive_sha256':ZIP_SHA,'opened_member':MEMBER,'raw_class_rows':rows,
        'canonical_key_quarantine':'Reuse the Friday audit complete-key negative-duration exclusion policy.',
        'eligibility_rule':'At least 100 unambiguous benign canonical groups and no DDoS/conflicting groups at a TCP port-80 endpoint; not an efficacy/score-based rule.',
        'tcp_port_80_endpoints':len(candidates),'metadata_eligible_endpoints':sum(c['metadata_inventory_eligible'] for c in candidates),
        'top_endpoints':candidates[:20],
        'target_endpoint':next((c for c in candidates if c['service']=='192.168.10.50:80'),None),
        'packet_training_ready':False,
        'next_action':'Audit candidate HTTP payload, direction, capture coverage and clock/count joins before assigning windows; use server/session grouping and disclose network-path differences.',
        'limitations':['A matching port is not proof of HTTP or comparable service behaviour.',
            'Destination IPs route/group streams only and must never enter predictor columns.',
            'The current clean target-positive/lab-negative pool is source-label confounded; this inventory alone does not solve it.',
            'No slow-family/external source or final test was opened.']}
    out=Path(__file__).resolve().parents[1]/'results/development/friday_benign_http_candidates.json'
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__=='__main__': main()
