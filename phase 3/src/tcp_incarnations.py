"""Conservative offline TCP-incarnation evidence, independent of labels/features.

Sequence/ACK coverage is observational consistency, not OS socket ground truth.
No inactivity timeout is used to invent a new incarnation. Missing/ambiguous
evidence stays unresolved; closed identities remain available for late packets.
"""
from dataclasses import dataclass, field

HALF = 1 << 31
MASK = (1 << 32) - 1
SYN, ACK, FIN, RST = 2, 16, 1, 4


def offset(seq, base):
    value = (int(seq) - base) & MASK
    return value if value < HALF else None


def includes(intervals, value):
    return value is not None and any(a <= value <= b for a, b in intervals)


def extend(intervals, start, end):
    """Closed byte-position intervals include the next byte ACK/empty-segment point."""
    if end >= HALF:
        return False
    merged = []
    for a, b in sorted(intervals + [(start, end)]):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    intervals[:] = merged
    return True


@dataclass
class Incarnation:
    identity: int
    key: tuple
    client_isn: int
    first_syn: float
    server_isn: int | None = None
    ambiguous: bool = False
    coverage_in: list = field(default_factory=lambda: [(0, 1)])
    coverage_out: list = field(default_factory=lambda: [(0, 1)])
    members: list = field(default_factory=list)
    first: float = float('inf')
    last: float = -float('inf')
    first_close: float | None = None
    fin_in: bool = False
    fin_out: bool = False
    handshake_ack: bool = False
    post_close_packets: int = 0
    exact_repeats: int = 0

    def possible(self, row):
        incoming = bool(row['inbound'])
        flags, payload = int(row['flags']), int(row['payload'])
        if float(row['timestamp']) < self.first_syn or self.ambiguous:
            return False
        own_base = self.client_isn if incoming else self.server_isn
        peer_base = self.server_isn if incoming else self.client_isn
        own_ranges = self.coverage_in if incoming else self.coverage_out
        peer_ranges = self.coverage_out if incoming else self.coverage_in
        # A SYN rejection can have arbitrary/zero server SEQ and no server ISN.
        if not incoming and self.server_isn is None:
            return bool(flags & RST and flags & ACK and payload == 0
                        and includes(self.coverage_in, offset(row['ack'], self.client_isn)))
        if own_base is None or not includes(own_ranges, offset(row['seq'], own_base)):
            return False
        if flags & ACK and (peer_base is None or not includes(peer_ranges, offset(row['ack'], peer_base))):
            return False
        return bool(payload or flags & (ACK | FIN | RST))

    def observe(self, index, row, exact_repeat=False):
        ts, flags = float(row['timestamp']), int(row['flags'])
        incoming = bool(row['inbound'])
        base = self.client_isn if incoming else self.server_isn
        ranges = self.coverage_in if incoming else self.coverage_out
        if base is not None:
            start = offset(row['seq'], base)
            if start is None or not extend(ranges, start, start + int(row['payload']) + bool(flags & SYN) + bool(flags & FIN)):
                self.ambiguous = True
        self.members.append(index)
        self.first, self.last = min(self.first, ts), max(self.last, ts)
        self.post_close_packets += int(self.first_close is not None and ts >= self.first_close)
        self.exact_repeats += int(exact_repeat)
        if incoming and flags & ACK and not flags & SYN and self.server_isn is not None:
            if int(row['seq']) == (self.client_isn + 1) & MASK and int(row['ack']) == (self.server_isn + 1) & MASK:
                self.handshake_ack = True
        if flags & FIN:
            if incoming:
                self.fin_in = True
            else:
                self.fin_out = True
        if self.first_close is None and (flags & RST or self.fin_in and self.fin_out):
            self.first_close = ts


def attribute_key(rows, indices, next_identity=0):
    """Attribute a complete chronological endpoint tuple; never choose by recency.

    Returns incarnations and index->identity/reason maps. A later unseen SYN or
    contradictory observation is not repaired by an arbitrary sequence tolerance.
    """
    key = (int(rows[indices[0]]['client']), int(rows[indices[0]]['port']))
    syns = {}
    for i in indices:
        row = rows[i]
        if row['inbound'] and int(row['flags']) & SYN and not int(row['flags']) & ACK:
            isn = int(row['seq'])
            if isn not in syns:
                syns[isn] = Incarnation(next_identity + len(syns), key, isn, float(row['timestamp']))
    # Pre-inventory exact handshake relationships. Conflicting server ISNs make
    # the client-SYN identity ambiguous rather than selecting the latest response.
    for i in indices:
        row = rows[i]
        if not row['inbound'] and int(row['flags']) & SYN and int(row['flags']) & ACK:
            c = syns.get((int(row['ack']) - 1) & MASK)
            if c is not None:
                isn = int(row['seq'])
                if c.server_isn is not None and c.server_isn != isn:
                    c.ambiguous = True
                else:
                    c.server_isn = isn
    assigned, reasons, signatures = {}, {}, {}
    for i in indices:
        row = rows[i]
        flags = int(row['flags'])
        signature = bytes(row['tcp_sha256'])
        candidates = []
        reason = 'sequence_ack_consistent'
        if row['inbound'] and flags & SYN and not flags & ACK:
            candidates = [syns[int(row['seq'])]]
            reason = 'initiating_syn'
        elif not row['inbound'] and flags & SYN and flags & ACK:
            c = syns.get((int(row['ack']) - 1) & MASK)
            candidates = [c] if c is not None else []
            reason = 'synack_matches_client_isn'
        elif not flags & SYN:
            candidates = [c for c in syns.values() if c.possible(row)]
        known_signatures = signatures.get(signature, set())
        # An exact repeated segment corroborates attribution; it cannot override
        # conflicting sequence candidates or create an identity without a SYN.
        if len(candidates) == 1 and not candidates[0].ambiguous:
            c = candidates[0]
            if known_signatures and known_signatures != {c.identity}:
                reasons[i] = 'conflicting_exact_segment_identity'
                continue
            repeated = c.identity in known_signatures
            c.observe(i, row, repeated)
            assigned[i] = c.identity
            reasons[i] = reason + ('_exact_repeat' if repeated else '')
            signatures.setdefault(signature, set()).add(c.identity)
        else:
            reasons[i] = 'ambiguous_identity' if candidates else 'no_supported_identity'
    return list(syns.values()), assigned, reasons
