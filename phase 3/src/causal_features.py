"""Packet-metadata features with explicit window closure, expiry and history reset.

This core accepts chronological events. A capture replay must handle late packets
before feeding it. Metadata identifiers are state keys, never returned predictors.
"""
from collections import deque
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Event:
    timestamp: float
    client: str
    client_port: int
    inbound: bool
    length: int
    flags: int


class Moments:
    def __init__(self): self.n=0; self.mean=0.; self.m2=0.
    def add(self,value):
        self.n+=1; delta=value-self.mean; self.mean+=delta/self.n; self.m2+=delta*(value-self.mean)
    @property
    def std(self): return math.sqrt(max(0.,self.m2/self.n)) if self.n else 0.


class CausalFeatures:
    """One destination-service stream; inactivity expires connections after 30 s.

    Connection age is known only when an initiating SYN was observed. Empty and
    partially observed starting windows are explicit. Instantiate anew per session.
    """
    SYN,ACK,FIN,RST=2,16,1,4
    def __init__(self, timeout=30):
        self.timeout=timeout; self.second=None; self.last_timestamp=-math.inf
        self.connections={}; self.history=deque(maxlen=20); self._reset_window()

    def _reset_window(self):
        self.counts={k:0 for k in ('packets_in','packets_out','bytes_in','bytes_out','syn_in',
            'ack_in','rst_in','synack_out','handshakes_completed','new_connections')}
        self.sources=set(); self.lengths=Moments(); self.iat=Moments(); self.last_inbound=None

    def _close(self):
        boundary=self.second+1
        for key in [k for k,v in self.connections.items() if boundary-v['last'] >= self.timeout]:
            del self.connections[key]
        known_ages=[boundary-v['start'] for v in self.connections.values() if v['start'] is not None]
        n=len(self.connections)
        row={'utc_second':self.second, **self.counts,'distinct_sources':len(self.sources),
             'packet_length_mean':self.lengths.mean,'packet_length_std':self.lengths.std,
             'inbound_iat_mean':self.iat.mean,'inbound_iat_std':self.iat.std,
             'active_connections':n,'known_age_connections':len(known_ages),
             'unknown_age_connections':n-len(known_ages),
             'active_age_mean':sum(known_ages)/len(known_ages) if known_ages else 0.,
             'active_age_max':max(known_ages,default=0.),
             'uncompleted_fraction':sum(not v['complete'] for v in self.connections.values())/n if n else 0.,
             'handshake_to_syn_ratio':self.counts['handshakes_completed']/max(1,self.counts['syn_in']),
             'in_out_byte_ratio':self.counts['bytes_in']/max(1,self.counts['bytes_out'])}
        incoming=self.counts['packets_in']
        row['packet_rate_change']=incoming-self.history[-1] if self.history else 0
        self.history.append(incoming)
        for h in (5,10,20):
            values=list(self.history)[-h:]
            row[f'packets_in_mean_{h}']=sum(values)/len(values)
            row[f'packets_in_std_{h}']=math.sqrt(sum((v-row[f'packets_in_mean_{h}'])**2 for v in values)/len(values))
        row['history_complete']=int(len(self.history)==20)
        self.second+=1; self._reset_window()
        return row

    def add(self,event):
        if event.timestamp < self.last_timestamp: raise ValueError('Events must be chronological')
        self.last_timestamp=event.timestamp
        s=int(event.timestamp)
        if self.second is None: self.second=s
        rows=[]
        while self.second < s: rows.append(self._close())
        direction='in' if event.inbound else 'out'
        self.counts[f'packets_{direction}']+=1
        self.counts[f'bytes_{direction}']+=event.length
        self.lengths.add(event.length)
        key=(event.client,event.client_port)
        # Expire before a later packet so tuple reuse is not treated as one connection.
        state=self.connections.get(key)
        if state and event.timestamp-state['last'] >= self.timeout:
            del self.connections[key]; state=None
        initial_syn=event.inbound and event.flags & self.SYN and not event.flags & self.ACK
        if state is None:
            state={'start':event.timestamp if initial_syn else None,'last':event.timestamp,
                   'synack':False,'complete':False,'fin_in':False,'fin_out':False}
            self.connections[key]=state; self.counts['new_connections']+=1
        elif initial_syn and state['complete']:
            state.update(start=event.timestamp,synack=False,complete=False,fin_in=False,fin_out=False)
            self.counts['new_connections']+=1
        state['last']=event.timestamp
        if event.inbound:
            self.sources.add(event.client)
            if self.last_inbound is not None: self.iat.add(event.timestamp-self.last_inbound)
            self.last_inbound=event.timestamp
            self.counts['syn_in']+=int(bool(initial_syn))
            self.counts['ack_in']+=int(bool(event.flags & self.ACK))
            self.counts['rst_in']+=int(bool(event.flags & self.RST))
            if state['start'] is not None and state['synack'] and event.flags & self.ACK and not initial_syn and not state['complete']:
                state['complete']=True; self.counts['handshakes_completed']+=1
        elif event.flags & self.SYN and event.flags & self.ACK:
            state['synack']=True; self.counts['synack_out']+=1
        if event.flags & self.FIN: state['fin_in' if event.inbound else 'fin_out']=True
        if event.flags & self.RST or state['fin_in'] and state['fin_out']:
            del self.connections[key]
        return rows

    def finish(self, boundary):
        """Emit only fully observed seconds strictly before an exclusive boundary."""
        rows=[]
        while self.second is not None and self.second < boundary: rows.append(self._close())
        return rows
