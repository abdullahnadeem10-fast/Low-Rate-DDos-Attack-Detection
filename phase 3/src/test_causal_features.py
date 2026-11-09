"""Meaningful protocol fixtures for connection state and temporal leakage."""
import unittest
from causal_features import CausalFeatures, Event


class CausalChecks(unittest.TestCase):
    def event(self,t,flags=16,inbound=True,port=40000):
        return Event(t,'fixture-client',port,inbound,100,flags)

    def test_handshake_and_bidirectional_fin(self):
        c=CausalFeatures()
        c.add(self.event(.1,2)); c.add(self.event(.2,18,False)); c.add(self.event(.3,16))
        row=c.finish(1)[0]
        self.assertEqual((row['packets_in'],row['packets_out'],row['syn_in'],row['handshakes_completed']),(2,1,1,1))
        self.assertEqual((row['active_connections'],row['uncompleted_fraction']),(1,0))
        c.add(self.event(1.1,17)); self.assertEqual(c.finish(2)[0]['active_connections'],1)
        c.add(self.event(2.1,17,False)); self.assertEqual(c.finish(3)[0]['active_connections'],0)

    def test_expiry_rst_and_unknown_initial_age(self):
        c=CausalFeatures(timeout=3)
        c.add(self.event(.1)); row=c.finish(1)[0]
        self.assertEqual((row['unknown_age_connections'],row['active_age_max']),(1,0))
        self.assertEqual(c.finish(4)[-1]['active_connections'],0)
        c.add(self.event(4.1,2)); c.add(self.event(4.2,4))
        self.assertEqual(c.finish(5)[0]['active_connections'],0)

    def test_future_changes_cannot_change_closed_windows(self):
        a,b=CausalFeatures(),CausalFeatures()
        a.add(self.event(.1,2)); b.add(self.event(.1,2))
        ar=a.add(self.event(4.1,16)); br=b.add(self.event(4.1,4))
        self.assertEqual(ar,br)
        self.assertNotEqual(a.finish(5)[0],b.finish(5)[0])
        self.assertFalse(any(k in ar[0] for k in ('client','port','label','Flow Duration')))

    def test_history_and_reset(self):
        c=CausalFeatures(); c.add(self.event(.1,2)); rows=c.finish(21)
        self.assertEqual(rows[18]['history_complete'],0)
        self.assertEqual(rows[19]['history_complete'],1)
        self.assertEqual(rows[20]['packets_in_mean_20'],0)
        clean=CausalFeatures(); clean.add(self.event(25.1)); row=clean.finish(26)[0]
        self.assertEqual(row['known_age_connections'],0)
        self.assertEqual(row['history_complete'],0)

    def test_disorder_rejected(self):
        c=CausalFeatures(); c.add(self.event(2.1))
        with self.assertRaises(ValueError): c.add(self.event(2.0))


if __name__=='__main__': unittest.main(verbosity=2)
