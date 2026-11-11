import unittest
from audit_benign_session import assemble,register_tcp
import dpkt
from collect_benign_repair import require_disjoint_seeds
from collect_benign_batch import select_windows, initial_partial_packets


class BenignAuditChecks(unittest.TestCase):
    def test_reordering_and_identical_retransmission(self):
        self.assertEqual(assemble([(103,b'def'),(100,b'abc'),(101,b'bcde')],100),b'abcdef')

    def test_gaps_and_conflicting_retransmission_fail(self):
        with self.assertRaises(ValueError): assemble([(100,b'ab'),(103,b'd')],100)
        with self.assertRaises(ValueError): assemble([(100,b'ab'),(101,b'x')],100)

    def test_sequence_wrap_is_not_a_gap(self):
        self.assertEqual(assemble([(0,b'cd'),(0xfffffffe,b'ab')],0xfffffffe),b'abcd')

    def test_partition_measurement_drops_warmup_and_partial_seconds(self):
        rows=[{'utc_second':str(i),'history_complete':str(int(i>=20)),'packets_in':'1'} for i in range(25)]
        result=select_windows(rows,19.5,23.5)
        self.assertEqual([int(r['utc_second']) for r in result],[20,21,22])

    def test_nonfinite_model_feature_fails(self):
        with self.assertRaises(ValueError):
            select_windows([{'utc_second':'20','history_complete':'1','packets_in':'nan'}],20,21)

    def test_first_partial_second_is_explicitly_counted(self):
        records=[(t,b'',0) for t in [100.8,100.9,101.,102.]]
        self.assertEqual(initial_partial_packets(records),2)

    def test_reused_port_and_delayed_old_payload_stay_separate(self):
        streams={}; key=('fixture',40000)
        for client,server in [(100,200),(100000,200000)]:
            register_tcp(streams,key,dpkt.tcp.TCP(seq=client,flags=2),True,16384)
            register_tcp(streams,key,dpkt.tcp.TCP(seq=server,ack=client+1,flags=18),False,16384)
            register_tcp(streams,key,dpkt.tcp.TCP(seq=client+1,flags=16,data=b'GET'),True,16384)
        register_tcp(streams,key,dpkt.tcp.TCP(seq=104,flags=16,data=b' OLD'),True,16384)
        self.assertEqual(len(streams[key]),2)
        self.assertEqual(assemble(streams[key][0]['in'],101),b'GET OLD')
        self.assertEqual(assemble(streams[key][1]['in'],100001),b'GET')

    def test_additive_client_seed_overlap_is_rejected(self):
        with self.assertRaises(ValueError):
            require_disjoint_seeds([{'seed':1002,'clients':3},{'seed':2002,'clients':3}])
        self.assertEqual(len(require_disjoint_seeds([{'seed':1002,'clients':3},{'seed':200002,'clients':3}])),6)


if __name__=='__main__': unittest.main(verbosity=2)
