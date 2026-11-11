from collections import defaultdict,Counter
import unittest
from audit_friday_http_services import qualified_keys,second_status


class HttpCandidateAuditChecks(unittest.TestCase):
    def test_count_agreement_without_http_or_with_a_mismatch_is_not_enough(self):
        groups={k:{'labels':{'BENIGN'},'fwd':2,'bwd':1} for k in range(3)}
        actual=defaultdict(Counter,{0:Counter(fwd=2,bwd=1),1:Counter(fwd=2,bwd=1),2:Counter(fwd=1,bwd=1)})
        self.assertEqual(qualified_keys(groups,actual,{0,2}),{0})

    def test_empty_or_partly_unknown_second_never_defaults_to_benign(self):
        self.assertEqual(second_status(0,0),'not_labelled')
        self.assertEqual(second_status(10,9),'uncertain')
        self.assertEqual(second_status(10,10),'benign_only')
        with self.assertRaises(ValueError): second_status(10,11)


if __name__=='__main__': unittest.main(verbosity=2)
