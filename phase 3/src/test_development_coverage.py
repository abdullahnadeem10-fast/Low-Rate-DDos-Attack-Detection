import unittest
from review_development_coverage import labelled_history_count


class KnownHistory(unittest.TestCase):
    def test_unknown_gap_is_not_a_benign_second(self):
        seconds=[100,101,102,104,105]
        self.assertEqual(labelled_history_count(seconds,1),5)
        self.assertEqual(labelled_history_count(seconds,3),1)
        self.assertEqual(labelled_history_count(seconds,5),0)

    def test_duplicate_clock_second_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'Repeated timestamp'):
            labelled_history_count([100,100],3)

    def test_group_boundaries_do_not_supply_prior_history(self):
        self.assertEqual(labelled_history_count([100,101],3)+labelled_history_count([102,103],3),0)


if __name__=='__main__': unittest.main()
