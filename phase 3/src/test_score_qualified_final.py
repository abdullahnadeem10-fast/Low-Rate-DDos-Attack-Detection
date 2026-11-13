import csv
from pathlib import Path
import tempfile
import unittest
from score_qualified_final import qualified_inputs


class QualifiedClock(unittest.TestCase):
    def fixture(self,root,gap=False):
        features=['packets_in']
        with (root/'features.csv').open('w',newline='',encoding='utf-8') as f:
            w=csv.writer(f);w.writerow(['utc_second','history_complete',*features])
            for t in range(100):
                if not(gap and t==70):w.writerow([t,1,0])
        with (root/'truth.csv').open('w',newline='',encoding='utf-8') as f:
            w=csv.writer(f);w.writerow(['utc_second','y','family','condition'])
            for t in range(60,90):
                if not(gap and t==70):w.writerow([t,0,'benign','ordinary'])
        return features,dict(features={'path':'features.csv'},ground_truth={'path':'truth.csv'},
            scorable_clock_segments=[dict(start=0,end=100,boundary_guard_seconds=50)],evaluation_intervals=[[60,90]])

    def test_missing_truth_is_unknown_and_warmup_retains_full_clock(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);features,record=self.fixture(root)
            clock,x,y,family,valid,evaluation=qualified_inputs(root,record,features)
            self.assertEqual(len(clock),100);self.assertEqual((y==-1).sum(),70)
            self.assertEqual(valid.sum(),50);self.assertEqual(evaluation.sum(),30)
            self.assertTrue(valid[50]);self.assertFalse(evaluation[50])

    def test_unreported_clock_gap_cannot_be_filled_or_compressed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);features,record=self.fixture(root,True)
            with self.assertRaisesRegex(ValueError,'Unreported observation gap'):qualified_inputs(root,record,features)

    def test_evaluation_outside_observation_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);features,record=self.fixture(root);record['scorable_clock_segments'][0]['end']=90
            record['evaluation_intervals']=[[80,100]]
            with self.assertRaisesRegex(ValueError,'outside qualified observation'):qualified_inputs(root,record,features)


if __name__=='__main__':unittest.main()
