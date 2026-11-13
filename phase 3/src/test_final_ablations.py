from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
from prepare_final_ablations import VARIANTS,ensure_new,signed_indices,calibration_scores,fit_control


class FinalAblations(unittest.TestCase):
    def test_missing_signed_feature_is_valid_after_history_ablation(self):
        self.assertEqual(signed_indices(['packets_in','bytes_in']),())
        self.assertEqual(signed_indices(['packets_in','packet_rate_change']),(1,))

    def test_published_output_guard_does_not_depend_on_private_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'published.json';p.write_text('{}')
            with self.assertRaises(FileExistsError):ensure_new([Path(tmp)/'missing_private',p])

    def test_attack_V_never_reaches_ablation_scoring(self):
        groups=[dict(meta=dict(id='c1',role='C1'),x=np.array([[1,2]])),dict(meta=dict(id='c2',role='C2'),x=np.array([[3,4]])),dict(meta=dict(id='v',role='V'),x=np.array([[999,999]]))]
        with patch('prepare_final_ablations.native_score',side_effect=lambda n,m,x,c:x[:,0]) as score:
            result=calibration_scores('HGB',None,groups,[0,1])
            self.assertEqual(set(result),{'c1','c2'});self.assertEqual(score.call_count,2)

    def test_controls_are_fixed_and_not_extra_search_grids(self):
        self.assertEqual(len(VARIANTS['no_rate_history']['remove']),7)
        self.assertEqual(len(VARIANTS['no_tcp_state_iat']['remove']),15)
        self.assertEqual(VARIANTS['no_persistence']['methods'],['AE','hybrid'])

    def test_weight_ablation_really_omits_sample_weights(self):
        groups=[];params=dict(HGB=dict(parameters=dict(max_iter=100,early_stopping=False)))
        with patch('prepare_final_ablations.labelled_matrix',return_value=(np.array([[1],[2]]),np.array([0,1]))),patch('prepare_final_ablations.HistGradientBoostingClassifier') as model:
            fit_control('HGB','no_hgb_class_weights',7,['packets_in'],[0],groups,params)
            self.assertNotIn('sample_weight',model.return_value.fit.call_args.kwargs)


if __name__=='__main__':unittest.main()
