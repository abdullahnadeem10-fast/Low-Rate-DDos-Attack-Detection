import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
import packet_model_policy as policy
from packet_model_policy import rule_statistic,calibrate,confusion,PacketTransform,BENIGN_CONDITIONS
from run_packet_model_development import labelled_matrix,fit_model,choose_rule,validation_metrics


def calibration_items(n=300):
    return [(dict(id=c,role='C2',condition=c,expected_y=0),np.arange(n),np.arange(n,dtype=float)) for c in sorted(BENIGN_CONDITIONS)]


def group(role,y,values,source='lab_benign_v3'):
    return dict(meta=dict(role=role,expected_y=y,source=source),x=np.asarray(values,dtype=float),
                known=np.ones(len(values),dtype=bool),y=np.full(len(values),y,dtype=np.int8))


class PacketModelPolicy(unittest.TestCase):
    def test_kth_largest_matches_strict_k_of_h_with_ties(self):
        scores=np.random.default_rng(7).integers(0,5,60).astype(float)
        for k,h in policy.RULES:
            values=rule_statistic(np.arange(60),scores,k,h)
            for tau in (0,1,2,3,4):
                expected=[np.sum(scores[t-h+1:t+1]>tau)>=k for t in range(h-1,60)]
                np.testing.assert_array_equal(values[h-1:]>tau,expected)

    def test_missing_second_does_not_join_clock_history(self):
        result=rule_statistic([1,2,4,5,6],[9]*5,2,3)
        self.assertTrue(np.isnan(result[:4]).all());self.assertEqual(result[4],9)

    def test_duplicate_or_backward_clock_is_rejected(self):
        for clock in ([1,1],[2,1]):
            with self.assertRaisesRegex(ValueError,'Clock'):rule_statistic(clock,[1,1],1,1)

    def test_future_append_does_not_change_decisions(self):
        a=rule_statistic(np.arange(12),np.arange(12),2,3)
        b=rule_statistic(np.arange(16),np.r_[np.arange(12),[999]*4],2,3)
        np.testing.assert_array_equal(a,b[:12])

    def test_group_boundary_resets_decision_state(self):
        for clock in ([1,2],[3,4]): self.assertTrue(np.isnan(rule_statistic(clock,[99,99],2,3)).all())

    def test_joint_strata_budget_and_smallest_order_statistic(self):
        tau,views=calibrate(calibration_items(),1,1)
        self.assertEqual(tau,296)
        self.assertTrue(all(v['false_positive_windows']<=v['allowed_false_positive_windows'] for v in views.values()))
        self.assertEqual(views['condition:flash']['false_positive_windows'],3)

    def test_small_strata_allow_zero_exceedances(self):
        tau,views=calibrate(calibration_items(13),1,1)
        self.assertEqual(tau,12);self.assertEqual(views['condition:flash']['false_positive_windows'],0)

    def test_saturation_is_preserved_instead_of_forcing_detection(self):
        items=calibration_items(13);items=[(g,t,np.ones(13)) for g,t,s in items]
        tau,_=calibrate(items,1,1);self.assertEqual(tau,1)
        self.assertEqual(confusion([1,1],[1,1],tau)['TP'],0)

    def test_unsupported_condition_is_not_an_automatic_pass(self):
        with self.assertRaisesRegex(ValueError,'Unsupported'):calibrate(calibration_items()[1:],1,1)

    def test_attack_or_wrong_role_cannot_calibrate(self):
        items=calibration_items();items[0][0]['role']='C1'
        with self.assertRaisesRegex(ValueError,'Only C2'):calibrate(items,1,1)
        items=calibration_items();items[0][0]['expected_y']=1
        with self.assertRaisesRegex(ValueError,'Attack group'):calibrate(items,1,1)

    def test_unknown_label_cannot_enter_confusion_counts(self):
        with self.assertRaisesRegex(ValueError,'labelled metric'):confusion([0,-1,1],[0,0,1],.5)

    def test_V_unknown_score_history_never_enters_ground_truth_counts(self):
        positive=group('V',1,np.zeros((100,2)),'CIC-DDoS2019_03-11')
        positive['meta'].update(id='positive',condition='public_syn_tcp443')
        positive['seconds']=np.arange(100);positive['known'][:]=False
        positive['known'][10:98:2]=True;positive['y'][:]=-1;positive['y'][positive['known']]=1
        benign=group('V',0,np.zeros((20,2)));benign['meta'].update(id='benign',condition='ordinary');benign['seconds']=np.arange(20)
        result=validation_metrics([positive,benign],dict(positive=np.full(100,.9),benign=np.full(20,.1)),3,5,.5)
        self.assertEqual(result['all_supported']['TP'],44)
        self.assertEqual(result['all_supported']['TN'],16)
        self.assertEqual(result['all_supported']['positive_windows']+result['all_supported']['benign_windows'],60)

    def test_transform_keeps_signed_feature_and_does_not_refit_on_validation(self):
        x=np.array([[-2,1],[0,2],[3,4]],dtype=float);m=PacketTransform((0,)).fit(x)
        self.assertLess(m.clean(x)[0,0],0)
        before=copy.deepcopy(m.scaler_.center_);m.transform([[1e9,1e9]])
        np.testing.assert_array_equal(before,m.scaler_.center_)

    def test_fit_matrix_never_includes_calibration_or_validation(self):
        groups=[group('T',0,[[1,1],[2,2]]),group('T',1,[[3,3]],'Friday_public'),
                group('T',0,[[4,4]],'Friday_public'),group('V',0,[[99,99]]),group('C1',0,[[88,88]]),group('C2',0,[[77,77]])]
        x,y=labelled_matrix(groups,'T',False,True)
        np.testing.assert_array_equal(x,[[1,1],[2,2],[3,3]])
        x,y=labelled_matrix(groups,'T',True,True);self.assertEqual(len(x),2);self.assertTrue(np.all(y==0))

    def test_AE_fit_receives_only_benign_T_and_early_stop_benign_V(self):
        groups=[group('T',0,[[1,2],[2,3]]),group('T',1,[[99,99]]),group('V',0,[[4,5]]),group('V',1,[[88,88]])]
        with patch('run_packet_model_development.BenignAutoencoder') as ae:
            fit_model('AE',dict(max_epochs=2,patience=1),7,['packet_rate_change','packets_in'],groups,[0,1])
            args=ae.return_value.fit.call_args.args
            np.testing.assert_array_equal(args[0],[[1,2],[2,3]]);np.testing.assert_array_equal(args[2],[[4,5]])

    def test_rule_tie_prefers_prespecified_lower_horizon(self):
        metric=dict(recall=.5,fpr=.01)
        rows=[dict(V=dict(common_5_window_support=metric)) for _ in range(3)]
        index,_=choose_rule([rows,rows]);self.assertEqual(index,0)

    def test_registry_guard_prevents_any_nonwhitelisted_source_loading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'changed.json';path.write_text('{}')
            with patch.object(policy,'ROOT',Path(tmp)):
                with self.assertRaisesRegex(ValueError,'exact v5'):
                    policy.load_inputs(dict(registry='changed.json',registry_sha256='bad'))


if __name__=='__main__':unittest.main()
