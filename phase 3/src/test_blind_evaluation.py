import unittest
import numpy as np
from blind_evaluation import decision_trace,window_metrics,alert_burden,episode_result,episode_summary,paired_cluster_bootstrap


def trace(first=0,last=220,positives=(),gaps=(),k=1,h=1):
    seconds=[t for t in range(first,last) if t not in gaps]
    scores=[1. if any(a<=t<b for a,b in positives) else 0. for t in seconds]
    return decision_trace(seconds,scores,k,h,.5)


class BlindEvaluation(unittest.TestCase):
    def test_strict_threshold_and_unobserved_history(self):
        rows=decision_trace(np.arange(7),[.5,.5,1,1,1,0,0],3,5,.5)
        self.assertTrue(all(r['alarm'] is None for r in rows[:4]))
        self.assertTrue(rows[4]['alarm'])
        self.assertFalse(decision_trace([0],[.5],1,1,.5)[0]['alarm'])

    def test_clock_gap_resets_input_history_and_rearming(self):
        rows=decision_trace([0,1,2,3,4,8,9,10],[0]*8,1,3,.5)
        self.assertIsNone(rows[5]['alarm']);self.assertIsNone(rows[6]['alarm'])
        self.assertFalse(rows[7]['alarm']);self.assertIsNone(rows[7]['alarm_episode_active'])

    def test_startup_alarm_is_not_a_qualified_onset(self):
        rows=trace(last=30,positives=[(0,30)])
        self.assertEqual(sum(r['new_alert_onset'] for r in rows),0)
        self.assertEqual(sum(r['unqualified_alert_start'] for r in rows),1)

    def test_five_quiet_seconds_rearm_but_short_off_gaps_do_not(self):
        rows=trace(last=30,positives=[(5,8),(10,12),(17,19)])
        self.assertEqual([r['utc_second'] for r in rows if r['new_alert_onset']],[5,17])

    def test_feature_invalidity_is_not_a_negative_decision(self):
        rows=decision_trace(np.arange(12),np.zeros(12),1,1,.5,feature_complete=[True]*6+[False]+[True]*5)
        self.assertIsNone(rows[6]['alarm']);self.assertIsNone(rows[7]['alarm_episode_active'])

    def test_unknown_labels_never_supply_TN_or_FN(self):
        rows=trace(last=12,positives=[(8,12)]);labels=[-1]*8+[1]*4
        m=window_metrics(rows,labels)
        self.assertEqual((m['TP'],m['TN'],m['FN'],m['unknown_windows']),(4,0,0,8))
        self.assertIsNone(m['fpr']);self.assertIsNone(m['AP'])

    def test_known_benign_history_support_is_explicit(self):
        rows=trace(last=12);labels=[0]*6+[-1]+[0]*5
        m=window_metrics(rows,labels)
        self.assertEqual(m['eligible_benign'],3)
        self.assertEqual(m['excluded_known_benign'],8)

    def test_primary_common_support_does_not_double_count_warmup(self):
        a=decision_trace(np.arange(10),np.zeros(10),1,1,.5)
        b=decision_trace(np.arange(10),np.zeros(10),3,5,.5)
        self.assertEqual(window_metrics(a,[0]*10)['eligible_benign'],6)
        self.assertEqual(window_metrics(b,[0]*10)['eligible_benign'],6)

    def test_warmup_can_supply_history_without_entering_measurement_denominator(self):
        rows=trace(last=20,positives=[(10,12)])
        result=window_metrics(rows,[0]*20,evaluation_mask=[False]*10+[True]*10)
        self.assertEqual((result['eligible_benign'],result['FP']),(10,2))

    def test_alert_burden_is_event_start_rate_not_alarm_window_FPR(self):
        rows=trace(last=30,positives=[(10,15)])
        b=alert_burden(rows,[0]*30)
        self.assertEqual(b['qualified_false_alert_starts'],1)
        self.assertEqual(window_metrics(rows,[0]*30)['FP'],5)

    def test_preexisting_alarm_gets_no_zero_delay_credit(self):
        rows=trace(positives=[(5,220)])
        result=episode_result(rows,20,20,210,0,220)
        self.assertEqual(result['status'],'miss');self.assertTrue(result['preexisting_alarm_at_onset'])
        self.assertIsNone(result['delay_seconds']);self.assertEqual(result['restricted_delay_seconds'],180)

    def test_preexisting_alarm_can_rearm_for_a_later_new_detection(self):
        rows=trace(positives=[(5,25),(31,220)])
        result=episode_result(rows,20,20,210,0,220)
        self.assertEqual(result['status'],'detected');self.assertEqual(result['delay_seconds'],13)

    def test_pre_onset_window_delivered_later_is_not_credited(self):
        rows=trace(positives=[(19,220)])
        result=episode_result(rows,20.25,20.25,210,0,220)
        self.assertEqual(result['status'],'miss')

    def test_window_end_and_reorder_are_included_in_replay_delay(self):
        rows=trace(positives=[(20,220)])
        result=episode_result(rows,20.25,20.25,210,0,220)
        self.assertEqual(result['delay_seconds'],1.75)

    def test_180_second_boundary_is_inclusive(self):
        rows=trace(last=240,positives=[(198,240)])
        self.assertEqual(episode_result(rows,20,20,230,0,240)['delay_seconds'],180)
        rows=trace(last=240,positives=[(199,240)])
        self.assertEqual(episode_result(rows,20,20,230,0,240)['status'],'miss')

    def test_episode_end_is_exclusive(self):
        rows=trace(positives=[(48,220)])
        self.assertEqual(episode_result(rows,20,20,50,0,220)['status'],'miss')

    def test_gap_after_detection_still_removes_primary_full_horizon_eligibility(self):
        rows=trace(positives=[(22,25)],gaps=[100])
        result=episode_result(rows,20,20,210,0,220)
        self.assertTrue(result['observed_detection']);self.assertFalse(result['episode_recall_eligible'])
        self.assertIsNone(result['delay_seconds'])

    def test_truncated_observation_is_censored_not_a_confident_miss(self):
        rows=trace(last=50)
        result=episode_result(rows,20,20,210,0,50)
        self.assertEqual(result['status'],'observation_censored');self.assertIsNone(result['binary_episode_hit'])

    def test_stale_pre_onset_history_is_not_observed_warmup(self):
        rows=trace(last=15)
        result=episode_result(rows,100,100,101,0,200)
        self.assertFalse(result['episode_recall_eligible'])

    def test_coarse_onset_never_creates_a_point_delay(self):
        rows=trace(positives=[(30,220)])
        result=episode_result(rows,20,25,210,0,220)
        self.assertIsNone(result['delay_seconds']);self.assertIsNone(result['binary_episode_hit'])
        self.assertTrue(result['single_alert_guarantees_timely_detection'])
        self.assertEqual(result['guaranteed_delay_interval_seconds'],[7,12])

    def test_summary_includes_misses_and_unscorable_bounds(self):
        hit=episode_result(trace(positives=[(22,220)]),20,20,210,0,220)
        miss=episode_result(trace(),20,20,210,0,220)
        censored=episode_result(trace(last=50),20,20,210,0,50)
        m=episode_summary([hit,miss,censored])
        self.assertEqual(m['episode_recall'],.5);self.assertEqual(m['all_recorded_hit_bounds'],[1/3,2/3])
        self.assertEqual(m['mean_penalty_coded_restricted_delay_seconds'],92)

    def test_fractional_or_duplicate_clock_is_rejected(self):
        for clock in ([1,1],[1,1.5]):
            with self.assertRaises(ValueError):decision_trace(clock,[0,0],1,1,.5)

    def test_future_append_cannot_change_earlier_trace(self):
        a=trace(last=20,positives=[(10,15)]);b=trace(last=30,positives=[(10,15),(20,30)])
        self.assertEqual(a,b[:20])


def pairs(parents=2,seeds=(7,19)):
    return [dict(parent=f'p{p}',stratum='family',session=f's{p}',seed=s,method=m,TP=8 if m=='hybrid' else 7,FN=2 if m=='hybrid' else 3,FP=0,TN=20)
            for p in range(parents) for s in seeds for m in ('AE','hybrid')]


class PairedBootstrap(unittest.TestCase):
    def test_one_capture_never_gets_a_window_based_CI(self):
        result=paired_cluster_bootstrap(pairs(1))
        self.assertEqual(result['status'],'insufficient_independent_parents');self.assertIsNone(result['CI95'])

    def test_seed_averaging_preserves_parent_count(self):
        result=paired_cluster_bootstrap(pairs())
        self.assertEqual(result['parent_count'],2);self.assertAlmostEqual(result['difference'],-.1)
        self.assertEqual(result['difference_order'],['AE','hybrid'])

    def test_missing_model_seed_or_pair_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'model seed'):paired_cluster_bootstrap(pairs()[:-1])
        with self.assertRaisesRegex(ValueError,'pairing'):paired_cluster_bootstrap([r for r in pairs() if not(r['parent']=='p1' and r['method']=='AE')])

    def test_shared_parent_across_strata_is_unsupported(self):
        r=pairs();r[-1]['stratum']='another_family'
        self.assertEqual(paired_cluster_bootstrap(r)['status'],'cross_stratum_parent_dependence')

if __name__=='__main__':unittest.main()
