import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from frozen_suite import contained,validate_qualification,authorize_qualification


def fixture():
    frozen=dict(sealed_at_utc=1000,source_slots={'lab_slow':dict(source_id='lab_final_slow',role='U',kind='lab'),
        'public_slow':dict(source_id='CICIDS2017/Wednesday',role='U',kind='public')},
        denied_development_parents=['CIC-DDoS2019/03-11','CICIDS2017/Friday'],denied_development_capture_hashes=['a'*64],
        feature_core_sha256='b'*64,predictor_columns=['fixture'])
    record=dict(freeze_sha256='c'*64,source_slot='lab_slow',source_id='lab_final_slow',role='U',parent_recording='new_session',
        group_id='new-session',raw_sha256='d'*64,qualification_pass=True,model_scores_used_for_qualification=False,
        unknown_or_idle_inferred_benign=False,feature_state_crosses_groups=False,feature_core_sha256='b'*64,predictor_columns=['fixture'],
        qualified_after_seal_utc=1100,payload_access_started_utc=1001,
        qualification_evidence={'provenance':{'sha256':'e'*64},'clock_labels':{'sha256':'f'*64}},
        scorable_clock_segments=[dict(start=2000,end=2300,core_reset=True,boundary_guard_seconds=50)],
        packet_quality=dict(truncated_records=0,selected_fragmented_tcp=0,late_selected_dropped=0,kernel_capture_drops=0),
        service=dict(protocol='TCP',port=80),label_provenance_verified=True,clock_alignment_verified=True,
        capture_started_utc=1002,isolated_private_lab_verified=True,all_planned_outcomes_retained=True)
    return frozen,record


class FrozenGate(unittest.TestCase):
    def test_qualified_new_lab_can_pass_without_fitting(self):
        frozen,record=fixture();self.assertTrue(validate_qualification(record,frozen,'c'*64))

    def test_development_parent_and_bytes_cannot_be_relabelled_final(self):
        for field,value in [('parent_recording','CIC-DDoS2019/03-11'),('raw_sha256','a'*64)]:
            f,r=fixture();r[field]=value
            with self.assertRaisesRegex(ValueError,'Development'):validate_qualification(r,f,'c'*64)

    def test_payload_access_must_follow_freeze_not_just_qualification(self):
        f,r=fixture();r['payload_access_started_utc']=999
        with self.assertRaisesRegex(ValueError,'accessed before'):validate_qualification(r,f,'c'*64)

    def test_model_score_driven_source_selection_is_rejected(self):
        f,r=fixture();r['model_scores_used_for_qualification']=True
        with self.assertRaisesRegex(ValueError,'score-selected'):validate_qualification(r,f,'c'*64)

    def test_unknown_idle_is_not_an_allowed_benign_label_basis(self):
        f,r=fixture();r['unknown_or_idle_inferred_benign']=True
        with self.assertRaisesRegex(ValueError,'labels/state'):validate_qualification(r,f,'c'*64)

    def test_no_cross_group_or_gap_state_carry(self):
        f,r=fixture();r['feature_state_crosses_groups']=True
        with self.assertRaises(ValueError):validate_qualification(r,f,'c'*64)
        f,r=fixture();r['scorable_clock_segments'][0]['core_reset']=False
        with self.assertRaisesRegex(ValueError,'reset/clock'):validate_qualification(r,f,'c'*64)

    def test_capture_loss_and_incompatible_service_fail_closed(self):
        f,r=fixture();r['packet_quality']['kernel_capture_drops']=1
        with self.assertRaises(ValueError):validate_qualification(r,f,'c'*64)
        for protocol,port in [('UDP',80),('TCP',12345)]:
            f,r=fixture();r['service']=dict(protocol=protocol,port=port)
            with self.assertRaisesRegex(ValueError,'Unsupported service'):validate_qualification(r,f,'c'*64)

    def test_public_unknown_kernel_drop_counter_is_not_fabricated_as_zero(self):
        f,r=fixture();r.update(source_slot='public_slow',source_id='CICIDS2017/Wednesday',parent_recording='CICIDS2017/Wednesday')
        r['packet_quality']['kernel_capture_drops']=None
        self.assertTrue(validate_qualification(r,f,'c'*64))

    def test_bad_schema_or_clock_alignment_is_rejected(self):
        f,r=fixture();r['predictor_columns']=['different']
        with self.assertRaisesRegex(ValueError,'feature contract'):validate_qualification(r,f,'c'*64)
        f,r=fixture();r['clock_alignment_verified']=False
        with self.assertRaisesRegex(ValueError,'truth/clock'):validate_qualification(r,f,'c'*64)

    def test_artifact_path_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'escapes'):contained(Path(tmp),'../other/weights.joblib')

    def test_overlapping_observation_segments_are_not_independent(self):
        f,r=fixture();r['scorable_clock_segments'].append(dict(start=2200,end=2400,core_reset=True,boundary_guard_seconds=50))
        with self.assertRaisesRegex(ValueError,'Overlapping'):validate_qualification(r,f,'c'*64)

    def test_incomplete_raw_fingerprint_and_old_lab_are_rejected(self):
        f,r=fixture();r['raw_sha256']='unknown'
        with self.assertRaisesRegex(ValueError,'fingerprint'):validate_qualification(r,f,'c'*64)
        f,r=fixture();r['capture_started_utc']=999
        with self.assertRaisesRegex(ValueError,'Old lab'):validate_qualification(r,f,'c'*64)

    def test_model_seal_alone_cannot_open_final_sources(self):
        f,r=fixture()
        with tempfile.TemporaryDirectory() as tmp,patch('frozen_suite.verify_freeze',return_value=(f,{'freeze_sha256':'c'*64})):
            with self.assertRaises(FileNotFoundError):authorize_qualification('lab_slow',Path(tmp))

    def test_nonfinite_observation_bound_is_rejected(self):
        f,r=fixture();r['scorable_clock_segments'][0]['end']=float('inf')
        with self.assertRaisesRegex(ValueError,'reset/clock'):validate_qualification(r,f,'c'*64)


if __name__=='__main__':unittest.main()
