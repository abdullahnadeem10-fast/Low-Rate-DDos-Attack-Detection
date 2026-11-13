"""Read-only frozen score suite and fail-closed final-source qualification gate.

This module never fits, calibrates, downloads or searches datasets. A freeze is
an integrity/analysis lock, not an accuracy claim or a qualification of test data.
"""
from pathlib import Path
import platform
import re
import joblib
import numpy as np
import sklearn
from packet_model_policy import ROOT,read,sha,require

FREEZE='results/development/final_freeze_v1.json'
GATE='results/development/final_freeze_gate_v1.json'


def contained(root,relative):
    require(isinstance(relative,str) and not Path(relative).is_absolute(),'Expected repository-relative artifact path')
    path=(root/relative).resolve();require(path.is_relative_to(root.resolve()),'Artifact escapes project')
    return path


def verify_freeze(root=ROOT,check_private=True):
    gate=read(root/GATE);path=root/FREEZE
    require(sha(path)==gate['freeze_sha256'],'Freeze seal changed')
    frozen=read(path)
    require(frozen['frozen'] and gate['engineering_gate_pass'] and not frozen['final_tests_run_at_seal'],'Not an eligible freeze')
    for name,expected in frozen['source_sha256'].items():require(sha(contained(root,name))==expected,'Frozen source changed: '+name)
    for name,expected in frozen['evidence_sha256'].items():require(sha(contained(root,name))==expected,'Frozen evidence changed: '+name)
    software=frozen['software']
    require(software['python']==platform.python_version() and software['numpy']==np.__version__ and software['sklearn']==sklearn.__version__,'Frozen runtime differs')
    if check_private:
        for component in frozen['components'].values():
            if component['method']=='rate':continue
            require(sha(contained(root,component['weights']['path']))==component['weights']['sha256'],'Frozen weights changed')
            require(sha(contained(root,component['C1_reference']['path']))==component['C1_reference']['sha256'],'Frozen C1 reference changed')
    return frozen,gate


class FrozenSuite:
    def __init__(self,root=ROOT):
        self.root=root;self.manifest,self.gate=verify_freeze(root);self.cache={}

    def score(self,case_id,x,columns):
        require(columns==self.manifest['predictor_columns'],'Frozen input order/schema differs')
        x=np.asarray(x,dtype=float)
        require(x.ndim==2 and x.shape[1]==30 and np.isfinite(x).all(),'Invalid frozen model input')
        unsigned=[i for i,n in enumerate(columns) if n!='packet_rate_change']
        require(np.all(x[:,unsigned]>=0),'Negative value outside signed frozen feature')
        require(case_id in self.manifest['cases'],'Unknown case; do not add post-test variants')
        case=self.manifest['cases'][case_id];values=[]
        for key in case['components']:
            item=self.manifest['components'][key];method=item['method']
            if method=='rate':score=x[:,columns.index('packets_in')]
            else:
                if key not in self.cache:
                    payload=joblib.load(contained(self.root,item['weights']['path']))
                    require(payload['features']==item['features'],'Weight input schema differs')
                    reference=np.load(contained(self.root,item['C1_reference']['path']),allow_pickle=False)
                    require(reference.shape==(1209,) and np.isfinite(reference).all() and np.all(np.diff(reference)>=0),'Invalid frozen reference')
                    self.cache[key]=(payload['model'],reference)
                model,reference=self.cache[key];idx=[columns.index(n) for n in item['features']];z=x[:,idx]
                if method=='AE':score=model.score(z)
                elif method=='IF':score=-model.named_steps['forest'].score_samples(model.named_steps['transform'].transform(z))
                else:score=model.predict_proba(z)[:,1]
            require(np.isfinite(score).all(),'Nonfinite final inference; report failure rather than change weights')
            if case['score_mode'] in ('c1_percentile','max_c1_percentiles'):
                require(method!='rate','Rate mapping is not a declared case')
                score=np.searchsorted(reference,score,side='right')/len(reference)
            values.append(score)
        return np.maximum.reduce(values) if case['score_mode']=='max_c1_percentiles' else values[0]


def authorize_qualification(slot_id,root=ROOT):
    frozen,gate=verify_freeze(root)
    require(slot_id in frozen['source_slots'],'Source not reserved in blind protocol')
    # Source-specific acquisition/collector adapters are a separate immutable
    # addendum, sealed BEFORE payload access; a model freeze alone cannot run it.
    seal=read(root/f'results/qualification/{slot_id}_acquisition_seal_v1.json')
    acquisition_path=contained(root,seal['path']);acquisition=read(acquisition_path)
    require(sha(acquisition_path)==seal['sha256'],'Acquisition addendum changed')
    require(acquisition['freeze_sha256']==gate['freeze_sha256'] and acquisition['source_slot']==slot_id,'Acquisition/freeze mismatch')
    require(np.isfinite(acquisition['sealed_at_utc']) and acquisition['sealed_at_utc']>=frozen['sealed_at_utc'],'Acquisition declaration predates freeze')
    require(acquisition['declared_before_payload_access'] is True and acquisition['model_scores_used_for_selection'] is False,'Invalid blind acquisition declaration')
    require(acquisition['source_sha256'] and acquisition['qualification_rules'] and acquisition['planned_units'],'Incomplete acquisition/qualification addendum')
    for path,expected in acquisition['source_sha256'].items():require(sha(contained(root,path))==expected,'Acquisition source changed')
    return dict(stage='qualification_only',source_slot=slot_id,freeze_sha256=gate['freeze_sha256'],
                acquisition_sha256=seal['sha256'],acquisition_sealed_at_utc=acquisition['sealed_at_utc'],
                raw_scoring_authorized=False,scope='Passive/source or new isolated-lab qualification only; no fitting or result-driven inclusion.')


def validate_qualification(record,frozen,freeze_sha):
    require(record['freeze_sha256']==freeze_sha,'Qualification belongs to another freeze')
    slot=record['source_slot'];require(slot in frozen['source_slots'],'Undeclared final source')
    spec=frozen['source_slots'][slot]
    require(record['source_id']==spec['source_id'] and record['role']==spec['role'],'Final source/role mismatch')
    require(record['parent_recording'] not in frozen['denied_development_parents'],'Development recording cannot become final')
    require(isinstance(record['group_id'],str) and re.fullmatch(r'[A-Za-z0-9_-]+',record['group_id']),'Unsafe/missing group identifier')
    require(re.fullmatch(r'[0-9a-f]{64}',record['raw_sha256']) is not None,'Missing exact raw fingerprint')
    require(record['raw_sha256'] not in frozen['denied_development_capture_hashes'],'Development bytes cannot become final')
    require(record['qualification_pass'] and record['model_scores_used_for_qualification'] is False,'Unqualified or score-selected source')
    require(record['unknown_or_idle_inferred_benign'] is False and record['feature_state_crosses_groups'] is False,'Invalid labels/state ownership')
    require(record['feature_core_sha256']==frozen['feature_core_sha256'] and record['predictor_columns']==frozen['predictor_columns'],'Changed final feature contract')
    require(np.isfinite(record['qualified_after_seal_utc']) and record['qualified_after_seal_utc']>=frozen['sealed_at_utc'],'Qualification predates freeze')
    require(np.isfinite(record['payload_access_started_utc']) and frozen['sealed_at_utc']<=record['payload_access_started_utc']<=record['qualified_after_seal_utc'],'Final payload accessed before freeze or after qualification')
    require(record['qualification_evidence']['provenance']['sha256'] and record['qualification_evidence']['clock_labels']['sha256'],'Qualification lacks evidence')
    require(record['scorable_clock_segments'] and all(np.isfinite([s['start'],s['end'],s['boundary_guard_seconds']]).all() and s['start']<s['end'] and s['core_reset'] and s['boundary_guard_seconds']>=50 for s in record['scorable_clock_segments']),'No qualified reset/clock segments')
    segments=sorted(record['scorable_clock_segments'],key=lambda s:s['start'])
    require(all(a['end']<=b['start'] for a,b in zip(segments,segments[1:])),'Overlapping observation segments')
    q=record['packet_quality']
    require(q['truncated_records']==0 and q['selected_fragmented_tcp']==0 and q['late_selected_dropped']==0,'Unsupported packet/capture quality')
    require(record['service']['protocol']=='TCP' and record['service']['port'] in (80,443),'Unsupported service/protocol')
    require(record['label_provenance_verified'] and record['clock_alignment_verified'],'Unsupported truth/clock')
    if spec['kind']=='lab':
        require(record['capture_started_utc']>frozen['sealed_at_utc'],'Old lab session cannot become final')
        require(q['kernel_capture_drops']==0 and record['isolated_private_lab_verified'] and record['all_planned_outcomes_retained'],'Invalid final lab capture/scope/selection')
    return True


def authorize_scoring(qualification_path,root=ROOT):
    frozen,gate=verify_freeze(root);record=read(qualification_path)
    acquisition=authorize_qualification(record['source_slot'],root)
    require(record['acquisition_sha256']==acquisition['acquisition_sha256'] and record['payload_access_started_utc']>=acquisition['acquisition_sealed_at_utc'],'Payload access preceded acquisition seal or addendum changed')
    validate_qualification(record,frozen,gate['freeze_sha256'])
    for file in [record['features'],record['ground_truth'],*record['qualification_evidence'].values()]:
        require(sha(contained(root,file['path']))==file['sha256'],'Qualified input/evidence bytes changed')
    return dict(stage='frozen_scoring_only',source_slot=record['source_slot'],freeze_sha256=gate['freeze_sha256'],
                qualification_sha256=sha(qualification_path),fitting_or_recalibration_allowed=False)
