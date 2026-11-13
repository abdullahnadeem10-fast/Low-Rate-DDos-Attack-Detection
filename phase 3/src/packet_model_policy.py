"""Temporal decisions/calibration for exploratory packet-window development.

No feature extraction, dataset acquisition, fitting or final-source access here.
Unknown labels never supply negative calibration/evaluation observations.
"""
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler

ROOT=Path(__file__).resolve().parents[1]
REGISTRY_SHA='885b74ab85552ac381d54f271fee9950b1dd64c48846b96a536bfb9e603e7735'
RULES=((1,1),(2,3),(3,5))
STRESS={'bursts','flash','long_download','congested_mixed'}
BENIGN_CONDITIONS={'public_http','ordinary','bursts','flash','mixed_keepalive','long_download','congested_mixed'}
SEEDS=(7,19,42,73,101)


def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def require(value,message):
    if not value: raise ValueError(message)


def rule_statistic(seconds,scores,k,h):
    """kth largest trailing h score; NaN denotes insufficient observed history.

Inputs belong to ONE group. Clock gaps invalidate windows, never zero-fill them.
Strict stat > tau equals at least k of the last h scores strictly exceeding tau.
"""
    seconds=np.asarray(seconds,dtype=np.int64);scores=np.asarray(scores,dtype=float)
    require(1<=k<=h and len(seconds)==len(scores),'Invalid temporal rule inputs')
    require(np.all(np.diff(seconds)>0),'Clock must be unique and increasing within group')
    require(np.isfinite(scores).all(),'Nonfinite decision score')
    result=np.full(len(scores),np.nan)
    if len(scores)>=h:
        sw=np.lib.stride_tricks.sliding_window_view(scores,h)
        tw=np.lib.stride_tricks.sliding_window_view(seconds,h)
        valid=(tw[:,-1]-tw[:,0])==h-1
        result[h-1:]=np.where(valid,np.partition(sw,h-k,axis=1)[:,h-k],np.nan)
    return result


def benign_views(items,h):
    """Independent per-group known-benign histories only; no cross-group state."""
    views=defaultdict(list)
    for group,seconds,scores in items:
        require(group['expected_y']==0,'Attack group reached benign calibration')
        require(group['condition'] in BENIGN_CONDITIONS,'Unmapped benign condition')
        values=np.asarray(scores,dtype=float);require(len(seconds)==len(values),'Length mismatch')
        # scores may already be trailing-rule statistics, with NaN at gaps.
        keep=np.isfinite(values)
        if keep.any():
            stratum='stress' if group['condition'] in STRESS else 'ordinary'
            for key in ('overall','stratum:'+stratum,'condition:'+group['condition']):
                views[key].extend(values[keep].tolist())
    return {key:np.asarray(values) for key,values in views.items()}


def calibrate(items,k,h,alpha=.01):
    """Smallest observed cutoff meeting ALL prespecified benign budgets.

Strict inequality handles ties. With n<100 at alpha=.01, zero exceedances are
required; n=0 is unsupported, never an automatic pass. Threshold may suppress
every attack and that negative result must be retained.
"""
    require(0<=alpha<1,'Invalid empirical false-positive budget')
    inputs=[]
    for group,seconds,values in items:
        require(group['role']=='C2','Only C2 may calibrate the operating threshold')
        inputs.append((group,seconds,rule_statistic(seconds,values,k,h)))
    views=benign_views(inputs,h)
    required={'overall','stratum:ordinary','stratum:stress'}|{'condition:'+c for c in BENIGN_CONDITIONS}
    require(required<=set(views),'Unsupported required calibration stratum')
    cutoffs=[]
    for values in views.values():
        n=len(values);allowed=math.floor(alpha*n+1e-12)
        cutoffs.append(float(np.sort(values)[n-allowed-1]))
    tau=max(cutoffs)
    report={key:{'eligible_windows':len(v),'false_positive_windows':int(np.sum(v>tau)),
                 'fpr':float(np.mean(v>tau)),'allowed_false_positive_windows':math.floor(alpha*len(v)+1e-12)} for key,v in views.items()}
    require(all(r['false_positive_windows']<=r['allowed_false_positive_windows'] for r in report.values()),'Calibration failed budget')
    return tau,report


def confusion(y,score,tau):
    y=np.asarray(y);score=np.asarray(score,dtype=float)
    require(len(y)==len(score) and np.isin(y,[0,1]).all() and np.isfinite(score).all(),'Invalid labelled metric inputs')
    p=score>tau;pos=y==1;neg=~pos
    tp=int(np.sum(p&pos));fn=int(np.sum(~p&pos));fp=int(np.sum(p&neg));tn=int(np.sum(~p&neg))
    return dict(TP=tp,FN=fn,FP=fp,TN=tn,positive_windows=tp+fn,benign_windows=fp+tn,
                recall=tp/(tp+fn) if tp+fn else None,fpr=fp/(fp+tn) if fp+tn else None,
                precision=tp/(tp+fp) if tp+fp else None,f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None)


class PacketTransform(BaseEstimator,TransformerMixin):
    """Signed log transform + median/robust scaling, fit by caller on T only."""
    def __init__(self,signed_columns=()): self.signed_columns=signed_columns
    def clean(self,x):
        z=np.asarray(x,dtype=float).copy()
        require(z.ndim==2 and all(0<=i<z.shape[1] for i in self.signed_columns),'Invalid signed schema')
        mask=np.zeros(z.shape[1],dtype=bool);mask[list(self.signed_columns)]=True
        z[~np.isfinite(z)|((z<0)&~mask[None,:])]=np.nan
        return np.where(mask[None,:],np.sign(z)*np.log1p(np.abs(z)),np.log1p(np.maximum(z,0)))
    def fit(self,x,y=None):
        self.imputer_=SimpleImputer(strategy='median',keep_empty_features=True)
        self.scaler_=RobustScaler().fit(self.imputer_.fit_transform(self.clean(x)))
        return self
    def transform(self,x): return self.scaler_.transform(self.imputer_.transform(self.clean(x)))


def checked_table(path,features,metadata=False):
    with path.open(encoding='utf-8',newline='') as f:
        reader=csv.DictReader(f); rows=list(reader)
        expected=set(features)|({'session_id','role','condition','y','utc_second','history_complete'} if metadata else {'utc_second','history_complete'})
        require(set(reader.fieldnames)==expected,'Predictor/metadata schema mismatch')
    seconds=np.asarray([int(r['utc_second']) for r in rows],dtype=np.int64)
    require(len(seconds)>0 and np.all(np.diff(seconds)>0),'Duplicate/out-of-order table clock')
    x=np.asarray([[float(r[p]) for p in features] for r in rows],dtype=float)
    require(np.isfinite(x).all(),'Nonfinite model features')
    return rows,seconds,x


def load_inputs(plan):
    registry_path=ROOT/plan['registry'];require(sha(registry_path)==REGISTRY_SHA==plan['registry_sha256'],'Only exact v5 whitelist is allowed')
    registry=read(registry_path);require(len(registry['groups'])==56,'Whitelist group count differs')
    features=registry['predictor_columns'];groups=[]
    for group in registry['groups']:
        path=ROOT/group['table'];require(sha(path)==group['sha256'],'Model table hash changed')
        rows,seconds,x=checked_table(path,features,True)
        require(len(rows)==group['expected_rows'],'Model row count changed')
        require(all((r['session_id'],r['role'],r['condition'],int(r['y']),int(r['history_complete']))==(group['id'],group['role'],group['condition'],group['expected_y'],1) for r in rows),'Group label/role/history mismatch')
        data=dict(meta=group,seconds=seconds,x=x,known=np.ones(len(rows),dtype=bool),y=np.full(len(rows),group['expected_y'],dtype=np.int8))
        if group['id']=='cic2019-03-11-syn-tcp443-v':
            source=plan['validation_positive_context'];context=ROOT/source['path']
            require(sha(context)==source['sha256'],'Permitted V context changed')
            full,ts,xx=checked_table(context,features,False)
            mask=(ts>=source['eligible_start'])&(ts<source['eligible_end'])&np.asarray([int(r['history_complete'])==1 for r in full])
            ts=ts[mask];xx=xx[mask];positions=np.searchsorted(ts,seconds)
            require(np.all(positions<len(ts)) and np.array_equal(ts[positions],seconds) and np.array_equal(xx[positions],x),'Known V rows differ from full permitted context')
            known=np.zeros(len(ts),dtype=bool);known[positions]=True
            y=np.full(len(ts),-1,dtype=np.int8);y[positions]=1
            data.update(seconds=ts,x=xx,known=known,y=y)
        groups.append(data)
    return features,groups
