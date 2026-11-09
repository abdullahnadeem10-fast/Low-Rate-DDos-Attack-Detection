"""Auxiliary completed-flow baselines, NOT the planned causal packet-window study.

Only Friday known-family CSV is read. V is development, never a final result.
Entire connection keys are kept out of multiple partitions; later rows are unscored.
"""
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import time
from zipfile import ZipFile

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits
from benign_autoencoder import BenignAutoencoder, benign_percentiles

from friday_packet_audit import ARCHIVE, MEMBER, OUT, ZIP_SHA

COLS=['Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets',
      'Total Length of Bwd Packets','Fwd Packet Length Mean','Bwd Packet Length Mean',
      'Flow IAT Mean','Flow IAT Std','SYN Flag Count','ACK Flag Count','RST Flag Count',
      'Packet Length Mean','Packet Length Std']


def minute(s):
    t=datetime.strptime(s,'%d/%m/%Y %H:%M')
    if t.date().isoformat()!='2017-07-07': raise ValueError('Unexpected date')
    return t.hour*60+t.minute


def partition(start,latest_end):
    for name,a,b in [('T',210,220),('C1',221,225),('C2',226,230),('T',231,240),('V',241,248)]:
        if start >= a and latest_end < b: return name
    return None


def canonical(row):
    ends=sorted([(row['Source IP'],int(row['Source Port'])),(row['Destination IP'],int(row['Destination Port']))])
    return (*ends,int(row['Protocol']))


def acquire_rows():
    with ARCHIVE.open('rb') as f:
        if hashlib.file_digest(f,'sha256').hexdigest()!=ZIP_SHA: raise ValueError('Archive checksum mismatch')
    candidates=[]; assignment=defaultdict(set); counts=Counter()
    with ZipFile(ARCHIVE) as z,z.open(MEMBER) as f:
        reader=csv.DictReader(io.TextIOWrapper(f,encoding='utf-8-sig'))
        for raw in reader:
            row={k.strip():v.strip() for k,v in raw.items()}
            if row['Label'] not in ('BENIGN','DDoS'): raise ValueError('Excluded/unexpected label')
            start=minute(row['Timestamp']); duration=float(row['Flow Duration'])/1e6
            if duration < 0: counts['negative_duration']+=1; continue
            # The printed minute admits a possible additional 60 seconds at flow start.
            end=start+1+duration/60
            split=partition(start,end)
            if split is None: counts['outside_development_intervals']+=1; continue
            key=canonical(row); assignment[key].add(split)
            x=[float(row[c]) for c in COLS]
            candidates.append((split,key,x,int(row['Label']=='DDoS')))
    sets={s:([],[]) for s in ('T','C1','C2','V')}
    for split,key,x,y in candidates:
        if len(assignment[key])!=1: counts['cross_partition_key_rows_removed']+=1; continue
        sets[split][0].append(x); sets[split][1].append(y)
    arrays={s:(np.array(x,dtype=np.float64),np.array(y,dtype=np.int8)) for s,(x,y) in sets.items()}
    keys={s:{key for split,key,x,y in candidates if split==s and len(assignment[key])==1} for s in sets}
    assert all(not keys[a]&keys[b] for a in sets for b in sets if a<b)
    for s,(x,y) in arrays.items():
        if not len(x): raise ValueError(f'Empty partition {s}')
        x[~np.isfinite(x)]=np.nan
    return arrays,dict(counts),{s:len(v) for s,v in keys.items()}


def metrics(y,score,tau):
    pred=score>tau
    tn,fp,fn,tp=map(int,confusion_matrix(y,pred,labels=[0,1]).ravel())
    return {'TP':tp,'FP':fp,'TN':tn,'FN':fn,'recall':tp/(tp+fn) if tp+fn else None,
            'fpr':fp/(fp+tn) if fp+tn else None,'precision':tp/(tp+fp) if tp+fp else None,
            'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
            'AP':float(average_precision_score(y,score)) if len(set(y))==2 else None,
            'ROC_AUC':float(roc_auc_score(y,score)) if len(set(y))==2 else None}


def main():
    started=time.perf_counter(); sets,exclusions,groups=acquire_rows()
    x,y=sets['T']; cx,cy=sets['C2']; vx,vy=sets['V']
    if set(y)!={0,1} or sum(cy==0)<100: raise ValueError('Insufficient training/calibration classes')
    algorithms={
        'LogisticRegression':make_pipeline(SimpleImputer(strategy='median',add_indicator=True),StandardScaler(),
                                           LogisticRegression(class_weight='balanced',max_iter=1000,random_state=7)),
        'RandomForest':make_pipeline(SimpleImputer(strategy='median',add_indicator=True),
                                     RandomForestClassifier(n_estimators=100,max_depth=12,class_weight='balanced',random_state=7,n_jobs=2)),
        'HistGradientBoosting':HistGradientBoostingClassifier(max_iter=100,max_leaf_nodes=15,early_stopping=False,random_state=7)}
    results={}
    for name,model in algorithms.items():
        t=time.perf_counter()
        with threadpool_limits(limits=2):
            if name=='HistGradientBoosting':
                freq=np.bincount(y,minlength=2); model.fit(x,y,sample_weight=len(y)/(2*freq[y]))
            else: model.fit(x,y)
            benign_scores=model.predict_proba(cx[cy==0])[:,1]
            tau=float(np.quantile(benign_scores,.99,method='higher'))
            score=model.predict_proba(vx)[:,1]
        results[name]={'threshold':tau,'C2_benign_rows':len(benign_scores),
                       'C2_fpr':float(np.mean(benign_scores>tau)),
                       'V_development_metrics':metrics(vy,score,tau),
                       'fit_and_score_seconds':round(time.perf_counter()-t,3)}
        print(name,json.dumps(results[name]),flush=True)
    # An auxiliary score-fusion check only. Flow rows have no one-second decision
    # sequence, so this does not implement or validate the planned persistence rule.
    with threadpool_limits(limits=2):
        ae=BenignAutoencoder().fit(x[y==0],y[y==0],vx[vy==0],vy[vy==0])
        r1x,r1y=sets['C1']; r1x=r1x[r1y==0]
        hgb=algorithms['HistGradientBoosting']
        supervised_reference=hgb.predict_proba(r1x)[:,1]
        anomaly_reference=ae.score(r1x)
        anomaly_cal=ae.score(cx[cy==0]); anomaly_v=ae.score(vx)
        supervised_cal=hgb.predict_proba(cx[cy==0])[:,1]
        supervised_v=hgb.predict_proba(vx)[:,1]
        hybrid_cal=np.maximum(benign_percentiles(supervised_reference,supervised_cal),benign_percentiles(anomaly_reference,anomaly_cal))
        hybrid_v=np.maximum(benign_percentiles(supervised_reference,supervised_v),benign_percentiles(anomaly_reference,anomaly_v))
    for name,cal,values in [('Autoencoder',anomaly_cal,anomaly_v),('HGB_AE_score_fusion',hybrid_cal,hybrid_v)]:
        tau=float(np.quantile(cal,.99,method='higher'))
        results[name]={'threshold':tau,'C2_benign_rows':len(cal),'C2_fpr':float(np.mean(cal>tau)),
                       'V_development_metrics':metrics(vy,values,tau),'score_only_no_persistence':True}
        print(name,json.dumps(results[name]),flush=True)
    report={'scope':'Auxiliary completed-flow development check; NOT final results or causal/live detection.',
            'source_member':MEMBER,'source_sha256':ZIP_SHA,'features':COLS,
            'partition_clock':'CSV values as written; absolute UTC conversion is not needed for this auxiliary order-only split.',
            'partitions':{s:{'rows':len(y),'benign':int(sum(y==0)),'known_DDoS':int(sum(y==1)),
                             'connection_groups':groups[s]} for s,(x,y) in sets.items()},
            'intervals_minutes_as_written':{'T':[[210,220],[231,240]],'C1':[[221,225]],'C2':[[226,230]],'V':[[241,248]]},
            'exclusions':exclusions,'results':results,
            'autoencoder':{'best_epoch':ae.best_epoch,'epochs_run':len(ae.history),'history':ae.history},
            'seconds':round(time.perf_counter()-started,3),
            'limitations':['One known flooding episode; contiguous blocks do not supply independent attack replications.',
                'Benign CSV flows span services; this is not a matched benign HTTP packet-window calibration set and service/traffic confounding remains possible.',
                'V was inspected only for development. No final K/U or external dataset was scored.',
                'Finished-flow features include end-of-flow information and cannot establish early detection or alert latency.',
                'C2 here is normal benign CSV traffic only; no benign-stress calibration, one-second persistence tuning or final freeze.',
                'One seed and prespecified settings are preliminary; full matched five-seed comparisons remain pending.']}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'completed_flow_development.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('Saved auxiliary development evidence.',flush=True)


if __name__=='__main__': main()
