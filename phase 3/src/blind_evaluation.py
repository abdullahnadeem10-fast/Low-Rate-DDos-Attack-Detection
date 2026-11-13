"""Frozen evaluation definitions; no model fitting or dataset discovery.

Decision state depends on scores, clocks and observation validity, NEVER labels.
Labels affect only metric eligibility. A replay availability proxy is explicitly
separate from measured end-to-end live latency.
"""
import math
import numpy as np
from sklearn.metrics import average_precision_score,roc_auc_score


def require(value,message):
    if not value:raise ValueError(message)


def clock_array(seconds):
    raw=np.asarray(seconds,dtype=float)
    require(raw.ndim==1 and np.isfinite(raw).all() and np.equal(raw,np.floor(raw)).all(),'Clock must contain finite integer seconds')
    values=raw.astype(np.int64);require(np.all(np.diff(values)>0),'Clock must be unique and increasing')
    return values


def decision_trace(seconds,scores,k,h,tau,feature_complete=None,reorder_seconds=1):
    clock=clock_array(seconds);scores=np.asarray(scores,dtype=float)
    require(scores.ndim==1 and len(scores)==len(clock) and not np.isinf(scores).any(),'Invalid score stream')
    require(1<=k<=h<=5 and np.isfinite(tau) and reorder_seconds==1,'Rule differs from frozen contract')
    complete=np.ones(len(clock),dtype=bool) if feature_complete is None else np.asarray(feature_complete,dtype=bool)
    require(complete.shape==scores.shape,'Feature-observation mask differs')
    valid=complete&np.isfinite(scores);rows=[];quiet=0;active=None
    for i,t in enumerate(clock):
        if i and t-clock[i-1]!=1:quiet=0;active=None
        observed=i>=h-1 and t-clock[i-h+1]==h-1 and bool(valid[i-h+1:i+1].all())
        stat=float(np.partition(scores[i-h+1:i+1],h-k)[h-k]) if observed else None
        alarm=bool(stat>tau) if observed else None
        new=False;unqualified=False
        if alarm is None:quiet=0;active=None
        elif alarm:
            new=quiet>=5;unqualified=not new and active is None
            quiet=0;active=True
        else:
            quiet+=1
            if quiet>=5:active=False
        rows.append(dict(utc_second=int(t),window_end_utc=int(t)+1,availability_proxy_utc=int(t)+2,
            input_valid=bool(valid[i]),statistic=stat,alarm=alarm,new_alert_onset=new,
            unqualified_alert_start=unqualified,alarm_episode_active=active))
    return rows


def window_metrics(trace,labels,history=5,evaluation_mask=None):
    require(history in (1,3,5) and len(trace)==len(labels),'Invalid metric history')
    labels=np.asarray(labels);require(np.isin(labels,[-1,0,1]).all(),'Labels must be -1 unknown,0 benign,1 attack')
    evaluation=np.ones(len(trace),dtype=bool) if evaluation_mask is None else np.asarray(evaluation_mask,dtype=bool)
    require(evaluation.shape==labels.shape,'Evaluation mask differs')
    clock=clock_array([r['utc_second'] for r in trace]);valid=[]
    for i,row in enumerate(trace):
        observed=i>=history-1 and clock[i]-clock[i-history+1]==history-1 and all(r['input_valid'] for r in trace[i-history+1:i+1])
        eligible=evaluation[i] and observed and row['alarm'] is not None and (labels[i]==1 or labels[i]==0 and bool(np.all(labels[i-history+1:i+1]==0)))
        valid.append(bool(eligible))
    valid=np.asarray(valid,dtype=bool);y=labels[valid].astype(int)
    alarms=np.asarray([bool(r['alarm']) for r in trace])[valid]
    stats=np.asarray([r['statistic'] if r['statistic'] is not None else np.nan for r in trace])[valid]
    pos=y==1;neg=y==0
    tp=int(np.sum(pos&alarms));fn=int(np.sum(pos&~alarms));fp=int(np.sum(neg&alarms));tn=int(np.sum(neg&~alarms))
    total_pos=int(np.sum((labels==1)&evaluation));total_neg=int(np.sum((labels==0)&evaluation));excluded_pos=total_pos-tp-fn;excluded_neg=total_neg-fp-tn
    return dict(TP=tp,FN=fn,FP=fp,TN=tn,eligible_positive=tp+fn,eligible_benign=fp+tn,
        total_known_positive=total_pos,total_known_benign=total_neg,unknown_windows=int(np.sum((labels==-1)&evaluation)),
        excluded_known_positive=excluded_pos,excluded_known_benign=excluded_neg,
        recall=tp/(tp+fn) if tp+fn else None,fpr=fp/(fp+tn) if fp+tn else None,
        precision=tp/(tp+fp) if tp+fp else None,f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
        AP=float(average_precision_score(y,stats)) if len(np.unique(y))==2 else None,
        ROC_AUC=float(roc_auc_score(y,stats)) if len(np.unique(y))==2 else None,
        all_known_recall_bounds=[tp/total_pos,(tp+excluded_pos)/total_pos] if total_pos else None,
        all_known_fpr_bounds=[fp/total_neg,(fp+excluded_neg)/total_neg] if total_neg else None,
        score_basis='kth-largest trailing-h decision statistic on stated eligible support',
        common_label_history=history)


def alert_burden(trace,labels,history=5,evaluation_mask=None):
    """Qualified starts in unambiguously benign context; unknowns unattributed."""
    require(len(trace)==len(labels),'Label length mismatch');labels=np.asarray(labels)
    require(np.isin(labels,[-1,0,1]).all(),'Invalid labels')
    evaluation=np.ones(len(trace),dtype=bool) if evaluation_mask is None else np.asarray(evaluation_mask,dtype=bool)
    require(evaluation.shape==labels.shape,'Evaluation mask differs')
    clock=clock_array([r['utc_second'] for r in trace]);required=max(history,6)
    starts=0;unattributed=0;eligible_seconds=0
    for i,row in enumerate(trace):
        eligible=evaluation[i] and i>=required-1 and clock[i]-clock[i-required+1]==required-1 and all(r['input_valid'] for r in trace[i-required+1:i+1]) and bool(np.all(labels[i-required+1:i+1]==0)) and row['alarm'] is not None
        eligible_seconds+=int(eligible)
        if evaluation[i] and row['new_alert_onset']:
            if eligible:starts+=1
            else:unattributed+=1
    return dict(qualified_false_alert_starts=starts,eligible_benign_seconds=eligible_seconds,
        false_alert_starts_per_hour=starts*3600/eligible_seconds if eligible_seconds else None,
        unattributed_qualified_starts=unattributed,
        unqualified_startup_or_gap_starts=sum(r['unqualified_alert_start'] for i,r in enumerate(trace) if evaluation[i]),
        scope='Event-start burden conditional on benign context, separate from alarm-window FPR.')


def episode_result(trace,onset_low,onset_high,end,observation_start,observation_end,horizon=180):
    require(all(np.isfinite(v) for v in (onset_low,onset_high,end,observation_start,observation_end)), 'Nonfinite episode bounds')
    require(onset_low<=onset_high<end and observation_start<observation_end and horizon==180,'Invalid/flexible episode bounds')
    clock_array([r['utc_second'] for r in trace])
    events=[r for r in trace if r['new_alert_onset']]
    base=dict(onset_interval_utc=[float(onset_low),float(onset_high)],end_exclusive_utc=float(end),
        observed_detection=False,episode_recall_eligible=False,binary_episode_hit=None,delay_seconds=None,
        replay_latency_basis='Window end + fixed1s reorder, not measured live end-to-end latency.')
    if onset_low!=onset_high:
        possible=[];guaranteed=[]
        for row in events:
            a=row['availability_proxy_utc'];e=row['window_end_utc']
            if a>=end:continue
            lo=max(onset_low,a-horizon);hi=min(onset_high,e)
            if lo<hi or lo==hi and hi<e:possible.append(a)
            if e>onset_high and a<=onset_low+horizon:guaranteed.append(a)
        return dict(base,status='interval_onset_not_point_scored',possible_new_alerts=len(possible),
            single_alert_guarantees_timely_detection=bool(guaranteed),
            guaranteed_delay_interval_seconds=[guaranteed[0]-onset_high,guaranteed[0]-onset_low] if guaranteed else None,
            reason='Coarse onset truth cannot produce a point delay or primary binary episode score.')
    onset=onset_low;limit=min(end,onset+horizon)
    pre=[r for r in trace if r['availability_proxy_utc']<=onset]
    positions={r['utc_second']:i for i,r in enumerate(trace)}
    def common_observed(t):
        i=positions.get(t,-1)
        return i>=4 and trace[i]['utc_second']-trace[i-4]['utc_second']==4 and all(r['input_valid'] for r in trace[i-4:i+1])
    pre_history=len(pre)>=5 and pre[-1]['availability_proxy_utc']==math.floor(onset) and pre[-1]['utc_second']-pre[-5]['utc_second']==4 and all(common_observed(r['utc_second']) for r in pre[-5:])
    preexisting=pre[-1]['alarm_episode_active'] if pre_history else None
    eligible=[r for r in events if r['window_end_utc']>onset and onset<=r['availability_proxy_utc']<=onset+horizon and r['availability_proxy_utc']<end]
    first=eligible[0] if eligible else None
    # Fixed full horizon, independent of whether/when a model detects. This
    # prevents model-dependent exclusion of misses after observation gaps.
    stop=limit
    # Opportunities use the originating window, so a pre-onset window delivered
    # after onset cannot be credited. End is exclusive; the180s limit inclusive.
    opportunities=[t for t in range(math.floor(onset),math.floor(stop)+1)
        if t+1>onset and t+2<=onset+horizon and t+2<end and t+2<=stop]
    coverage=observation_start<=onset and observation_end>=limit and all(common_observed(t) for t in opportunities)
    complete=bool(pre_history and coverage)
    if first:
        delay=first['availability_proxy_utc']-onset
        return dict(base,status='detected' if complete else 'detected_observation_unqualified',
            observed_detection=True,episode_recall_eligible=complete,binary_episode_hit=1 if complete else None,
            delay_seconds=float(delay) if complete else None,observed_alert_delay_seconds=float(delay),
            preexisting_alarm_at_onset=preexisting,restricted_delay_seconds=float(delay) if complete else None,
            observation_complete_until_limit=complete)
    return dict(base,status='miss' if complete else 'observation_censored',
        episode_recall_eligible=complete,binary_episode_hit=0 if complete else None,preexisting_alarm_at_onset=preexisting,
        restricted_delay_seconds=float(limit-onset) if complete else None,
        observation_horizon_seconds=float(limit-onset),observation_complete_until_limit=complete)


def episode_summary(results):
    eligible=[r for r in results if r['episode_recall_eligible']]
    hits=sum(r['binary_episode_hit'] for r in eligible);n=len(results)
    unscored=n-len(eligible)
    return dict(total_recorded_episodes=n,scorable_exact_episodes=len(eligible),hits=hits,misses=len(eligible)-hits,
        unscored_or_censored_episodes=unscored,episode_recall=hits/len(eligible) if eligible else None,
        all_recorded_hit_bounds=[hits/n,(hits+unscored)/n] if n else None,
        mean_penalty_coded_restricted_delay_seconds=float(np.mean([r['restricted_delay_seconds'] for r in eligible])) if eligible else None,
        exact_detected_delay_median_seconds=float(np.median([r['delay_seconds'] for r in eligible if r['binary_episode_hit']==1])) if hits else None,
        latency_scope='Restricted delay includes fully observed misses at their fixed horizon; no detected-only speed superiority claim.')


def paired_cluster_bootstrap(records,metric='recall',draws=2000,seed=20261113,expected_seeds=None):
    """Average seeds inside session, pool within parent, then paired strata draw.

Each row: parent,stratum,session,seed,method,TP,FN,FP,TN. Every parent must
belong to exactly one prespecified stratum. No pooling correlated windows or
algorithm seeds as independent traffic replications. Unsupported designs => N/A.
"""
    require(metric in ('recall','fpr') and draws==2000,'Statistical protocol changed')
    methods=sorted({r['method'] for r in records});require(len(methods)==2,'Paired comparison requires two methods')
    by_session={};parents={}
    for r in records:
        key=(r['parent'],r['stratum'],r['session'],r['method'])
        by_session.setdefault(key,[]).append(r)
        if r['parent'] in parents and parents[r['parent']]!=r['stratum']:
            return dict(status='cross_stratum_parent_dependence',difference=None,CI95=None,
                reason='One parent spans strata; do not split it into falsely independent recordings.')
        parents[r['parent']]=r['stratum']
    cells={};pair_sessions={};seen_seeds={}
    for (parent,stratum,session,method),rows in by_session.items():
        require(len({r['seed'] for r in rows})==len(rows),'Duplicate algorithm seed within session')
        seeds={r['seed'] for r in rows}
        target=set(expected_seeds[method]) if expected_seeds is not None else seen_seeds.setdefault(method,seeds)
        require(seeds==target,'Missing or extra prespecified model seed')
        require(all(all(np.isfinite(r[k]) and r[k]>=0 for k in ('TP','FN','FP','TN')) for r in rows),'Invalid confusion counts')
        pair_sessions.setdefault((parent,stratum,session),set()).add(method)
        cell=cells.setdefault((parent,stratum,method),np.zeros(4))
        cell+=np.mean([[r[k] for k in ('TP','FN','FP','TN')] for r in rows],axis=0)
    require(all(v==set(methods) for v in pair_sessions.values()),'Incomplete session pairing')
    strata={s:sorted(p for p,st in parents.items() if st==s) for s in set(parents.values())}
    if not strata or any(len(v)<2 for v in strata.values()):
        return dict(status='insufficient_independent_parents',difference=None,CI95=None,parent_count=len(parents))
    def rate(v):
        num,den=(v[0],v[0]+v[1]) if metric=='recall' else (v[2],v[2]+v[3])
        return num/den if den else None
    def difference(selected):
        totals=[sum((cells[(p,parents[p],m)] for p in selected),np.zeros(4)) for m in methods]
        values=[rate(v) for v in totals]
        return values[0]-values[1] if all(v is not None for v in values) else None
    observed=difference(list(parents));rng=np.random.default_rng(seed);values=[]
    for _ in range(draws):
        selected=[]
        for stratum in sorted(strata):
            pool=strata[stratum];selected.extend(rng.choice(pool,size=len(pool),replace=True).tolist())
        value=difference(selected)
        if value is not None:values.append(value)
    if observed is None or len(values)!=draws:
        return dict(status='unsupported_metric_denominator',difference=observed,CI95=None,valid_draws=len(values))
    return dict(status='descriptive_paired_parent_bootstrap',difference=observed,CI95=np.quantile(values,[.025,.975]).tolist(),
        difference_order=methods,draws=draws,parent_count=len(parents),seed=seed,
        scope='Conditional on observed source/session clusters; no window/seed independence or population FPR guarantee.')
