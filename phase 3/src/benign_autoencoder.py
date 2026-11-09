"""Benign-only dense AE with grouped external early stopping (CPU scikit-learn).

partial_fit preserves Adam state across epochs. All fitted preprocessing is benign
training only. Validation affects epoch choice, never fitted scaling/imputation.
"""
from copy import deepcopy
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import RobustScaler


class BenignAutoencoder:
    def __init__(self,seed=7,max_epochs=100,patience=10):
        self.seed=seed; self.max_epochs=max_epochs; self.patience=patience

    @staticmethod
    def clean(x):
        x=np.asarray(x,dtype=float).copy()
        x[~np.isfinite(x) | (x<0)]=np.nan
        return np.log1p(x)

    def fit(self,x,y,x_val,y_val):
        if np.any(np.asarray(y)!=0) or np.any(np.asarray(y_val)!=0):
            raise ValueError('AE fitting and early stopping must contain benign observations only')
        self.imputer=SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)
        z=self.imputer.fit_transform(self.clean(x))
        self.keep=np.ptp(z,axis=0)>0
        if not self.keep.any(): raise ValueError('No varying benign input features')
        self.scaler=RobustScaler().fit(z[:,self.keep])
        z=self.scaler.transform(z[:,self.keep])
        v=self.transform(x_val)
        network=MLPRegressor(hidden_layer_sizes=(32,16,8,16,32),activation='relu',solver='adam',
            alpha=0.,batch_size=min(256,len(z)),learning_rate_init=.001,shuffle=True,random_state=self.seed)
        self.history=[]; best=float('inf'); stale=0
        for epoch in range(1,self.max_epochs+1):
            network.partial_fit(z,z)
            error=float(np.mean((network.predict(v)-v)**2))
            if not np.isfinite(error): raise ValueError('Non-finite AE reconstruction error')
            self.history.append({'epoch':epoch,'benign_validation_mse':error})
            if error < best-1e-8:
                best=error; self.model=deepcopy(network); self.best_epoch=epoch; stale=0
            else: stale+=1
            if stale>=self.patience: break
        return self

    def transform(self,x):
        return self.scaler.transform(self.imputer.transform(self.clean(x))[:,self.keep])

    def score(self,x):
        z=self.transform(x)
        return np.mean((self.model.predict(z)-z)**2,axis=1)


def benign_percentiles(reference,values):
    reference=np.sort(np.asarray(reference,dtype=float))
    if not len(reference) or not np.isfinite(reference).all(): raise ValueError('Invalid score reference')
    return np.searchsorted(reference,np.asarray(values),side='right')/len(reference)
