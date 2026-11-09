"""Benign-only fit guards, training-only transforms, and split-boundary fixtures."""
import unittest
import numpy as np
from benign_autoencoder import BenignAutoencoder, benign_percentiles
from train_flow_development import canonical, partition


class DevelopmentModelChecks(unittest.TestCase):
    def test_connection_groups_ignore_direction(self):
        a={'Source IP':'192.0.2.1','Source Port':'50000','Destination IP':'192.0.2.2','Destination Port':'80','Protocol':'6'}
        b=dict(a); b['Source IP'],b['Destination IP']=a['Destination IP'],a['Source IP']
        b['Source Port'],b['Destination Port']=a['Destination Port'],a['Source Port']
        self.assertEqual(canonical(a),canonical(b))

    def test_uncertain_flow_end_cannot_cross_split(self):
        self.assertEqual(partition(210,211),'T')
        self.assertIsNone(partition(219,220))
        self.assertIsNone(partition(220,220.5))
        self.assertEqual(partition(221,222),'C1')
        self.assertIsNone(partition(247,248))

    def test_ae_refuses_attack_training_or_early_stopping(self):
        x=np.ones((8,2)); y=np.zeros(8)
        for a,b in [(np.ones(8),y),(y,np.ones(8))]:
            with self.assertRaises(ValueError): BenignAutoencoder().fit(x,a,x,b)

    def test_ae_preprocessing_only_fits_benign_training(self):
        x=np.array([[i,i%3,7.] for i in range(1,17)],dtype=float); x[0,0]=np.nan
        v=np.array([[100.+i,10.+i,8.] for i in range(1,9)])
        model=BenignAutoencoder(max_epochs=3,patience=2).fit(x,np.zeros(len(x)),v,np.zeros(len(v)))
        self.assertTrue(np.allclose(model.imputer.statistics_,np.nanmedian(np.log1p(x),axis=0)))
        # The missing first value adds a learned indicator column. The constant
        # original feature is removed, while the varying missingness flag is kept.
        self.assertEqual(model.keep.tolist(),[True,True,False,True])
        scores=model.score(v)
        self.assertEqual(scores.shape,(8,)); self.assertTrue(np.isfinite(scores).all())
        self.assertLessEqual(len(model.history),3)

    def test_percentile_ties_and_extreme_scores_are_explicit(self):
        mapped=benign_percentiles([0.,1.,1.,2.],[-1.,0.,1.,2.,20.])
        self.assertEqual(mapped.tolist(),[0.,.25,.75,1.,1.])
        with self.assertRaises(ValueError): benign_percentiles([],np.ones(2))


if __name__=='__main__': unittest.main(verbosity=2)
