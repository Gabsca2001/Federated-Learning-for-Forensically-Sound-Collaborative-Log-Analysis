from pathlib import Path
import sys,unittest
import numpy as np
import torch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from reference_objective_diagnostic import target_distributions,matched_root_weights,loss_gradient

class ObjectiveTests(unittest.TestCase):
    def test_local_normalization_changes_the_mixture(self):
        p,m=target_distributions({'x':{'a':9,'b':1},'y':{'a':0,'b':10}},{'a':1,'b':9})
        self.assertAlmostEqual(p['a'],1/12);self.assertAlmostEqual(m['a'],.25)
        self.assertAlmostEqual(sum(m.values()),1)

    def test_unweighted_local_and_pooled_targets_match(self):
        p,m=target_distributions({'x':{'a':9,'b':1},'y':{'a':1,'b':29}},{'a':1,'b':1})
        self.assertEqual(p,m)

    def test_importance_weights_recover_target_on_root_counts(self):
        target={'a':.2,'b':.8};counts={'a':8,'b':2}
        w=matched_root_weights(target,counts);total=sum(counts[c]*w[c] for c in counts)
        for c in counts:self.assertAlmostEqual(counts[c]*w[c]/total,target[c])

    def test_bad_inputs_fail(self):
        with self.assertRaises(ValueError):target_distributions({'x':{'a':0}},{'a':1})
        with self.assertRaises(ValueError):matched_root_weights({'a':.5,'b':.5},{'a':1,'b':0})
        with self.assertRaises(ValueError):matched_root_weights({'a':2.},{'a':1})

    def test_weighted_mean_gradient_against_analytic_linear_case(self):
        model=torch.nn.Linear(2,2).double()
        with torch.no_grad():model.weight.zero_();model.bias.zero_()
        grad,_=loss_gradient(model,torch.eye(2,dtype=torch.float64),torch.tensor([0,1]),torch.tensor([1.,3.],dtype=torch.float64),torch)
        np.testing.assert_array_equal(grad[0],[[-.125,.375],[.125,-.375]])
        np.testing.assert_array_equal(grad[1],[.25,-.25])

    def test_gradient_directional_difference_on_smooth_head(self):
        model=torch.nn.Linear(2,2).double()
        with torch.no_grad():model.weight.zero_();model.bias.zero_()
        x=torch.eye(2,dtype=torch.float64);y=torch.tensor([0,1]);w=torch.tensor([1.,3.],dtype=torch.float64)
        grad,_=loss_gradient(model,x,y,w,torch);eps=1e-5
        with torch.no_grad():
            model.bias[0]+=eps;plus=float(torch.nn.functional.cross_entropy(model(x),y,weight=w))
            model.bias[0]-=2*eps;minus=float(torch.nn.functional.cross_entropy(model(x),y,weight=w))
        self.assertAlmostEqual((plus-minus)/(2*eps),grad[1][0],places=9)

if __name__=='__main__':unittest.main()
