from pathlib import Path
import sys,unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from coherent_gradient_protocol import *
from coherent_gradient_recovery import resume_after_root_expansion

def setup():
    old={'source_validation_sha256':'e'*64,'window_ids':['a'],'weights':{'x':1.},'loss_contract':'c'*64}
    new={**old,'window_ids':['a','b']}
    c=make_context(parent_model_sha256='a'*64,base_tensor_digest=digest(array_record([np.zeros(1)])),round_number=1,
        attempt_id='old',protocol_sha256='b'*64,loss_contract_sha256='c'*64,roster=['u'],method='coherent_fltrust',root_reference_sha256=digest(old))
    _,event=assess_round([np.zeros(1)],{},None,c)
    state=transition(initial_state('a'*64,'b'*64),event,None)
    return state,c,old,new

class RecoveryTests(unittest.TestCase):
    def test_new_material_root_evidence_resumes_without_round_advance(self):
        s,c,o,n=setup();result,proof=resume_after_root_expansion(s,c,o,n,'f'*64)
        self.assertEqual(result['phase'],'active');self.assertEqual(result['last_committed_round'],0)
        self.assertEqual(result['parent_model_sha256'],'a'*64);self.assertEqual(proof['additional_root_ids'],['b'])

    def test_identical_reference_and_same_policy_cannot_retry(self):
        s,c,o,n=setup()
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,o,'f'*64)
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,n,'b'*64)

    def test_changed_parent_or_source_is_rejected(self):
        s,c,o,n=setup();s['parent_model_sha256']='f'*64
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,n,'f'*64)
        s,c,o,n=setup();n['source_validation_sha256']='f'*64
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,n,'f'*64)

    def test_reference_replacement_and_duplicate_ids_do_not_count_as_growth(self):
        s,c,o,n=setup();n['window_ids']=['b','c']
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,n,'f'*64)
        n['window_ids']=['a','a','b']
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,n,'f'*64)

    def test_single_expansion_budget_cannot_be_exhausted_by_retrying(self):
        s,c,o,n=setup();s['root_expansion_count']=1
        with self.assertRaises(ValueError):resume_after_root_expansion(s,c,o,n,'f'*64)

if __name__=='__main__':unittest.main()
