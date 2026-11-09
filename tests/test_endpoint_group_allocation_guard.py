"""Prevent seed-retry collisions from inflating campaign-allocation counts."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from endpoint_group_allocation_guard import allocation_identity,require_unique_allocations

def row(name):return {'window_id':name}

class AllocationGuardTests(unittest.TestCase):
    def test_actual_duplicate_rejected_despite_different_seed_labels(self):
        a=allocation_identity({'a':[row('x')],'b':[row('y')]})
        with self.assertRaisesRegex(ValueError,'duplicate allocation'):
            require_unique_allocations({'seed-1':a,'seed-2':a})

    def test_identity_is_invariant_to_iteration_and_row_order(self):
        a={'a':[row('x'),row('y')],'b':[row('z')]}
        b={'b':[row('z')],'a':[row('y'),row('x')]}
        self.assertEqual(allocation_identity(a),allocation_identity(b))

    def test_duplicate_occurrence_or_changed_population_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicated training occurrence'):
            allocation_identity({'a':[row('x')],'b':[row('x')]})
        a=allocation_identity({'a':[row('x')],'b':[row('y')]})
        b=allocation_identity({'a':[row('x')],'b':[row('z')]})
        with self.assertRaisesRegex(ValueError,'training population'):
            require_unique_allocations({'one':a,'two':b})

    def test_different_memberships_on_same_population_pass(self):
        a=allocation_identity({'a':[row('x')],'b':[row('y')]})
        b=allocation_identity({'a':[row('y')],'b':[row('x')]})
        self.assertEqual(len(require_unique_allocations({'one':a,'two':b})),2)

if __name__=='__main__':unittest.main()
