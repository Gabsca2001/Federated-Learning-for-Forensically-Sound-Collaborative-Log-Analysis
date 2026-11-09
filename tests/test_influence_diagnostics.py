from fractions import Fraction as F

import numpy as np
import pytest

from fl_forensics.influence_diagnostics import influence_diagnostics


def example(**changes):
    data = dict(before_coefficients={'r': F(1, 4), 'a': F(1, 4), 'b': F(1, 2)},
        frozen_coefficients={'a': F(1, 3), 'b': F(2, 3)},
        after_coefficients={'a': F(1, 3), 'b': F(2, 3)},
        before_actions={'r': 'accepted', 'a': 'accepted', 'b': 'accepted'},
        after_actions={'a': 'accepted', 'b': 'accepted'}, removed_ids={'r'},
        original_model=[np.array([1.])], frozen_model=[np.array([2.])], after_model=[np.array([2.])])
    data.update(changes)
    return influence_diagnostics(**data)


def test_removal_only_does_not_claim_policy_effect():
    result = example()
    assert result['removed_original_weight'] == {'numerator': '1', 'denominator': '4'}
    assert result['survivor_policy_total_variation']['numerator'] == '0'
    assert result['survivor_action_changed'] is False
    assert result['direct_removal_model_l2'] == 1
    assert result['additional_policy_model_l2'] == 0


def test_zero_weight_source_can_change_policy_without_changing_model():
    result = example(before_coefficients={'r': F(0), 'a': F(1, 2), 'b': F(1, 2)},
        frozen_coefficients={'a': F(1, 2), 'b': F(1, 2)},
        after_coefficients={'a': F(0), 'b': F(1)},
        after_actions={'a': 'quarantined', 'b': 'accepted'},
        original_model=[np.array([7.])], frozen_model=[np.array([7.])], after_model=[np.array([7.])])
    assert result['removed_original_weight']['numerator'] == '0'
    assert result['survivor_policy_total_variation'] == {'numerator': '1', 'denominator': '2'}
    assert result['survivor_action_changed'] is True
    assert result['total_model_l2'] == 0


def test_scalar_model_distances_must_not_be_added():
    result = example(original_model=[np.array([0.])], frozen_model=[np.array([1.])], after_model=[np.array([0.])])
    assert result['direct_removal_model_l2'] == result['additional_policy_model_l2'] == 1
    assert result['total_model_l2'] == result['vector_decomposition_residual_l2'] == 0


def test_failed_frozen_aggregate_has_undefined_policy_comparison():
    result = example(frozen_coefficients=None, frozen_model=None)
    assert result['survivor_policy_total_variation'] is None
    assert result['additional_policy_model_l2'] is None
    assert result['total_model_l2'] == 1


@pytest.mark.parametrize('changes', [
    {'after_actions': {'a': 'accepted'}},
    {'after_coefficients': {'a': F(-1), 'b': F(2)}},
    {'after_coefficients': {'a': F(1, 4), 'b': F(1, 4)}},
    {'after_coefficients': {'a': .5, 'b': .5}},
    {'frozen_coefficients': {'a': F(1, 2), 'b': F(1, 2)}},
    {'after_model': [np.array([np.nan])]},
    {'after_model': [np.array([1., 2.])]},
])
def test_rejects_invalid_domains(changes):
    with pytest.raises(ValueError):
        example(**changes)
