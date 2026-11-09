import copy

import numpy as np
import pytest

from fl_forensics.bounded_aggregation import aggregate_bounded, removal_norm_bound, verify_bounded


def run(updates=None, **kw):
    args = {
        "masses": {"a": 1, "b": 3},
        "mandatory_gates": {"a": True, "b": True},
        "limits": [2.0],
        "reference_digest": "a" * 64,
        "minimum_contributors": 1,
    }
    args.update(kw)
    return aggregate_bounded([[10.0]], updates or {"a": [[110.0]], "b": [[9.0]]}, **args)


def test_known_clipped_weighted_result_and_original_unchanged():
    updates = {"a": [[110.0]], "b": [[9.0]]}
    before = copy.deepcopy(updates)
    model, report = run(updates)
    np.testing.assert_allclose(model, [[9.75]], atol=0, rtol=0)
    assert updates == before
    assert report["contributions"]["a"]["clipping_factors"] == [0.02]


def test_failed_gate_has_zero_effect_even_with_enormous_mass():
    a, _ = run(masses={"a": 100000, "b": 3}, mandatory_gates={"a": False, "b": True})
    np.testing.assert_allclose(a, [[9.0]])


def test_quorum_failure_does_not_restore_rejected_mass():
    model, r = run(mandatory_gates={"a": False, "b": True}, minimum_contributors=2)
    assert model is None and r["contributions"]["a"]["effective_mass"] == "0"


@pytest.mark.parametrize("limits", [[0.0], [-1.0], [float("nan")], [float("inf")], [1.0, 2.0]])
def test_invalid_limits_rejected(limits):
    with pytest.raises(ValueError):
        run(limits=limits)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_nonfinite_client_rejected(value):
    with pytest.raises(ValueError):
        run({"a": [[value]], "b": [[1.0]]})


def test_shape_change_rejected():
    with pytest.raises(ValueError):
        run({"a": [[1.0, 2.0]], "b": [[1.0]]})


def test_negative_mass_rejected():
    with pytest.raises(ValueError):
        run(masses={"a": -1, "b": 2})


def test_tampered_derived_object_detected():
    _, r = run()
    r["contributions"]["a"]["derived_float64_delta"][0]["values"][0] = 100.0
    with pytest.raises(ValueError):
        verify_bounded(
            [[10.0]],
            {"a": [[110.0]], "b": [[9.0]]},
            r,
            masses={"a": 1, "b": 3},
            mandatory_gates={"a": True, "b": True},
            limits=[2.0],
            reference_digest="a" * 64,
            minimum_contributors=1,
        )


def test_independent_triangle_bound_with_survivor_renormalization():
    rng = np.random.default_rng(7)
    base = [np.zeros(8)]
    clients = list("abcde")
    updates = {c: [rng.normal(size=8) * 100] for c in clients}
    masses = {c: i + 1 for i, c in enumerate(clients)}
    full, r = aggregate_bounded(
        base,
        updates,
        masses=masses,
        mandatory_gates=dict.fromkeys(clients, True),
        limits=[0.3],
        reference_digest="a" * 64,
        minimum_contributors=1,
    )
    for c in clients:
        remaining = {k: v for k, v in updates.items() if k != c}
        reduced, _ = aggregate_bounded(
            base,
            remaining,
            masses={k: masses[k] for k in remaining},
            mandatory_gates=dict.fromkeys(remaining, True),
            limits=[0.3],
            reference_digest="a" * 64,
            minimum_contributors=1,
        )
        bound = removal_norm_bound(r["contributions"][c]["normalized_weight"], [0.3])[0]
        assert np.linalg.norm(full[0] - reduced[0]) <= bound + 1e-15


def test_removing_only_contributor_has_no_renormalized_bound():
    with pytest.raises(ValueError):
        removal_norm_bound("1", [2.0])
