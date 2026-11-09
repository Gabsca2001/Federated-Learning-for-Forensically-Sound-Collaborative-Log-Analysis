import pytest
from test_client_envelope_policy import policy, step

from fl_forensics.persistent_envelope_policy import PersistentEnvelopePolicy


def new_policy(k=3, minimum=2):
    old = policy(minimum)
    return PersistentEnvelopePolicy(
        old.cal, old.envelope, confirmation_rounds=k, minimum_contributors=minimum
    )


def test_bounded_confirmation_breaks_episode_peak_suppression():
    old, new = policy(), new_policy()
    for t in range(1, 16):
        risk = 2.4 if t == 1 else 2.1
        prior, current = step(old, t, risk), step(new, t, risk)
        assert not prior["quarantine_current_round"]
        assert current["quarantine_current_round"] == ([] if t < 3 else ["a"])


@pytest.mark.parametrize("k", [2, 3, 4])
def test_periodic_peaks_do_not_restart_the_current_high_bound(k):
    p = new_policy(k)
    for t in range(1, 16):
        result = step(p, t, 20 if t % 3 == 1 else 2.01)
        if t >= k:
            assert result["quarantine_current_round"] == ["a"]


def test_evidence_gap_and_unsupported_context_reset_confirmation():
    p = new_policy()
    step(p, 1, 2.4)
    step(p, 2, 2.1)
    assert not step(p, 3, 0)["quarantine_current_round"]
    step(p, 4, 2.4)
    step(p, 5, 2.1, support=False)
    assert not step(p, 6, 2.1)["quarantine_current_round"]
    assert not step(p, 7, 2.1)["clients"]["a"]["bounded_persistence_proposal"]
    assert step(p, 8, 2.1)["quarantine_current_round"] == ["a"]


def test_failed_gate_zero_mass_and_quorum_never_restore_it():
    p = new_policy(minimum=3)
    result = step(p, 1, 2.4, gates={"a": False, "b": True, "c": True})
    assert result["proposed_effective_masses"]["a"] == "0"
    assert not result["proposal_quorum_satisfied"]


def test_exact_retry_is_idempotent_and_conflicting_retry_rejected():
    p = new_policy()
    previous = p.head
    first = step(p, 1, 2.4, previous=previous)
    assert step(p, 1, 2.4, previous=previous) == first
    with pytest.raises(ValueError):
        step(p, 1, 2.4, previous=previous, source="b" * 64)


def test_bounded_channel_does_not_claim_that_current_excess_proves_malice():
    p = new_policy()
    step(p, 1, 2.4)
    step(p, 2, 2.1)
    result = step(p, 3, 2.1)
    assert result["clients"]["a"]["bounded_persistence_proposal"]
    assert not result["automatic_deployment_validated"]
    assert not result["client_ban_performed"]
