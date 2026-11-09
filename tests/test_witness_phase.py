"""Versioned cutoff and live phase tests; TSA/numerical doubles are explicit.

The separate Docker experiment exercises real swtpm and RFC3161. These tests
use existing signed fixture keys and the existing deterministic numerical
backend, while retaining the actual intake, trust, decision and graph code.
"""

from datetime import timedelta

import pytest
import test_round_derivation as derivation
from test_submission_witness import SignedTestClock, _verify
from test_submission_witness import case as _base_case

from fl_forensics import submission_witness as witness
from fl_forensics import witness_round as live
from fl_forensics.canonical import sha256_file
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.storage import load_json
from fl_forensics.trust import revoke_enrollment
from fl_forensics.witness_models import WitnessPolicy
from fl_forensics.witness_round_models import WitnessRoundReceipt

case = _base_case


def phase_store(base, tmp_path, deadline, *, levels=None):
    signer = SoftwareECDSASigner.generate()
    policy = witness.create_witness_policy(
        context=base.context,
        coordinator_public_key=base.coordinator_key,
        client_public_keys=base.client_keys,
        signer=signer,
        trust_store=base.witness_params["trust_store"],
        tsa_policy_oid="1.2.3.4.1",
        registration_deadline=deadline.isoformat(),
        client_signing_trust_levels=levels,
    )
    params = dict(
        base.witness_params,
        policy=policy,
        expected_policy_digest=policy.core_digest,
        signer=signer,
        witness_public_key=load_public_key(signer.public_pem()),
    )
    base.witness_params = params
    base.witness_policy = policy
    base.witness_store = witness.WitnessStore(database=tmp_path / "phase.sqlite3", **params)
    return base.witness_store


@pytest.mark.parametrize("offset", [-11, -10, 300, 301])
def test_cutoff_must_be_strictly_inside_authenticated_context(case, tmp_path, offset):
    # Fixture context is issued at now-10 and expires at now+300 seconds.
    issued = witness._time(case.context.core.issued_at)
    expires = witness._time(case.context.core.expires_at)
    cutoff = (
        issued
        if offset == -10
        else issued - timedelta(seconds=1)
        if offset == -11
        else expires + timedelta(seconds=offset - 300)
    )
    with pytest.raises(witness.WitnessError, match="strictly inside"):
        phase_store(case, tmp_path, cutoff)


@pytest.mark.parametrize("offset,expected", [(-2, "eligible"), (0, "ambiguous"), (2, "late")])
def test_v2_cutoff_is_authoritative_even_before_round_expiry(case, tmp_path, offset, expected):
    cutoff = case.now + timedelta(seconds=30)
    store = phase_store(case, tmp_path, cutoff)
    case.clock.now = cutoff + timedelta(seconds=offset)
    ack = store.register(case.receipts[0])
    assert ack.core.eligibility == expected
    case.clock.now = cutoff + timedelta(seconds=4)
    snapshot = store.close()
    report = _verify(case, snapshot)
    assert report["status"] == "verified_registration_set"
    assert report["evidence_profile"] == "independent_witness_rfc3161_v2"
    assert report["eligible_receipt_count"] == int(expected == "eligible")
    assert case.clock.now < witness._time(case.context.core.expires_at)


@pytest.mark.parametrize("offset", [-3, 0])
def test_v2_closure_cannot_precede_or_straddle_cutoff(case, tmp_path, offset):
    cutoff = case.now + timedelta(seconds=30)
    store = phase_store(case, tmp_path, cutoff)
    case.clock.now = cutoff + timedelta(seconds=offset)
    with pytest.raises(witness.WitnessError, match="closure is not proven"):
        store.close()
    case.clock.now = cutoff + timedelta(seconds=2)
    assert store.close().closure


def test_changed_signed_cutoff_cannot_substitute_for_external_policy_pin(case, tmp_path):
    cutoff = case.now + timedelta(seconds=30)
    store = phase_store(case, tmp_path, cutoff)
    original = store.policy.core_digest
    core = store.policy.core.model_copy(
        update={"registration_deadline": (cutoff + timedelta(seconds=5)).isoformat()}
    )
    changed = WitnessPolicy(**witness._signed(core, store.signer))
    with pytest.raises(witness.WitnessError, match="external pin"):
        witness.verify_policy(
            policy=changed,
            context=case.context,
            expected_policy_digest=original,
            **{
                k: case.witness_params[k]
                for k in (
                    "witness_public_key",
                    "coordinator_public_key",
                    "client_public_keys",
                    "trust_store",
                )
            },
        )


def test_v1_does_not_gain_a_deadline_field_or_change_round_expiry_rule(case):
    data = case.witness_policy.model_dump(mode="json")
    assert data["core"]["domain"] == "fl-independent-witness-policy-v1"
    assert "registration_deadline" not in data["core"]
    assert WitnessPolicy.model_validate(data).model_dump(mode="json") == data
    data["core"]["registration_deadline"] = case.now.isoformat()
    with pytest.raises(ValueError):
        WitnessPolicy.model_validate(data)


def test_v2_timestamp_outage_and_restart_preserve_the_cutoff(case, tmp_path):
    cutoff = case.now + timedelta(seconds=30)
    store = phase_store(case, tmp_path, cutoff)
    ack = store.register(case.receipts[0])
    reopened = witness.WitnessStore(database=store.database, **case.witness_params)
    assert reopened.register(case.receipts[0]) == ack
    case.clock.now = cutoff + timedelta(seconds=2)
    case.clock.fail = True
    with pytest.raises(OSError):
        reopened.close()
    case.clock.fail = False
    snapshot = reopened.close()
    assert snapshot.policy == store.policy
    assert reopened.close() == snapshot


@pytest.fixture
def integrated(tmp_path, monkeypatch, request):
    d = derivation.RoundDerivationTests(
        "test_nominal_derivation_binds_receipts_decisions_scoring_and_checkpoint"
    )
    d.setUp()
    try:
        d._prepare(minimum=getattr(request, "param", 1))
        keys = {name: load_public_key(signer.public_pem()) for name, signer in d.signers.items()}
        clock = SignedTestClock(witness._time(d.context.core.issued_at) + timedelta(seconds=2))
        monkeypatch.setattr(witness, "verify_timestamp", clock.verify)
        monkeypatch.setattr(live, "verify_timestamp", clock.verify)
        signer = SoftwareECDSASigner.generate()
        trust = b"unit-test-clock-only"
        cutoff = witness._time(d.context.core.issued_at) + timedelta(seconds=4)
        policy = witness.create_witness_policy(
            context=d.context,
            coordinator_public_key=d.fixture.coordinator.private_key.public_key(),
            client_public_keys=keys,
            signer=signer,
            trust_store=trust,
            tsa_policy_oid="1.2.3.4.1",
            client_signing_trust_levels={name: "swtpm" for name in keys},
            registration_deadline=cutoff.isoformat(),
        )
        params = {
            "policy": policy,
            "context": d.context,
            "expected_policy_digest": policy.core_digest,
            "signer": signer,
            "witness_public_key": load_public_key(signer.public_pem()),
            "coordinator_public_key": d.fixture.coordinator.private_key.public_key(),
            "client_public_keys": keys,
            "trust_store": trust,
            "timestamp_provider": clock,
        }
        store = witness.WitnessStore(database=tmp_path / "integrated.sqlite3", **params)

        def close(selected=("client01", "client02"), late=()):
            acks = [store.register(d.receipts[c]) for c in selected]
            clock.now = cutoff + timedelta(seconds=2)
            acks += [store.register(d.receipts[c]) for c in late]
            clock.now = cutoff + timedelta(seconds=3)
            snapshot = store.close()
            proof = {
                k: params[k]
                for k in (
                    "expected_policy_digest",
                    "witness_public_key",
                    "coordinator_public_key",
                    "client_public_keys",
                    "trust_store",
                )
            }
            proof.update(
                snapshot=snapshot,
                expected_closure_digest=snapshot.closure.core_digest,
                retained_acknowledgements=acks,
            )
            return proof

        d.close_witness = close
        d.clock = clock
        d.witness_store = store
        yield d
    finally:
        d.doCleanups()


def _admit(d, proof):
    return live.admit_witnessed_round(**d._options(), coordinator_workspace=d.workspace, **proof)


def _offline(d, proof):
    options = d._options()
    options.pop("submissions_root")
    return live.verify_witnessed_round(**options, **proof)


def test_live_round_reconstructs_intake_decisions_weights_and_offline_retry(integrated):
    d = integrated
    proof = d.close_witness()
    report = _admit(d, proof)
    assert report["status"] == "verified_witness_round", report
    assert report["coverage_verified"] and report["phase_order_verified"]
    assert report["admission_decisions_verified"] and report["coefficients_verified"]
    assert not report["delivery_verified"]
    original = (d.workspace / "witness-round/receipt.json").read_bytes()
    d.clock.fail = True
    assert _offline(d, proof)["status"] == "verified_witness_round"
    assert _admit(d, proof)["idempotent"]
    assert (d.workspace / "witness-round/receipt.json").read_bytes() == original


def test_late_registered_update_never_reaches_scoring_or_checkpoint(integrated):
    d = integrated
    proof = d.close_witness(selected=("client01",), late=("client02",))
    report = _admit(d, proof)
    assert report["status"] == "verified_witness_round", report
    assert report["ready_payload_count"] == 1
    assert not (d.workspace / "witness-round/submissions/client02").exists()
    assert report["round_verification"]["accepted_count"] == 1


def test_missing_payload_retains_eligible_receipt_and_negative_intake(integrated):
    d = integrated
    proof = d.close_witness()
    d._remove(d.fixture.submissions_root / "client02/update.json")
    report = _admit(d, proof)
    assert report["status"] == "verified_witness_round", report
    inventory = load_json(d.workspace / "witness-round/inventory.json")
    assert {e["outcome"] for e in inventory["core"]["entries"]} == {
        "ready_for_admission",
        "rejected_missing_payload",
    }
    assert report["eligible_receipt_count"] == 2 and report["ready_payload_count"] == 1
    assert report["round_verification"]["accepted_count"] == 1


def test_eligible_registration_does_not_override_later_enrollment_revocation(integrated):
    d = integrated
    proof = d.close_witness()
    revoke_enrollment(
        workspace=d.fixture.trust,
        client_id="client02",
        reason="phase test",
        revoked_at=d.now.isoformat(),
    )
    report = _admit(d, proof)
    assert report["status"] == "verified_witness_round", report
    assert report["round_verification"]["quarantined_count"] == 1
    assert report["round_verification"]["accepted_count"] == 1


def test_round_expiry_prevents_admission_before_any_publication(integrated, monkeypatch):
    d = integrated
    proof = d.close_witness()
    monkeypatch.setattr(live, "_now", lambda: witness._time(d.context.core.expires_at))
    with pytest.raises(witness.WitnessError, match="phase window"):
        _admit(d, proof)
    assert not (d.workspace / "witness-round").exists()
    assert not (d.workspace / "checkpoint/manifest.json").exists()


def test_expiry_during_computation_never_gets_a_completed_witness_receipt(integrated, monkeypatch):
    d = integrated
    proof = d.close_witness()
    now = live._now()
    values = iter([now, now, witness._time(d.context.core.expires_at)])
    monkeypatch.setattr(live, "_now", lambda: next(values))
    with pytest.raises(witness.WitnessError, match="phase window"):
        _admit(d, proof)
    assert not (d.workspace / "witness-round/receipt.json").exists()
    assert _offline(d, proof)["status"] == "invalid"


def test_coordinator_cannot_omit_an_eligible_inventory_entry_even_if_resigned(integrated):
    d = integrated
    proof = d.close_witness()
    assert _admit(d, proof)["status"] == "verified_witness_round"
    path = d.workspace / "witness-round/inventory.json"
    d._resign(
        path,
        id_field="inventory_id",
        prefix="round-input-inventory-",
        change=lambda core: core.update(entries=core["entries"][:1]),
    )
    binding_path = d.workspace / "witness-round/receipt.json"
    binding = WitnessRoundReceipt.model_validate(load_json(binding_path))
    core = binding.core.model_copy(update={"inventory_sha256": sha256_file(path)})
    changed = WitnessRoundReceipt(**witness._signed(core, d.fixture.coordinator))
    d._replace(binding_path, changed.model_dump_json().encode())
    assert _offline(d, proof)["status"] == "invalid"


def test_wrong_external_closure_pin_or_mutated_checkpoint_is_rejected(integrated):
    d = integrated
    proof = d.close_witness()
    bad = dict(proof, expected_closure_digest="0" * 64)
    with pytest.raises(witness.WitnessError, match="closure"):
        _admit(d, bad)
    assert _admit(d, proof)["status"] == "verified_witness_round"
    path = d.workspace / "checkpoint/global-model.json"
    d._replace(path, path.read_bytes() + b" ")
    assert _offline(d, proof)["status"] == "invalid"


def test_invalid_update_is_retained_as_negative_intake_and_never_scored(integrated):
    d = integrated
    proof = d.close_witness()
    path = d.fixture.submissions_root / "client02/update.json"
    d._replace(path, path.read_bytes() + b" ")
    report = _admit(d, proof)
    assert report["status"] == "verified_witness_round", report
    inventory = load_json(d.workspace / "witness-round/inventory.json")
    assert any(e["outcome"] == "rejected_invalid_payload" for e in inventory["core"]["entries"])
    assert report["round_verification"]["accepted_count"] == 1


@pytest.mark.parametrize("integrated", [2], indirect=True)
def test_insufficient_eligible_quorum_produces_no_completed_checkpoint(integrated):
    d = integrated
    proof = d.close_witness(selected=("client01",), late=("client02",))
    report = _admit(d, proof)
    assert report["status"] == "failed_witness_round", report
    assert report["coverage_verified"] and not report["checkpoint_created"]
    assert not (d.workspace / "checkpoint/manifest.json").exists()
    assert not (d.workspace / "witness-round/receipt.json").exists()
