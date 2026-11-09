"""Protocol adversarial tests with a signed deterministic clock test double.

Only the timestamp-provider boundary is replaced here. The production profile
has no such fallback. Real OpenSSL/TSA verification is exercised separately.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
import test_submission_evidence as receipt_examples

from fl_forensics import submission_witness as witness
from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_bytes
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key, verify_digest_signature
from fl_forensics.submission_witness_cli import make_server
from fl_forensics.witness_models import TimestampEvidence
from fl_forensics.witness_time import TimeInterval


class SignedTestClock:
    def __init__(self, now):
        self.now = now
        self.accuracy = timedelta(seconds=1)
        self.signer = SoftwareECDSASigner.generate()
        self.key = load_public_key(self.signer.public_pem())
        self.fail = False

    def stamp(self, subject):
        if self.fail:
            raise OSError("test TSA unavailable")
        payload = {
            "test_only": True,
            "imprint": sha256_bytes(subject),
            "lower": (self.now - self.accuracy).isoformat(),
            "upper": (self.now + self.accuracy).isoformat(),
        }
        response = {
            "payload": payload,
            "signature": self.signer.sign_digest(digest_object(payload)),
        }
        return TimestampEvidence(
            request_b64=base64.b64encode(subject).decode(),
            response_b64=base64.b64encode(canonical_json_bytes(response)).decode(),
        )

    def verify(self, subject, evidence, *, policy, trust_store):
        response = json.loads(base64.b64decode(evidence.response_b64))
        payload = response["payload"]
        if (
            not verify_digest_signature(self.key, digest_object(payload), response["signature"])
            or payload["imprint"] != sha256_bytes(subject)
            or base64.b64decode(evidence.request_b64) != subject
            or sha256_bytes(trust_store) != policy.core.tsa_trust_store_sha256
        ):
            raise ValueError("invalid signed test-clock evidence")
        return TimeInterval(witness._time(payload["lower"]), witness._time(payload["upper"]))


@pytest.fixture
def case(tmp_path, monkeypatch):
    base = receipt_examples.SubmissionEvidenceTests()
    base.setUp()
    signer = SoftwareECDSASigner.generate()
    key = load_public_key(signer.public_pem())
    clock = SignedTestClock(base.now)
    monkeypatch.setattr(witness, "verify_timestamp", clock.verify)
    trust = b"test-clock-authority-not-an-RFC3161-certificate"
    policy = witness.create_witness_policy(
        context=base.context,
        coordinator_public_key=base.coordinator_key,
        client_public_keys=base.client_keys,
        signer=signer,
        trust_store=trust,
        tsa_policy_oid="1.2.3.4.1",
    )
    params = {
        "policy": policy,
        "context": base.context,
        "expected_policy_digest": policy.core_digest,
        "signer": signer,
        "witness_public_key": key,
        "coordinator_public_key": base.coordinator_key,
        "client_public_keys": base.client_keys,
        "trust_store": trust,
        "timestamp_provider": clock,
    }
    store = witness.WitnessStore(database=tmp_path / "witness.db", **params)
    base.witness_store, base.witness_policy, base.witness_signer = store, policy, signer
    base.clock, base.witness_params, base.test_path = clock, params, tmp_path
    yield base
    base.tearDown()


def _close(case):
    case.clock.now = witness._time(case.context.core.expires_at) + timedelta(seconds=2)
    return case.witness_store.close()


def _verify(case, snapshot, **overrides):
    params = {
        k: case.witness_params[k]
        for k in (
            "expected_policy_digest",
            "witness_public_key",
            "coordinator_public_key",
            "client_public_keys",
            "trust_store",
        )
    }
    params.update(snapshot=snapshot, expected_closure_digest=snapshot.closure.core_digest)
    params.update(overrides)
    return witness.verify_witness_snapshot(**params)


def _inventory(case, snapshot, inventory=None):
    params = {
        k: case.witness_params[k]
        for k in (
            "expected_policy_digest",
            "witness_public_key",
            "coordinator_public_key",
            "client_public_keys",
            "trust_store",
        )
    }
    return witness.verify_witness_inventory(
        snapshot=snapshot,
        expected_closure_digest=snapshot.closure.core_digest,
        inventory=case._inventory() if inventory is None else inventory,
        bundle_paths=case.bundle_paths,
        **params,
    )


def test_full_registration_closure_and_inventory(case):
    acks = [case.witness_store.register(r) for r in case.receipts]
    snapshot = _close(case)
    report = _verify(case, snapshot, retained_acknowledgements=acks)
    assert report["registration_set_verified"] and report["deadline_verified"]
    assert report["eligible_receipt_count"] == 2
    assert not report["coverage_verified"]
    report = _inventory(case, snapshot)
    assert report["status"] == "verified_eligible_intake"
    assert report["coverage_verified"]
    assert not report["delivery_verified"] and not report["admission_decisions_verified"]


def test_coordinator_signed_omission_is_detected(case):
    for receipt in case.receipts:
        case.witness_store.register(receipt)
    snapshot = _close(case)
    inventory = case._inventory()
    omitted = case._resign(inventory, entries=inventory.core.entries[1:])
    report = _inventory(case, snapshot, omitted)
    assert report["deadline_verified"] and not report["coverage_verified"]
    assert report["status"] == "invalid_inventory"
    assert len(report["intake_verification"]["missing_submission_ids"]) == 1


def test_inventory_cannot_add_unregistered_submissions(case):
    case.witness_store.register(case.receipts[0])
    report = _inventory(case, _close(case))
    assert report["status"] == "invalid_inventory"
    assert not report["coverage_verified"]
    assert report["intake_verification"]["additional_inventory_submission_ids"]


def test_missing_payload_has_an_authenticated_negative_intake_outcome(case):
    for receipt in case.receipts:
        case.witness_store.register(receipt)
    snapshot = _close(case)
    case.bundle_paths = {}
    inventory = case._inventory()
    assert all(entry.outcome == "rejected_missing_payload" for entry in inventory.core.entries)
    assert _inventory(case, snapshot, inventory)["status"] == "verified_eligible_intake"


def test_all_witnessed_equivocations_are_accounted_for(case):
    path, _ = case._bundle("client01", variant=12)
    case.receipts.append(case._receipt(path, "client01"))
    for receipt in case.receipts:
        case.witness_store.register(receipt)
    snapshot = _close(case)
    inventory = case._inventory()
    assert sum(e.outcome == "rejected_conflict" for e in inventory.core.entries) == 2
    assert _inventory(case, snapshot, inventory)["status"] == "verified_eligible_intake"


@pytest.mark.parametrize("offset,expected", [(-2, "eligible"), (0, "ambiguous"), (2, "late")])
def test_deadline_uses_TSA_interval_not_claimed_client_time(case, offset, expected):
    case.clock.now = witness._time(case.context.core.expires_at) + timedelta(seconds=offset)
    ack = case.witness_store.register(case.receipts[0])
    assert ack.core.eligibility == expected
    snapshot = _close(case)
    report = _verify(case, snapshot)
    assert report["registration_set_verified"]
    assert report["eligible_receipt_count"] == int(expected == "eligible")


def test_registration_before_open_is_not_eligible(case):
    case.clock.now = witness._time(case.context.core.issued_at) - timedelta(seconds=2)
    assert case.witness_store.register(case.receipts[0]).core.eligibility == "before_open"


@pytest.mark.parametrize("seconds", [-5, 0])
def test_cannot_close_before_or_straddling_deadline(case, seconds):
    case.clock.now = witness._time(case.context.core.expires_at) + timedelta(seconds=seconds)
    with pytest.raises(witness.WitnessError, match="closure is not proven"):
        case.witness_store.close()
    assert _verify(case, _close(case))["registration_set_verified"]


def test_empty_sealed_log_does_not_certify_intake_completeness(case):
    snapshot = _close(case)
    report = _verify(case, snapshot)
    assert report["registration_set_verified"] and report["eligible_receipt_count"] == 0
    report = _inventory(case, snapshot, case._inventory(receipts=[]))
    assert report["status"] == "insufficient_evidence"
    assert not report["coverage_verified"]


def test_immutable_idempotent_retries_survive_restart_and_close(case):
    ack = case.witness_store.register(case.receipts[0])
    reopened = witness.WitnessStore(database=case.witness_store.database, **case.witness_params)
    assert reopened.register(case.receipts[0]) == ack
    snapshot = _close(case)
    case.clock.fail = True
    assert reopened.register(case.receipts[0]) == ack
    assert reopened.close() == snapshot
    assert reopened.snapshot() == snapshot
    with pytest.raises(witness.WitnessError, match="closed"):
        reopened.register(case.receipts[1])


def test_concurrent_retries_have_one_sequence_and_one_acknowledgement(case):
    with ThreadPoolExecutor(max_workers=8) as pool:
        acks = list(pool.map(lambda _: case.witness_store.register(case.receipts[0]), range(16)))
    assert all(ack == acks[0] for ack in acks)
    assert len(_close(case).registrations) == 1


def test_failed_timestamp_rolls_back_without_sequence_gap(case):
    case.clock.fail = True
    with pytest.raises(OSError, match="unavailable"):
        case.witness_store.register(case.receipts[0])
    case.clock.fail = False
    assert case.witness_store.register(case.receipts[0]).core.subject.sequence == 1


def test_time_rollback_is_rejected(case):
    case.witness_store.register(case.receipts[0])
    case.clock.now -= timedelta(seconds=10)
    with pytest.raises(witness.WitnessError, match="backwards"):
        case.witness_store.register(case.receipts[1])


@pytest.mark.parametrize(
    "change", ["truncate", "reorder", "duplicate", "tamper", "policy", "head", "ca"]
)
def test_snapshot_mutations_fail_closed(case, change):
    for receipt in case.receipts:
        case.witness_store.register(receipt)
    snapshot = _close(case)
    overrides = {}
    if change == "truncate":
        snapshot = snapshot.model_copy(update={"registrations": snapshot.registrations[:-1]})
    elif change == "reorder":
        snapshot = snapshot.model_copy(
            update={"registrations": list(reversed(snapshot.registrations))}
        )
    elif change == "duplicate":
        snapshot = snapshot.model_copy(update={"registrations": snapshot.registrations * 2})
    elif change == "tamper":
        first = snapshot.registrations[0]
        changed = first.model_copy(
            update={"core": first.core.model_copy(update={"eligibility": "late"})}
        )
        snapshot = snapshot.model_copy(
            update={"registrations": [changed, snapshot.registrations[1]]}
        )
    elif change == "policy":
        overrides["expected_policy_digest"] = "0" * 64
    elif change == "head":
        overrides["expected_closure_digest"] = "0" * 64
    else:
        overrides["trust_store"] = b"coordinator-selected-other-authority"
    report = _verify(case, snapshot, **overrides)
    assert report["status"] == "invalid" and not report["deadline_verified"]


def test_missing_external_closure_pin_is_rejected(case):
    assert not _verify(case, _close(case), expected_closure_digest="")["registration_set_verified"]


def test_retained_acknowledgement_detects_witness_fork(case):
    ack = case.witness_store.register(case.receipts[0])
    original = _close(case)
    case.clock.now = case.now
    fork = witness.WitnessStore(database=case.test_path / "fork.db", **case.witness_params)
    fork.register(case.receipts[1])
    case.clock.now = witness._time(case.context.core.expires_at) + timedelta(seconds=2)
    fork_snapshot = fork.close()
    assert not _verify(case, fork_snapshot, expected_closure_digest=original.closure.core_digest)[
        "registration_set_verified"
    ]
    report = _verify(case, fork_snapshot, retained_acknowledgements=[ack])
    assert not report["registration_set_verified"]
    assert "acknowledgement" in report["errors"][0]


def test_automatic_mutation_of_journal_rows_is_rejected(case):
    case.witness_store.register(case.receipts[0])
    with sqlite3.connect(case.witness_store.database) as connection:
        for command in (
            "DELETE FROM registrations",
            "UPDATE registrations SET receipt_digest='bad'",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(command)


def test_same_key_as_coordinator_is_not_an_independent_witness(case):
    with pytest.raises(witness.WitnessError, match="separate signing key"):
        witness.create_witness_policy(
            context=case.context,
            coordinator_public_key=case.coordinator_key,
            client_public_keys=case.client_keys,
            signer=case.coordinator,
            trust_store=case.witness_params["trust_store"],
            tsa_policy_oid="1.2.3.4.1",
        )


def test_invalid_client_signature_cannot_enter_log(case):
    receipt = case.receipts[0].model_copy(update={"signature": case.receipts[1].signature})
    with pytest.raises(witness.WitnessError, match="client receipt"):
        case.witness_store.register(receipt)
    assert len(_close(case).registrations) == 0


def test_round_replay_cannot_enter_log(case):
    other = case._resign_receipt(case.receipts[0], updates={"round_number": 2})
    with pytest.raises(witness.WitnessError, match="client receipt"):
        case.witness_store.register(other)


def test_client_cannot_relabel_a_software_key_as_TPM(case):
    receipt = case._resign_receipt(case.receipts[0], updates={"signing_trust_level": "tpm2"})
    receipt = receipt.model_copy(
        update={"signature": receipt.signature.model_copy(update={"trust_level": "tpm2"})}
    )
    with pytest.raises(witness.WitnessError, match="client receipt"):
        case.witness_store.register(receipt)


def test_http_endpoint_registers_and_exposes_only_final_snapshot(case):
    server = make_server(case.witness_store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(url + "/snapshot")
        assert error.value.code == 409
        request = urllib.request.Request(
            url + "/receipts", data=canonical_json_bytes(case.receipts[0].model_dump(mode="json"))
        )
        with urllib.request.urlopen(request) as response:
            ack = json.load(response)
        assert ack["core"]["eligibility"] == "eligible"
        snapshot = _close(case)
        with urllib.request.urlopen(url + "/snapshot") as response:
            assert json.load(response)["closure"]["core_digest"] == snapshot.closure.core_digest
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(url + "/close", data=b"{}"))
        assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
