"""Authority-pinned adapter tests; secure-round fixture uses software TPM doubles."""

import pytest
import test_secure_round as secure_examples

from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.storage import load_json, write_once
from fl_forensics.submission_witness_cli import export_enrollment_bindings


@pytest.fixture
def enrollment_case(tmp_path):
    case = secure_examples.SecureRoundAdmissionTests(
        "test_nominal_bundle_passes_every_admission_check"
    )
    case.setUp()
    workspace = case._aggregation_workspace()
    from pathlib import Path

    root = Path(case.temporary.name)
    options = {
        "context_path": workspace / "public" / "round-context.json",
        "trust_workspace": case.trust,
        "authority_public_key_path": case.trust / "authority" / "enrollment-authority.public.pem",
        "coordinator_public_key_path": workspace / "public" / "coordinator.public.pem",
        "output": tmp_path / "keys.json",
    }
    # Follow the existing fixture's public layout rather than inventing keys.
    if not options["coordinator_public_key_path"].exists():
        options["coordinator_public_key_path"] = root / "export-coordinator.pem"
        write_once(options["coordinator_public_key_path"], case.coordinator.public_pem())
    yield case, options
    case.tearDown()


def test_export_uses_authority_signed_esk_and_level(enrollment_case):
    case, options = enrollment_case
    report = export_enrollment_bindings(**options)
    assert report["status"] == "exported_verified_enrollment_bindings"
    assert not report["runtime_attestation_verified"]
    bindings = load_json(options["output"])
    enrollment = load_json(case.node / "enrollment_record.json")["core"]
    assert bindings["client01"]["trust_level"] == enrollment["trust_level"]
    assert (
        options["output"].parent / bindings["client01"]["public_key"]
    ).read_text() == enrollment["esk_public_key_pem"]


def test_export_rejects_coordinator_selected_wrong_authority(enrollment_case, tmp_path):
    _, options = enrollment_case
    key_path = tmp_path / "wrong-authority.pem"
    write_once(key_path, SoftwareECDSASigner.generate().public_pem())
    options["authority_public_key_path"] = key_path
    with pytest.raises(ValueError):
        export_enrollment_bindings(**options)
    assert not options["output"].exists()
