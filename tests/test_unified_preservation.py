"""Archive/commitment adversaries; stage and TSA doubles are explicitly scoped.

The separate live case must execute actual M2–M7 and external RFC3161. These
tests isolate M8 packing/reconstruction while retaining real signed receipts.
"""

import io
import tarfile

import pytest
from test_checkpoint_verification import retain_profile
from test_witness_phase import _admit
from test_witness_phase import integrated as _integrated

from fl_forensics import unified_preservation as m8
from fl_forensics.recovery import _tar_info
from fl_forensics.storage import write_json_once, write_once

integrated = _integrated


@pytest.fixture
def package(integrated, tmp_path, monkeypatch):
    d = integrated
    proof = d.close_witness()
    assert _admit(d, proof)["status"] == "verified_witness_round"
    root = tmp_path / "public"
    profile = retain_profile(d, proof, root / "witness")
    write_json_once(root / "witness/profile.json", profile)
    spec = m8.SystemChainSpec(
        dataset="dataset",
        partition="partition",
        trust="trust",
        campaign="campaign",
        witness_profile="witness/profile.json",
        prediction="products/prediction",
        explanation="products/explanation",
        attack_mapping="products/attack",
        report="products/report",
        prediction_config="configs/prediction.yaml",
        explanation_config="configs/explanation.yaml",
        attack_config="configs/attack.yaml",
        report_config="configs/report.yaml",
        graph="graph",
        graph_manifest_sha256="a" * 64,
        expected_rounds=1,
    )
    write_json_once(root / "system-chain.json", spec.model_dump(mode="json"))
    write_json_once(
        root / "dataset/manifest.json",
        {
            "source_files": [
                {"relative_path": "original.parquet", "sha256": "b" * 64, "size_bytes": 8}
            ]
        },
    )
    write_json_once(root / "campaign/campaign-manifest.json", {"core": {"selected_round": 1}})
    write_once(root / "retained-public-object.txt", b"public snapshot bytes")
    checked = {
        "round_count": 1,
        "selected_round": 1,
        "campaign": {"accepted_contribution_count": 2},
        "investigation": {"case_count": 1},
    }
    monkeypatch.setattr(m8, "verify_system_chain", lambda root: checked)
    monkeypatch.setattr(m8, "verify_timestamp", d.clock.verify)
    from datetime import timedelta

    d.clock.now += timedelta(seconds=60)
    output = tmp_path / "preserved"
    result = m8.create_unified_preservation(
        root=root, output=output, signer=d.fixture.coordinator, timestamp_provider=d.clock
    )
    return root, output, result


def test_archive_reconstructs_all_committed_inputs_and_accounting(package):
    _root, output, result = package
    report = m8.verify_unified_recovery(
        archive_path=output / "recovery.tar", expected_closure_sha256=result["closure_sha256"]
    )
    assert report["status"] == "verified_unified_recovery"
    assert len(report["verified_stages"]) == 5 and report["accepted_contributions"] == 2
    assert not report["administrative_independence_demonstrated"]
    assert not report["source_record_coverage_replayed"]


def test_recovery_requires_external_closure_pin(package):
    _root, output, _result = package
    with pytest.raises(ValueError, match="externally retained"):
        m8.verify_unified_recovery(
            archive_path=output / "recovery.tar", expected_closure_sha256="0" * 64
        )


@pytest.mark.parametrize(
    "change",
    ["payload", "missing", "extra", "duplicate", "traversal", "symlink", "metadata", "timestamp"],
)
def test_recovery_rejects_archive_mutations(package, tmp_path, change):
    _root, output, result = package
    with tarfile.open(output / "recovery.tar", "r:") as source:
        contents = [(m.name, source.extractfile(m).read()) for m in source.getmembers()]
    target = "payload/retained-public-object.txt"
    if change == "payload":
        contents = [(n, b"x" * len(v) if n == target else v) for n, v in contents]
    elif change == "missing":
        contents = [(n, v) for n, v in contents if n != target]
    elif change == "extra":
        contents.append(("payload/unregistered", b"extra"))
    elif change == "duplicate":
        contents.append(next((n, v) for n, v in contents if n == target))
    elif change == "traversal":
        contents.append(("payload/../../outside", b"outside"))
    elif change == "timestamp":
        contents = [
            (n, b"x" * len(v) if n == "assurance/timestamp.json" else v) for n, v in contents
        ]
    path = tmp_path / (change + ".tar")
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, value in sorted(contents):
            info = _tar_info(name, len(value))
            if name == target and change == "metadata":
                info.uid = 123
            if name == target and change == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                info.size = 0
                archive.addfile(info)
            else:
                archive.addfile(info, io.BytesIO(value))
    with pytest.raises((ValueError, KeyError)):
        m8.verify_unified_recovery(
            archive_path=path, expected_closure_sha256=result["closure_sha256"]
        )
    assert not (tmp_path / "outside").exists()


def test_private_key_and_symbolic_link_cannot_enter_inventory(package):
    root, _output, _result = package
    spec = m8.SystemChainSpec.model_validate(m8.load_json(root / "system-chain.json"))
    private = root / "unexpected.private.pem"
    private.write_bytes(b"private material must be rejected by name")
    with pytest.raises(ValueError, match="private key"):
        m8._inventory(root, spec)
    private.unlink()
    (root / "shortcut").symlink_to(root / "retained-public-object.txt")
    with pytest.raises(ValueError, match="symlinks"):
        m8._inventory(root, spec)
