"""Versioned M8 closure for the explicit unified witnessed-chain profile.

Reuses the existing inventory models, Merkle construction, RFC3161 verifier
and deterministic USTAR metadata. The old fixed thirty-round accounting
profiles remain unchanged. Recovery recomputes the declared complete chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, Literal

from pydantic import Field

from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .checkpoint_verification import (
    CheckpointVerificationProfile,
    verification_arguments,
    witness_proof,
)
from .merkle import _tree_manifest
from .models import HEX_256_PATTERN, SignatureBlock, StrictModel
from .preservation import _artifact
from .preservation_models import (
    ExcludedMaterial,
    ExternalEvidenceBinding,
    PreservationCore,
    PreservationManifest,
    PreservationState,
)
from .recovery import _tar_info
from .round_derivation import implementation_sha256
from .storage import load_json, write_json_once, write_once
from .submission_witness import _bytes, _signed, _verify_signed
from .system_chain import SystemChainSpec, chain_path, verify_system_chain
from .witness_models import TimestampEvidence
from .witness_time import TimestampProvider, verify_timestamp


class UnifiedClosureCore(StrictModel):
    profile: Literal["m8-unified-witnessed-chain-v1"] = "m8-unified-witnessed-chain-v1"
    system_spec_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    preservation_sha256: str = Field(pattern=HEX_256_PATTERN)
    merkle_sha256: str = Field(pattern=HEX_256_PATTERN)
    root_sha256: str = Field(pattern=HEX_256_PATTERN)
    timestamp_sha256: str = Field(pattern=HEX_256_PATTERN)
    anchor_subject_sha256: str = Field(pattern=HEX_256_PATTERN)
    round_count: int = Field(gt=0)
    selected_round: int = Field(gt=0)
    accepted_contributions: int = Field(ge=0)
    investigation_cases: int = Field(gt=0)
    administrative_independence_demonstrated: Literal[False] = False
    global_artifact_completeness_verified: Literal[False] = False
    source_record_coverage_replayed: Literal[False] = False
    attack_resistance_evaluated: Literal[False] = False


class UnifiedClosure(StrictModel):
    core: UnifiedClosureCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


ASSURANCE = {
    "preservation-manifest.json",
    "merkle-tree.json",
    "anchor-subject.json",
    "timestamp.json",
    "closure.json",
}


def _safe(value: str) -> str:
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "\\" in value or not relative.parts:
        raise ValueError("unsafe unified recovery path")
    return relative.as_posix()


def _policy(root: Path, spec: SystemChainSpec):
    args = verification_arguments(chain_path(root, spec.witness_profile))
    profile = CheckpointVerificationProfile.model_validate(args["verification_profile"])
    return witness_proof(profile.rounds["1"], args["profile_root"])


def _check_final_time(root: Path, spec: SystemChainSpec, interval) -> None:
    args = verification_arguments(chain_path(root, spec.witness_profile))
    profile = CheckpointVerificationProfile.model_validate(args["verification_profile"])
    for reference in profile.rounds.values():
        proof = witness_proof(reference, args["profile_root"])
        closed = proof["snapshot"].closure
        previous = verify_timestamp(
            _bytes(closed.core.subject),
            closed.timestamp,
            policy=proof["snapshot"].policy,
            trust_store=proof["trust_store"],
        )
        if interval.lower < previous.upper:
            raise ValueError("final preservation timestamp precedes witnessed closure")


def _inventory(root: Path, spec: SystemChainSpec) -> PreservationManifest:
    items = []
    prefixes = {
        spec.dataset: "M2",
        spec.partition: "M3",
        spec.trust: "M4",
        spec.campaign: "M5",
        spec.prediction: "M7.1",
        spec.explanation: "M7.2",
        spec.attack_mapping: "M7.3",
        spec.report: "M7.4",
        spec.graph: "derivation",
    }
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlinks are forbidden in unified public evidence")
        if not path.is_file():
            continue
        relative = _safe(path.relative_to(root).as_posix())
        if path.suffix == ".pem" and (
            "private" in path.name.lower() or b"PRIVATE KEY" in path.read_bytes()
        ):
            raise ValueError("private key material cannot enter unified public preservation")
        milestone = next(
            (label for prefix, label in prefixes.items() if relative.startswith(prefix + "/")),
            "contract",
        )
        items.append(
            _artifact(
                path=path,
                root=root,
                artifact_role="declared-unified-chain-input",
                milestone=milestone,
                workspace_role="derivation-chain",
                preservation_class="required-recomputation-input",
            )
        )
    descriptors = [item.model_dump(mode="json") for item in items]
    source = load_json(chain_path(root, spec.dataset) / "manifest.json")
    external = [
        ExternalEvidenceBinding(
            relative_path=str(item["relative_path"]),
            sha256=str(item["sha256"]),
            size_bytes=int(item["size_bytes"]),
            binding_source=spec.dataset + "/manifest.json",
        )
        for item in source.get("source_files", [])
    ]
    if not external:
        raise ValueError("unified M2 evidence lacks original source-file commitments")
    core = PreservationCore(
        derivation_chain=items,
        trust_assurance=[],
        campaign_assurance=[],
        external_evidence=external,
        excluded_material=[ExcludedMaterial(pattern="*private*.pem", reason="private-key-custody")],
        selected_derivation_round=int(
            load_json(chain_path(root, spec.campaign) / "campaign-manifest.json")["core"][
                "selected_round"
            ]
        ),
        campaign_rounds=list(range(1, spec.expected_rounds + 1)),
        preservation_state=PreservationState(
            artifact_count=len(items),
            total_size_bytes=sum(x.size_bytes for x in items),
            inventory_sha256=sha256_bytes(canonical_json_bytes(descriptors)),
        ),
    )
    digest = digest_object(core.model_dump(mode="json"))
    return PreservationManifest(
        preservation_id="m8-preservation-" + digest[:24], core=core, canonical_core_sha256=digest
    )


class _HashReader:
    def __init__(self, handle):
        self.handle = handle
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        value = self.handle.read(size)
        self.digest.update(value)
        return value


def create_unified_preservation(
    *, root: Path, output: Path, signer: Any, timestamp_provider: TimestampProvider
) -> dict:
    if output.exists():
        raise ValueError("unified preservation requires a new output workspace")
    if output.resolve().is_relative_to(root.resolve()):
        raise ValueError("M8 output must be outside the inventoried evidence root")
    checked = verify_system_chain(root)
    spec = SystemChainSpec.model_validate(load_json(root / "system-chain.json"))
    proof = _policy(root, spec)
    if signer.key_id != spec_key_id(proof):
        raise ValueError("unified closure signer differs from the authenticated coordinator")
    preserved = _inventory(root, spec)
    output.mkdir(parents=True)
    write_json_once(output / "preservation-manifest.json", preserved.model_dump(mode="json"))
    tree = _tree_manifest(preserved, sha256_file(output / "preservation-manifest.json"))
    write_json_once(output / "merkle-tree.json", tree.model_dump(mode="json"))
    anchor = {
        "domain": "fl-unified-preservation-subject-v1",
        "system_spec_sha256": sha256_file(root / "system-chain.json"),
        "implementation_sha256": implementation_sha256(),
        "preservation_sha256": sha256_file(output / "preservation-manifest.json"),
        "merkle_sha256": sha256_file(output / "merkle-tree.json"),
        "root_sha256": tree.core.root_sha256,
    }
    subject = canonical_json_bytes(anchor)
    evidence = timestamp_provider.stamp(subject)
    interval = verify_timestamp(
        subject, evidence, policy=proof["snapshot"].policy, trust_store=proof["trust_store"]
    )
    _check_final_time(root, spec, interval)
    write_once(output / "anchor-subject.json", subject)
    write_json_once(output / "timestamp.json", evidence.model_dump(mode="json"))
    core = UnifiedClosureCore(
        system_spec_sha256=anchor["system_spec_sha256"],
        implementation_sha256=implementation_sha256(),
        preservation_sha256=anchor["preservation_sha256"],
        merkle_sha256=anchor["merkle_sha256"],
        root_sha256=anchor["root_sha256"],
        timestamp_sha256=sha256_file(output / "timestamp.json"),
        anchor_subject_sha256=sha256_bytes(subject),
        round_count=spec.expected_rounds,
        selected_round=checked["selected_round"],
        accepted_contributions=checked["campaign"]["accepted_contribution_count"],
        investigation_cases=checked["investigation"]["case_count"],
    )
    closure = UnifiedClosure(**_signed(core, signer))
    write_json_once(output / "closure.json", closure.model_dump(mode="json"))
    sources = {
        "payload/" + x.relative_path: (root / x.relative_path, x.sha256, x.size_bytes)
        for x in preserved.core.derivation_chain
    }
    sources.update(
        {
            "assurance/" + name: (
                output / name,
                sha256_file(output / name),
                (output / name).stat().st_size,
            )
            for name in ASSURANCE
        }
    )
    fd = os.open(output / "recovery.tar", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with (
        os.fdopen(fd, "wb") as handle,
        tarfile.open(fileobj=handle, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for name, (path, digest, size) in sorted(sources.items()):
            with path.open("rb") as source:
                reader = _HashReader(source)
                archive.addfile(_tar_info(name, size), reader)
                if reader.digest.hexdigest() != digest:
                    raise ValueError("preserved source changed during recovery export")
    return {
        "status": "preserved_unified_chain",
        "closure_sha256": sha256_file(output / "closure.json"),
        "archive_sha256": sha256_file(output / "recovery.tar"),
        "archive_bytes": (output / "recovery.tar").stat().st_size,
        "artifact_count": len(preserved.core.derivation_chain),
        "root_sha256": tree.core.root_sha256,
        "timestamp_lower": interval.lower.isoformat(),
        "timestamp_upper": interval.upper.isoformat(),
        "administrative_independence_demonstrated": False,
    }


def spec_key_id(proof: dict) -> str:
    from .crypto import public_key_id

    return public_key_id(proof["coordinator_public_key"])


def verify_unified_recovery(*, archive_path: Path, expected_closure_sha256: str) -> dict:
    with TemporaryDirectory(prefix="unified-chain-recovery-") as temporary:
        base = Path(temporary)
        with tarfile.open(archive_path, "r:") as archive:
            members = archive.getmembers()
            names = [_safe(m.name) for m in members]
            if len(names) != len(set(names)) or any(not m.isfile() for m in members):
                raise ValueError("recovery contains duplicate or non-regular entries")
            for member in members:
                expected = _tar_info(member.name, member.size)
                if any(
                    getattr(member, k) != getattr(expected, k)
                    for k in ("mode", "uid", "gid", "mtime", "uname", "gname")
                ):
                    raise ValueError("recovery metadata differs from deterministic USTAR profile")
            assurance = {}
            for name in ASSURANCE:
                member = archive.getmember("assurance/" + name)
                if member.size > 64 * 1024 * 1024:
                    raise ValueError("oversized recovery assurance object")
                assurance[name] = archive.extractfile(member).read()
            if sha256_bytes(assurance["closure.json"]) != expected_closure_sha256:
                raise ValueError("recovery closure differs from externally retained pin")
            closure = UnifiedClosure.model_validate_json(assurance["closure.json"])
            for name, expected_digest in [
                ("preservation-manifest.json", closure.core.preservation_sha256),
                ("merkle-tree.json", closure.core.merkle_sha256),
                ("anchor-subject.json", closure.core.anchor_subject_sha256),
                ("timestamp.json", closure.core.timestamp_sha256),
            ]:
                if sha256_bytes(assurance[name]) != expected_digest:
                    raise ValueError("recovery assurance commitment mismatch")
            preserved = PreservationManifest.model_validate_json(
                assurance["preservation-manifest.json"]
            )
            entries = preserved.core.derivation_chain
            expected_names = {"assurance/" + n for n in ASSURANCE} | {
                "payload/" + _safe(x.relative_path) for x in entries
            }
            if (
                len({x.relative_path for x in entries}) != len(entries)
                or set(names) != expected_names
            ):
                raise ValueError("recovery file set differs from the committed inventory")
            if names != sorted(names):
                raise ValueError("recovery entries are not deterministically ordered")
            root = base / "payload"
            root.mkdir()
            for entry in entries:
                member = archive.getmember("payload/" + entry.relative_path)
                if member.size != entry.size_bytes:
                    raise ValueError("recovery artifact size mismatch")
                destination = root / _safe(entry.relative_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with archive.extractfile(member) as source, destination.open("xb") as target:
                    while block := source.read(1024 * 1024):
                        digest.update(block)
                        target.write(block)
                if digest.hexdigest() != entry.sha256:
                    raise ValueError("recovery artifact digest mismatch")
        if implementation_sha256() != closure.core.implementation_sha256:
            raise ValueError("unified recovery requires its preserved source release")
        if sha256_file(root / "system-chain.json") != closure.core.system_spec_sha256:
            raise ValueError("system specification commitment mismatch")
        spec = SystemChainSpec.model_validate(load_json(root / "system-chain.json"))
        proof = _policy(root, spec)
        _verify_signed(closure, proof["coordinator_public_key"])
        expected_tree = _tree_manifest(preserved, closure.core.preservation_sha256)
        if expected_tree.model_dump(mode="json") != json.loads(assurance["merkle-tree.json"]):
            raise ValueError("Merkle commitment does not reconstruct")
        if expected_tree.core.root_sha256 != closure.core.root_sha256:
            raise ValueError("Merkle root differs from closure")
        subject = json.loads(assurance["anchor-subject.json"])
        expected_subject = {
            "domain": "fl-unified-preservation-subject-v1",
            "system_spec_sha256": closure.core.system_spec_sha256,
            "implementation_sha256": closure.core.implementation_sha256,
            "preservation_sha256": closure.core.preservation_sha256,
            "merkle_sha256": closure.core.merkle_sha256,
            "root_sha256": closure.core.root_sha256,
        }
        if subject != expected_subject or assurance["anchor-subject.json"] != canonical_json_bytes(
            expected_subject
        ):
            raise ValueError("timestamp subject differs from final preservation commitments")
        interval = verify_timestamp(
            assurance["anchor-subject.json"],
            TimestampEvidence.model_validate_json(assurance["timestamp.json"]),
            policy=proof["snapshot"].policy,
            trust_store=proof["trust_store"],
        )
        _check_final_time(root, spec, interval)
        checked = verify_system_chain(root)
        if _inventory(root, spec) != preserved:
            raise ValueError("recovered preservation descriptors do not reconstruct")
        if (
            checked["round_count"],
            checked["selected_round"],
            checked["campaign"]["accepted_contribution_count"],
            checked["investigation"]["case_count"],
        ) != (
            closure.core.round_count,
            closure.core.selected_round,
            closure.core.accepted_contributions,
            closure.core.investigation_cases,
        ):
            raise ValueError("recovered campaign/investigation accounting mismatch")
        return {
            "status": "verified_unified_recovery",
            "verified_stages": [
                "inventory",
                "merkle",
                "external_timestamp",
                "recovery",
                "campaign_and_investigation_accounting",
            ],
            "round_count": closure.core.round_count,
            "accepted_contributions": closure.core.accepted_contributions,
            "investigation_cases": closure.core.investigation_cases,
            "artifact_count": len(entries),
            "timestamp_lower": interval.lower.isoformat(),
            "timestamp_upper": interval.upper.isoformat(),
            "administrative_independence_demonstrated": False,
            "global_artifact_completeness_verified": False,
            "source_record_coverage_replayed": False,
            "attack_resistance_evaluated": False,
        }


def add_system_commands(subparsers):
    chain = subparsers.add_parser(
        "system-chain-verify", help="verify the explicit witnessed M2–M7 composition"
    )
    chain.add_argument("--evidence-root", type=Path, required=True)
    create = subparsers.add_parser(
        "m8-unified-create", help="preserve a unified witnessed chain with a fresh timestamp"
    )
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--authority-private-key", type=Path, required=True)
    create.add_argument("--tsa-url", required=True)
    verify = subparsers.add_parser(
        "m8-unified-verify", help="reconstruct the unified chain from its recovery archive"
    )
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--expected-closure-sha256", required=True)


def run_system_command(arguments):
    if arguments.command == "system-chain-verify":
        return verify_system_chain(arguments.evidence_root)
    if arguments.command == "m8-unified-create":
        from .crypto import SoftwareECDSASigner
        from .witness_time import RFC3161Provider

        if not arguments.tsa_url.startswith("https://"):
            raise ValueError("unified external timestamp profile requires HTTPS")
        return create_unified_preservation(
            root=arguments.evidence_root,
            output=arguments.output,
            signer=SoftwareECDSASigner.load(arguments.authority_private_key),
            timestamp_provider=RFC3161Provider(arguments.tsa_url),
        )
    return verify_unified_recovery(
        archive_path=arguments.archive, expected_closure_sha256=arguments.expected_closure_sha256
    )
