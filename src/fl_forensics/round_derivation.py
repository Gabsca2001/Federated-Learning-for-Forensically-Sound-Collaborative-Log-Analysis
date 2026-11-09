"""Receipt-bound admission, explicit scoring provenance and FedAvg derivation.

This profile verifies the supplied evidence set, not delivery or independently
witnessed deadlines. Legacy checkpoints acquire no new guarantees implicitly.
"""

from __future__ import annotations

import importlib.metadata
import inspect
import math
import platform
from datetime import UTC
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

import numpy as np

from .byzantine import model_delta, update_indicators
from .canonical import digest_object, sha256_bytes, sha256_file
from .crypto import public_key_id, verify_digest_signature
from .round_derivation_models import (
    DerivationEdge,
    DerivationNode,
    RoundDerivationBinding,
    RoundDerivationBindingCore,
    RoundDerivationManifest,
    RoundDerivationManifestCore,
    RoundScoringState,
    RoundScoringStateCore,
    SubmissionFinalDisposition,
)
from .storage import load_json, write_json_once, write_once
from .submission_evidence import verify_submission_coverage
from .submission_evidence_models import RoundInputInventory
from .submission_evidence_workspace import _inputs


class RoundDerivationError(ValueError):
    """Missing, inconsistent or non-recomputable derivation evidence."""


def implementation_sha256() -> str:
    root = Path(__file__).resolve().parent
    return digest_object({path.name: sha256_file(path) for path in sorted(root.glob("*.py"))})


def _signed(model: Any, core: Any, id_field: str, prefix: str, signer: Any) -> Any:
    from .secure_round import _signature

    digest = digest_object(core.model_dump(mode="json"))
    return model(
        **{
            id_field: prefix + digest,
            "core": core,
            "core_digest": digest,
            "signature": _signature(signer, digest, "software-development"),
        }
    )


def _verify_signature(value: Any, key: Any, id_field: str, prefix: str) -> None:
    digest = digest_object(value.core.model_dump(mode="json"))
    if not (
        value.core_digest == digest
        and getattr(value, id_field) == prefix + digest
        and value.signature.key_id == public_key_id(key)
        and value.signature.trust_level == "software-development"
        and verify_digest_signature(key, digest, value.signature.value_b64)
    ):
        raise RoundDerivationError(f"invalid signed artifact: {id_field}")


def _numeric(value: Any) -> Any:
    """Preserve finite binary floats as explicit hexadecimal strings in new cores."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RoundDerivationError("non-finite numerical state")
        return "float_hex:" + value.hex()
    if isinstance(value, dict):
        return {key: _numeric(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_numeric(item) for item in value]
    return value


def _binding_core(inputs: dict[str, Any], inventory_path: Path) -> RoundDerivationBindingCore:
    inventory = RoundInputInventory.model_validate(load_json(inventory_path))
    report = verify_submission_coverage(inventory=inventory, **inputs)
    if not (
        report["coverage_verified"]
        and report["inventory_fully_recomputed"]
        and report["intake_outcomes_verified"]
    ):
        raise RoundDerivationError(
            "complete derivation requires full, recomputable client evidence"
        )
    entries = {(item.client_id, item.bundle_sha256) for item in inventory.core.entries}
    # Every payload actually offered in a context slot must be inventoried.
    for client in inputs["context"].core.clients:
        candidates = {
            path for path in inputs["bundle_paths"].values() if path.parent.name == client.client_id
        }
        for path in candidates:
            if (client.client_id, sha256_file(path)) not in entries:
                raise RoundDerivationError("a submitted bundle is not covered by the inventory")
    return RoundDerivationBindingCore(
        context_digest=inputs["context"].core_digest,
        input_inventory_sha256=sha256_file(inventory_path),
        receipt_core_digests=sorted({item.core_digest for item in inputs["evidence_receipts"]}),
        blocked_client_ids=sorted(
            {
                item.client_id
                for item in inventory.core.entries
                if item.outcome != "ready_for_admission"
            }
        ),
        implementation_sha256=implementation_sha256(),
    )


def prepare_round_derivation(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    client_receipts: Path | None,
    input_inventory_path: Path | None = None,
    coordinator_workspace: Path | None = None,
    create: bool = False,
    require: bool = False,
) -> RoundDerivationBinding | None:
    from .in_round_admission import _implementation_sha256, _load_bound_contract
    from .secure_round import _coordinator_signer

    root = workspace / "derivation"
    binding_path = root / "binding.json"
    requested = require or input_inventory_path is not None or client_receipts is not None
    artifacts_exist = any(
        (root / name).exists()
        for name in ("binding.json", "input-inventory.json", "scoring-state.json", "manifest.json")
    )
    if not requested and not artifacts_exist:
        return None
    if client_receipts is None:
        raise RoundDerivationError("client evidence is required for the bound derivation profile")
    if not binding_path.is_file() and (not create or input_inventory_path is None):
        raise RoundDerivationError("required derivation binding is missing")
    inputs = _inputs(
        workspace=workspace,
        trust_workspace=trust_workspace,
        client_receipts=client_receipts,
        submissions_root=submissions_root,
    )
    context = inputs["context"]
    for name, expected in (
        ("base-model.json", context.core.base_model_sha256),
        ("training-contract.json", context.core.training_contract_sha256),
        ("partition-manifest.json", context.core.partition_manifest_sha256),
        ("federation.yaml", context.core.federation_config_sha256),
    ):
        if sha256_file(workspace / "public" / name) != expected:
            raise RoundDerivationError(f"authenticated public input changed: {name}")
    inventory_path = root / "input-inventory.json"
    if binding_path.is_file():
        if input_inventory_path is not None and (
            sha256_file(input_inventory_path) != sha256_file(inventory_path)
        ):
            raise RoundDerivationError("supplied inventory differs from the frozen round inventory")
        binding = RoundDerivationBinding.model_validate(load_json(binding_path))
        _verify_signature(binding, inputs["coordinator_public_key"], "binding_id", "round-binding-")
        expected = _binding_core(inputs, inventory_path)
        if binding.core != expected:
            raise RoundDerivationError("derivation binding does not recompute")
        return binding
    if (workspace / "checkpoint" / "manifest.json").exists() or any(
        (workspace / folder).exists() for folder in ("decisions", "in-round-decisions")
    ):
        raise RoundDerivationError("bind the inventory before trust/scoring, not after decisions")
    if _load_bound_contract(workspace).core.implementation_sha256 != _implementation_sha256():
        raise RoundDerivationError("new derivations require the current admission contract")
    expected = _binding_core(inputs, input_inventory_path)
    write_once(inventory_path, input_inventory_path.read_bytes())
    binding = _signed(
        RoundDerivationBinding,
        expected,
        "binding_id",
        "round-binding-",
        _coordinator_signer(
            workspace,
            create=False,
            coordinator_workspace=coordinator_workspace or workspace.parent.parent,
        ),
    )
    write_json_once(binding_path, binding.model_dump(mode="json"))
    return binding


def _scoring_core(
    *,
    workspace: Path,
    context: Any,
    contract: Any,
    records: list[dict[str, Any]],
    statistical_state: dict[str, Any],
    base: dict[str, Any],
) -> RoundScoringStateCore:
    from .federated_model import arrays_from_export

    eligible = [
        record
        for record in records
        if record["bundle"] is not None and record["trust_decision"].core.status == "accepted"
    ]
    scored = [record for record in eligible if record["client_id"] in statistical_state]
    raw = []
    if scored:
        base_arrays = arrays_from_export(base, np=np)
        deltas = [
            model_delta(
                base_arrays,
                arrays_from_export(load_json(record["submission"] / "update.json"), np=np),
            )
            for record in scored
        ]
        raw = update_indicators(deltas, client_ids=[record["client_id"] for record in scored])
    disagreement = workspace / "public" / "m6-disagreement-contract.json"
    return RoundScoringStateCore(
        context_digest=context.core_digest,
        inventory_sha256=sha256_file(workspace / "derivation" / "input-inventory.json"),
        admission_contract_sha256=sha256_file(
            workspace / "public" / "in-round-admission-contract.json"
        ),
        validation_split_sha256=contract.core.validation_split_sha256,
        trust_eligible_client_ids=[record["client_id"] for record in eligible],
        scored_client_ids=[record["client_id"] for record in scored],
        ordered_bundle_sha256=[record["bundle_sha256"] for record in scored],
        computation_status="computed" if scored else "skipped_insufficient_candidates",
        disagreement_contract_sha256=sha256_file(disagreement) if disagreement.is_file() else None,
        numerical_state=_numeric(
            {
                "collective_indicators": raw,
                "per_client_statistics": {
                    record["client_id"]: statistical_state[record["client_id"]]["statistics"]
                    for record in scored
                },
                "calibration_references": contract.core.indicator_references,
            }
        ),
    )


def _backend_profile(aggregate: Any, weights: list[float]) -> dict[str, str]:
    try:
        source = inspect.getsource(aggregate).encode("utf-8")
        name = f"{aggregate.__module__}.{aggregate.__qualname__}"
    except (OSError, TypeError, AttributeError) as exc:
        raise RoundDerivationError("aggregation backend source must be identifiable") from exc
    profile = {
        "callable": name,
        "source_sha256": sha256_bytes(source),
        "python": platform.python_version(),
        "numpy": np.__version__,
        "weight_semantics": "Decimal mass converted to binary float; multiply/sum/divide backend",
        "binary_weight_sum_hex": sum(weights).hex() if weights else float(0).hex(),
    }
    for package in ("cryptography", "pydantic", "scikit-learn", "torch", "flwr"):
        try:
            profile["version:" + package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            profile["version:" + package] = "not_installed"
    if hasattr(aggregate, "forensic_profile"):
        profile.update(aggregate.forensic_profile)
    return profile


def _dispositions(
    *,
    inventory: RoundInputInventory,
    decisions: list[tuple[Any, Path]],
    records: list[dict[str, Any]],
    contract: Any,
    scored_ids: list[str],
    aggregated: bool,
) -> tuple[list[SubmissionFinalDisposition], Decimal, list[str]]:
    by_client = {item.core.client_id: (item, path) for item, path in decisions}
    by_record = {item["client_id"]: item for item in records}
    total = sum((Decimal(item.core.effective_weight_decimal) for item, _ in decisions), Decimal(0))
    order = [
        item.core.client_id
        for item, _ in decisions
        if Decimal(item.core.effective_weight_decimal) > 0
    ]
    dispositions = []
    for entry in inventory.core.entries:
        factor, mass = Decimal(0), Decimal(0)
        decision_hash = trust_hash = runtime_hex = None
        gate, scored = False, False
        if entry.outcome != "ready_for_admission":
            kind, status = "protocol_rejection", entry.outcome
            if entry.client_id in by_client:
                raise RoundDerivationError("intake-rejected client entered runtime admission")
        else:
            if entry.client_id not in by_client:
                raise RoundDerivationError("submission lacks a final admission decision")
            decision, path = by_client[entry.client_id]
            record = by_record[entry.client_id]
            if decision.core.bundle_sha256 != entry.bundle_sha256:
                raise RoundDerivationError("final decision refers to another bundle")
            kind, status = "runtime_admission", decision.core.final_status
            factor = (
                Decimal(1)
                if status == "accepted"
                else Decimal(str(contract.core.accepted_downweight_factor))
                if status == "accepted_downweighted"
                else Decimal(0)
            )
            mass = Decimal(decision.core.effective_weight_decimal)
            gate = all(check.passed for check in decision.core.m5_checks)
            if mass != Decimal(decision.core.num_examples) * factor or (not gate and mass != 0):
                raise RoundDerivationError("non-compensation or effective mass violation")
            scored = entry.client_id in scored_ids
            decision_hash, trust_hash = (
                sha256_file(path),
                sha256_file(record["trust_decision_path"]),
            )
            if mass > 0:
                runtime_hex = float(mass).hex()
        alpha = Fraction(mass) / Fraction(total) if aggregated else None
        dispositions.append(
            SubmissionFinalDisposition(
                submission_id=entry.submission_id,
                client_id=entry.client_id,
                bundle_sha256=entry.bundle_sha256,
                kind=kind,
                intake_outcome=entry.outcome,
                decision_sha256=decision_hash,
                trust_decision_sha256=trust_hash,
                final_status=status,
                mandatory_gate_passed=gate,
                participated_in_scoring=scored,
                policy_factor_decimal=format(factor, "f"),
                effective_weight_decimal=format(mass, "f"),
                alpha_numerator=str(alpha.numerator) if alpha is not None else None,
                alpha_denominator=str(alpha.denominator) if alpha is not None else None,
                runtime_weight_hex=runtime_hex,
            )
        )
    if {
        entry.client_id
        for entry in inventory.core.entries
        if entry.outcome == "ready_for_admission"
    } != set(by_client):
        raise RoundDerivationError("runtime decisions and inventoried submissions differ")
    return dispositions, total, order


def _graph(
    *,
    workspace: Path,
    context: Any,
    inventory: RoundInputInventory,
    dispositions: list[SubmissionFinalDisposition],
    scoring: RoundScoringState,
    checkpoint_hash: str | None,
    status: str,
) -> tuple[list[DerivationNode], list[DerivationEdge]]:
    nodes: dict[str, DerivationNode] = {}
    edges: set[tuple[str, str, str]] = set()

    def node(
        kind: str,
        digest: str,
        *,
        prefix: str | None = None,
        commitment_only: bool = False,
        occurrence_id: str | None = None,
    ) -> str:
        identity = (prefix or kind) + ":" + (digest if occurrence_id is None else occurrence_id)
        nodes[identity] = DerivationNode(
            node_id=identity,
            kind=kind,
            sha256=digest,
            availability="commitment_only" if commitment_only else "available",
        )
        return identity

    ctx = node("round_context", context.core_digest)
    inv = node(
        "round_input_inventory", sha256_file(workspace / "derivation" / "input-inventory.json")
    )
    binding = node(
        "round_derivation_binding", sha256_file(workspace / "derivation" / "binding.json")
    )
    score = node(
        "round_scoring_state",
        sha256_file(workspace / "derivation" / "scoring-state.json"),
        prefix="scoring",
    )
    contract = node("admission_contract", scoring.core.admission_contract_sha256)
    validation = node("validation_split", scoring.core.validation_split_sha256)
    target = (
        node("checkpoint", checkpoint_hash)
        if checkpoint_hash is not None
        else node(
            "round_outcome", digest_object({"context": context.core_digest, "status": status})
        )
    )
    edges.update(
        {
            (ctx, score, "dec"),
            (inv, binding, "dec"),
            (binding, score, "dec"),
            (contract, score, "dec"),
            (validation, score, "num" if scoring.core.scored_client_ids else "audit"),
        }
    )
    from .live_bounded_aggregation import enabled as bounded_enabled

    bounded_node = None
    if checkpoint_hash is not None and bounded_enabled(workspace):
        bounded_node = node(
            "bounded_update_derivation", sha256_file(workspace / "bounded-update-derivation.json")
        )
        limit_node = node(
            "aggregation_limits", sha256_file(workspace / "public/observable-assets/bounds.json")
        )
        base_node = node("base_model", context.core.base_model_sha256)
        edges.update(
            {
                (base_node, bounded_node, "num"),
                (limit_node, bounded_node, "num"),
                (bounded_node, target, "num"),
                (contract, bounded_node, "dec"),
            }
        )
    by_id = {item.submission_id: item for item in inventory.core.entries}
    for item in dispositions:
        entry = by_id[item.submission_id]
        bundle = node(
            "update_bundle",
            item.bundle_sha256,
            # Identical bundle bytes can be claimed in another context/client slot.
            # Keep that rejected submission separate from the original occurrence.
            occurrence_id=item.submission_id,
            commitment_only=entry.outcome != "ready_for_admission",
        )
        final = node("submission_final_disposition", digest_object(item.model_dump(mode="json")))
        edges.update({(ctx, bundle, "audit"), (inv, final, "dec"), (bundle, final, "audit")})
        for receipt_digest in entry.receipt_core_digests:
            receipt = node("submission_receipt_core", receipt_digest)
            edges.update({(receipt, inv, "audit"), (receipt, bundle, "audit")})
        if item.trust_decision_sha256 is not None:
            trust = node("trust_decision", item.trust_decision_sha256)
            decision = node("admission_decision", item.decision_sha256)
            edges.update(
                {(bundle, trust, "dec"), (trust, decision, "dec"), (decision, final, "audit")}
            )
            if item.participated_in_scoring:
                edges.update({(bundle, score, "num"), (score, decision, "dec")})
        if checkpoint_hash is not None and Decimal(item.effective_weight_decimal) > 0:
            edges.update({(bundle, bounded_node or target, "num"), (decision, target, "dec")})
        elif checkpoint_hash is not None and item.decision_sha256 is not None:
            edges.add((decision, target, "audit"))
            if bounded_node is not None:
                edges.add((bundle, bounded_node, "audit"))
        # The signed final disposition documents an already produced round outcome.
        edges.add((target, final, "audit"))
    return [nodes[key] for key in sorted(nodes)], [
        DerivationEdge(source=source, target=target_id, kind=kind)
        for source, target_id, kind in sorted(edges)
    ]


def _check_graph(core: RoundDerivationManifestCore) -> None:
    ids = [node.node_id for node in core.nodes]
    if len(set(ids)) != len(ids):
        raise RoundDerivationError("duplicate graph node")
    successors: dict[str, set[str]] = {identity: set() for identity in ids}
    for edge in core.edges:
        if edge.source not in successors or edge.target not in successors:
            raise RoundDerivationError("unresolved graph endpoint")
        successors[edge.source].add(edge.target)
    visiting, complete = set(), set()

    def visit(identity: str) -> None:
        if identity in visiting:
            raise RoundDerivationError("cycle in round derivation")
        if identity in complete:
            return
        visiting.add(identity)
        for child in successors[identity]:
            visit(child)
        visiting.remove(identity)
        complete.add(identity)

    for identity in ids:
        visit(identity)


def materialize_round_derivation(
    *,
    workspace: Path,
    context: Any,
    contract: Any,
    records: list[dict[str, Any]],
    missing: list[str],
    statistical_state: dict[str, Any],
    decisions: list[tuple[Any, Path]],
    base: dict[str, Any],
    aggregate: Any,
    now: Any,
    aggregated: bool,
    create: bool,
    coordinator_workspace: Path | None = None,
) -> dict[str, Any]:
    """Build or independently recompute both signed artifacts from actual round inputs."""
    from .secure_round import _coordinator_public_key, _coordinator_signer

    root, key = workspace / "derivation", _coordinator_public_key(workspace)
    inventory = RoundInputInventory.model_validate(load_json(root / "input-inventory.json"))
    expected_scoring = _scoring_core(
        workspace=workspace,
        context=context,
        contract=contract,
        records=records,
        statistical_state=statistical_state,
        base=base,
    )
    signer = (
        _coordinator_signer(
            workspace,
            create=False,
            coordinator_workspace=coordinator_workspace or workspace.parent.parent,
        )
        if create
        else None
    )
    scoring_path = root / "scoring-state.json"
    if create and not scoring_path.exists():
        scoring = _signed(
            RoundScoringState, expected_scoring, "scoring_id", "round-scoring-", signer
        )
        write_json_once(scoring_path, scoring.model_dump(mode="json"))
    scoring = RoundScoringState.model_validate(load_json(scoring_path))
    _verify_signature(scoring, key, "scoring_id", "round-scoring-")
    if scoring.core != expected_scoring:
        raise RoundDerivationError("scoring population or numerical state does not recompute")
    dispositions, total, order = _dispositions(
        inventory=inventory,
        decisions=decisions,
        records=records,
        contract=contract,
        scored_ids=scoring.core.scored_client_ids,
        aggregated=aggregated,
    )
    checkpoint_path = workspace / "checkpoint" / "manifest.json"
    if not aggregated and checkpoint_path.exists():
        raise RoundDerivationError("failed round unexpectedly has a checkpoint")
    checkpoint_hash = sha256_file(checkpoint_path) if aggregated else None
    status = "aggregated" if aggregated else "failed_without_checkpoint"
    nodes, edges = _graph(
        workspace=workspace,
        context=context,
        inventory=inventory,
        dispositions=dispositions,
        scoring=scoring,
        checkpoint_hash=checkpoint_hash,
        status=status,
    )
    core = RoundDerivationManifestCore(
        context_digest=context.core_digest,
        input_inventory_sha256=sha256_file(root / "input-inventory.json"),
        binding_sha256=sha256_file(root / "binding.json"),
        scoring_state_sha256=sha256_file(scoring_path),
        checkpoint_sha256=checkpoint_hash,
        round_status=status,
        protocol_rejected_client_ids=sorted(
            {item.client_id for item in dispositions if item.kind == "protocol_rejection"}
        ),
        missing_client_ids=missing,
        dispositions=dispositions,
        total_effective_weight_decimal=format(total, "f"),
        aggregation_order=order,
        backend_profile=_backend_profile(
            aggregate,
            [
                float(Decimal(item.core.effective_weight_decimal))
                for item, _ in decisions
                if Decimal(item.core.effective_weight_decimal) > 0
            ],
        ),
        nodes=nodes,
        edges=edges,
        implementation_sha256=implementation_sha256(),
        created_at=now.astimezone(UTC).isoformat(),
    )
    _check_graph(core)
    manifest_path = root / "manifest.json"
    if create and not manifest_path.exists():
        manifest = _signed(
            RoundDerivationManifest, core, "manifest_id", "round-derivation-", signer
        )
        write_json_once(manifest_path, manifest.model_dump(mode="json"))
    manifest = RoundDerivationManifest.model_validate(load_json(manifest_path))
    _verify_signature(manifest, key, "manifest_id", "round-derivation-")
    if manifest.core != core:
        raise RoundDerivationError("derivation manifest, weights or graph do not recompute")
    runtime_clients = {item.core.client_id for item, _ in decisions}
    rejected_clients = set(core.protocol_rejected_client_ids)
    if runtime_clients & rejected_clients or set(missing) & (runtime_clients | rejected_clients):
        raise RoundDerivationError("client accounting categories overlap")
    if runtime_clients | rejected_clients | set(missing) != {
        item.client_id for item in context.core.clients
    }:
        raise RoundDerivationError("client accounting is incomplete")
    return {
        "verification_scope": "receipt_bound_round_derivation",
        "derivation_status": "verified",
        "round_status": status,
        "admission_decisions_verified": True,
        "derivation_verified": True,
        "scoring_population_verified": True,
        "coefficients_verified": aggregated,
        "deadline_verified": False,
        "delivery_verified": False,
        "derivation_manifest_id": manifest.manifest_id,
        "property_statuses": {
            "admission_decisions": "verified",
            "scoring_population": "verified",
            "coefficients": "verified" if aggregated else "not_defined_without_checkpoint",
            "deadline": "not_checked",
            "delivery": "not_checked",
        },
    }


def verify_failed_round_derivation(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    validation_split_path: Path,
    binding: RoundDerivationBinding,
) -> dict[str, Any]:
    from .disagreement_experiment import load_bound_disagreement_contract
    from .in_round_admission import (
        _compute_statistical_state,
        _load_bound_contract,
        _load_or_create_runtime_decisions,
        _load_or_create_trust_records,
        _load_validation_rows,
        dependencies,
    )
    from .secure_round import _load_context, _parse_time

    manifest = RoundDerivationManifest.model_validate(
        load_json(workspace / "derivation" / "manifest.json")
    )
    if manifest.core.round_status != "failed_without_checkpoint":
        raise RoundDerivationError("missing checkpoint for a purportedly aggregated round")
    now = _parse_time(manifest.core.created_at)
    context, contract = _load_context(workspace / "public"), _load_bound_contract(workspace)
    if not (_parse_time(context.core.issued_at) <= now < _parse_time(context.core.expires_at)):
        raise RoundDerivationError("failed-round closure is outside context lifetime")
    disagreement = load_bound_disagreement_contract(workspace / "public")
    rows = _load_validation_rows(
        workspace=workspace, validation_split_path=validation_split_path, contract=contract
    )
    records, missing = _load_or_create_trust_records(
        workspace=workspace,
        trust_workspace=trust_workspace,
        submissions_root=submissions_root,
        now=now,
        create=False,
        blocked_client_ids=set(binding.core.blocked_client_ids),
    )
    base = load_json(workspace / "public" / "base-model.json")
    statistical = _compute_statistical_state(
        records=records,
        base=base,
        validation_rows=rows,
        batch_size=context.core.batch_size,
        contract=contract,
        disagreement_contract=disagreement,
    )
    if contract.core.primary_policy == "observable_envelope":
        from .live_envelope import apply_live_envelope

        statistical = apply_live_envelope(
            workspace=workspace,
            trust_workspace=trust_workspace,
            validation_split_path=validation_split_path,
            context=context,
            contract=contract,
            records=records,
            base=base,
            statistical_state=statistical,
            create=False,
        )
    decisions = _load_or_create_runtime_decisions(
        workspace=workspace,
        records=records,
        statistical_state=statistical,
        contract=contract,
        disagreement_contract=disagreement,
        now=now,
        create=False,
    )
    contributing = [
        item for item, _ in decisions if Decimal(item.core.effective_weight_decimal) > 0
    ]
    if len(contributing) >= contract.core.minimum_contributors:
        raise RoundDerivationError("a failed-without-checkpoint round has sufficient contributors")
    result = materialize_round_derivation(
        workspace=workspace,
        context=context,
        contract=contract,
        records=records,
        missing=missing,
        statistical_state=statistical,
        decisions=decisions,
        base=base,
        aggregate=dependencies()[4],
        now=now,
        aggregated=False,
        create=False,
    )
    return {
        "status": "verified",
        "workspace": str(workspace),
        "checkpoint_id": None,
        "global_model_sha256": None,
        "aggregate_recomputed": False,
        "trust_recomputed": True,
        "statistics_recomputed": True,
        "decisions_recomputed": True,
        "accepted_count": len(contributing),
        "downweighted_count": sum(
            item.core.final_status == "accepted_downweighted" for item in contributing
        ),
        "quarantined_count": len(decisions) - len(contributing),
        "missing_count": len(missing),
        "errors": [],
        "error_count": 0,
        **result,
    }
