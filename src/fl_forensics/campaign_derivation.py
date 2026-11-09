"""Reconstruct multiround dependencies; do not infer a numerical causal effect."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from .campaign_derivation_models import (
    CampaignDerivationCore,
    CampaignDerivationManifest,
    CampaignGraphEdge,
    CampaignGraphNode,
    CampaignProductReference,
    CampaignRoundReference,
)
from .canonical import digest_object, sha256_bytes, sha256_file
from .crypto import DigestSigner
from .in_round_admission_models import InRoundSecureCheckpoint
from .investigation_models import (
    AttackMappingBundleManifest,
    ExplanationBundleManifest,
    InvestigationReportBundleManifest,
    PredictionBundleManifest,
)
from .review_ledger import authenticate_review_subject
from .round_derivation import _graph, _signed, _verify_signature, implementation_sha256
from .round_derivation_models import RoundDerivationManifest, RoundScoringState
from .secure_round_models import SecureRoundContext
from .storage import write_json_once
from .submission_evidence_models import RoundInputInventory


class CampaignDerivationError(ValueError):
    """Missing, inconsistent, or unpinned evidence in the requested graph."""


def _pinned(path: Path, expected: str, model: Any) -> Any:
    data = path.read_bytes()
    if sha256_bytes(data) != expected:
        raise CampaignDerivationError(f"changed pinned artifact: {path}")
    return model.model_validate_json(data)


def _acyclic(nodes: Mapping[str, Any], edges: set[tuple[str, str, str]]) -> None:
    successors: dict[str, set[str]] = {node: set() for node in nodes}
    degrees = dict.fromkeys(nodes, 0)
    for source, target, _kind in edges:
        if source not in nodes or target not in nodes:
            raise CampaignDerivationError("unresolved campaign graph endpoint")
        if target not in successors[source]:
            successors[source].add(target)
            degrees[target] += 1
    pending = deque(sorted(node for node, degree in degrees.items() if degree == 0))
    visited = 0
    while pending:
        visited += 1
        for child in sorted(successors[pending.popleft()]):
            degrees[child] -= 1
            if degrees[child] == 0:
                pending.append(child)
    if visited != len(nodes):
        raise CampaignDerivationError("cycle in campaign graph")


_PRODUCTS = {
    "m7_prediction_bundle_manifest": (
        "prediction",
        PredictionBundleManifest,
        "bundle_id",
        "m7-prediction-bundle-",
        {"predictions_sha256": "predictions.json", "lineage_sha256": "lineage.json"},
    ),
    "m7_explanation_bundle_manifest": (
        "explanation",
        ExplanationBundleManifest,
        "explanation_bundle_id",
        "m7-explanation-bundle-",
        {
            "integrated_gradients_sha256": "integrated-gradients.json",
            "prototype_reference_sha256": "prototype-reference.json",
            "prototype_distances_sha256": "prototype-distances.json",
        },
    ),
    "m7_attack_mapping_bundle_manifest": (
        "attack_mapping",
        AttackMappingBundleManifest,
        "attack_mapping_bundle_id",
        "m7-attack-mapping-bundle-",
        {"attack_mappings_sha256": "attack-mappings.json"},
    ),
    "m7_investigation_report_bundle_manifest": (
        "investigation_report",
        InvestigationReportBundleManifest,
        "investigation_report_bundle_id",
        "m7-investigation-report-bundle-",
        {
            "investigation_report_sha256": "investigation-report.json",
            "report_markdown_sha256": "report.md",
        },
    ),
}


def reconstruct_campaign_graph(
    *,
    round_workspaces: Mapping[str, Path],
    product_workspaces: Mapping[str, Path],
    coordinator_public_key: Any,
    created_at: str,
    producer_implementation_sha256: str | None = None,
) -> CampaignDerivationCore:
    """Authenticate and rebuild the graph for an explicitly provided evidence set.

    Map keys are pinned manifest byte hashes. Paths are locators, not authority.
    The full numerical verifier must be run separately with its preserved release.
    """
    nodes: dict[str, CampaignGraphNode] = {}
    edges: set[tuple[str, str, str]] = set()
    rounds, products = [], []
    contexts: dict[str, Any] = {}
    checkpoints: dict[str, tuple[Any, Any]] = {}
    product_values: dict[str, Any] = {}

    def node(
        identity: str, kind: str, digest: str, context: str, availability: str = "available"
    ) -> str:
        previous = nodes.get(identity)
        if previous is not None:
            if previous.kind != kind or previous.sha256 != digest:
                raise CampaignDerivationError("conflicting campaign graph identity")
            nodes[identity] = previous.model_copy(
                update={"contexts": sorted(set(previous.contexts + [context]))}
            )
            if previous.availability != availability:
                raise CampaignDerivationError("conflicting availability claim")
        else:
            nodes[identity] = CampaignGraphNode(
                node_id=identity,
                kind=kind,
                sha256=digest,
                availability=availability,
                contexts=[context],
            )
        return identity

    for manifest_hash, workspace in sorted(round_workspaces.items()):
        authenticate_review_subject(
            round_workspace=workspace,
            trusted_coordinator_key=coordinator_public_key,
            expected_manifest_sha256=manifest_hash,
        )
        manifest = _pinned(
            workspace / "derivation" / "manifest.json", manifest_hash, RoundDerivationManifest
        )
        context_data = (workspace / "public" / "round-context.json").read_bytes()
        context = SecureRoundContext.model_validate_json(context_data)
        if context.core_digest != manifest.core.context_digest:
            raise CampaignDerivationError("round context changed after authentication")
        # Recheck the context signature on this exact byte snapshot.
        from .secure_round import _verify_signed

        if not _verify_signed(context, coordinator_public_key):
            raise CampaignDerivationError("invalid round context signature")
        if context.core_digest in contexts:
            raise CampaignDerivationError("duplicate round context")
        contexts[context.core_digest] = context
        inventory = _pinned(
            workspace / "derivation" / "input-inventory.json",
            manifest.core.input_inventory_sha256,
            RoundInputInventory,
        )
        scoring = _pinned(
            workspace / "derivation" / "scoring-state.json",
            manifest.core.scoring_state_sha256,
            RoundScoringState,
        )
        expected_nodes, expected_edges = _graph(
            workspace=workspace,
            context=context,
            inventory=inventory,
            dispositions=manifest.core.dispositions,
            scoring=scoring,
            checkpoint_hash=manifest.core.checkpoint_sha256,
            status=manifest.core.round_status,
        )
        if manifest.core.nodes != expected_nodes or manifest.core.edges != expected_edges:
            raise CampaignDerivationError("round graph differs from declared round evidence")
        for item in manifest.core.dispositions:
            mass = Decimal(item.effective_weight_decimal)
            if not mass.is_finite() or mass < 0 or (mass > 0 and not item.mandatory_gate_passed):
                raise CampaignDerivationError("invalid declared aggregation mass")
            if item.participated_in_scoring != (item.client_id in scoring.core.scored_client_ids):
                raise CampaignDerivationError("submission/scoring population mismatch")
        for item in manifest.core.nodes:
            observed = item.kind in {
                "round_context",
                "round_input_inventory",
                "round_derivation_binding",
                "round_scoring_state",
                "submission_final_disposition",
                "trust_decision",
                "admission_decision",
                "checkpoint",
                "round_outcome",
            }
            node(
                item.node_id,
                item.kind,
                item.sha256,
                context.core_digest,
                "available" if observed else "commitment_only",
            )
        edges.update((edge.source, edge.target, edge.kind) for edge in manifest.core.edges)
        if manifest.core.checkpoint_sha256 is None:
            outcome = next(
                item.node_id for item in manifest.core.nodes if item.kind == "round_outcome"
            )
            edges.add((f"scoring:{manifest.core.scoring_state_sha256}", outcome, "dec"))
        manifest_node = node(
            f"round-manifest:{manifest_hash}", "round_manifest", manifest_hash, context.core_digest
        )
        for item in manifest.core.dispositions:
            edges.add(
                (
                    f"submission_final_disposition:{digest_object(item.model_dump(mode='json'))}",
                    manifest_node,
                    "audit",
                )
            )
        checkpoint = None
        if manifest.core.checkpoint_sha256 is not None:
            checkpoint = _pinned(
                workspace / "checkpoint" / "manifest.json",
                manifest.core.checkpoint_sha256,
                InRoundSecureCheckpoint,
            )
            if (
                manifest.core.round_status != "aggregated"
                or checkpoint.core.context_digest != context.core_digest
                or checkpoint.core.context_id != context.context_id
                or checkpoint.core.campaign_id != context.core.campaign_id
                or checkpoint.core.round_number != context.core.round_number
                or checkpoint.core.previous_checkpoint_sha256
                != context.core.previous_checkpoint_sha256
                or checkpoint.core.base_model_sha256 != context.core.base_model_sha256
            ):
                raise CampaignDerivationError("checkpoint/context chain mismatch")
            expected_inputs = {
                (
                    item.client_id,
                    item.bundle_sha256,
                    item.decision_sha256,
                    item.effective_weight_decimal,
                )
                for item in manifest.core.dispositions
                if Decimal(item.effective_weight_decimal) > 0
            }
            actual_inputs = [
                (
                    item.client_id,
                    item.bundle_sha256,
                    item.decision_sha256,
                    item.effective_weight_decimal,
                )
                for item in checkpoint.core.accepted_inputs
            ]
            if set(actual_inputs) != expected_inputs or len(actual_inputs) != len(expected_inputs):
                raise CampaignDerivationError("checkpoint inputs differ from positive dispositions")
            if (
                sha256_file(workspace / "checkpoint" / "global-model.json")
                != checkpoint.core.global_model_sha256
            ):
                raise CampaignDerivationError("changed checkpoint model")
            cp = manifest.core.checkpoint_sha256
            if cp in checkpoints:
                raise CampaignDerivationError("duplicate checkpoint occurrence")
            checkpoints[cp] = (checkpoint, context)
            # Content equality does not merge two independently produced model occurrences.
            model = node(
                f"checkpoint-model:{cp}",
                "checkpoint_model",
                checkpoint.core.global_model_sha256,
                context.core_digest,
            )
            edges.add((f"checkpoint:{cp}", model, "num"))
            edges.add((f"checkpoint:{cp}", manifest_node, "audit"))
        rounds.append(
            CampaignRoundReference(
                manifest_sha256=manifest_hash,
                context_digest=context.core_digest,
                context_sha256=sha256_bytes(context_data),
                campaign_id=context.core.campaign_id,
                round_number=context.core.round_number,
                previous_checkpoint_sha256=context.core.previous_checkpoint_sha256,
                base_model_sha256=context.core.base_model_sha256,
                checkpoint_sha256=manifest.core.checkpoint_sha256,
                global_model_sha256=checkpoint.core.global_model_sha256 if checkpoint else None,
                submissions={
                    item.submission_id: f"update_bundle:{item.submission_id}"
                    for item in manifest.core.dispositions
                },
            )
        )

    for reference in rounds:
        base = node(
            f"round-base:{reference.context_digest}",
            "round_base_model",
            reference.base_model_sha256,
            reference.context_digest,
        )
        ctx = f"round_context:{reference.context_digest}"
        edges.add((base, ctx, "audit"))
        if reference.previous_checkpoint_sha256 == "0" * 64:
            if reference.round_number != 1:
                raise CampaignDerivationError("noninitial round refers to genesis")
        else:
            parent = checkpoints.get(reference.previous_checkpoint_sha256)
            if parent is None:
                raise CampaignDerivationError("missing parent checkpoint; chain is incomplete")
            checkpoint, parent_context = parent
            if (
                parent_context.core.round_number + 1 != reference.round_number
                or checkpoint.core.global_model_sha256 != reference.base_model_sha256
            ):
                raise CampaignDerivationError("round number/base model breaks the parent chain")
            edges.add((f"checkpoint-model:{reference.previous_checkpoint_sha256}", base, "num"))
            edges.add((f"checkpoint:{reference.previous_checkpoint_sha256}", ctx, "dec"))
        # The base is used to evaluate deltas/validation and is the declared training base.
        workspace = round_workspaces[reference.manifest_sha256]
        manifest = _pinned(
            workspace / "derivation" / "manifest.json",
            reference.manifest_sha256,
            RoundDerivationManifest,
        )
        score = f"scoring:{manifest.core.scoring_state_sha256}"
        scoring = _pinned(
            workspace / "derivation" / "scoring-state.json",
            manifest.core.scoring_state_sha256,
            RoundScoringState,
        )
        if scoring.core.scored_client_ids:
            edges.add((base, score, "num"))
        if reference.checkpoint_sha256:
            # Signed successful inputs identify which local models used this base.
            checkpoint, _context = checkpoints[reference.checkpoint_sha256]
            for item in manifest.core.dispositions:
                if Decimal(item.effective_weight_decimal) > 0:
                    edges.add((base, f"update_bundle:{item.submission_id}", "num"))

    import json

    for manifest_hash, workspace in sorted(product_workspaces.items()):
        data = (workspace / "manifest.json").read_bytes()
        if sha256_bytes(data) != manifest_hash:
            raise CampaignDerivationError("changed pinned product manifest")
        kind, model, id_field, prefix, _payloads = _PRODUCTS[json.loads(data)["artifact_type"]]
        value = model.model_validate_json(data)
        core_value = value.core.model_dump(mode="json")
        # M7 preserves two historical serialization profiles. Attack mappings and
        # reports include the trailing newline in the core hash; predictions and
        # explanations use the strict formal serializer without that newline.
        if kind == "attack_mapping":
            from .attack_mapping import _canonical_json_bytes as encode_core

            digest = sha256_bytes(encode_core(core_value))
        elif kind == "investigation_report":
            from .investigation_report import _canonical_json_bytes as encode_core

            digest = sha256_bytes(encode_core(core_value))
        else:
            digest = digest_object(core_value)
        if (
            value.canonical_core_sha256 != digest
            or getattr(value, id_field) != prefix + digest[:24]
        ):
            raise CampaignDerivationError("invalid content-addressed product identity")
        product_values[manifest_hash] = (kind, value, workspace)

    # Resolve semantic source relations by hashes, never by input order or folder name.
    for manifest_hash, (kind, value, workspace) in sorted(product_values.items()):
        source = value.core.sources if kind == "prediction" else value.core.source
        cp_hash = source.checkpoint_manifest_sha256 if kind == "prediction" else None
        if kind != "prediction":
            parent = product_values.get(source.prediction_manifest_sha256)
            if parent is None or parent[0] != "prediction":
                raise CampaignDerivationError("missing prediction source manifest")
            cp_hash = parent[1].core.sources.checkpoint_manifest_sha256
            if source.prediction_bundle_id != parent[1].bundle_id:
                raise CampaignDerivationError("product refers to another prediction identity")
        if cp_hash not in checkpoints:
            raise CampaignDerivationError("product uses an unknown checkpoint")
        checkpoint, context = checkpoints[cp_hash]
        expected = {
            "campaign_id": context.core.campaign_id,
            "round_number": context.core.round_number,
            "global_model_sha256": checkpoint.core.global_model_sha256,
            "partition_manifest_sha256": context.core.partition_manifest_sha256,
        }
        if any(getattr(source, name) != item for name, item in expected.items()):
            raise CampaignDerivationError("product source differs from its checkpoint")
        if kind == "prediction" and (
            source.context_id != context.context_id
            or source.checkpoint_id != checkpoint.checkpoint_id
            or source.round_context_sha256
            != sha256_bytes(
                (
                    round_workspaces[
                        next(
                            r.manifest_sha256
                            for r in rounds
                            if r.context_digest == context.core_digest
                        )
                    ]
                    / "public"
                    / "round-context.json"
                ).read_bytes()
            )
        ):
            raise CampaignDerivationError("prediction context identity mismatch")
        identity = node(f"{kind}:{manifest_hash}", kind, manifest_hash, context.core_digest)
        dependencies = []
        if kind == "prediction":
            dependencies.append((f"checkpoint-model:{cp_hash}", "num"))
            edges.add((f"checkpoint:{cp_hash}", identity, "audit"))
        elif kind == "explanation":
            dependencies.append((f"checkpoint-model:{cp_hash}", "num"))
        for field, parent_kind, id_name in (
            ("prediction_manifest_sha256", "prediction", "prediction_bundle_id"),
            ("explanation_manifest_sha256", "explanation", "explanation_bundle_id"),
            ("attack_manifest_sha256", "attack_mapping", "attack_mapping_bundle_id"),
        ):
            if not hasattr(source, field):
                continue
            parent_hash = getattr(source, field)
            parent = product_values.get(parent_hash)
            if parent is None or parent[0] != parent_kind:
                raise CampaignDerivationError(f"missing {parent_kind} source manifest")
            parent_value = parent[1]
            parent_id = getattr(parent_value, _PRODUCTS[parent_value.artifact_type][2])
            if getattr(source, id_name) != parent_id:
                raise CampaignDerivationError("product source identity mismatch")
            # All source payload commitments must match their referenced parent cores.
            for name in type(source).model_fields:
                if (
                    hasattr(parent_value.core, name)
                    and name.endswith("_sha256")
                    and getattr(source, name) != getattr(parent_value.core, name)
                ):
                    raise CampaignDerivationError("product source payload commitment mismatch")
            parent_context = (
                parent_value.core.sources
                if parent_kind == "prediction"
                else parent_value.core.source
            )
            if (
                parent_context.global_model_sha256 != source.global_model_sha256
                or parent_context.campaign_id != source.campaign_id
                or parent_context.round_number != source.round_number
            ):
                raise CampaignDerivationError("product sources belong to different checkpoints")
            for link in ("prediction_manifest_sha256", "explanation_manifest_sha256"):
                if (
                    hasattr(source, link)
                    and hasattr(parent_context, link)
                    and getattr(source, link) != getattr(parent_context, link)
                ):
                    raise CampaignDerivationError(
                        "product sources refer to different derivation branches"
                    )
            edges.add((f"{parent_kind}:{parent_hash}", identity, "audit"))
            # Follow actual input payloads, preserving numerical vs rule/audit use.
            for filename in _PRODUCTS[parent_value.artifact_type][4].values():
                relation = "num"
                if filename in {"lineage.json", "prototype-reference.json"}:
                    relation = "audit"
                elif kind == "attack_mapping":
                    relation = "dec" if parent_kind == "prediction" else "audit"
                elif parent_kind == "attack_mapping":
                    relation = "dec"
                dependencies.append((f"product-payload:{parent_hash}:{filename}", relation))
        for field, filename in _PRODUCTS[value.artifact_type][4].items():
            path = workspace / filename
            digest = getattr(value.core, field)
            available = "available" if path.is_file() else "missing"
            if available == "available" and sha256_file(path) != digest:
                raise CampaignDerivationError("changed product payload")
            payload = node(
                f"product-payload:{manifest_hash}:{filename}",
                f"{kind}_payload",
                digest,
                context.core_digest,
                available,
            )
            for dependency, relation in dependencies:
                edges.add(
                    (dependency, payload, "audit" if filename == "lineage.json" else relation)
                )
            # Manifests commit already produced payloads, never generate their own inputs.
            edges.add((payload, identity, "audit"))
        products.append(
            CampaignProductReference(
                manifest_sha256=manifest_hash, kind=kind, context_digest=context.core_digest
            )
        )

    _acyclic(nodes, edges)
    return CampaignDerivationCore(
        rounds=sorted(rounds, key=lambda r: (r.campaign_id, r.round_number, r.manifest_sha256)),
        products=sorted(products, key=lambda p: p.manifest_sha256),
        nodes=[nodes[key] for key in sorted(nodes)],
        edges=[CampaignGraphEdge(source=s, target=t, kind=k) for s, t, k in sorted(edges)],
        producer_implementation_sha256=producer_implementation_sha256 or implementation_sha256(),
        created_at=created_at,
    )


def create_campaign_derivation(
    *,
    output: Path,
    round_workspaces: Mapping[str, Path],
    product_workspaces: Mapping[str, Path],
    coordinator_public_key: Any,
    signer: DigestSigner,
    authority_public_key: Any,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    if any(
        output.resolve().is_relative_to(path.resolve())
        for path in [*round_workspaces.values(), *product_workspaces.values()]
    ):
        raise CampaignDerivationError("keep the campaign graph outside its historical sources")
    path = output / "manifest.json"
    previous = (
        CampaignDerivationManifest.model_validate_json(path.read_bytes()) if path.exists() else None
    )
    if previous is not None:
        _verify_signature(previous, authority_public_key, "manifest_id", "campaign-derivation-")
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise CampaignDerivationError("creation time must include an offset")
    when = timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if previous is not None and created_at is None:
        when = previous.core.created_at
    core = reconstruct_campaign_graph(
        round_workspaces=round_workspaces,
        product_workspaces=product_workspaces,
        coordinator_public_key=coordinator_public_key,
        created_at=when,
    )
    if previous is not None:
        if previous.core != core:
            raise CampaignDerivationError("existing campaign snapshot has different evidence")
        manifest = previous
    else:
        manifest = _signed(
            CampaignDerivationManifest, core, "manifest_id", "campaign-derivation-", signer
        )
        _verify_signature(manifest, authority_public_key, "manifest_id", "campaign-derivation-")
        write_json_once(path, manifest.model_dump(mode="json"))
    return {
        "status": "created",
        "manifest_sha256": sha256_file(path),
        "manifest_id": manifest.manifest_id,
        "round_count": len(core.rounds),
        "product_count": len(core.products),
    }


def verify_campaign_derivation(
    *,
    workspace: Path,
    expected_sha256: str,
    round_workspaces: Mapping[str, Path],
    product_workspaces: Mapping[str, Path],
    coordinator_public_key: Any,
    authority_public_key: Any,
) -> dict[str, Any]:
    report = {
        "status": "failed",
        "errors": [],
        "historical_rounds_numerically_recomputed": False,
        "product_payloads_recomputed": False,
        "global_artifact_completeness_verified": False,
    }
    try:
        manifest = _pinned(workspace / "manifest.json", expected_sha256, CampaignDerivationManifest)
        _verify_signature(manifest, authority_public_key, "manifest_id", "campaign-derivation-")
        core = reconstruct_campaign_graph(
            round_workspaces=round_workspaces,
            product_workspaces=product_workspaces,
            coordinator_public_key=coordinator_public_key,
            created_at=manifest.core.created_at,
            producer_implementation_sha256=manifest.core.producer_implementation_sha256,
        )
        current_availability = {node.node_id: node.availability for node in core.nodes}
        signed_availability = {node.node_id: node.availability for node in manifest.core.nodes}
        comparison = core.model_copy(
            update={
                "nodes": [
                    node.model_copy(
                        update={
                            "availability": signed_availability.get(node.node_id, node.availability)
                        }
                    )
                    for node in core.nodes
                ]
            }
        )
        if comparison != manifest.core:
            raise CampaignDerivationError("campaign graph differs from reconstructed evidence")
        missing = [node.node_id for node in core.nodes if node.availability == "missing"]
        report.update(
            status="verified",
            manifest_sha256=expected_sha256,
            source_authentication_verified=True,
            structure_reconstructed=True,
            evidence_scope=core.evidence_scope,
            round_count=len(core.rounds),
            product_count=len(core.products),
            missing_payload_nodes=missing,
            node_availability=current_availability,
            supplied_product_payloads_complete=not missing,
            reconstruction_implementation_sha256=implementation_sha256(),
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        report["errors"].append(str(exc))
    return report


def structural_blast_radius(
    *,
    workspace: Path,
    expected_sha256: str,
    submission_id: str,
    round_workspaces: Mapping[str, Path],
    product_workspaces: Mapping[str, Path],
    coordinator_public_key: Any,
    authority_public_key: Any,
) -> dict[str, Any]:
    report = verify_campaign_derivation(
        workspace=workspace,
        expected_sha256=expected_sha256,
        round_workspaces=round_workspaces,
        product_workspaces=product_workspaces,
        coordinator_public_key=coordinator_public_key,
        authority_public_key=authority_public_key,
    )
    if report["status"] != "verified":
        return report
    try:
        manifest = _pinned(workspace / "manifest.json", expected_sha256, CampaignDerivationManifest)
        origins = [
            reference.submissions[submission_id]
            for reference in manifest.core.rounds
            if submission_id in reference.submissions
        ]
        if len(origins) != 1:
            raise CampaignDerivationError("unknown or ambiguous submission origin")
        start = origins[0]
        nodes = {item.node_id: item for item in manifest.core.nodes}
        successors: dict[str, list[Any]] = defaultdict(list)
        for edge in manifest.core.edges:
            successors[edge.source].append(edge)
        flags = {"num": 1, "dec": 2, "audit": 4}
        pending = deque([(start, 0, [start], [])])
        seen = {(start, 0)}
        found: dict[str, list[dict[str, Any]]] = defaultdict(list)
        while pending:
            current, signature, path, kinds = pending.popleft()
            for edge in successors[current]:
                marker = signature | flags[edge.kind]
                if (edge.target, marker) in seen:
                    continue
                seen.add((edge.target, marker))
                route, types = path + [edge.target], kinds + [edge.kind]
                category = (
                    "documentary_dependency"
                    if marker & 4
                    else ("decision_dependency" if marker & 2 else "numerical_dependency")
                )
                found[edge.target].append(
                    {"category": category, "nodes": route, "edge_kinds": types}
                )
                pending.append((edge.target, marker, route, types))
        reachable = [
            {
                **nodes[identity].model_dump(mode="json"),
                "snapshot_availability": nodes[identity].availability,
                "availability": report["node_availability"][identity],
                "paths": found[identity],
                "numerical_effect_demonstrated": False,
            }
            for identity in sorted(found)
        ]
        report.update(
            submission_id=submission_id,
            origin_node=start,
            reachable=reachable,
            counts_by_kind=dict(sorted(Counter(item["kind"] for item in reachable).items())),
            numerical_effect_demonstrated=False,
            path_rule="one shortest witness per reachable edge-type set; no multiplication of coefficients along mixed paths",
            interpretation="Recorded dependency in the supplied evidence graph; neither damage nor a demonstrated numerical change.",
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        report["status"] = "failed"
        report["errors"].append(str(exc))
    return report


def structural_blast_radius_set(
    *,
    submission_ids: list[str],
    **common: Any,
) -> dict[str, Any]:
    """Union explicitly selected historical submissions, retaining per-origin witnesses.

    Selection is an analyst input. No client-wide semantic accusation or permanent
    exclusion is inferred. Descendants are counted once, even with several causes.
    """
    if not submission_ids or len(submission_ids) != len(set(submission_ids)):
        return {"status": "failed", "errors": ["selection must be nonempty and unique"]}
    reports = [
        structural_blast_radius(submission_id=sid, **common) for sid in sorted(submission_ids)
    ]
    failed = [r for r in reports if r["status"] != "verified"]
    if failed:
        return {"status": "failed", "errors": [e for r in failed for e in r["errors"]]}
    merged: dict[str, dict[str, Any]] = {}
    for report in reports:
        for item in report["reachable"]:
            if item["node_id"] not in merged:
                merged[item["node_id"]] = {**item, "paths": []}
            merged[item["node_id"]]["paths"].extend(
                {**path, "origin_submission_id": report["submission_id"]} for path in item["paths"]
            )
    first = reports[0]
    return {
        **{
            k: v
            for k, v in first.items()
            if k not in {"submission_id", "origin_node", "reachable", "counts_by_kind"}
        },
        "selected_submission_ids": sorted(submission_ids),
        "selection_semantics": "explicit-historical-submission-set; no automatic client-wide claim",
        "origins": [
            {
                "submission_id": r["submission_id"],
                "node_id": r["origin_node"],
                "reachable_count": len(r["reachable"]),
            }
            for r in reports
        ],
        "reachable": [merged[key] for key in sorted(merged)],
        "counts_by_kind": dict(sorted(Counter(item["kind"] for item in merged.values()).items())),
        "unique_reachable_count": len(merged),
        "sum_of_per_origin_counts": sum(len(r["reachable"]) for r in reports),
    }
