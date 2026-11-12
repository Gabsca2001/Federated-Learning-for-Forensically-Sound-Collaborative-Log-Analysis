"""Retrospective interventions over pinned historical evidence.

Outputs are analyst-signed experimental derivations, never fresh client updates,
Quotes or retroactively changed admission records.
"""

from __future__ import annotations

import copy
import json
import math
from datetime import UTC, datetime
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

import numpy as np
from pydantic import Field, field_validator

from .campaign_derivation import _pinned
from .canonical import sha256_bytes, sha256_file
from .crypto import DigestSigner
from .federated_model import arrays_from_export, delta_l2
from .in_round_admission import (
    _compute_statistical_state,
    _load_bound_contract,
    _runtime_decision_core,
)
from .in_round_admission_models import InRoundContributionDecision, InRoundSecureCheckpoint
from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc
from .preprocessing import derived_json_bytes
from .review_ledger import authenticate_review_subject
from .round_derivation import (
    _backend_profile,
    _numeric,
    _signed,
    _verify_signature,
    implementation_sha256,
)
from .round_derivation_models import RoundDerivationManifest
from .secure_round_models import (
    ContributionDecision,
    SecureRoundContext,
    UpdateBundle,
    tensor_schema,
)
from .storage import write_json_once, write_once


class CounterfactualError(ValueError):
    """Intervention cannot be reproduced within the declared evidence boundary."""


class CounterfactualRoundCore(StrictModel):
    domain: Literal["fl-counterfactual-round-v1"] = "fl-counterfactual-round-v1"
    source_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    mode: Literal["frozen_decisions", "rescore_round"]
    removed_submission_ids: list[str]
    source_evidence_sha256: dict[str, str]
    status: Literal["aggregated", "failed_without_model"]
    model_sha256: str | None
    analysis_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    created_at: str
    trust_checks: Literal["frozen_historical_effective_checks_no_new_quote"] = (
        "frozen_historical_effective_checks_no_new_quote"
    )
    client_updates: Literal["pinned_historical_input_bytes_not_resigned"] = (
        "pinned_historical_input_bytes_not_resigned"
    )

    _created_utc = field_validator("created_at")(_require_utc)


class CounterfactualRoundManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["counterfactual_round_manifest"] = "counterfactual_round_manifest"
    manifest_id: str
    core: CounterfactualRoundCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


def _aggregate(
    base: dict[str, Any], entries: list[dict[str, Any]], masses: dict[str, Decimal], minimum: int
) -> dict[str, Any] | None:
    selected = [
        (entry, masses[entry["submission_id"]])
        for entry in entries
        if masses[entry["submission_id"]] > 0
    ]
    if len(selected) < minimum:
        return None
    from .federated_model import dependencies

    aggregate = dependencies()[4]
    updates = [
        (arrays_from_export(entry["update"], np=np), float(mass)) for entry, mass in selected
    ]
    if any(not math.isfinite(weight) or weight <= 0 for _values, weight in updates):
        raise CounterfactualError("nonrepresentable operational aggregation weight")
    arrays = aggregate(updates)
    result = copy.deepcopy(base)
    for parameter, array in zip(result["parameters"], arrays, strict=True):
        parameter["values"] = np.asarray(array, dtype=np.dtype(parameter["dtype"])).tolist()
    return result


def _alphas(
    entries: list[dict[str, Any]], masses: dict[str, Decimal], valid: bool
) -> dict[str, Fraction] | None:
    total = sum(masses.values(), Decimal(0))
    if not valid or total <= 0:
        return None
    return {
        entry["submission_id"]: Fraction(masses[entry["submission_id"]]) / Fraction(total)
        for entry in entries
    }


def _fraction(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _proposal_metrics(
    expected_clients: list[str],
    dispositions: list[Any],
    entries: list[dict[str, Any]],
    removed: set[str],
    before_alpha: dict[str, Fraction] | None,
    after_alpha: dict[str, Fraction] | None,
    actions: dict[str, str],
) -> dict[str, Any]:
    """Original Delta/J on Kreq, with explicit padding for absent clients.

    The original proposal did not specify an action for an absent slot. Here
    absence is an operational marker, not a trust decision or semantic label.
    Unlike the survivor diagnostic, J includes the removal itself.
    """
    if len(set(expected_clients)) != len(expected_clients):
        raise CounterfactualError("duplicate expected client")
    expected = set(expected_clients)
    runtime = {}
    protocol: dict[str, set[str]] = {}
    for item in dispositions:
        if item.client_id not in expected:
            raise CounterfactualError("disposition outside expected clients")
        if item.kind == "protocol_rejection":
            protocol.setdefault(item.client_id, set()).add(item.final_status)
    for entry in entries:
        client = entry["client_id"]
        if client not in expected or client in runtime or client in protocol:
            raise CounterfactualError("ambiguous client slot in fixed population")
        runtime[client] = entry
    if removed - {entry["submission_id"] for entry in entries}:
        raise CounterfactualError("only runtime-admission submissions can be removed")
    before_actions = {}
    after_actions = {}
    for client in expected_clients:
        if client in runtime:
            entry = runtime[client]
            sid = entry["submission_id"]
            before_actions[client] = {
                "kind": "runtime_admission",
                "action": entry["runtime"].core.final_status,
            }
            after_actions[client] = (
                {"kind": "not_submitted"}
                if sid in removed
                else {"kind": "runtime_admission", "action": actions[sid]}
            )
        else:
            action = (
                {"kind": "protocol_rejection", "statuses": sorted(protocol[client])}
                if client in protocol
                else {"kind": "not_submitted"}
            )
            before_actions[client] = action
            after_actions[client] = action

    def vector(alpha: dict[str, Fraction] | None) -> dict[str, Fraction] | None:
        if alpha is None:
            return None
        return {
            client: alpha.get(runtime[client]["submission_id"], Fraction(0))
            if client in runtime
            else Fraction(0)
            for client in expected_clients
        }

    old, new = vector(before_alpha), vector(after_alpha)
    changed = [
        client for client in expected_clients if before_actions[client] != after_actions[client]
    ]
    return {
        "definition_profile": "original-fixed-expected-client-population-v1",
        "expected_client_ids": expected_clients,
        "absence_convention": "not_submitted pads missing and removed runtime slots; protocol-rejection history is unchanged",
        "coefficients_before": {k: _fraction(v) for k, v in old.items()}
        if old is not None
        else None,
        "coefficients_after": {k: _fraction(v) for k, v in new.items()}
        if new is not None
        else None,
        "delta_l1": _fraction(sum((abs(new[k] - old[k]) for k in expected_clients), Fraction(0)))
        if old is not None and new is not None
        else None,
        "actions_before": before_actions,
        "actions_after": after_actions,
        "j_any_action_change": int(bool(changed)),
        "changed_client_ids": changed,
        "interpretation": "J includes removal itself; neither J nor Delta alone proves an indirect scoring effect or malice",
    }


def _calculate(
    *,
    round_workspace: Path,
    expected_source_manifest_sha256: str,
    submissions_root: Path,
    validation_split_path: Path,
    coordinator_public_key: Any,
    mode: str,
    removed_submission_ids: list[str],
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, str]]:
    if mode not in {"frozen_decisions", "rescore_round"}:
        raise CounterfactualError("unknown intervention mode")
    if len(set(removed_submission_ids)) != len(removed_submission_ids):
        raise CounterfactualError("duplicate removed submission")
    authenticate_review_subject(
        round_workspace=round_workspace,
        trusted_coordinator_key=coordinator_public_key,
        expected_manifest_sha256=expected_source_manifest_sha256,
    )
    manifest = _pinned(
        round_workspace / "derivation/manifest.json",
        expected_source_manifest_sha256,
        RoundDerivationManifest,
    )
    context_data = (round_workspace / "public/round-context.json").read_bytes()
    context = SecureRoundContext.model_validate_json(context_data)
    from .secure_round import _verify_signed

    if (
        not _verify_signed(context, coordinator_public_key)
        or context.core_digest != manifest.core.context_digest
    ):
        raise CounterfactualError("changed historical context")
    base_data = (round_workspace / "public/base-model.json").read_bytes()
    if sha256_bytes(base_data) != context.core.base_model_sha256:
        raise CounterfactualError("changed historical base model")
    base = json.loads(base_data)
    with TemporaryDirectory(prefix="fl-counterfactual-public-") as temporary_public:
        public_snapshot = Path(temporary_public)
        for name, expected_hash in (
            ("training-contract.json", context.core.training_contract_sha256),
            ("partition-manifest.json", context.core.partition_manifest_sha256),
            ("in-round-admission-contract.json", None),
            ("in-round-admission.yaml", None),
        ):
            data = (round_workspace / "public" / name).read_bytes()
            if expected_hash is not None and sha256_bytes(data) != expected_hash:
                raise CounterfactualError("changed bound public input")
            write_once(public_snapshot / "public" / name, data)
        contract = _load_bound_contract(public_snapshot)
        contract_hash = sha256_file(public_snapshot / "public/in-round-admission-contract.json")
    validation_data = validation_split_path.read_bytes()
    if sha256_bytes(validation_data) != contract.core.validation_split_sha256:
        raise CounterfactualError("changed validation split")
    validation = json.loads(validation_data)
    rows = validation.get("rows", {}).get("validation")
    if (
        validation.get("split") != "validation"
        or not isinstance(rows, list)
        or len(rows) != contract.core.validation_row_count
    ):
        raise CounterfactualError("invalid isolated validation split")
    known = {item.submission_id for item in manifest.core.dispositions}
    if set(removed_submission_ids) - known:
        raise CounterfactualError("unknown removed submission")
    evidence = {
        "context": sha256_bytes(context_data),
        "base": sha256_bytes(base_data),
        "validation": sha256_bytes(validation_data),
        "admission_contract": contract_hash,
    }
    entries = []
    with TemporaryDirectory(prefix="fl-counterfactual-inputs-") as temporary:
        frozen = Path(temporary)
        for disposition in manifest.core.dispositions:
            if disposition.kind != "runtime_admission":
                if (
                    Decimal(disposition.effective_weight_decimal) != 0
                    or disposition.participated_in_scoring
                ):
                    raise CounterfactualError(
                        "protocol-rejected input claims numerical participation"
                    )
                continue
            client_id = disposition.client_id
            if Path(client_id).name != client_id or client_id in {".", ".."}:
                raise CounterfactualError("unsafe client locator")
            source = submissions_root / client_id
            if not source.resolve().is_relative_to(submissions_root.resolve()):
                raise CounterfactualError("submission locator escapes its root")
            bundle_data = (source / "bundle.json").read_bytes()
            if sha256_bytes(bundle_data) != disposition.bundle_sha256:
                raise CounterfactualError("changed historical bundle bytes")
            runtime = _pinned(
                round_workspace / "in-round-decisions" / f"{client_id}.json",
                disposition.decision_sha256,
                InRoundContributionDecision,
            )
            trust_data = (round_workspace / "decisions" / f"{client_id}.json").read_bytes()
            if sha256_bytes(trust_data) != disposition.trust_decision_sha256:
                raise CounterfactualError("changed trust bytes")
            trust = ContributionDecision.model_validate_json(trust_data)
            destination = frozen / client_id
            write_once(destination / "trust.json", trust_data)
            bundle = None
            update = None
            try:
                bundle = UpdateBundle.model_validate_json(bundle_data)
            except ValueError:
                if (
                    disposition.participated_in_scoring
                    or Decimal(disposition.effective_weight_decimal) > 0
                ):
                    raise CounterfactualError("invalid numerical bundle") from None
            if bundle is not None:
                update_data = (source / "update.json").read_bytes()
                if sha256_bytes(update_data) != bundle.core.update_sha256:
                    raise CounterfactualError("changed numerical update bytes")
                update = json.loads(update_data)
                if tensor_schema(update) != tensor_schema(base):
                    raise CounterfactualError("update tensor schema mismatch")
                arrays = arrays_from_export(update, np=np)
                if any(not np.isfinite(array).all() for array in arrays):
                    raise CounterfactualError("nonfinite numerical update")
                write_once(destination / "update.json", update_data)
                evidence[f"update:{client_id}"] = sha256_bytes(update_data)
            mass = Decimal(disposition.effective_weight_decimal)
            if (
                not mass.is_finite()
                or mass < 0
                or runtime.core.effective_weight_decimal != disposition.effective_weight_decimal
                or runtime.core.final_status != disposition.final_status
            ):
                raise CounterfactualError("inconsistent frozen decision/mass")
            if mass > 0 and (not disposition.mandatory_gate_passed or update is None):
                raise CounterfactualError("invalid positive frozen contribution")
            evidence[f"bundle:{client_id}"] = disposition.bundle_sha256
            evidence[f"runtime:{client_id}"] = disposition.decision_sha256
            evidence[f"trust:{client_id}"] = disposition.trust_decision_sha256
            entries.append(
                {
                    "submission_id": disposition.submission_id,
                    "client_id": client_id,
                    "bundle": bundle,
                    "update": update,
                    "runtime": runtime,
                    "mass": mass,
                    "record": {
                        "client_id": client_id,
                        "submission": destination,
                        "bundle": bundle,
                        "bundle_sha256": disposition.bundle_sha256,
                        "trust_decision": trust,
                        "trust_decision_path": destination / "trust.json",
                        "checks": list(runtime.core.m5_checks),
                        "raw_attestation_status": runtime.core.trust.raw_status,
                    },
                }
            )
        # Reproduce the recorded aggregation before attributing a removal effect.
        order = manifest.core.aggregation_order
        # The historical manifest records client IDs in the operational backend order.
        positive = {entry["client_id"]: entry for entry in entries if entry["mass"] > 0}
        if len(set(order)) != len(order) or set(order) != set(positive):
            raise CounterfactualError("historical aggregation order/mass mismatch")
        ordered = [positive[client] for client in order]
        original_masses = {entry["submission_id"]: entry["mass"] for entry in entries}
        total_mass = sum(original_masses.values(), Decimal(0))
        if Decimal(manifest.core.total_effective_weight_decimal) != total_mass:
            raise CounterfactualError("historical total mass mismatch")
        for disposition in manifest.core.dispositions:
            mass = Decimal(disposition.effective_weight_decimal)
            if manifest.core.checkpoint_sha256 is not None:
                expected_alpha = Fraction(mass) / Fraction(total_mass)
                expected_runtime = float(mass).hex() if mass > 0 else None
                if (disposition.alpha_numerator, disposition.alpha_denominator) != (
                    str(expected_alpha.numerator),
                    str(expected_alpha.denominator),
                ) or disposition.runtime_weight_hex != expected_runtime:
                    raise CounterfactualError("historical coefficient/operational weight mismatch")
            elif (
                disposition.alpha_numerator is not None or disposition.alpha_denominator is not None
            ):
                raise CounterfactualError("failed historical round claims coefficients")
        from .live_bounded_aggregation import enabled as bounded_enabled
        from .live_probe_gate import enabled as probe_enabled

        if probe_enabled(round_workspace):
            raise CounterfactualError(
                "probe/rollback-profile removals change peer medians and the rollback decision; counterfactual replay is unsupported (fail closed)"
            )
        if bounded_enabled(round_workspace):
            raise CounterfactualError(
                "bounded-profile removals require the explicit clipped-delta adapter; legacy raw-update counterfactual aggregation is unsupported"
            )
        baseline = _aggregate(base, ordered, original_masses, contract.core.minimum_contributors)
        original_model = None
        if manifest.core.checkpoint_sha256 is not None:
            checkpoint = _pinned(
                round_workspace / "checkpoint/manifest.json",
                manifest.core.checkpoint_sha256,
                InRoundSecureCheckpoint,
            )
            inputs = [
                (item.client_id, item.bundle_sha256, item.effective_weight_decimal)
                for item in checkpoint.core.accepted_inputs
            ]
            if inputs != [
                (
                    entry["client_id"],
                    entry["runtime"].core.bundle_sha256,
                    entry["runtime"].core.effective_weight_decimal,
                )
                for entry in ordered
            ]:
                raise CounterfactualError("historical checkpoint input order/weights mismatch")
            original_data = (round_workspace / "checkpoint/global-model.json").read_bytes()
            if sha256_bytes(original_data) != checkpoint.core.global_model_sha256:
                raise CounterfactualError("changed historical global model")
            original_model = json.loads(original_data)
            if baseline is None or derived_json_bytes(baseline) != original_data:
                raise CounterfactualError(
                    "historical aggregate does not reproduce under this backend"
                )
        elif baseline is not None:
            raise CounterfactualError("failed historical round unexpectedly produces a model")
        survivors = [
            entry for entry in entries if entry["submission_id"] not in removed_submission_ids
        ]
        frozen_masses = {entry["submission_id"]: entry["mass"] for entry in survivors}
        frozen_order = [
            entry for entry in ordered if entry["submission_id"] not in removed_submission_ids
        ]
        conditional = _aggregate(
            base, frozen_order, frozen_masses, contract.core.minimum_contributors
        )
        masses = dict(frozen_masses)
        actions = {
            entry["submission_id"]: entry["runtime"].core.final_status for entry in survivors
        }
        decisions = {}
        if mode == "rescore_round":
            if contract.core.primary_policy == "observable_envelope":
                raise CounterfactualError(
                    "observable envelope rescoring requires a newly supported cohort and authenticated prefix; frozen-decisions mode remains available"
                )
            records = [entry["record"] for entry in survivors]
            state = _compute_statistical_state(
                records=records,
                base=base,
                validation_rows=rows,
                batch_size=context.core.batch_size,
                contract=contract,
                disagreement_contract=None,
            )
            for entry in survivors:
                decision = _runtime_decision_core(
                    context=context,
                    contract=contract,
                    record=entry["record"],
                    statistical_state=state,
                    disagreement_contract=None,
                    decided_at=entry["runtime"].core.decided_at,
                )
                sid = entry["submission_id"]
                masses[sid] = Decimal(decision.effective_weight_decimal)
                actions[sid] = decision.final_status
                decisions[sid] = _numeric(decision.model_dump(mode="json"))
            # Runtime iterates the context's client order, not the positive subset order.
            rank = {client.client_id: index for index, client in enumerate(context.core.clients)}
            new_order = sorted(survivors, key=lambda entry: rank[entry["client_id"]])
            result = _aggregate(base, new_order, masses, contract.core.minimum_contributors)
        else:
            result = conditional
        original_alpha = _alphas(entries, original_masses, baseline is not None)
        conditional_alpha = _alphas(survivors, frozen_masses, conditional is not None)
        alpha = _alphas(survivors, masses, result is not None)
        changes = [
            entry["submission_id"]
            for entry in survivors
            if actions[entry["submission_id"]] != entry["runtime"].core.final_status
        ]
        delta = (
            sum((abs(alpha[sid] - original_alpha[sid]) for sid in masses), Fraction(0))
            if alpha is not None and original_alpha is not None
            else None
        )
        rescoring_delta = (
            sum((abs(alpha[sid] - conditional_alpha[sid]) for sid in masses), Fraction(0))
            if alpha is not None and conditional_alpha is not None
            else None
        )
        analysis = {
            "proposal_metrics": _proposal_metrics(
                [client.client_id for client in context.core.clients],
                manifest.core.dispositions,
                entries,
                set(removed_submission_ids),
                original_alpha,
                alpha,
                actions,
            ),
            "mode": mode,
            "removed_submission_ids": sorted(removed_submission_ids),
            "surviving_submission_ids": sorted(masses),
            "comparison_population": "surviving runtime-admission submissions; protocol rejection history unchanged",
            "status": "aggregated" if result is not None else "failed_without_model",
            "historical_aggregate_reproduced": baseline is not None,
            "historical_policy_decisions_revalidated": False,
            "frozen_historical_trust_checks": True,
            "new_attestation_performed": False,
            "subsequent_client_training_performed": False,
            "masses": {sid: str(mass) for sid, mass in sorted(masses.items())},
            "coefficients": {sid: _fraction(value) for sid, value in sorted(alpha.items())}
            if alpha is not None
            else None,
            "actions": actions,
            "counterfactual_decision_cores": decisions,
            "survivor_action_changes": sorted(changes),
            "survivor_action_change_fraction": _fraction(Fraction(len(changes), len(survivors)))
            if survivors
            else None,
            "survivor_coefficient_l1_delta": _fraction(delta) if delta is not None else None,
            "additional_coefficient_l1_delta_from_rescoring": _fraction(rescoring_delta)
            if rescoring_delta is not None
            else None,
            "model_l2_delta": format(
                delta_l2(
                    arrays_from_export(original_model, np=np),
                    arrays_from_export(result, np=np),
                    np=np,
                ),
                ".17g",
            )
            if original_model is not None and result is not None
            else None,
            "model_bytes_equal": derived_json_bytes(original_model) == derived_json_bytes(result)
            if original_model is not None and result is not None
            else None,
            "interpretation": "Conditional experimental effect under frozen historical trust and supplied inputs; not unlearning or a new secure checkpoint.",
        }
        from .influence_diagnostics import influence_diagnostics

        analysis["separated_influence_diagnostics"] = influence_diagnostics(
            before_coefficients=original_alpha,
            frozen_coefficients=conditional_alpha,
            after_coefficients=alpha,
            before_actions={
                entry["submission_id"]: entry["runtime"].core.final_status for entry in entries
            },
            after_actions=actions,
            removed_ids=set(removed_submission_ids),
            original_model=arrays_from_export(original_model, np=np)
            if original_model is not None
            else None,
            frozen_model=arrays_from_export(conditional, np=np)
            if conditional is not None
            else None,
            after_model=arrays_from_export(result, np=np) if result is not None else None,
        )
        dispositions = {item.submission_id: item for item in manifest.core.dispositions}
        analysis["historical_gate_and_scoring_membership"] = {
            entry["submission_id"]: {
                "client_id": entry["client_id"],
                "observed_trust_eligible": entry["record"]["trust_decision"].core.status
                == "accepted",
                "effective_mandatory_gate_passed": dispositions[
                    entry["submission_id"]
                ].mandatory_gate_passed,
                "participated_in_scoring": dispositions[
                    entry["submission_id"]
                ].participated_in_scoring,
            }
            for entry in entries
        }
        from .federated_model import dependencies

        analysis["backend_profile"] = _backend_profile(
            dependencies()[4], [float(mass) for mass in masses.values() if mass > 0]
        )
        return analysis, result, evidence


def create_counterfactual_round(
    *,
    output: Path,
    round_workspace: Path,
    expected_source_manifest_sha256: str,
    submissions_root: Path,
    validation_split_path: Path,
    coordinator_public_key: Any,
    authority_public_key: Any,
    signer: DigestSigner,
    mode: str,
    removed_submission_ids: list[str],
) -> dict[str, Any]:
    if any(
        output.resolve().is_relative_to(path.resolve())
        for path in (round_workspace, submissions_root)
    ):
        raise CounterfactualError("keep the intervention outside historical sources")
    analysis, model, evidence = _calculate(
        round_workspace=round_workspace,
        expected_source_manifest_sha256=expected_source_manifest_sha256,
        submissions_root=submissions_root,
        validation_split_path=validation_split_path,
        coordinator_public_key=coordinator_public_key,
        mode=mode,
        removed_submission_ids=removed_submission_ids,
    )
    analysis_data = derived_json_bytes(analysis)
    model_data = derived_json_bytes(model) if model is not None else None
    path = output / "manifest.json"
    previous = (
        CounterfactualRoundManifest.model_validate_json(path.read_bytes())
        if path.exists()
        else None
    )
    if previous is not None:
        _verify_signature(previous, authority_public_key, "manifest_id", "counterfactual-round-")
    core = CounterfactualRoundCore(
        source_manifest_sha256=expected_source_manifest_sha256,
        mode=mode,
        removed_submission_ids=sorted(removed_submission_ids),
        source_evidence_sha256=evidence,
        status=analysis["status"],
        model_sha256=sha256_bytes(model_data) if model_data is not None else None,
        analysis_sha256=sha256_bytes(analysis_data),
        implementation_sha256=implementation_sha256(),
        created_at=previous.core.created_at
        if previous
        else datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )
    if previous is not None and previous.core != core:
        raise CounterfactualError("existing intervention has different inputs or implementation")
    manifest = previous or _signed(
        CounterfactualRoundManifest, core, "manifest_id", "counterfactual-round-", signer
    )
    _verify_signature(manifest, authority_public_key, "manifest_id", "counterfactual-round-")
    write_once(output / "analysis.json", analysis_data)
    if model_data is not None:
        write_once(output / "model.json", model_data)
    write_json_once(path, manifest.model_dump(mode="json"))
    return {
        "status": core.status,
        "manifest_sha256": sha256_file(path),
        "manifest_id": manifest.manifest_id,
        **analysis,
    }


def verify_counterfactual_round(
    *,
    workspace: Path,
    expected_sha256: str,
    round_workspace: Path,
    submissions_root: Path,
    validation_split_path: Path,
    coordinator_public_key: Any,
    authority_public_key: Any,
) -> dict[str, Any]:
    try:
        manifest = _pinned(
            workspace / "manifest.json", expected_sha256, CounterfactualRoundManifest
        )
        _verify_signature(manifest, authority_public_key, "manifest_id", "counterfactual-round-")
        if manifest.core.implementation_sha256 != implementation_sha256():
            raise CounterfactualError(
                "use the preserved source release to recompute this intervention"
            )
        analysis, model, evidence = _calculate(
            round_workspace=round_workspace,
            expected_source_manifest_sha256=manifest.core.source_manifest_sha256,
            submissions_root=submissions_root,
            validation_split_path=validation_split_path,
            coordinator_public_key=coordinator_public_key,
            mode=manifest.core.mode,
            removed_submission_ids=manifest.core.removed_submission_ids,
        )
        expected_analysis = derived_json_bytes(analysis)
        if (
            evidence != manifest.core.source_evidence_sha256
            or sha256_bytes(expected_analysis) != manifest.core.analysis_sha256
            or (workspace / "analysis.json").read_bytes() != expected_analysis
            or analysis["status"] != manifest.core.status
        ):
            raise CounterfactualError("intervention analysis does not reproduce")
        if model is not None:
            data = derived_json_bytes(model)
            if (
                sha256_bytes(data) != manifest.core.model_sha256
                or (workspace / "model.json").read_bytes() != data
            ):
                raise CounterfactualError("intervention model does not reproduce")
        elif manifest.core.model_sha256 is not None or (workspace / "model.json").exists():
            raise CounterfactualError("failed intervention claims a model")
        return {
            "status": "verified",
            "intervention_recomputed": True,
            "new_training_performed": False,
            "new_attestation_performed": False,
            "analysis": analysis,
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        return {"status": "failed", "errors": [str(exc)]}
