"""One explicit M2–M8 composition; alternative experiments retain their profiles.

This profile joins existing verifiers. It does not infer independent witness
administration, upstream capture completeness or poisoning resistance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field

from .models import HEX_256_PATTERN, StrictModel
from .storage import load_json


class SystemChainSpec(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["unified-witnessed-fedavg-v1"] = "unified-witnessed-fedavg-v1"
    dataset: str
    partition: str
    trust: str
    campaign: str
    witness_profile: str
    prediction: str
    explanation: str
    attack_mapping: str
    report: str
    prediction_config: str
    explanation_config: str
    attack_config: str
    report_config: str
    graph: str
    graph_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    expected_rounds: int = Field(gt=0)
    source_manifest: str = "source/manifest.json"


def chain_path(root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("system-chain inputs must be relative to its public evidence root")
    result = root / relative
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError("system-chain input escapes its public evidence root")
    return result


def verify_system_chain(root: Path) -> dict:
    from .campaign_derivation import verify_campaign_derivation
    from .canonical import sha256_file
    from .checkpoint_verification import verification_arguments
    from .config import load_yaml
    from .crypto import load_public_key
    from .investigation_report import verify_investigation_report_bundle
    from .round_derivation import implementation_sha256
    from .secure_campaign import verify_secure_campaign

    spec = SystemChainSpec.model_validate(load_json(root / "system-chain.json"))

    def path(name: str) -> Path:
        return chain_path(root, getattr(spec, name))

    source = load_json(path("source_manifest"))
    current = {p.name: sha256_file(p) for p in Path(__file__).parent.glob("*.py")}
    if (
        source.get("implementation_sha256") != implementation_sha256()
        or source.get("files") != current
    ):
        raise ValueError("system source manifest differs from the executing release")
    for name, digest in current.items():
        if sha256_file(path("source_manifest").parent / "src/fl_forensics" / name) != digest:
            raise ValueError("retained source bytes differ from the executing release")

    verification = verification_arguments(path("witness_profile"))
    prediction_config, _digest = load_yaml(path("prediction_config"))
    if (
        prediction_config.get("checkpoint_verification") != verification["verification_profile"]
        or path("prediction_config").parent != path("witness_profile").parent
    ):
        raise ValueError("campaign and M7 must use the same trusted witness profile and path base")
    if set(verification["verification_profile"]["rounds"]) != {
        str(i) for i in range(1, spec.expected_rounds + 1)
    }:
        raise ValueError("witness profile must exactly cover the declared campaign rounds")
    for reference in verification["verification_profile"]["rounds"].values():
        for key in (
            "snapshot",
            "witness_public_key",
            "coordinator_public_key",
            "client_keys",
            "tsa_trust_store",
        ):
            candidate = (verification["profile_root"] / reference[key]).resolve()
            if not candidate.is_relative_to(root.resolve()):
                raise ValueError("witness verification input escapes the public evidence root")
        for value in reference["acknowledgements"]:
            if not (verification["profile_root"] / value).resolve().is_relative_to(root.resolve()):
                raise ValueError("retained acknowledgement escapes the public evidence root")
    campaign = verify_secure_campaign(
        workspace=path("campaign"),
        trust_workspace=path("trust"),
        partition_manifest_path=path("partition") / "manifest.json",
        server_evaluation_path=path("partition") / "server/evaluation.json",
        **verification,
    )
    if campaign["status"] != "verified" or campaign["round_count"] != spec.expected_rounds:
        raise ValueError(f"unified M4/M5 verification failed: {campaign.get('errors')}")
    selected = int(campaign["selected_round"])
    selected_round = path("campaign") / f"rounds/round-{selected:03d}"
    context = load_json(selected_round / "public/round-context.json")
    if context["core"]["aggregation_strategy"] != "FedAvg":
        raise ValueError("unified-witnessed-fedavg-v1 requires the declared FedAvg context")
    # M7 transitively verifies M2, M3, the selected witnessed checkpoint,
    # predictions, explanations, mapping and reporting with the same config.
    products = verify_investigation_report_bundle(
        round_workspace=selected_round,
        trust_workspace=path("trust"),
        partition_workspace=path("partition"),
        dataset_workspace=path("dataset"),
        prediction_workspace=path("prediction"),
        explanation_workspace=path("explanation"),
        attack_workspace=path("attack_mapping"),
        workspace=path("report"),
        prediction_config_path=path("prediction_config"),
        explanation_config_path=path("explanation_config"),
        attack_config_path=path("attack_config"),
        config_path=path("report_config"),
    )
    if products["status"] != "verified":
        raise ValueError(f"unified M2/M3/M7 verification failed: {products.get('errors')}")
    coordinator_key = load_public_key(
        (path("campaign") / "authority/round-coordinator.public.pem").read_bytes()
    )
    rounds = {
        sha256_file(p): p.parent.parent
        for p in sorted(path("campaign").glob("rounds/round-*/derivation/manifest.json"))
    }
    if len(rounds) != spec.expected_rounds:
        raise ValueError("system graph does not cover the complete declared round set")
    product_paths = {
        name: path(name) for name in ("prediction", "explanation", "attack_mapping", "report")
    }
    graph = verify_campaign_derivation(
        workspace=path("graph"),
        expected_sha256=spec.graph_manifest_sha256,
        round_workspaces=rounds,
        product_workspaces={sha256_file(p / "manifest.json"): p for p in product_paths.values()},
        coordinator_public_key=coordinator_key,
        authority_public_key=coordinator_key,
    )
    if graph["status"] != "verified":
        raise ValueError(f"unified graph verification failed: {graph.get('errors')}")
    return {
        "status": "verified_system_chain",
        "profile": spec.profile,
        "round_count": spec.expected_rounds,
        "selected_round": selected,
        "campaign": campaign,
        "investigation": products,
        "graph": graph,
        "source_record_coverage_replayed": False,
        "global_artifact_completeness_verified": False,
        "administrative_independence_demonstrated": False,
        "attack_resistance_evaluated": False,
    }
