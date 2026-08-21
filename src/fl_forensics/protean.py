"""PROTEAN training, prototype aggregation, and inference primitives.

This module is deliberately separate from the immutable M3 FedAvg baseline.
It implements the three-term local objective described in PROTEAN while
retaining the repository's frozen model architecture and class weighting for
a controlled comparison on the same Data24 partitions.
"""

from __future__ import annotations

from typing import Any

PROTEAN_PAPER = "https://arxiv.org/abs/2507.05524"
SUPPORTED_AGGREGATIONS = {"support_weighted_mean", "coordinate_median"}


def _arrays_from_rows(
    rows: list[dict[str, Any]], *, class_names: list[str], np: Any
) -> tuple[Any, Any]:
    if not rows:
        return (
            np.empty((0, 0), dtype=np.float32),
            np.empty((0,), dtype=np.int64),
        )
    label_indices = {name: index for index, name in enumerate(class_names)}
    unknown = sorted({str(row["label"]) for row in rows} - set(label_indices))
    if unknown:
        raise ValueError(f"rows contain labels outside the model vocabulary: {unknown}")
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    labels = np.asarray(
        [label_indices[str(row["label"])] for row in rows], dtype=np.int64
    )
    return features, labels


def _class_support(labels: Any, *, class_names: list[str], np: Any) -> dict[str, int]:
    counts = np.bincount(labels, minlength=len(class_names))
    return {name: int(counts[index]) for index, name in enumerate(class_names)}


def _validated_global_prototypes(
    *,
    global_prototypes: dict[str, list[float]] | None,
    class_names: list[str],
    embedding_dimension: int,
    device: Any,
    torch: Any,
    np: Any,
) -> dict[str, Any]:
    if global_prototypes is None:
        return {}
    unknown = sorted(set(global_prototypes) - set(class_names))
    if unknown:
        raise ValueError(f"global prototypes contain unknown classes: {unknown}")
    tensors: dict[str, Any] = {}
    for name, values in global_prototypes.items():
        array = np.asarray(values, dtype=np.float32)
        if array.shape != (embedding_dimension,):
            raise ValueError(f"global prototype dimension mismatch for {name}")
        if not bool(np.isfinite(array).all()):
            raise ValueError(f"global prototype contains non-finite values for {name}")
        tensors[name] = torch.from_numpy(array.copy()).to(device=device)
    return tensors


def train_local_protean(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
    class_weights: dict[str, float],
    global_prototypes: dict[str, list[float]] | None,
    prototype_alignment_weight: float,
    proximal_weight: float,
    minimum_local_support: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    seed: int,
    device_name: str,
    torch: Any,
    np: Any,
) -> dict[str, Any]:
    """Train one client with classification, prototype, and proximal losses.

    Round one passes no global prototypes, so only the supervised and proximal
    terms are active. For later rounds, a batch class contributes to prototype
    alignment only when the class has enough support in the client's complete
    training snapshot and a previous-round global prototype exists.
    """

    if not rows:
        raise ValueError("a client cannot train on an empty snapshot")
    if len(set(class_names)) != len(class_names) or not class_names:
        raise ValueError("class names must be non-empty and unique")
    if prototype_alignment_weight < 0 or proximal_weight < 0:
        raise ValueError("PROTEAN loss weights must be non-negative")
    if minimum_local_support < 1:
        raise ValueError("minimum local prototype support must be positive")
    if epochs < 1 or batch_size < 1 or learning_rate <= 0:
        raise ValueError("invalid local training parameters")
    if not hasattr(model, "encoder") or not hasattr(model, "classification_head"):
        raise ValueError("PROTEAN requires an encoder and classification head")

    from .federated_model import seed_everything

    seed_everything(seed, torch=torch, np=np)
    device = torch.device(device_name)
    features, labels = _arrays_from_rows(rows, class_names=class_names, np=np)
    supports = _class_support(labels, class_names=class_names, np=np)
    eligible_classes = {
        name for name, support in supports.items() if support >= minimum_local_support
    }
    dataset = torch.utils.data.TensorDataset(
        torch.from_numpy(features), torch.from_numpy(labels)
    )
    generator = torch.Generator().manual_seed(seed)
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=min(batch_size, len(dataset)),
        shuffle=True,
        generator=generator,
        num_workers=0,
    )
    weights = torch.tensor(
        [class_weights[name] for name in class_names],
        dtype=torch.float32,
        device=device,
    )
    criterion = torch.nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    model.to(device)
    base_parameters = [
        parameter.detach().clone() for parameter in model.parameters()
    ]
    embedding_dimension = int(model.classification_head.in_features)
    prototype_tensors = _validated_global_prototypes(
        global_prototypes=global_prototypes,
        class_names=class_names,
        embedding_dimension=embedding_dimension,
        device=device,
        torch=torch,
        np=np,
    )

    objective_sum = 0.0
    supervised_sum = 0.0
    prototype_sum = 0.0
    proximal_sum = 0.0
    total_seen = 0
    optimizer_steps = 0
    aligned_class_terms = 0
    for _epoch in range(epochs):
        model.train()
        for batch_features, batch_labels in loader:
            batch_features = batch_features.to(device)
            batch_labels = batch_labels.to(device)
            optimizer.zero_grad()
            embeddings = model.encoder(batch_features)
            outputs = model.classification_head(embeddings)
            supervised_loss = criterion(outputs, batch_labels)

            prototype_terms = []
            for class_index, class_name in enumerate(class_names):
                if (
                    class_name not in eligible_classes
                    or class_name not in prototype_tensors
                ):
                    continue
                mask = batch_labels == class_index
                if not bool(mask.any().item()):
                    continue
                local_prototype = embeddings[mask].mean(dim=0)
                difference = local_prototype - prototype_tensors[class_name]
                prototype_terms.append(difference.square().sum())
            if prototype_terms:
                prototype_loss = torch.stack(prototype_terms).sum()
            else:
                prototype_loss = embeddings.new_zeros(())

            parameter_terms = [
                (parameter - base).square().sum()
                for parameter, base in zip(
                    model.parameters(), base_parameters, strict=True
                )
            ]
            proximal_penalty = 0.5 * torch.stack(parameter_terms).sum()
            objective = (
                supervised_loss
                + prototype_alignment_weight * prototype_loss
                + proximal_weight * proximal_penalty
            )
            if not bool(torch.isfinite(objective).item()):
                raise ValueError("non-finite PROTEAN local objective")
            objective.backward()
            optimizer.step()

            count = len(batch_labels)
            objective_sum += float(objective.detach().cpu().item()) * count
            supervised_sum += float(supervised_loss.detach().cpu().item()) * count
            prototype_sum += float(prototype_loss.detach().cpu().item()) * count
            proximal_sum += float(proximal_penalty.detach().cpu().item()) * count
            total_seen += count
            optimizer_steps += 1
            aligned_class_terms += len(prototype_terms)

    model.to("cpu")
    return {
        "train_loss": objective_sum / total_seen,
        "objective_loss": objective_sum / total_seen,
        "supervised_loss": supervised_sum / total_seen,
        "prototype_alignment_loss": prototype_sum / total_seen,
        "proximal_penalty": proximal_sum / total_seen,
        "prototype_alignment_weight": prototype_alignment_weight,
        "proximal_weight": proximal_weight,
        "num_examples": len(dataset),
        "optimizer_steps": optimizer_steps,
        "epochs": epochs,
        "class_support": supports,
        "eligible_local_prototype_classes": sorted(eligible_classes),
        "received_global_prototype_classes": sorted(prototype_tensors),
        "prototype_aligned_class_terms": aligned_class_terms,
        "first_round_without_prototypes": not prototype_tensors,
    }


def extract_local_prototypes(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
    minimum_local_support: int,
    batch_size: int,
    device_name: str,
    torch: Any,
    np: Any,
) -> dict[str, Any]:
    """Compute full-snapshot class means without retaining row embeddings."""

    if not rows:
        raise ValueError("cannot extract prototypes from an empty snapshot")
    if minimum_local_support < 1 or batch_size < 1:
        raise ValueError("prototype support and batch size must be positive")
    features, labels = _arrays_from_rows(rows, class_names=class_names, np=np)
    dataset = torch.utils.data.TensorDataset(
        torch.from_numpy(features), torch.from_numpy(labels)
    )
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=min(batch_size, len(dataset)),
        shuffle=False,
        num_workers=0,
    )
    device = torch.device(device_name)
    model.to(device)
    model.eval()
    embedding_dimension = int(model.classification_head.in_features)
    sums = [np.zeros(embedding_dimension, dtype=np.float64) for _ in class_names]
    supports = [0 for _ in class_names]
    with torch.no_grad():
        for batch_features, batch_labels in loader:
            embeddings = model.encoder(batch_features.to(device)).cpu().numpy()
            batch_label_values = batch_labels.numpy()
            for class_index in range(len(class_names)):
                mask = batch_label_values == class_index
                count = int(mask.sum())
                if count:
                    sums[class_index] += embeddings[mask].astype(np.float64).sum(axis=0)
                    supports[class_index] += count
    model.to("cpu")

    prototypes: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(class_names):
        if supports[index] < minimum_local_support:
            continue
        values = np.asarray(sums[index] / supports[index], dtype=np.float32)
        if not bool(np.isfinite(values).all()):
            raise ValueError(f"non-finite local prototype for {name}")
        prototypes[name] = {
            "support": supports[index],
            "values": values.tolist(),
        }
    return {
        "schema_version": "1.0",
        "artifact_type": "protean_local_class_prototypes",
        "embedding_dimension": embedding_dimension,
        "minimum_local_support": minimum_local_support,
        "class_support": {
            name: supports[index] for index, name in enumerate(class_names)
        },
        "prototypes": prototypes,
    }


def aggregate_global_prototypes(
    *,
    submissions: list[dict[str, Any]],
    class_names: list[str],
    minimum_local_support: int,
    class_quorum: int,
    method: str,
    previous_global_prototypes: dict[str, list[float]] | None,
    np: Any,
) -> dict[str, Any]:
    """Aggregate eligible class prototypes and record fail-closed decisions."""

    if method not in SUPPORTED_AGGREGATIONS:
        raise ValueError(f"unsupported prototype aggregation: {method}")
    if minimum_local_support < 1 or class_quorum < 1:
        raise ValueError("prototype support and quorum must be positive")
    client_ids = [str(item["client_id"]) for item in submissions]
    if len(client_ids) != len(set(client_ids)):
        raise ValueError("prototype submissions contain duplicate client IDs")
    previous = previous_global_prototypes or {}
    unknown_previous = sorted(set(previous) - set(class_names))
    if unknown_previous:
        raise ValueError(f"previous prototypes contain unknown classes: {unknown_previous}")

    ordered = sorted(submissions, key=lambda item: str(item["client_id"]))
    classes: dict[str, dict[str, Any]] = {}
    embedding_dimension: int | None = None
    for class_name in class_names:
        eligible = []
        for submission in ordered:
            prototype = submission.get("prototypes", {}).get(class_name)
            if prototype is None:
                continue
            support = int(prototype["support"])
            if support < minimum_local_support:
                continue
            values = np.asarray(prototype["values"], dtype=np.float32)
            if values.ndim != 1 or not bool(np.isfinite(values).all()):
                raise ValueError(f"invalid submitted prototype for {class_name}")
            if embedding_dimension is None:
                embedding_dimension = int(values.shape[0])
            if values.shape != (embedding_dimension,):
                raise ValueError("submitted prototype dimensions do not match")
            eligible.append((str(submission["client_id"]), support, values))

        client_list = [client_id for client_id, _support, _values in eligible]
        support_list = [support for _client_id, support, _values in eligible]
        if len(eligible) >= class_quorum:
            matrix = np.stack([values for _client_id, _support, values in eligible])
            if method == "support_weighted_mean":
                aggregate = np.average(
                    matrix.astype(np.float64),
                    axis=0,
                    weights=np.asarray(support_list, dtype=np.float64),
                )
            else:
                aggregate = np.median(matrix.astype(np.float64), axis=0)
            values = np.asarray(aggregate, dtype=np.float32)
            classes[class_name] = {
                "status": "aggregated",
                "aggregation": method,
                "values": values.tolist(),
                "eligible_client_ids": client_list,
                "eligible_client_count": len(eligible),
                "eligible_supports": support_list,
                "total_support": sum(support_list),
                "required_quorum": class_quorum,
            }
            continue

        previous_values = previous.get(class_name)
        if previous_values is not None:
            values = np.asarray(previous_values, dtype=np.float32)
            if values.ndim != 1 or not bool(np.isfinite(values).all()):
                raise ValueError(f"invalid previous global prototype for {class_name}")
            if embedding_dimension is None:
                embedding_dimension = int(values.shape[0])
            if values.shape != (embedding_dimension,):
                raise ValueError("previous prototype dimension does not match")
            status = "retained_previous"
            stored_values: list[float] | None = values.tolist()
        else:
            status = "unavailable"
            stored_values = None
        classes[class_name] = {
            "status": status,
            "aggregation": None,
            "values": stored_values,
            "eligible_client_ids": client_list,
            "eligible_client_count": len(eligible),
            "eligible_supports": support_list,
            "total_support": sum(support_list),
            "required_quorum": class_quorum,
        }

    return {
        "schema_version": "1.0",
        "artifact_type": "protean_global_class_prototypes",
        "embedding_dimension": embedding_dimension,
        "minimum_local_support": minimum_local_support,
        "class_quorum": class_quorum,
        "aggregation": method,
        "classes": classes,
    }


def available_prototype_values(
    global_artifact: dict[str, Any],
) -> dict[str, list[float]]:
    """Return only class vectors that are usable in the next round."""

    return {
        str(name): list(record["values"])
        for name, record in global_artifact["classes"].items()
        if record.get("values") is not None
    }


def nearest_prototype_predictions(
    *,
    embeddings: Any,
    class_names: list[str],
    global_prototypes: dict[str, list[float]],
    np: Any,
) -> dict[str, Any]:
    """Assign each embedding to the nearest available global prototype."""

    matrix = np.asarray(embeddings, dtype=np.float32)
    if matrix.ndim != 2:
        raise ValueError("embeddings must be a two-dimensional matrix")
    available_indices = [
        index for index, name in enumerate(class_names) if name in global_prototypes
    ]
    if not available_indices:
        raise ValueError("nearest-prototype inference requires a global prototype")
    prototype_matrix = np.stack(
        [
            np.asarray(global_prototypes[class_names[index]], dtype=np.float32)
            for index in available_indices
        ]
    )
    if prototype_matrix.shape[1] != matrix.shape[1]:
        raise ValueError("prototype and embedding dimensions do not match")
    distances = np.linalg.norm(
        matrix[:, np.newaxis, :] - prototype_matrix[np.newaxis, :, :], axis=2
    )
    nearest_positions = distances.argmin(axis=1)
    predictions = [available_indices[int(position)] for position in nearest_positions]
    nearest_distances = distances.min(axis=1)
    if len(available_indices) > 1:
        ordered_distances = np.sort(distances, axis=1)
        margins = ordered_distances[:, 1] - ordered_distances[:, 0]
        margin_values: list[float | None] = [float(value) for value in margins]
    else:
        margin_values = [None for _ in range(len(matrix))]
    return {
        "prediction_indices": predictions,
        "nearest_distances": [float(value) for value in nearest_distances],
        "distance_margins": margin_values,
        "available_classes": [class_names[index] for index in available_indices],
        "unavailable_classes": [
            name for name in class_names if name not in global_prototypes
        ],
    }
