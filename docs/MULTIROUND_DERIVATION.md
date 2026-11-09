> Update 2026-11-03: the attacked multiround case now includes 20 live rounds,
> 300 fresh emulated-TPM Quotes, 296 independently replayed local trainings,
> explicit-set radii, and actual investigative products. See
> [ATTESTED_DBA_REPLAY.md](ATTESTED_DBA_REPLAY.md) for intervention scope,
> observed effects and limits. The earlier benign-removal case remains preserved.

# Multiround derivation and structural blast radius

This profile reconstructs a signed view of explicitly supplied manifests:
receipt-bound rounds, checkpoint chains, alternative branches, and M7 prediction,
explanation, mapping, and reporting products. The reference is R08/P5.
The graph does not automatically measure a numerical change or damage.

## Inputs, trusted root, and boundary

The source specification contains `rounds` and `products`, each a list of objects
with `manifest_sha256` and `workspace`. Relative paths are resolved against the
specification file. A path locates an object; its hash binds the bytes.
Verification also requires independently trusted public keys for the historical
coordinator and the authority signing the new graph.

```json
{
  "rounds": [
    {"manifest_sha256": "REPLACE_WITH_DERIVATION_MANIFEST_SHA256", "workspace": "evidence/round-001"},
    {"manifest_sha256": "REPLACE_WITH_DERIVATION_MANIFEST_SHA256", "workspace": "evidence/round-002"}
  ],
  "products": [
    {"manifest_sha256": "REPLACE_WITH_M7_MANIFEST_SHA256", "workspace": "evidence/predictions"}
  ]
}
```

The placeholders are not valid hashes: replace them with retained pins.
Reconstructing the same view requires the same source set. The report states
`global_artifact_completeness_verified=false`: it does not prove that every
product ever created was presented to the verifier.

Rounds are authenticated against their pinned manifests; historical signatures
and references, the base, checkpoints, and declared inputs are checked. The
round graph is reconstructed from its artifacts and compared with its manifest.
Full numerical policy and aggregation replay remains a separate operation
requiring the preserved release: `historical_rounds_numerically_recomputed=false`.

M7 manifests are validated using their schemas, core digests, identities, and
exact source bindings. The graph signature commits to this view of their bytes;
it does not replace recomputation of inference, explanations, or reports.
Reportability flags in products remain those products' declarations; this
endpoint reports `product_payloads_recomputed=false`.

## Chains, branches, and availability

Genesis is allowed only at round 1. Every other round must include its previous
checkpoint, whose number immediately precedes it and whose model is byte-identical
to the new base. A missing intermediate round makes reconstruction fail; it is
not silently treated as a new genesis. Cycles, missing endpoints, and inconsistent
identities are rejected.

Two branches may produce identical numerical content. Model occurrences remain
bound to their respective checkpoints: equal bytes do not create a dependency
between independent branches. Product comparison uses exact parent-manifest
hashes as well as campaign, round, and model identity.

Availability distinguishes:

- `available`: the object is present and checked in the supplied view;
- `commitment_only`: an authenticated reference exists, without this endpoint
  verifying the payload, for example a client bundle or external receipt;
- `missing`: a product payload is known from a manifest but is currently unavailable.

A missing payload remains reachable. If it reappears with the correct hash, it
can be checked without rewriting the signed view; the report distinguishes
current availability from `snapshot_availability`. A present but altered
payload makes verification fail. Losing a required source manifest instead
prevents reconstruction of the structure and is reported as an error.

## Edge and query semantics

`num` denotes declared numerical use, `dec` a decision dependency, and `audit` a
documentation/verification link. Manifests commit to already produced payloads;
they are not represented as numerical causes of their own inputs. M7 dependencies
pass through the payloads actually referenced. In ATT&CK mapping, attributions
and distances are audit evidence, rather than variables selecting rules based
on the predicted class.

The query starts from an unambiguous submission identifier. It returns reachable
nodes, counts by type, availability, and paths with edge-type sequences. It retains
a shortest path for each reachable set of edge types, avoiding exponential
enumeration of equivalent paths.

The categories are `numerical_dependency` for numerical-only paths,
`decision_dependency` for decision paths possibly mixed with numerical edges,
and `documentary_dependency` for paths containing audit edges. Coefficients are
not multiplied along mixed paths. A zero-alpha input can reach scoring and,
through it, decisions about other contributions.

Every result retains `numerical_effect_demonstrated=false`: dependency is not an
observed change, damage, or responsibility. A review can motivate selecting a
submission for investigation without converting its label into ground truth.

## CLI

WSL example, run from the original repository with its `.venv`:

```bash
.venv/bin/fl-forensics campaign-derive \
  --workspace analysis/graph \
  --sources analysis/sources.json \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-public-key trusted/graph-authority.public.pem \
  --authority-private-key private/graph-authority.private.pem

.venv/bin/fl-forensics campaign-verify \
  --workspace analysis/graph \
  --sources analysis/sources.json \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-public-key trusted/graph-authority.public.pem \
  --expected-sha256 "$GRAPH_MANIFEST_SHA256"

.venv/bin/fl-forensics campaign-blast-radius \
  --workspace analysis/graph \
  --sources analysis/sources.json \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-public-key trusted/graph-authority.public.pem \
  --expected-sha256 "$GRAPH_MANIFEST_SHA256" \
  --submission-id "$SUBMISSION_ID"
```

Retain the view pin according to the threat model. A signature and hash read
only from the same replaceable copy cannot establish absence of rollback or
alternative views. The signing profile is software development. The graph is
written outside historical sources, which are not rewritten by queries.
