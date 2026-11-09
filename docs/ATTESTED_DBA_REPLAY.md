# Attacked multiround derivation and bounded counterfactual replay

## Correspondence and purpose

This case implements the graph/replay scenario accepted in the supervisor's
second exchange: follow an accepted contribution through later checkpoints and
investigative products, then distinguish that structural reachability from a
direct reaggregation and genuine subsequent retraining. Its scope is a bounded
mechanism study. The separate 15-round, three-seed DBA benchmark remains the
source for the broader attack/common-update defense comparison.

The five-round horizon is an implementation choice: three attack rounds and
two clean continuation rounds. It is not a horizon prescribed by the supervisor,
an estimate of convergence, or evidence that longer-term effects disappear.

## Frozen protocol

- Data24, 15 IID partitions; the clean partition snapshots remain immutable.
- Original MLP (128/64, 32-dimensional embedding), zero dropout, Adam,
  10 local epochs, batch 128, learning rate 0.001, deterministic round/client
  seeds, and training-derived global class weights.
- Three component holders: client01, client06, client11; feature indices
  13, 17, 24 respectively; trigger value 12 in standardized feature space.
  Each poisons 50% of hash-ranked training rows in rounds 1–3, with benign as
  the attack target. Rounds 4–5 have no poisoned local rows.
- The original fixed in-round composite calibration, admission rules, quorum,
  and coefficient verification remain in force. The policy uses its ordinary
  indicators; it does not consume the experimental attacker identities.
- Fresh swtpm Quotes before every branch/round; client ESKs sign updates and
  receipts. This is emulated TPM 2.0, without a physical hardware or hostile
  host-administrator protection claim.
- All validation windows are evaluated at every fixed round, with clean input,
  the complete trigger, and each component separately. Reference labels are
  preserved. There is no test access or outcome-based endpoint selection.
- Actual M7 prediction, explanation, ATT&CK mapping, and reporting bundles use
  the first two validation window IDs in lexicographic order at the final
  round of the original and two intervention trajectories. These are clean
  input windows, not a claim to explain all triggered validation predictions.

The poisoned input is a declared deterministic training transformation bound
inside the signed training contract. The client checks the clean snapshot hash
first, applies that transformation, then commits its source/training row hashes
and selected row identities in signed metrics. A passing Quote therefore does
not establish that the training examples are benign. This is an openly
instrumented controlled experiment, not a demonstration of undetectable code
replacement or an independently discovered attacker.

The experiment's training claim covers the clean commitment plus the declared
transformation. Unannounced modifications to an already pinned snapshot remain
rejected by the ordinary client path. This case validates derivation and replay
for the declared poisoned computation; it does not demonstrate a bypass of that
snapshot check or establish the truth of primary log capture.

## Intervention scope

| Branch | Intervention | Subsequent participation |
|---|---|---|
| `baseline` | Original attacked trajectory | All clients in every round |
| `remove-client01-round1` | Remove client01's round-1 submission before local training/aggregation | Client01 returns in round 2, including its declared attacks in rounds 2–3 |
| `remove-client01-rounds1-3` | Remove the explicit set of client01's round-1, round-2, and round-3 submissions | Client01 returns with clean training in rounds 4–5 |
| `control` | Repeat the original attacked protocol with no removal | All clients in every round |

Every branch begins from the same model bytes. Every later local training uses
that branch's actual previous checkpoint; the optimizer is freshly constructed
under the recorded training protocol. No historical later update is reused as
a substitute for retraining. Control checkpoint equality tests numerical
reproducibility; fresh contexts, Quotes, signatures, and occurrence identities
are expected to differ.

Removing a whole contribution measures its total effect, including its ordinary
learning content. It does not isolate the poisoning component from the benign
part of that contribution. The repeated attacked control is a reproducibility
control, not an additional clean-data trajectory or an attack-efficacy baseline.
The other two attackers remain in both interventions. Lower ASR, successful
mitigation, and monotone improvement with more removals are not assumed.

## Structural queries and the set extension

`campaign-blast-radius` accepts repeated `--submission-id` arguments. A single
argument retains the earlier response shape. A repeated argument requests an
explicit, nonempty, duplicate-free historical set; unknown origins fail the
query rather than being silently skipped. The query does not infer a blanket
accusation against every past or future update of a client.

For a supplied authenticated graph G and a selected submission set S, the
reported structural set is

`Reach_G(S) = union(Reach_G(s) for s in S)`.

Each artifact is counted once. Paths retain their originating submission and
edge types. Since every single-origin verifier returns only graph edges, taking
the union preserves witnessed reachability; conversely every descendant of any
selected source is included by its single-origin traversal. This establishes
the set identity relative to G, not global completeness outside the supplied
manifest view. The implementation retains a shortest witness per reachable
edge-type set and origin. Mixed paths are not converted into numerical weights.

The case compares the single round-1 source with the three explicitly selected
baseline sources. Their structural perimeter may be identical even though
their intervention effects differ: the earliest source may already reach all
later affected artifacts. Set size or graph size is not a severity measure.

The graph snapshot closes after the declared M7 products. Later analyst-side
evaluation, counterfactual and review outputs are bound by the separate signed
intervention/case closure. They are not silently counted as M7 products inside
that earlier snapshot. The supplied-view limit applies to these counts as well
as to any unregistered or future product.

## Numerical and semantic verification

Two direct round-1 analyses preserve the historical trust evidence:
`frozen_decisions` and `rescore_round`. They are separately signed analyst
artifacts and are compared with the actual first live intervention checkpoint.
Later-round distances and changed clean/triggered classifications come from
the genuinely retrained trajectories, not from graph arrows or frozen-update
reaggregation. Every stored local model is independently retrained from its
own pinned base and compared byte for byte in the frozen runtime.
Here independent replay means a separate execution of the same preserved
implementation, not an independent implementation or external auditor.

The authoritative trajectory-distance report is
`analysis/trajectory-comparison.json`: it promotes the stored float32 parameter
values to float64 before subtraction and the L2 norm. The retained runner check
in `reports/numerical-comparison.json` subtracts in float32 before promotion;
tiny rounding differences between those diagnostic values are expected. The
case tables use the former definition. Checkpoint equality is always checked
by exact bytes, independently of either norm.

Clean accuracy, macro-F1, the complete/component ASR denominators, and the
untriggered non-target-to-target rate are retained. A high triggered target rate
alone is insufficient to prove a learned backdoor if the model already predicts
the target on untriggered input. Changes in parameters, probabilities, class
labels, and explanation attributions are reported separately. Attribution
distances are compared only for matching target classes.

After the historical trajectories close, separate semantic review ledgers can
attribute the known poisoned submissions in rounds 1–3 to experimental ground
truth. The reviews bind the signed metrics and independent transformation
replay. Their expected heads are retained separately. They do not rewrite the
historical `not_reviewed` labels, operational decisions, coefficients, or models;
their labels do not imply a successful automatic detector or real-world proof
of intent. Clean rounds 4–5 are not automatically labelled malicious merely
because the same clients previously poisoned data.

## Limits carried into the thesis

- Reachability is relative to the supplied pinned round/product manifests.
  It does not enumerate unregistered products or establish observed damage.
- The trigger is in processed feature space. Its realizability in primary
  network logs is not established.
- A single bounded seed/horizon is a case study, not a statistical superiority
  claim, certified unlearning result, or general causal guarantee.
- The client timestamps and locally retained protocol do not add independent
  delivery, registration-time, or deadline verification.
- Signature verification, numerical replay, negative verifier tests, and manual
  formal reasoning provide different evidence. Passing tests do not replace a
  mathematical proof of the universal statements.
- The local verification export omits signing secrets but contains dataset
  snapshots. It is an evidence package, not a claim of publication clearance.

The completed case report and pinned closure supply the observed counts and
effects. The thesis is updated only in the later writing step.

## Observed case results

| Selected sources | Unique descendants | Checkpoint models | Product manifests |
|---|---:|---:|---:|
| `remove-client01-round1` (1 submissions) | 311 | 5 | 4 |
| `remove-client01-rounds1-3` (3 submissions) | 311 | 5 | 4 |

| Branch | Final model L2 from original | Clean accuracy | Clean macro-F1 | Complete-trigger ASR | Untriggered target rate |
|---|---:|---:|---:|---:|---:|
| `baseline` | 0.000000000 | 0.974558 | 0.936919 | 0.000000 | 0.000000 |
| `remove-client01-round1` | 0.388520122 | 0.974868 | 0.939536 | 0.000000 | 0.000000 |
| `remove-client01-rounds1-3` | 0.412999319 | 0.974868 | 0.939536 | 0.000000 | 0.000000 |
| `control` | 0.000000000 | 0.974558 | 0.936919 | 0.000000 | 0.000000 |

The final complete-trigger ASR is zero in the original, both interventions
and the repeated attacked control. This is a negative attack-efficacy finding
under this bounded protocol: it does not demonstrate elimination of a successful
backdoor or establish general defense effectiveness. Known poisoned inputs can
have recorded and numerical influence without achieving the attack target.


The local retained evidence is `artifacts/revision-attested-dba-v1/`. See its
`intervention-manifest.json`, `postchecks/summary.json`, graph, and separate reviews.
