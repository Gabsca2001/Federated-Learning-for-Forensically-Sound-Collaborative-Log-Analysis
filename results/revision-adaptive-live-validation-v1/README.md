# Bounded adaptive and live-TPM validation — 3 November 2026

The retreat envelope now runs inside the signed live admission path, before
aggregation. Its observed adaptive limitation remains unresolved. The new
bounded-persistence candidates are retained as experimental code and were not
promoted after failing the predeclared development guardrail. This step does not
claim reliable automatic identification of malicious clients.

## Version and scope

Parent formal completion: `ca48267410724f4ddb20fbc0226e486f143b562527fde5411f416844f653cb91`.
Current 117-file package: `9756ea7efd479992a9aecfc45953b476131e1ad9edfa0bfae32032db50839ff7`.
Full suite: **652 tests passed**, two existing Typer deprecation warnings.
The source archive includes the preceding releases. Historical evidence is
verified under its preserved release and is never re-signed as current evidence.
The thesis, Git index and deferred ToN-IoT work are unchanged.

## Development result: persistence is not sufficient evidence of current poisoning

The experiment was frozen before scoring 48 previously used development cases.
Frozen clean predictors, global references and individual envelopes were kept
unchanged. Ground-truth identities were used only for evaluation and candidate
selection on these development cases, never by the detector.

| Candidate on old trajectories | Poisoned updates proposed for quarantine | Never-attacker updates | Currently clean scheduled-attacker updates |
|---|---:|---:|---:|
| Existing retreat policy | 452 | 0 | 0 |
| Retreat plus confirmation after 2 high rounds | 476 | 0 | 1 |
| Retreat plus confirmation after 3 high rounds | 474 | 0 | 1 |
| Retreat plus confirmation after 4 high rounds | 472 | 0 | 1 |

All new candidates failed the criterion requiring no such false interventions
and no quorum loss. These are conditional replays over old trajectories, not new
active-defense efficacy estimates. The one event is IID development seed
463593, stream-012, client12 at round 15, after the scheduled attack ended at
round 14. Current unmodified training still reacts to a contaminated shared
base. Its two risks, 0.8186864 and 0.7559457, exceed clean limits 0.7707873 and
0.7437924. The old retreat channel releases it; persistence alone does not.

The additional policy has a narrow mathematical guarantee: for an eligible
client in supported, ordered observations, K consecutive positive dual-view
client-envelope excesses trigger its bounded channel by the Kth observation,
independently of earlier peak magnitude. A non-high or unsupported observation
resets that channel. This says nothing about semantic malice. False-positive
free release on every unmodified update does not follow from this premise.

## Real adaptive model-update pilot

Two matched non-IID six-round CPU trajectories use seed 551593 and fixed
attackers client02/client07/client13. The adaptive adversary knows the frozen
policy and predictor. Each round really trains 15 poisoned/ordinary endpoints
and 15 unmodified endpoints, then searches ten fixed interpolation or
extrapolation factors for the three attacker updates. Candidate ASR queries use
validation data. The detector sees only model observations and clean references.
This privileged search and post-training manipulation are **offline**, without
new TPM signatures or a claim of an undetected live training-contract bypass.

Client07 and client13 retain positive current excess while their initial peak
suppresses quarantine in rounds 2–6. All three submitted attacker updates remain
permitted in this pilot. Maximum full-trigger validation ASR is
**0.3365%**; final ASR is
**0.2243%**, versus zero throughout the matched
clean trajectory. Final parameter L2 difference from matched clean is
**2.413257012**. Small ASR does not establish recovery of clean model state.

All **270 local trainings, 60 candidate searches and 12 aggregates** were
independently repeated and matched the retained models, decisions and metrics.
The three-round bounded candidate would propose client07/client13 from round 3
on these frozen old-policy updates. That diagnostic does not predict its active
future bases or prove ASR mitigation, and does not override its development
failure. A finite six-round pilot establishes this bounded evasion example,
not an infinite realizable trajectory or security against every adaptive attack.

## Fresh live integration with swtpm

Three separate five-round trajectories use a new non-IID training seed 541593:
clean training with the policy enforced; DBA with authenticated statistical
proposals recorded but unapplied; and DBA with the proposals enforced. All start
from the same retained model. Three DBA rounds followed by two clean
continuations exercise confirmation, exclusion, release and predecessor replay.
They are **15 round instances, not one 15-round chain**.

The case contains **225 fresh verified swtpm Quotes and 225 local trainings**.
Every round and all three final campaigns verify under the retained image.
The active arm excludes client07/client13 at rounds 2 and 3: **4/9 currently
poisoned updates**, with no observed currently benign exclusions. Client02 is
missed. The clean arm excludes no client. Every fixed full-trigger validation
ASR is zero in all three arms, including the unapplied-proposal control.
Consequently this is a mechanism and integration validation, **not evidence of
an ASR advantage**. Full/component-trigger, clean utility and scope-qualified
wall-time measurements are retained for all endpoints in
[live-fixed-endpoints.json](live-fixed-endpoints.json).

Each node uses its own TPM state, socket, partition and output. The head reads
verified public/local models, not raw client rows. In the live adapter the head
shares the coordinator process; process-level denial of coordinator access to
raw partitions is not claimed. Quote measurements cover the declared components,
not a physical TPM, an entire host or independently verified wall-clock time.

The integration binds the four frozen predictor/calibration assets in the
signed training context. The audit-result digest appears in the signed primary
decisions; those decisions determine the actual checkpoint inputs and masses.
Verification recomputes the current frame and policy history and verifies the
predecessor rounds. Full campaign verification additionally checks the model
and checkpoint chain. The complete authenticated prefix and its submissions,
client receipts, frozen assets and trust records are required inputs; a lone
signed checkpoint is insufficient. Auxiliary old composite statistics are
retained for inspection, but do not select the new primary decision. Its binary
score is a block indicator, not a probability of malice.

An explicit partition/training binding now allows only `seed`, `local_epochs`
and `rounds` to change against the exact original partition configuration.
Partitioning, model settings and all other fields must remain equal. Both
configurations and the declared differences are bound to the signed context.
The exact old partition hash and client/model schema remain mandatory; no
unverified cohort-ID remapping is performed. A genesis model is separately
schema/finite checked and its exact bytes are bound as the signed base model.

## Real failure without a checkpoint

A separate one-round negative case starts from a schema-valid zero model,
outside the frozen state-support range: distance 7.1259948 versus limit
2.4604774. It adds **15 fresh valid Quotes, 15 unmodified local trainings and
15 valid TPM-signed bundles**. All mandatory gates pass. The statistical head
abstains and still exposes eligible proposed mass, but the live adapter assigns
zero final mass to every contribution and creates **no checkpoint**.

The failed-round verifier reconstructs trust, statistical results, decisions
and derivation with zero errors. Coefficients correctly remain
`not_defined_without_checkpoint`; they are not falsely marked verified.
This conservative complete-cohort profile also aborts on missing or failed
mandatory gates. That is an availability tradeoff; no calibrated partial-cohort
operation is claimed. Quorum failure never restores rejected contribution mass.

Five additional mutations on disposable copies of the valid active campaign
are rejected: current audit result, predecessor audit history, client bundle
signature, signed final mass and predecessor checkpoint. The unmodified copy
verifies, and original signed evidence is unchanged.

## Formal and thesis boundaries

The preceding formal correspondence remains a versioned historical milestone.
The new live profile adds finite evidence for mandatory-gate non-compensation,
actual mass enforcement, asset/history binding and unsupported-context failure.
It does not turn empirical anomaly detection into a semantic truth theorem.
The old single-round rescoring adapter explicitly rejects this new cohort-bound
profile; frozen historical decisions remain a distinct supported analysis.

Receipt completeness remains conditional on supplied retained client receipts.
There is no independent append-only witness, trusted deadline or delivery
guarantee. Blast radius remains structural reachability over the supplied
authenticated artifact set, separate from numerical/causal replay. This step
adds no group-collusion proof, physical TPM campaign or ToN-IoT evaluation.

The professor's retrospective group requirement remains separate from this
optional automatic-quarantine research. This result must be written as an
implemented and tested live mechanism with a demonstrated adaptive limitation,
not as validated reliable automatic client exclusion. A quantitative live
mitigation claim would still require an attack-effective matched control and a
longer separately declared efficacy campaign. Any revised automatic rule must
also address clean responses to contaminated states and be evaluated on newly
reserved active trajectories after freezing its calibration and error budget.

## Reproduction and incidents

The source/test/controller archive, exact image ID and local frozen image tar
are retained, with source and artifact digests. Earlier attempts are preserved:
one image omitted a declared measured Dockerfile; the first initialization
rejected the full-config partition mismatch before training; an offline export
schema error stopped after 15 clean trainings and before its first detector
query. The negative-case generic runner demanded checkpoint coefficients even
though the verifier correctly accepted a failed round; a specialized closure
checks their absence without retraining or altering evidence. None of these
attempts is counted as a successful primary trajectory.

The final closure is signed by a local software analyst key. It is an integrity
record, not independent timestamping, TPM signing of the analysis, or external
scientific certification. See [VALIDATION_SUMMARY.json](VALIDATION_SUMMARY.json).
