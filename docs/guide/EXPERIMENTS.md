# Experimental findings and comparison boundaries

The studies use different attacker capabilities, model states, aggregation
operators and information budgets. A stored verification success indicates
reproducibility of the declared checks, not success of a defense hypothesis.
The [results catalogue](../../results/CATALOG.md) retains every study directory.

## DBA and literature comparisons

The DBA variants assign distinct trigger components to colluding experimental
identities. Complete-trigger controls train with all components. Evaluation
retains the complete trigger and individual components; construction alone does
not establish that their composition is necessary for attack success.

FLAME and WeiDetect comparisons use matched input updates and retain clipping,
noise, auxiliary-data and fallback qualifications. Common-input outputs are not
separately evolving defended campaigns. FedGradTrace is a separate gradient-
history study with literal formula interpretations and a normalized adaptation:
25 of 32 histories complete and seven terminal numerical failures are reproduced.
It is not reported as a complete original-system reproduction.

The [dated requirement audit](../EMAIL_REQUIREMENTS_STATUS_20261106.md) records
those source-bound comparisons and the earlier Data22 transfer diagnosis. Data22
development does not replace the deferred independent ToN-IoT evaluation.

## Data22 transfer diagnosis and representation follow-up

The frozen Data24 checkpoint misses 104 of 110 Data22 attack windows
(`results/m5-external-generalization-local-test-v1`). The representation
follow-up cited by the thesis is retained in two local artifact directories:

| Study | Content | Location |
| --- | --- | --- |
| Central screening | Seven representations, three seeds, selection recorded before external and test access; standard selected at 0.96445 mean validation macro-F1 | `artifacts/revision-preprocessing-screening-v1/` |
| Federated follow-up | Standard and log-transformed quantitative measures, three seeds, thirty rounds; the second variant is an exploratory choice made after the Data22 result | `artifacts/revision-preprocessing-federated-v1/` |
| Source record | Frozen tested library, launch and closure scripts, and the original progress notes, with a `SHA256SUMS` index | `artifacts/revision-preprocessing-source-record-20261102/` |

The federated protocol records `library_source_path` outside this repository;
the source record preserves that frozen library. These directories are not
tracked by Git and are not registered study publications.

## Admission and aggregation findings

| Study | Supported finding | Limit |
| --- | --- | --- |
| [Gate mechanisms](../../results/revision-gate-mechanism-audit-v1/README.md) | Fixed-input policy equivalences, statistical compensation and normalized-mass effects are quantified | No universal winning original gate |
| [Mass feasibility](../../results/revision-admission-mass-feasibility-v1/) | The specified retention/group-share targets are incompatible on the examined original non-IID mass contracts | A fail-closed guard does not supply training continuity |
| [Capped-final](../CAPPED_FINAL_RESULTS.md) | 108 completed histories; transformed coefficients satisfy the ceiling and improve the declared clean conditions | The poisoning-defense objective fails; no promotion |
| [Coherent endpoint DBA](../../results/revision-coherent-endpoint-dba-v1/README.md) | Four effective raw attacks have zero observed full/component ASR under the declared defended profile | All four final defended models still differ from their clean references |
| [Late retrospective correction](../../results/revision-endpoint-retrospective-groups-v2/README.md) | Learned-endpoint attacks transfer poorly to earlier selectors; late correction leaves contamination | Later replay cannot erase earlier poisoned checkpoints |

## V4 diagnosis and V5 correction

The [V4 diagnosis](../../results/revision-selector-diagnosis-v1/README.md) found
that benign updates can genuinely reduce rare-class F1 at contaminated parents.
Treating this utility risk as malicious identity created false members. A
ten-round median also diluted intermittent five-round anomalies. V5 separates
the channels and calibrates an episode statistic before assessment.

The new assessment comprises fourteen histories on two new actual allocation
memberships and different scheduled attacker rosters. Both methods use the same
observations and clean fitting/calibration resources.

| Selected group memberships | V4 | V5 |
| --- | ---: | ---: |
| Scheduled adversarial memberships selected | 24 | 22 |
| Benign memberships selected | 8 | 0 |
| Scheduled adversarial memberships missed | 12 | 14 |

Counts refer to client-history roles, not independent people. V5 improves
observed selected-group precision while losing two true memberships overall.
Both methods select no group in either clean control. Ineffective raw controls
remain reported; norm-limited attacks that fail to succeed do not establish
resistance to successful evasion.

All six effective raw attacks have complete V5 selected groups. Forty-two
full-origin branches retrain fifteen rounds from the preserved pre-attack
checkpoint; surviving attackers relearn and requery at corrected parents.
Joint removal reproduces every same-excluded-roster clean checkpoint in all
six cases. This comparison excludes the same clients in both arms and does not
selectively erase only poisoned rows or restore the original full-roster model.

In four cases, joint removal reaches zero final worst-trigger ASR while every
single removal leaves nonzero ASR. In two cases a single removal also reaches
zero, but its final parameter L2 distance to the same-roster clean reference is
0.0596475583. Thus zero ASR alone does not establish model restoration. Benign
group controls retain nonzero ASR; individual/joint comparisons support a
qualified group-level effect, not proof of intentional collusion.

Final clean macro-F1 loss to the original full-roster reference is 0.0302
percentage points in the first allocation and zero in the second. Per-class and
intermediate effects remain available. The [V5 report](../../results/revision-episodic-attribution-recovery-v1/README.md)
and [group interpretation](../../results/revision-episodic-attribution-recovery-v1/GROUP_INTERPRETATION.md)
contain the protocols, tables, figures and residual limits. The study records
40 focused test passes; it does not change the operational admission default.
