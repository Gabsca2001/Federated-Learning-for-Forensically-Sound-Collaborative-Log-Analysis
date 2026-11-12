# Probe gate and global rollback in the signed secure profile (swtpm live case)

This is a mechanism demonstration, not an efficacy study. Efficacy is established in
`../revision-probe-keynorm-confirm/` and `../revision-global-probe-confirm/`.

## What changed in `src/`

All of it is opt-in: nothing changes unless `runtime_admission.probe_policy` is declared.

* `src/fl_forensics/probe_gate.py`: pure probe functions, ported from the confirmed research gates.
* `src/fl_forensics/live_probe_gate.py`: the frozen `probe-policy.json`, pinned by SHA-256 in the
  bound configuration. It writes two derivations, and the verifier recomputes both bit for bit:
  * `probe-gate-result.json`. A flagged client receives a signed `probe_keynorm` primary decision
    with zero mass, so exclusion goes through the ordinary admission decision.
  * `probe-rollback-result.json`. On alarm, the checkpoint equals the previous global model, and the
    candidate is kept as `rejected-candidate.json`.

  Modes:
  * `enforce`
  * `audit_only`
  * `rollback_only`: the client probe only records, while the rollback is enforced.
* `in_round_admission.py`:
  * installs the policy;
  * applies the client probe after the envelope, both when creating and when verifying;
  * applies the rollback after aggregation;
  * includes the new modules in the implementation hash.
* `round_derivation.py`: new nodes in the signed derivation graph:
  * `probe_policy`
  * `probe_gate_derivation` (bundle → probe → admission decision)
  * `global_probe_decision` (→ checkpoint)
  * `rejected_candidate` and `base_model` → checkpoint, on rollback

  The failed-round path also replays the probe.
* `counterfactual_round.py`: removal replay fails closed for the probe profile, because removing a
  client changes the peer medians and the rollback decision.
* Tests: `tests/test_live_probe_gate.py`, 11 tests. The full suite passes: 1058/1058.

## Live case

* Run with `scripts/revision_live_probe_rollback.py` and `Dockerfile.revision-live-probe-rollback`.
* Lab: `artifacts/revision-live-probe-rollback-v1`.
* Setup copied from `revision-live-bounded-tpm-v2`: 15 clients with emulated TPMs, non-IID partition,
  bounded + envelope profile, and the declared single-feature DBA (client03/08/12, rounds 1–3).
* 3 branches × 5 rounds. Every round passed `verify_in_round_secure_round` with
  `require_derivation=True`, and all 3 campaigns were finalised and verified.

| Branch | Probe mode | Client flags (rounds 1–3) | Honest flags | Rollback |
|---|---|---|---|---|
| clean | enforce | none | 0 | 0/5 |
| active (DBA) | enforce | 3, 3, 2 attackers (excluded) | 0 | 0/5 |
| rollback (DBA) | rollback_only | 3, 3, 2 attackers (recorded, not excluded) | 0 | **0/5** (max drift score 0.20, threshold 1.5) |

**Limit:** the rollback path never triggered live. In this configuration, clipping and the envelope
already keep the global drift far below the threshold even when the DBA updates are admitted. The
`rejected_candidate` branch of the graph is therefore covered by unit tests only, not by a signed
live round.

## Second live case: no clipping (declared after the first case, threshold and attack unchanged)

* Lab: `artifacts/revision-live-probe-rollback-fedavg-v1`, run with `--variant fedavg`.
* Configuration: the same DBA under plain FedAvg with the original retreat envelope (`control.yaml`).
  The client probe only records (`rollback_only`).
* All 5 rounds and the campaign verified.

Result: **no rollback** (drift scores 0.15, 0, 0, 0, 0.20; threshold 1.5).

* The three attackers were admitted only in round 1.
* In rounds 2–3 the retreat envelope quarantined them (round 3 admitted client03 alone).
* So the backdoor never had enough admitted mass to move the global model. This is case 1:
  the attack was contained upstream, and the global probe correctly stayed silent.
  It is not a missed detection.

The rollback path therefore remains covered by unit tests only. A live rollback would need an
attack that passes every client-level control, such as the adaptive attacker of the research
engine. The signed profile does not implement such an attacker. The threshold was not lowered and
the attack was not strengthened to force a rollback.
