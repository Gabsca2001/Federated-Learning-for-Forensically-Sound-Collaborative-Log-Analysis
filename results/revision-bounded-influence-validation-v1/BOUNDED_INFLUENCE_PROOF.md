# Conditional influence bound for the containment profile

This annex describes the new derived-delta profile. Earlier formal closures
remain attached to their original implementations and aggregation semantics.

For tensor l, fixed base W, original local model U_i, and fixed positive clean
reference C_l, define d_i = U_i-W and
lambda_i,l = min(1,C_l/||d_i,l||), with lambda=1 for a zero delta.
The derived delta is v_i,l=lambda_i,l*d_i,l. The original signed U_i is retained;
its signature is not transferred to v_i. A separate derivation records the
original hashes, C, lambda, effective masses, float64 derived tensors and digest.

The admission procedure supplies nonnegative effective mass m_i. Mandatory-gate
failure implies m_i=0. Statistical quarantine also sets m_i=0. If the required
quorum or positive total is absent, no checkpoint is defined; rejected mass is
never restored to make quorum. Otherwise a_i=m_i/sum_j(m_j), and
W_next,l = W_l + sum_i(a_i*v_i,l), before the final checkpoint-dtype export.

## Norm containment

For every retained contribution, ||v_i,l||<=C_l in exact real arithmetic.
Nonnegative normalized masses give ||sum_i a_i*v_i,l||<=sum_i a_i*C_l=C_l
by the triangle inequality. No assumption about the client's intent is used.
An empirical calibration quantile does not assert that every benign client
lies below C, nor does the norm conclusion bound classification error or ASR.

## Fixed-input removal

Freeze the original observations, base, clipping map, C and survivor admission
masses. Remove client k with a_k<1 and renormalize survivors. Let
mu_-k,l=sum_(i!=k)(a_i/(1-a_k))*v_i,l. The direct change is
a_k*(v_k,l-mu_-k,l), whose norm is at most 2*a_k*C_l.
For a removed group K of total mass A<1, the same decomposition gives
2*A*C_l. This is conditional direct reaggregation. Rescoring survivors or
retraining future rounds changes the premises and is not covered by this proof.
An actual survivor checkpoint additionally requires the configured quorum.
If that quorum fails, the algebraic vector bound does not authorize creation
of a checkpoint that the live policy would reject.

## Numerical interpretation

The implementation stores derived deltas and accumulates in float64, then
casts the checkpoint to its declared dtype. A removal certificate measures the
two export-rounding errors e_full,l and e_removed,l and checks the actual
exported checkpoint distance against 2*a_k*C_l+e_full,l+e_removed,l, with an
explicit 1e-12 numerical comparison allowance. This is finite numerical
verification, not proof-assistant certification of floating-point arithmetic.
The live adapter additionally requires exact array agreement between its
report aggregate and numerical backend, using one deterministic input order.

## Dependence, coefficient and semantics

The normalized a_i applies to the derived contribution. Relative to the raw
delta, the tensor-specific coefficient is a_i*lambda_i,l; a single a_i alone
does not describe raw-update influence after clipping. Equivalently, each tensor
has base coefficient 1-sum_i(a_i*lambda_i,l). The live graph includes an explicit
bounded-update derivation node between original bundles and the checkpoint,
with the frozen limits and base as dependencies. Admission decisions determine
the actual masses; clipping factors describe the separate transformation.
All of these are distinct from retrospective semantic labels or intent.

These coefficients describe an algebraic representation at the observed inputs.
Clipping is nonlinear, so they are not marginal derivatives or demonstrated
causal effects. The original fixed-client Delta and binary J must keep their
declared meanings; tensor coefficients cannot silently replace the original
mass coefficients in those measures. Numerical effect still requires an explicit
comparison with its stated removal/rescoring/retraining premises.

## Code and evidence correspondence

| Obligation | Premises | Code / check | Evidence |
|---|---|---|---|
| Original-byte integrity | Caller authenticates the enrolled client and bundle | Signature, context/base/update-hash verification before derivation | 75 retained genuine swtpm bundles checked; new live round verification |
| Derivation reconstruction | Fixed original models, base, C and masses | `aggregate_bounded`, `verify_bounded`; live materialization and digest comparison | Numerical tests, every bounded offline round, live replay and tamper tests |
| Non-compensation | Mandatory gate checked before positive mass | Gate masks, original live admission, quorum rejection | Unit regressions and complete live verification |
| Direct influence bound | Frozen inputs and survivor decisions, a_k<1 | Per-client removal certificates and both export-rounding allowances | 854 prospective certificates plus signed-input derivations |
| Live checkpoint equality | Frozen profile/assets and exact backend | Same backend in create/verify; report/backend order agreement | Final-source full suite and new swtpm campaign |
| Semantic malice | No such premise is supplied by a norm bound | No theorem of malicious intent | No such claim |

Receipt completeness, deadlines, independent witness assumptions, retrospective
review immutability and the structural/causal distinction keep their existing
scope. The legacy raw-update counterfactual adapter explicitly rejects the new
bounded profile; this annex's clipped-delta removal operation is separate.
