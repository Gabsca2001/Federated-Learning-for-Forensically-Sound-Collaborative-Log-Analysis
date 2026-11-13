# Experimental rule and recovery contract

This documents a new research adapter. It does not revise the thesis equations,
the formal derivation core or an operational admission policy.

## Individual anomaly and concurrent activity

For client i and observed round t in 1,...,10, the channels are

    x[i,t,1] = log(1 + relative_norm[i,t])
    x[i,t,2] = validation_impact[i,t].

The fit reference pools all client/round observations in two declared clean
allocation histories. Each channel has median m[k] and scale

    scale[k] = max(floor[k], 1.4826 * MAD[k]),
    floor = (0.05, 0.005).

The per-round score and persistent client score are

    score[i,t] = max_k max(0, (x[i,t,k] - m[k]) / scale[k])
    persistent[i] = median_t score[i,t].

Three separate clean allocation histories determine tau: the largest persistent
score over all calibration campaigns and clients. A client is individually
anomalous only when persistent[i] > tau.

For each pair, coactivity is the fraction of ten rounds in which both round
scores strictly exceed tau. Gamma is the larger of 0.3 and every calibration
pair's coactivity fraction. A candidate pair requires both clients individually
anomalous and coactivity > gamma. Maximal cliques form group hypotheses.
The selected group must leave ten contributors. Rank by larger size, then larger
minimum member persistence, then client tuple. No known attacker count is used;
an oversized clique is retained as evidence and is not silently truncated.

Median-centered direction, per-tensor deviation profiles and temporal indicator
correlations are retained separately. Concurrent anomalous activity need not
mean similar tensor directions, maliciousness or intentional coordination.
Calibration maxima from three histories do not establish a population error bound.

## Whole-vector relative-radius adversary

Let d be the honest coherent gradient step and b the poisoned Adam endpoint
minus the actual current parent. The unrestricted family exports

    u(alpha) = d + alpha * (b-d).

The relative-radius family exports

    u(alpha) = d + alpha * ||d|| * (b-d) / ||b-d||,
    ||u(alpha)|| <= (1+alpha) * ||d|| <= 5 * ||d||.

All norms span the complete model. Zero-direction handling is explicit. Both
families use alpha in {0,0.125,0.5,1,2,4}. Alpha zero is an honest unmodified
export, even when the identity is scheduled as adversarial. The finite family
does not exhaust attacks that evade the retrospective detector.

## Full-origin counterfactual

For frozen excluded set H, start from preserved pre-attack W0 and compute

    W_H[t] = W_H[t-1] + sum_(i not in H) weight_H[i] * u_H[i,t],
    weight_H[i] = n[i] / sum_(j not in H) n[j].

Every honest u_H[i,t] is freshly trained at W_H[t-1]. Every surviving attacker
relearns its poisoned endpoint there and reevaluates six factors against the
fresh same-excluded-roster clean reference. It cannot reuse its original vector
or original selected alpha from a different parent. The fixed attack ends at
R10; R11-15 are its declared unmodified continuation. Quorum stays ten.

Compare every replay checkpoint with C_H[t], a separately executed clean history
with exactly H excluded, the same W0, original unpoisoned survivor data and the
same honest training rule. If all active attackers are in H, then the training
inputs/operators coincide and induction predicts W_H[t] = C_H[t] for all t.
The verifier checks canonical checkpoint hashes and final parameter distance.

This is conditional restoration to the client-exclusion counterfactual. It
assumes a clean W0, correct attribution, complete attacker removal and the
declared deterministic data/training contract. It omits all benign and poisoned
contributions by H during the replayed R1-15 interval. Earlier benign influence
already present in the shared W0 remains. It is not restoration to the original full-roster
model, proof of W0 cleanliness, certified selective unlearning of poisoned rows
or a general operational guarantee. Zero tested ASR with unequal C_H parameters
does not satisfy exact recovery.
