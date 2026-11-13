# Numerical mechanism and interpretation

This note describes a separate experimental operator. It does not modify the
formal derivation model or an operational admission policy.

Let d_i be a submitted whole-model delta, r the trusted-root gradient step,
and E the clients passing the mandatory gate with nonzero delta. Write m=|E|.
All norms and inner products span the entire flattened parameter vector.

The existing cosine-weighted operator uses

    s_i = max(0, cosine(d_i,r)) if i is eligible, else 0
    w_i = s_i / sum_j s_j
    z_i = ||r|| d_i / ||d_i||
    update = sum_i w_i z_i.

The ablation retains exactly the same per-client normalization and sets

    w_i = 1/m for i in E, else 0
    update = (1/m) sum_{i in E} z_i.

The norm-only root direction cannot affect the output at fixed root magnitude.
Positive rescaling of an individual submitted vector cannot affect its z_i.
An opposing or orthogonal vector remains included if nonzero and admitted;
there is no statistical malicious-client identification in this operator.
Zero or invalid roots and insufficient support pause without a new checkpoint.
Both operators retain the quorum of ten positive-weight contributors.

By the triangle inequality, either aggregate has norm at most ||r||. This
bounds each current numerical step, not ASR, semantic cleanliness or cumulative
poison removal. Float32 checkpoint export adds ordinary rounding. A small norm
budget may limit useful learning as well as attack movement. The root is still
trusted clean information; removing direction weighting does not remove that
assumption or establish a deployable constant, public or root-free scale.

Uniform weights imply a group's normalized-vector coefficient share is at most
min(|G|,m)/m. With three malicious identities and m>=10, this share is at most
0.3; in the fully supported 15-client cases it is 0.2. This is a consequence of
equal weights, not a discovery of those identities or a bound on original
FedAvg sample mass. Coefficients multiplying unnormalized raw deltas need not
sum to one. No 80% retained sample-mass contract is asserted.

Matched initial factor queries isolate the operator at the same warm parent.
After the first commit, each defense and its adaptive attacker follow their
own parents. The whole-trajectory comparison measures that coupled behavior;
it is not a common-input causal intervention at every later round.

If both rules yield zero measured ASR, the observations cannot identify cosine
weighting as necessary. A nonzero residual parameter distance still excludes
an exact-unlearning claim, even when all tested trigger ASRs remain zero.
