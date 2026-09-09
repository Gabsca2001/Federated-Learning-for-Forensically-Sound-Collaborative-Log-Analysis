# Forensic explanation of the real TPM admission failure

## Decision

`client03` was authorized to train in round 30 by the passing M4 result
`attestation-512a4355e0397407b09dfe82`. Its local update was computed over
473 training examples and signed by its enrolled TPM ESK.

After local training and before aggregation, PCR 10 in the
`sha256` bank changed from `0000000000000000000000000000000000000000000000000000000000000000` to
`3d5d21697035b776c5731db907c54efb462a85bdce569e6a53f4ea05d1c38bc2` after extending measurement
`46bd17be2508159f1fd57637a43b982147822385f07b908a2da279d12efabb66`. A fresh challenge produced Quote
`quote-04e98af17a38055e63202e8c`, authentically signed by the enrolled AK. The Quote therefore
proves the observed changed state; it does not prove compliance with the expected baseline.
The M4 verifier returned signed result `attestation-65fee64e3f0f801c1ee531d0` with status
`failed_measurement`.

The pre- and post-reattestation bundles retain the same update digest
`f23056942da2cf6bb6ce6bc8b068643a47e6731bb4c73972b055490da6698e1a` and metrics digest
`5091dcb1c34e2f72d30976d742aee05136ee5ad1a845ed246cc8d958233307c7`. This isolates the treatment variable: the model
update did not change; only the fresh trust evidence changed.

Six of seven M5 checks passed. The only failed check was `fresh_attestation`. M6 therefore
made decision `in-round-decision-2517b6db3a2755ef90fe5593` with status `trust_quarantined`. Statistical
scoring is deliberately absent (`statistics = null`): the fail-closed trust gate runs before
statistical admission. The nominal FedAvg weight was 473,
the effective weight was zero, and `client03` is absent from the 14 accepted checkpoint inputs.

## Aggregation effect

Reconstructing weighted FedAvg from the 15 preserved submissions gives checkpoint error
`7.69450728e-07` L2. Restoring only this
client at full nominal weight while holding all other round inputs fixed would move the
aggregate by `0.020356380` L2.

Compared with the clean paired campaign, the selected round remains 25 and precedes the
failure. Selected validation macro-F1 and isolated test macro-F1 therefore change by
`0.000000000` and
`0.000000000`. At round 30 the
validation macro-F1 is unchanged, while validation loss changes by
`-0.000813667`. The checkpoint
parameter distance from the clean reference rises from
`0.000201582` before the intervention to `0.020355122` after it.

## Interpretation boundary

This single-seed, one-client, one-round swtpm experiment proves that an authentic but
non-conforming post-training TPM Quote is detected and excludes the corresponding signed
update from the real FedAvg checkpoint. It does not establish the average utility cost of
earlier or repeated failures, nor does an unchanged class-level F1 prove that exclusions are
always performance-neutral. Those questions require the planned multi-seed and sensitivity
experiments.
