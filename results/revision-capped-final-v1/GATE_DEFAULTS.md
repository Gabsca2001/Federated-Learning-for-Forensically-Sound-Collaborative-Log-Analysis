# Effective admission defaults

The standard `configs/in-round-admission.yaml` selects `gated_composite`,
policy ID `m5-in-round-gated-composite-v1`, with a minimum of ten contributors.
M5's `--in-round-admission-config` argument is optional and has no automatic
default path: the extra in-round statistical policy is installed only when
explicitly supplied. Mandatory secure-round trust/integrity checks still apply.

The separate unified witnessed profile explicitly binds
`configs/revision-unified-v2-admission.yaml`, selecting `tpm_only` with a quorum
of ten. This profile-specific choice does not overwrite the standard file.

The capped-final study uses `tpm_only` admission for all four numerical arms:
raw FedAvg, robust bounded aggregation, capped sample proposal and capped robust
proposal. Their method keys identify aggregation operators. They do not identify
four different hard admission gates. Prerequisite trust is assumed passed in this
software study; there are no new TPM quotes. Statistical decisions are retained
as diagnostics/common-input controls, not used to exclude clients in those arms.

The inherited `training.minimum_contributors=8` is not the active quorum in this
study. The controller reads `runtime_admission.minimum_contributors=10` and
passes that value to its numerical operators and checks.

No default or threshold was changed to complete this campaign. A historical
default is not evidence of statistical superiority or operational validation.
The current finite experiment must finish before drawing new performance claims.
