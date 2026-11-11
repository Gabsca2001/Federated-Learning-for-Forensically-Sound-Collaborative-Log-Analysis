# ToN-IoT confirmation of head gate v2: development findings (no study run)

2026-11-10. Development only (validation split; test never opened). Data and code:
`scripts/ton_fl_adapter.py`, `scripts/ton_fl_pilot.py`, `scripts/ton_fl_dev.py`;
stage reports in `artifacts/ton-fl-gate-v1/dev-stage-{a,a2,b,c}.json`.

## Data adapter
Verified host/minute windows (80,172; same 25 features as Data24), binary labels.
The chronological split reproduces the published support exactly (train 67,959,
validation 7,707 after the flow-end embargo rule, test 4,093). Warm start trained
on a disjoint 15% of training windows; FL pool of 15,000 windows (13.3% attack).

## Findings
1. **Data24 trigger is invalid on ToN.** Features 13/17/24 at 12 standard units give
   100% "ASR" on the clean model (pilot): nothing to learn, harm not measurable.
2. **Inherited training configuration fails.** Balanced class weights + 10 local epochs:
   IID F1 stuck at ≈0.69; non-IID collapses 0.90 → 0.51. Uniform weights, 1 local epoch,
   learning rate 0.0003 give stable clean F1 0.867 (IID) and 0.890 (non-IID).
3. **Transferred DBA is ineffective under the stable configuration.** Best trigger
   (features 1/6/15 at 12 units; clean ASR 0.10–0.27 baseline): paired harm over the
   10-round attack window 13.3 points IID and ≤1 point non-IID, unchanged when the
   poisoned fraction rises from 50% to 100%. Below the 20-point effective-control rule.

## Consequence
A ToN replication of the Data24 DBA comparison would contain only ineffective controls
and could not test the gate. Options: test the scaled (adaptive) attack on ToN first;
or report the ToN outcome as a negative transfer finding (backdoor efficacy depends on
training configuration and data) and stop. No protocol was frozen and no gate result
on ToN is claimed.
