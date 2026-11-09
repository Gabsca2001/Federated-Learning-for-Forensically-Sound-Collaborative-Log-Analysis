# Accepted DBA programme and scope of the latest experiments

The original supervisor comment asked for more attack variability, explicitly
suggesting DBA, and stronger literature comparisons under the same attack
protocol. The detailed experimental design was proposed by the student and
accepted by the supervisor. These are requirements for a well-described
evaluation, not a promise of perfect automatic attacker exclusion.

## Student proposal accepted in the first reply

Source: supplied transcript70152b64-6d6e-455f-9a64-c1404d00b597, lines34–37.

1. Implement genuine distributed trigger composition, distinguished from the
   previously considered collusion scenario. Different malicious clients train
   on their assigned individual components; the complete backdoor is evaluated
   after aggregation.
2. Evaluate the complete trigger AND each individual component. Do not infer
   compositional success from a full-trigger-only poisoning control.
3. Match malicious identities/count, activation rounds and total poisoned-row
   budget when comparing distributed versus the existing full backdoor. Full
   trigger training changes more feature coordinates per poisoned row; disclose
   this remaining difference rather than claiming equal feature-edit budgets.
4. Report clean accuracy, full/component ASR, treatment of manipulated
   contributions, false positives on benign clients and persistence in later
   rounds.
5. Compare FLAME and WeiDetect on the same incoming updates where compatible,
   retaining actual method mechanisms and information budgets. FedGradTrace
   could be evaluated separately subject to available time. Costs, utility,
   attack results, detection and benign exclusion were part of the proposal.

The supervisor accepted this and suggested investigating whether decision
records and derivation could retrospectively identify coordinated groups using
indicator/tensor correlation.

## Later accepted retrospective design

Source: supplied transcript095d6d4c-485f-4f39-9cfa-bd11b2606b65, lines17–20.

- Use decision indicators and update tensors: median-centered similarity,
  indicator correlation across rounds and per-tensor deviations.
- Calibrate thresholds on clean campaigns without malicious identity labels.
- Compare individual and joint removal of selected groups. The broader accepted
  multiround proposal distinguishes direct reaggregation from genuine later
  retraining on a corrected checkpoint.
- Present candidate groups compatible with coordinated/collusive behavior.
  Similarity can arise from local data, so this is not proof of collusion.
- Describe conditions, assumptions, conclusions and the reasoning explicitly.

## What the current studies add

The already retained original DBA/baseline and group studies are the direct
evidence for the accepted programme. The latest coherent-gradient experiments
are additional defense research and do not replace those matched comparisons
or establish new retrospective group detection results.

The first new coherent study has data-only distributed/full poisoning plus a
declared gradient-scaling extension. All six raw attack controls fail its fixed
effectiveness criterion. Zero ASR therefore cannot establish defense success;
the three actual pauses remain availability counterexamples.

The separate endpoint study gives malicious clients ten-epoch poisoned Adam
training and interpolation/scaling of their resulting endpoint deltas. Honest
clients still follow the coherent one-step gradient protocol. This is a more
capable Byzantine model-update scenario built from distributed/full poisoned
datasets, not an ordinary honest-gradient data-only DBA run. Malicious training,
query and row budgets are declared and matched across compared defenders.

Every conclusion must distinguish distributed compositional success, full-trigger
control success, ineffective attack controls, complete defended trajectories,
retained parents after pause, and blocked shadow queries. No fresh TPM training
attestation, production gradient adapter, raw-traffic trigger realizability,
independent-data guarantee or new collusion proof is claimed here.

The companion source index pins the original supplied transcript bytes. The
correspondence is reference material and is not edited by these experiments.
