# Unified model and verified representative M2–M8 chain

The original WSL repository now has a shared explicit verification context and
a complete selected execution profile. It connects M2/M3 source/partition
bindings, actual M4/M5 software-TPM admission, external witness deadlines,
real M7 products, authenticated graph dependencies and a new named M8 closure.
The working tree remains the original repository on `revision/derivation-protocol`.
The preservation TAR and source ZIP are evidence snapshots, not replacement
working copies. The manuscript is frozen and has not been edited.

## What changed

- `checkpoint_verification.py` supplies strict, caller-provided policy/closure
  references and public evidence. M5 campaign and M7 checkpoint verification
  use the same phase verifier. Missing proof or an incompatible legacy checkpoint
  has no fallback to a weaker profile.
- `system_chain.py` declares the common artifact roles and composes the existing
  verifiers under `unified-witnessed-fedavg-v1`. The campaign and M7 must use the
  same witness profile/path base and all declared rounds must be covered. Retained
  source files are checked against the executing package.
- `unified_preservation.py` adds `m8-unified-witnessed-chain-v1`. It reuses the
  existing preservation models, Merkle construction, strict RFC3161 verification
  and deterministic TAR metadata, and reconstructs the complete selected chain
  and its accounting from the archive. Earlier fixed thirty-round M8 profiles
  remain unchanged.
- The CLI exposes `system-chain-verify`, `m8-unified-create`,
  `m8-unified-verify`, and an explicit campaign `--checkpoint-verification` input.
  M7 consumes the context through its digest-bound prediction configuration,
  which is propagated through explanation, mapping and report verification.

## Actual validation

| Check | Observed result |
| --- | --- |
| Full current suite | **773 passed**, 21 new tests, two existing dependency warnings |
| Focused integration/archive tests | **35 passed** |
| Fresh live case | One round, fifteen isolated software-TPM clients, one local epoch |
| Genuine client contributions | Fifteen freshly trained TPM-signed updates; fifteen timely eligible/admitted submissions |
| Actual external timestamps | Seventeen: fifteen registrations, one witness closure, one final M8 root anchor |
| M7 investigation | Two validation windows selected lexicographically before inference; prediction, IG/prototypes, ATT&CK mapping and reports recomputed |
| Authenticated graph | 97 nodes, 277 typed edges, actual declared round/product sources |
| M8 commitment | 408 artifacts and 7 external source-file bindings; 415 Merkle leaves |
| Recovery TAR | 2,498,723,840 bytes (2.33 GiB) |
| Offline recovery | Original public source workspace and private keys absent from the verifier mounts; network disabled |
| Physical relocation | Copied archive reconstructs in the preserved CPU image |
| Actual negative controls | Three M7 profile/phase negatives, wrong M8 closure pin and changed bytes in the real report payload rejected |
| Current runtime binding | All declared measured source/configuration files match both image and host |
| TSA certificates | All seventeen token chains and valid authenticated cached CRLs checked as of audit capture |
| Thesis freeze | All 110 guarded manuscript/figure files unchanged |

The graph endpoint intentionally reports that it does not itself repeat M5
numerics or M7 computation. The enclosing system verifier performs those full
checks separately on exactly the same declared manifests. Those scoped graph
flags therefore remain distinct from the completed composed verification.

## Exact source and archive identity

Core modules: **130**. Package SHA256:
`8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64`.

Executed CPU image:
`sha256:edd7ee2a19e2a66c9f741a8bf0f9769bd4255c708c97d15909aa80424fc2a467`.

Final archive SHA256:
`ceb74ae034d39471e6ce8231602fbfa1fe1bff1998880283f28923c31b5447c6`.

Retained final closure SHA256:
`999ae7caacdff3cdef41df48174434a2176eb0c39c2d77937af811559f8738d3`.

Merkle root:
`2b00b8fa6bfb31d97a99b6145fee9169ceb7754bc7ba758ee8264e3df9f0b908`.

The archive checksum is retained separately and was checked before recovery
and again after mutation controls. Trust in the supplied expected closure/policy
references remains explicit; a file named "pins" is not an independent witness.
The image/build source snapshot and actual publisher overrides are separately
retained. Publisher controllers are not claimed as TPM-measured code.

## Profiles kept separate

The common model is not one algorithm with every option enabled. Original
TPM-only/sequential/composite policies, PROTEAN, DBA, literature adaptations,
retrospective groups, reviews, direct counterfactuals, subsequent retraining and
bounded/robust aggregation keep their explicit contracts and result versions.
This clean integration case does not replace or rerun those scientific studies.
Earlier signed artifacts, numerical endpoints, proofs and source releases remain
unchanged; newer code does not grant them new properties retroactively.

The stronger per-record ingestion-coverage adapter also remains an explicit
optional profile. The selected case verifies the ordinary M2 snapshot/lineage
and M3 partitions but does not repeat that earlier occurrence-level experiment.
Accordingly `source_record_coverage_replayed=false` is preserved in the closure.

Administrative independence is still unproved: both local roles share an
administrator and no distinct operator resource is available. Likewise this
case establishes neither global capture/product completeness, physical-TPM
protection, network-delivery completeness, attack resistance, certified unlearning
nor statistical superiority. Their flags remain false rather than being inferred
from successful integration. ToN-IoT remains deferred.

## Preserved execution history

The first e9171187 release completed a nominal M5-only pilot. It is retained
as a preliminary execution, not counted as the final complete chain. The final
release adds two explicit legacy-type/profile downgrade regressions and uses a
new image, baseline, keys and workspace.

Initial M8 unit development corrected an adapter call to the existing Merkle
constructor before either final runtime was accepted. The complete final suite
passes. The first actual final-chain publisher then completed M7/graph/system
verification but could not start the networked M8 container because Docker's
bridge device was absent. No M8 code or timestamp request ran in that attempt.
The separately retained publisher retry uses host networking only for the
final TSA request. Training and every offline verification retain network
isolation. Transient WSL control-channel timeouts occurred while M7 kept
progressing; no WSL restart, old-server reset or historical-state rewrite occurred.

The first final-audit harness used `report.json` instead of the actual
`investigation-report.json` TAR path. Its already completed source, M7 and
relocated-recovery checks are preserved. The audit resumed with the correct
locator, mutated only a dedicated archive copy, and completed the negative
control, certificate checks and source preservation. No protocol change or
weakened verifier was used to resolve that harness issue.

## Evidence and next use

`validation.json` records the final counts and boundaries. `SYSTEM_MODEL.md`
defines the common objects/relations and profile composition;
`profile-correspondence.json` binds functions, exact lines/hashes, hypotheses
and evidence. The `recovery/` directory contains the actual archive, root/time
proof and retained digests. Individual negative-control reports, actual runtime
commands, source release and executed publisher controllers are also retained.

Repository commands are ordinary original-WSL commands. To verify the preserved
archive, use the recorded CPU image with `m8-unified-verify --archive ...
--expected-closure-sha256 ...`, supplying the expected digest from its accepted
retention channel. Source-compatible numerical behavior is part of the contract.
The existing successful recovery command records are executable examples.

The implementation/consolidation is complete for the selected profile. The
next writing step may use this stable model, profile table and evidence without
rewriting correct equations or conflating the parallel experiments. No thesis
editing is performed automatically by this publication step.
