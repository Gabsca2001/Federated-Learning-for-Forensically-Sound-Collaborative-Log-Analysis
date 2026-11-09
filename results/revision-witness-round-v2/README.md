# Witness-to-M5 live phase validation

The v2 policy signs a registration cutoff strictly before context expiry.
Two fresh one-round Docker/swtpm cases exercise the complete receipt,
closed-set inventory, actual admission, effective-weight and checkpoint path.
All 127 core modules match the executed image and source release.

| Case | Registered | Eligible | Ready | Accepted | Trust quarantine |
| --- | ---: | ---: | ---: | ---: | ---: |
| Nominal | 15 | 15 | 15 | 15 | 0 |
| Negative intake/trust | 14 | 13 | 12 | 11 | 1 |

In the negative case, client13 is unregistered, client15 is registered late,
client14 has an eligible receipt but an unavailable metrics payload, and
client12 is revoked after registration. Only eleven contributions have positive
weight. Missing-payload and quarantine dispositions have zero effective weight.
Both cases reconstruct offline after witness/TSA shutdown, and also after
relocating this public package. No private keys or TPM private state are included.

Coordinator-signed omission, extra unregistered/late inventory entries and
truncated witness history are rejected. The real historical witness-v1 snapshot
still verifies with its original retained policy/head pins. The full suite
passes 752 tests, including 22 new phase tests; two dependency warnings remain.

See `validation.json`, `additional-audit.json`, the relocated verification
reports, and the final artifact index. `executed-source-release.zip` preserves
the actual image source, controller and configuration. The first v1 attempt
is retained separately: its negative-case controller stopped while JSON-encoding
an already-created revocation record. It is not counted as a completed two-case
result. V2 repeats both cases in new state after correcting that boundary.

This is a local protocol pilot, not an attack-resistance or independent-seed
utility study. The TSA is a local development authority; administrative
independence and external TSA acceptance are not demonstrated. Registration
times have RFC3161 evidence under that authority. Admission/completion times
remain signed coordinator-clock claims and require trusted execution. Late
completion produces no completed witness-round receipt. This profile does not
claim universal crash-atomic publication or network-delivery completeness.

The old server on port 8765 is a separate closed development record. The two
new case services are deliberately stopped for offline verification.
ToN-IoT remains deferred. No default admission defense was changed.
