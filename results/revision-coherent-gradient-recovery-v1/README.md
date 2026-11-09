# Linked clean root-expansion recovery

This separate protocol links to both original clean paused states. It expands
each48-row reference to the complete60-row pool already excluded from metrics,
adds exactly12 rows and preserves parent, loss contract and committed-round count.
No quorum is lowered. Only one expansion is allowed; no identical-evidence retry.

Both branches reach15 committed rounds and pass clean F1 guards at10/15, with
zero F1 loss versus matched coherent FedAvg. The full trajectories and recovery
proofs replay. Original four-of-six primary completion remains unchanged. This
tests clean training availability, not decontamination or attack resistance.
See the primary README, verification.json, protocols and signed evidence.
