# Retirement of four superseded historical replicas

The current thesis text was not used as a retention constraint. Four early
targeted adaptive replicas, seeds 342593 through 345593, were retired with the
project owner's authorization. They were completed experiments, not invalid
runs. Their attack was uninformative under the frozen protocol; later untargeted
and revision campaigns remain available for the current investigation.

The operation removed 58,616 files. After retaining about 21.6 MB of records,
the measured net Linux file allocation reduction was **8,601,600,000 bytes**
(8.60 decimal GB, about 8.01 GiB). Directory allocation is not included in this
conservative figure. A second compact record copy, about 20.8 MB, is retained
in this Windows workspace. No full multi-GB backup was created.

The retained record contains 328 verified copies of evaluations, manifests,
execution locks, selected checkpoint bundles and public keys, plus an inventory
of the removed files and their SHA-256 hashes. The original aggregate report
and the exploratory seed 341593-v4 remain untouched. Exact historical TPM-chain
validation and full trajectory reconstruction for the four retired replicas
are no longer possible. Hash inventories identify bytes; they cannot restore
them. Some retained historical references therefore name unavailable artifacts.

No current revision dependency was found in the recorded text scan. Before and
after restarting WSL, checks passed for the 163 original protected anchors
(including the previously documented preserved interrupted attempts), all 138
generation-source locks, current publication checksums and 45 exact historical
checkpoint comparisons. Six FL image IDs and all 152 original container IDs
are unchanged. This is an integrity check, not a rerun of every scientific test.
Current capped-defense failures, calibration inputs, formal-model evidence,
multiround replay evidence and live-TPM campaigns were not deleted. The thesis
was not edited.

Linux discard completed. Offline VHD compaction did **not** start: Windows
reported that the administrator confirmation was cancelled. No second elevation
attempt or alternative privileged compaction was made. WSL was restarted and
the retained evidence passed the checks above. Consequently the 8.60 GB Linux
reduction must not be reported as 8.60 GB newly free on C:. Current host free
space and VHD length are recorded separately in compaction-result.json.

A later successful offline compaction would require stopping WSL again and
accepting the Windows administrator prompt. The existing DiskPart script is
prepared, but must not be run while WSL is using the disk. Linux deletion and
later host reclamation are overlapping savings, not additive amounts.

The separate coefficient-only investigation is documented in
../capped-final-20261106/exact-group-exploration/README.md. It does not establish
an improved poisoning defense, change operational defaults or modify the
completed campaign. No large new training run was started during this cleanup.
