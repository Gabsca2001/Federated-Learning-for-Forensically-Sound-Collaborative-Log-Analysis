# Administrative independence: actual condition and acceptance evidence

The user confirmed on 5 November 2026 that no resource with a distinct trusted
administrator is currently available. There is therefore no demonstrated
independent witness administration in this run. A separate local process,
container, Linux username or remotely rented machine controlled through the
same administrator credentials cannot establish this organizational fact.

The external TSA has separate ownership and signing keys. Its public signatures
can independently authenticate time under the accepted pinned CA. This does
not transfer management of the receipt witness to the TSA or make the local
witness operator independent from the coordinator.

## Minimal deployment that can close this condition

Use a laboratory or other trusted operator's machine/account whose privileged
access is outside the coordinator administrator's control. The operator must
create the witness signing key and journal there, keep private material local,
and manage the TLS service and closure. The coordinator receives only the
public witness key, policy, acknowledgements, snapshots and authorized public
references. It must have no shared root/sudo/Docker-management account, witness
private-key copy or write access to the witness journal/backups.

The verifier must receive the witness key/policy digest and final closure
digest through the accepted operator channel, independently of the coordinator's
inventory. Retained client acknowledgements must remain available for fork and
omission checks. Availability and witness honesty remain assumptions; this is
not Byzantine consensus or a universal anti-censorship guarantee.

## Evidence to collect when the operator is available

Record the real witness and coordinator operators, controlled hosts/accounts,
privilege boundaries and authorized public exchange paths. Preserve the service
configuration and identifiers of the separately retained policy/closure pins.
Run the same receipt/intake/M5 verification in that deployment and retain:

- a coordinator-identity attempt to read the witness private key and journal,
  or modify either, rejected by the actual access controls;
- a coordinator attempt to close/reset the service rejected by its public API;
- verified client acknowledgements and an operator-closed complete eligible set;
- rejection of a newly coordinator-signed omitted or extra inventory;
- verification by a third relying party using independently obtained pins;
- restart/backup behavior that preserves keys, cutoff, acknowledged history and
  final closure without reopening an expired context.

No person, host, credential or successful access-control result is invented in
this report. The current local witness cannot honestly be marked administratively
independent. The existing code and prepared deployment sequence can be used on
the independent operator's host once that concrete resource exists.
