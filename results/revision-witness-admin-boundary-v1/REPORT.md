# Administrative separation: decisive local audit

The current local deployment does not meet the witness administrative-separation
requirement. This is an observed counterexample, not merely the absence of a
successful test. No thesis file, protocol implementation, key or journal was
modified to obtain this result.

## Necessary condition and counterexample

Let A_C be the principals that administer the coordinator, K_W the witness's
private signing key, and J_W the witness's private journal. A necessary condition
for the intended separation is:

`IndependentAdministration(W,C) => for every a in A_C:
not CanRead(a,K_W) and not CanModify(a,J_W) and not CanAdminister(a,W)`.

The existing experiment is administered from the same local operating-system
principal, UID 1000. The audit successfully loaded both actual coordinator and
witness private keys as that principal and verified their public identifiers
against the already signed witness policy. It also read the actual witness
journal and its fifteen registrations. The operating system reports that this
principal has write access to that journal. No journal write was performed.
The key/journal byte hashes before and after the audit are identical. Private
key material is never printed or copied into this report.

There is therefore a concrete principal in A_C with `CanRead(a,K_W)`. This
contradicts the necessary condition above. It does not follow that the
coordinator application itself has that filesystem access: its recorded Docker
mounts do not include private witness state. Application isolation passed;
independent administration did not.

The successful unprivileged UID 65534 denial tests in the previous operation
report do not invalidate this counterexample. They exercise a less privileged
identity, while the actual local administrator retains access to both roles.

## What remains verified

The external TSA adoption, strict RFC3161 checks, fifteen-receipt closed-set
accounting, actual M5 admission, disconnected public reconstruction, omission
and truncation negatives, sealed backup/restore, acknowledged-state process
restart and development HTTPS tests remain valid within their recorded scope.
The 127-module core and its historical validation remain unchanged.

An external TSA signs time evidence for commitments. That service does not
administer the local witness, authenticate an independently complete collection
of client registrations, or independently retain this deployment's final policy
and closure references. Its presence cannot satisfy the missing administration
condition. The current protocol guarantees remain conditional on the published
honest-witness, trusted-authority and independently retained-reference assumptions.
The audit does not establish those assumptions as facts of this local deployment.

## Required external change

A real distinct trusted operator must control the witness host/account, signing
key, journal and backups, without privileged access by the coordinator's
administrator. That operator must distribute the public key/policy and final
closure references through its own accepted channel. The user has confirmed
that no such resource/operator is currently available.

No local coding change, additional repeated experiment, newly named account,
container or rented machine controlled by the same administrator can supply
the missing organizational fact. A different cryptographic architecture would
need a separately stated assurance goal; it would not by itself prove the
original administrative-separation requirement.

The already prepared laboratory kit provides the next executable steps once
that actual resource exists. Acceptance must then repeat the deployment and
privilege checks with the real coordinator credentials and independently
obtained public references. No institution or person has been contacted or
assigned a fictitious role.

## Evidence

`administrative-boundary.json` records the actual public key identifiers, UID,
readability checks, journal count, unchanged-byte checks and scope. `audit.py`
preserves the read-only audit controller. The preceding external-TSA and
operational evidence remains in the original WSL results directories; this
audit does not overwrite those reports or promote their provisional flags.

The manuscript freeze remains in effect. ToN-IoT remains deferred.
