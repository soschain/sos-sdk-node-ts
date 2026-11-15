# Controller recovery coordinator

`ProfileRecoveryService` owns the fixed two-share recovery protocol and one-use
generation coordination. It consumes the SOS Data recovery identity, record and
outbox contracts. The host must authenticate the account and contact, authorize
the specific controller profile, select custody and provide an atomic repository.
Selecting an identity or possessing a record is not recovery authorization.

The historical email record and notification discriminators remain unchanged
solely for stored-format compatibility. Email AAD retains the exact newline
transcript, normalized email and generation. Telephone recovery has a separate
version/contact branch and AAD domain; it never puts a phone number in email.
Both use the existing versioned, checksummed recovery-code profile.

The coordinator returns only the recovery or replacement code after persistence
commits. It passes recovered material only to the trusted host resealing callback,
and clears its owned temporary byte buffers. A KMS or repository failure is an
operational failure, not a wrong-PIN event. No notification is sent directly.

The repository must atomically compare the expected generation and exact current
owner/profile, replace the protected profile envelope, revoke every configured
session family for that owner/profile, and write the notification outbox record.
It must preserve unrelated profiles and roll back every write on failure. Initial
enrollment can compose the host's one-use grant and completion writes in its same
transaction. The initial prepared data record and its application-finalizer
callback remain in the host repository closure; `enroll(identity, seed)` passes
only the recovery record to `put`. No callable handle is cloned or serialized.
The coordinator's injected-port tests do not prove that host
transaction or replace its real-vault regression.

`RegisteredProfileSessions.preparePinReplacement` reuses existing public-key
validation and PIN envelope preparation outside the transaction. Its managed
`commit(port)` snapshots the exact current profile, reads both configured session
families before writing, and denies a changed profile. A recovery repository can
read its generation, application/grant and outbox first, invoke this commit, then write its recovery
and outbox records in the same transaction. The existing `replacePin` operation
delegates to this same preparation and commit.

The synthetic compatibility fixture was newly captured from historical published
modules, not a production record. Its provenance records registry tarball SRI and
exact module hashes. No verified source checkout URL was available for that
runtime, so no GitHub source attribution is invented. Package tests import only
static encrypted/hash vectors and owned runtime modules.

`createGoogleKmsProfileRecovery` in `profile-sealer` provides the fixed configured
Google KMS byte port for 32-byte shares. It reuses the existing workload-token,
configured-key, timeout and redirect policy while preserving exact base64 bytes
and binary AAD. Host selection of local-test custody versus Google KMS stays
explicit. Its loopback HTTP tests do not establish live IAM or KMS readiness.

The host still composes its profile store, recovery routes, verified contact and
initial enrollment authority through the repository and preparation ports.
