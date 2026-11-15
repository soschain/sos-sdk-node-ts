# Controller-owned pending identity evidence

`ControllerIdentityEvidenceVault` is the same usecase for the host-selected memory
or durable vault. The host injects its configured sealer and a trusted,
read-only `resolveCustody(participant, cardId, action, transaction?)` callback.
The callback resolves the authenticated account, current card/controller,
relationship and authorization lease from authoritative records. Browser
identifiers, upload method and UI capabilities do not grant access.

The class accepts separate subject, controller and relationship files. Any
permitted nonempty subset is valid, with three distinct slots at most. Pending
uploads do not produce a signature, verification assertion, professional
attestation or provisional registration. Proposed identifiers are private
submitted claims, separate from the resolver's authoritative target binding.

Commands and byte buffers are snapshotted before awaits. Private metadata and
bounded media chunks are sealed with AAD binding scope, owner/card, stage/file
and slot/index. Media digests and content IDs use the existing Antifraud
SHA3-384 profile. The chunk bound keeps the configured string sealer suitable
for its existing KMS payload boundary; no controller wallet keys are invented.
Every custody await is followed by current authorization, and transactional
rechecks precede writes or return of protected bytes. Resolver callbacks must
finish authoritative reads before writes and must not perform custody or
external side effects inside a transaction.

Receipts expose only pending state and opaque file IDs/slots. `download` requires
fresh current authority and returns protected bytes and private download metadata
to the trusted BFF for streaming; no external storage URL is returned. A new
valid PIN/session lease can read already committed evidence for its unchanged
owner/card binding. An in-flight upload cannot cross a changed authority lease.

Interrupted chunks resume immutably for the same command/content. Divergent
retries fail rather than overwrite. Publication requires complete readback and
canonical media integrity; partial stages are absent from `list`. Reset first
blocks the exact card's old epoch, deletes its sealed files/chunks, and retains
only small opaque retry tombstones. Other cards and owners are preserved.

`controllerIdentityEvidenceCollections(scopeKey)` returns the canonical stages,
chunks and evidence collections. Trusted workspace deletion can remove exactly
the old generation's collections without invoking a removed workspace resolver.
Public `reset` still requires current card authority. `cleanupExpired` is scoped,
bounded host maintenance, never an unauthenticated browser endpoint. Retention is
explicit host configuration, separate from authorization-session expiry.

The existing professional provisional-evidence runtime is unchanged. Its creator,
registration and invitation contract is not used as a controller permission.
