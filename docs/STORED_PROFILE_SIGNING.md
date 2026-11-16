# Sign an admitted stored-profile operation

Import `signStoredProfilePayload` from `sos-sdk-node-ts/stored-profile-signing`.
The trusted host supplies its transactional vault, profile sealer, exact profile
and session collections, and the verified owner, actor, provider and route
binding. The command selects one of the two profiles defined by
`sos-data-utils-ts/registered-profile-contract`:

- `IndividualIdentityPresentation` signs ES384 VP claims through the selected
  registered-profile session and its runtime VP key.
- `OrganizationActorDetachedCredential` signs the exact supplied UTF-8 string
  or byte array through a sealed wallet session and its profile actor key.

The caller must first validate the credential, subject relationship, legal
representation and operation-specific permission. In particular, selecting a
signing profile does not establish those permissions. Individual claims bind
the issuer, subject and VP holder to the stored actor, while the command's
subject binds the selected session and accepted SMART scopes.

## Existing records and custody

The operation preserves the existing purpose-specific ES384 derivation,
including custom `walletKeyDerivationId` values and registered public material.
It derives only the selected signing purpose. It does not enroll replacement
keys or change the profile's confidential-storage policy.

Registered sessions use their existing `sessionId:unlocked-wallet-seed` AAD.
Sealed wallet sessions retain SHA-256 token IDs and the existing
`ownerId:profileId:sessionId:wallet-session-seed` AAD. Tokens and seeds stay in
the trusted server operation. A missing profile or session credential revision
means zero; mismatched revisions are rejected. A new session producer must
capture the current profile revision, then recheck the profile in its commit
transaction after any sealing await.

## Result and concurrent changes

The result contains only `jws`, `verificationMethod` and a sanitized public
P-384 JWK. There is no wallet object, callback, reusable signing handle or
private-key result. PIN unlock and its committed failure counters remain the
responsibility of `RegisteredProfileSessions`; signing neither resets counters
nor reopens a PIN envelope.

The operation reads and validates the profile and session in a transaction,
unseals outside that transaction, signs, then reads both again in a transaction.
It rejects revoked, expired, locked or changed records before releasing the
signature. All transaction reads precede writes, and this operation itself
writes no records. Host admission that depends on other domain records still
needs its own current-authority checks.
