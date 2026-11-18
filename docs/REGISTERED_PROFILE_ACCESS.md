# Registered profile access

`RegisteredProfileAccess` composes the existing transactional custody sessions,
registered communication wallet and configured-gateway signature verification.
It supports listing individual-controller profile metadata, actor unlock and
resolution, encrypted subject discovery, SMART subject selection, clinical
session resolution and lock. It does not enroll actors or replace the complete
profile-management facade.

The trusted host supplies the authenticated account, provider and route, fresh
OIDC token and contact verified from that account. These inputs must not come
from browser authority claims. The configured provider selects recipient and
response-signing keys; decrypted fields never select a trusted key resolver.
The current use case admits registered individual-controller self/controller
profiles. Employee presentation and other actor admission are separate work.

Directory discovery executes the existing Organization and accepted-License
queries through an explicit encrypted exchange port. The default directory
client retains its existing plaintext contract for existing callers. Registered
discovery validates each returned Organization UUID, canonical private subject
DID and public alias using SOS Data's identity reader. A discovered assignment
is not a clinical grant. Refresh atomically replaces the directory snapshot and
clears previous selected-subject, attester, scopes and sealed token state while
persisting the same confirmed aliases in the profile in that transaction.
Role-code tails retain their relationship semantics: ONESELF is self, RESPRSN
is controller and other assignments are member. A returned real RelatedPerson
identifier becomes a FHIR personal attester, independently for each card.

`readAuthorizedSubjects` returns the accepted directory array through the same
signed query without writing the profile or session. It preserves a selected
SMART subject, scopes and sealed token. Exact current profile/session snapshots
and expiry are checked before the query and again before returning its result;
a concurrent lock or change denies the read. Hosts must perform directory and
custody awaits outside datastore transactions, then recheck their captured
authority snapshot through the supplied transaction port when composing another
operation. This read neither persists discoveries nor confers clinical access.

Selection requires an exact alias in that session's latest directory. Its
provider-confirmed canonical subject is used in SMART Composition scopes. The
normal runtime `openid-id-token-signing` ES384 key signs `private_key_jwt` with
the stored DCR client as `iss` and `sub`, exact SMART endpoint as `aud`, current
`iat`, a five-minute `exp` and fresh `jti`. It is a distinct capability from
actor and VP signing; their existing client-bound methods remain unchanged.

The configured gateway signature, envelope issuer/audience/operation/thread,
access JWT issuer/audience/actor/time, its own nonempty token identifier, granted
scopes and response patient all must match. The access JWT `sub` is the actor; the separately bound response
patient is the selected canonical subject. Missing granted scopes never fall
back to requested scopes. Existing Composition r/rs/cruds permissions are
supported here; every granted action and section must be a subset of a requested
permission. Narrower grants are retained exactly and foreign/extra grants fail.

The signed SMART response carries the original request operation identifier and
thread. The access token's `jti` identifies that token independently; it need not
repeat the request identifier. Both bindings are checked before the token is
sealed into the selected session.

`gateway.smartTokenVerification` is an explicit host-selected algorithm and
signing-key resolver, separate from outer PQC communication verification.
The actual gateway can sign SMART with ES384, explicitly configured ES256, or
its configured PQC key while outer transport stays PQC. Use
`resolveRegisteredSmartTokenSigningJwk` with a fixed algorithm and optional
fixed verification-method pin to select one authentication key from the expected
provider document. ES384 requires P-384 and ES256 requires P-256. A token header
cannot choose the resolver URL, provider, algorithm policy or method pin. There
is no automatic algorithm fallback; wrong material, private fields, ambiguity,
foreign relationships and unconfigured algorithms fail closed. Normal profile
six-key derivation and client-assertion purpose remain unchanged.

Tokens are sealed under `<sessionId>:access-token`. Network and cryptographic
work happens before a transaction that rechecks exact profile and session
snapshots, credential revision and session expiry. A concurrent lock, PIN
rewrap, refresh or selection cannot commit stale authority or resurrect a
session. Clinical-token expiry denies clinical resolution while preserving a
still-live actor session for fresh authorization. Normal actor lock revokes
both uses by deleting the same session.

Actor and clinical results include a secret-free profile view and actual
registered encrypted transport and compact-document capabilities. Clinical
profile views overlay the selected card's effective actor mode and attester;
they never reuse a base profile's relationship for a different card. Pack
binds the stored actor and DCR client, and unpack verifies configured-gateway
signature, response issuer/audience and a thread opened by that adapter.
Capabilities recheck the unchanged profile/session before and after work;
clinical capabilities also enforce the current grant expiry. No raw seed or
private key is returned.

The protocol suite uses real registered JWS/JWE bytes and independent
verification through an injected synthetic HTTP peer. It proves SDK protocol
and persistence behavior, not acceptance by an online gateway or a completed
portal migration. Existing retained directory, custody and transport suites
remain necessary. The original orchestration evidence is available at
[ServerProfileSessionManager](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/server-profile-session-manager.ts)
and [ServerProfileSession](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/server-profile-session.ts).
These are source references only; this package imports no historical runtime.
The separate SMART signature profile follows the current
[gateway token issuer](https://github.com/soschain/sos-gw-node-ts/blob/main/src/managers/OpenIdAuthManager.ts)
and its [published DID relationships](https://github.com/soschain/sos-gw-node-ts/blob/main/src/utils/did-backend.ts).
