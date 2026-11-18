# Clinical document Health Cards

The Node root exports `createOrganizationClinicalDocumentKeyVault`,
`createClinicalDocumentHealthCardIssuer` and `verifyClinicalDocumentHealthCard`.
The issuer uses independent random organization P-256 keys sealed by the host's
existing `ServerProfileSealer` and transactional vault. Keys have a fixed SHC
purpose; profile/communication keys and PQ companion proofs stay separate.

Create custody with `{vault, sealer, collection}`. Create the issuer with
`{keys, documents, issuers: [{organizationReference, issuer}], nowSeconds?}`.
Call `issue({operationId, documentReference, expectedRevision})`; the result is
`{issuer, documentReference, documentRevision, compactJws, qrValues}`.
`publicJwks(issuer)` supplies public keys for the host's configured
`issuer + '/.well-known/jwks.json'` endpoint. No private signing handle escapes.
Public lookup never creates custody: a configured organization without an
authorized issuance returns an empty key set.

`documents.readAuthorizedDocument({documentReference})` is a trusted server
port, called repeatedly across custody awaits. It must read the actual stored
document and current authenticated author, organization membership, licence,
installation, explicit clinical group and subject permission. Return the stored
`revision`, `authorizationRevision`, `organizationReference`, `subjectReference`,
`licensedClinicalAuthor`, `permittedResourceTypes`, `fhirVersion: '4.0.1'`,
`clinicalCreatorBinding` and original native R4 `bundle`, together with its
`documentReference`. A browser role, normalized binding or Demo fallback does not
establish that authority. Revisions and authority changes prevent release.
The issuer preserves the stored document; the existing Data SHC codec performs
standard minimization on an exchange copy. PractitionerRole assignment authors
and optional attestation retain their FHIR meaning.

The existing `OrganizationWorkforceVaultProvider` accepts either its legacy
email inputs or an Antifraud `ActorContactInput` through `invite({contact, ...})`,
`activate(verifiedContact, ...)`, `requireActive(verifiedContact, ...)` and
`requireActiveInstallation(verifiedContact, ...)`. Contact normalization does
not establish possession. Phone invitations carry actual phone identity; no
email alias is manufactured. They use the same capacity reservations, one-use
activation, atomic profile callback, sealed-code context and installation
generation lifecycle as email invitations.

For clinical issuance, call `requireClinicalAuthor({verifiedContact,
organizationReference, sector, profileId, clientInstanceId, requiredGroup})`.
It returns `{seat, registration, assignmentIdentifier}` from one current transactional read only when
the seat/employee/licence/device are active and the exact group is explicitly
stored. Legacy absent-licence/installation/group fallbacks cannot authorize this
method. Supported author scope is medical doctors (including the existing
generic doctor profile), generalist/specialist physicians, nursing,
midwifery, dentists and veterinarians; other occupations retain their workforce
lifecycle but cannot author through this clinical method. Role membership alone
does not establish a licence or subject permission. The host still checks the current protected profile/PIN session,
resource-specific clinical role scope and subject permission; invoke it on each
authorized-document read rather than caching a prior successful admission.
When the caller already owns a transaction in the same Pro workforce vault,
pass that trusted `IVaultRepository` as the second argument; admission reads
directly through it and opens no nested transaction. Never pass a Personal
peer's transaction to inspect Pro workforce state. Cross-host persistence and
remote peer checks remain separate operations, without a distributed atomicity
claim.

The controller invitation/reissue producer persists a dedicated UUID-URN
`assignmentIdentifier`. It survives activation, pending reissue and reload;
seat-hash IDs and device IDs remain unchanged. Use this admitted identifier as
the clinical creator's assignment/`authorIdentifier`, together with the actual
protected profile's separate actor UUID. New sealed invitation codes bind the
assignment in v2 AAD. Pre-assignment pending codes retain their v1 AAD and
ordinary activation behavior. Legacy seats without an assignment cannot obtain
clinical signing authority through reads or activation; the controller must
perform a legitimate reissue through the existing lifecycle.

Verify with `{credential, trustedIssuers, fetchImpl?, nowSeconds?}`. Credential
input accepts compact JWS, complete numeric `shc:/` strings/chunks or a signed
`.smart-health-card` JSON file. The verifier uses the configured exact HTTPS
issuer JWKS endpoint without redirects, native ES256/P1363, thumbprint key IDs
and bounded encoded/inflated/JWKS data. It returns a verified payload only after
signature checks. A short lookup label is not a complete numeric credential.
Public `crlVersion` and `x5c` metadata is compatible; accepting it does not prove
revocation status or certificate-chain trust. This API does not scan images or
claim online licence enforcement by itself.

To select a configured issuer without copying a decoder into each host, call
`inspectClinicalDocumentHealthCardIssuer(input)`. It reuses the same bounded
compact/numeric/signed-file parser and returns only
`{issuer, signatureVerified: false}`. Even a tampered signature can yield this
hint: it is a locator, not evidence. Match it against the server's known issuer
registry or explicit configured trust before full verification. The helper
does no network access and returns no clinical payload or authority decision.

## Separate organization post-quantum companion

`createOrganizationClinicalDocumentProofKeyVault({vault, sealer, collection})`
creates an opaque, fixed-purpose `clinical-document-pq-proof` custody capability.
Authorized issuance creates an independent random 32-byte organization seed,
sealed with organization, purpose, algorithm and key-ID AAD. Expanded ML-DSA
private keys and seed buffers are cleared after use. Communication and profile
keys/seeds are not used.

`createClinicalDocumentCompanionIssuer({documents, keys, proofKeys, issuers,
nowSeconds?})` takes the same authorized-document port and ES key capability,
plus the new proof capability. Its `issue(command)` returns the ordinary ES256
card fields and a separate `companion: {alg, kid, detachedJws, pqcValues}`. This
RFC 7797 ML-DSA-65 proof signs the **exact compact ES256 JWS bytes**. Its protected
header binds the fixed purpose, issuer and organization. The original SHC is
unchanged. The same current authorization snapshot is checked before and after
proof custody/signing; no companion is released following revocation.

`publicProofJwks(issuer)` is also read-only. The host may combine its public AKP
keys with `publicJwks(issuer)` EC keys at the existing configured issuer JWKS
endpoint. Seeds and private parameters must never enter that projection.
`verifyClinicalDocumentCompanion({credential, companion,
trustedIssuers, fetchImpl?, nowSeconds?})` verifies both ordinary SHC and the
separate proof against that same issuer/organization. Companion accepts the
detached JWS or existing AF `pqc:/` URI/QR values; the existing codec defines
their encoding. There is no arbitrary credential-selected discovery endpoint.
The credential accepts the standard verifier's compact JWS, numeric SHC QR
string/chunk array or signed-file wrapper. Both verifiers share one bounded
internal normalizer; the detached signature always covers the contained
compact JWS bytes, including when its presentation uses another encoding.

ML-DSA JOSE registration is defined by
[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html). This companion is a
separate SOS clinical-proof profile, **not a PQ signature mode of SMART Health
Cards 1.4**. Scanning/presentation of the two artifacts remains host UI work.

Reference: [SMART Health Cards Framework](https://spec.smarthealth.cards/).
