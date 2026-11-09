# Changelog

## Unreleased

- Accept one BFF-verified phone or email contact in the existing portable
  professional resolution APIs, retaining the separate `verifiedEmail` input
  for compatibility. Use the shared Antifraud identity contract rather than
  placing a phone in an email field or inventing an employee DID.
- Bind a fetched operational employee DID to the selected contact and alias
  role, preserving organization/jurisdiction checks. Reject ambiguous contact
  inputs before provider queries. Direct UUID authorization URNs remain
  pre-DCR routing; GW `Token/_exchange` still verifies the issued licence's
  contact, organization, employee UUID and role before activation/DCR.
- Correct a development-stage test assumption: a CDS employee authorization
  URN encodes the employee UUID, not the stable contact hash. Use the published
  UUID builder for fixtures and prove routing needs no early employee-DID read.
  Derive operational DID fixtures from the contact separately. No GW identifier
  format or exchange protocol changes. The earlier 67-case result included
  incorrect professional fixtures and is superseded by the corrected gate.
- Add contact-aware `createEmployeeActivationGrant` and
  `employeeActivationGrantMatchesContact` over the existing V1 grant model.
  Explicit phone/email inputs produce the existing opaque actor identifier;
  raw contact, new wire fields and inferred authority are not added. The
  matcher does not establish identity verification, grant ownership or TTL.
  The role catalogue and managed-wallet enrollment remain separate.
- Corrected Node 26.13.0 validation passes 15 focused cases, all 67 SDK cases
  without skips and typechecking using real-format UUID authorization fixtures.
  The immutable Antifraud 0.2.0 candidate is the only installed package delta;
  all other baseline package versions and the tracked manifest/lock are retained.
- Install published `antifraud-data-utils-ts@0.2.0` as an exact direct registry
  dependency and retain the incoming 0.2.2 recipient/contact and Web Push work.
  Align the actual install to the merged lock, including incoming
  `sos-data-utils-ts@0.6.30`. Verify all 130 installed Antifraud public files
  against the published artifact; no local package references remain.
- The combined Node 26.13.0 registry gate passes all 93 SDK tests without skips
  and typechecking. All 95 installed package versions match the lockfile.
  This proves the merged SDK contract, not complete portal/GW phone lifecycle,
  deployed push delivery or the independent clinical/permissions/research gates.

## 0.2.2 - 2026-11-09

- Bind browser push registrations to a verified actor and environment, seal
  subscription credentials through the injected sealer, and keep explicit
  per-device jobs, retry leases, revocation and provider acceptance status in
  the shared transactional vault. Send RFC 8291 Web Push with VAPID and reject
  private destinations at connection time. Device delivery is not inferred
  from provider acceptance.
- Commit Demo call notifications with their Communication and enforce an
  atomic recipient-session answer claim; sibling sessions cannot obtain a
  second recipient grant or end the accepted call.

- Index new call Communications by an opaque scoped recipient key and expose
  recipient-bound notification reads independently of the attended card's
  ownership or selection. Revoked/expired Demo generations are excluded.

- Resolve call recipients from explicit card emergency contacts independently
  of controller authority. An empty contact list denies new calls; retained
  call history keeps its original recipient and Encounter context immutable.
- Validate contact projections before directory persistence, preserving the
  existing controller-only compatibility profile for records without contacts.

## 0.2.1 - 2026-11-08

- Allow trusted BFF card registration and generation revocation to join a caller-owned vault transaction,
  so the synthetic directory and existing workspace commit or roll back
  together. Keep standalone registration and collision checks unchanged.
- Three focused cases prove creation/reset rollback, retry without duplication and
  retained standalone collision denial. No RTC browser gate is repeated for this change.
- Validation: 59 SDK tests pass, plus the consuming Personal BFF's six
  phone-only Demo creation/retry/reload browser journeys across its three
  configured presentation flavours and desktop/light plus mobile/dark.

## 0.2.0 - 2026-11-07

- Add a shared BFF Demo exchange over the existing transactional vault, with
  memory/durable adapters injected by the owning application. Synthetic card
  directory and call Communications no longer require a GW or a parallel store.
- Add a bounded, credential-authenticated peer-BFF transport locked to a
  server-configured Demo scope. Reject placeholder credentials, wrong scopes,
  expired/revoked generations and unauthorized participants.
- Enforce call identity, terminal-state and idempotency invariants in the vault
  transaction, including same-clock transitions and cross-subject call-ID
  collisions. Keep GW asynchronous correlation and real authority untouched.
- Return bounded error codes without reflecting malformed request contents or
  provider exception messages in the peer response.

## 0.1.22 - 2026-11-07

- Add an atomic vault capability and a process-owned memory adapter over the
  existing vault implementation. Competing one-time claims serialize and a
  failed multi-record operation rolls back; durable adapters retain native
  database transactions. BFF account security uses the same storage port.
- Add a vault-backed server passkey store. Registration consumes its ceremony
  atomically; authentication updates the verified counter and issues access in
  one transaction. Replayed counters and duplicate access are rejected, and
  competing consumers receive a one-use grant at most once. Logical collection
  names are supplied by the host; the adapter owns deployment namespacing.

## 0.1.21 - 2026-11-07

- Add a product-neutral Node helper that issues short-lived LiveKit grants only
  after the BFF authorizes a canonical portal call Communication. Chat and
  assistant services are not part of this RTC boundary.
- Preserve the employee DID as the RTC participant identity when its BFF has
  revalidated membership in the call's exact professional Group.
- Keep provider API keys in the BFF and bind every grant to the canonical call
  id/room and exact participant. Personal and Professional therefore share one
  authorization-to-RTC transition instead of maintaining separate signaling
  implementations.

## 0.1.20 - 2026-11-04

- Consume the index-service `areaServed` contract from `sos-data-utils-ts@0.6.22`
  and forward optional ISO country filtering through the remote provider catalog
  before applying the same filter locally with `sos-sdk-core-ts@0.5.5`.

## 0.1.19 - 2026-11-04

- Discover existing professional employee DID documents from an exact
  configured provider using country, optional regional jurisdiction,
  organization legal identifier, sector and verified email. Return only roles
  whose authoritative DID document binds the expected employee authorization.

## 0.1.18 - 2026-11-03

- Add a trusted Node client for subject-card provider advertisements and
  federated authorized-subject reads. Provider failures remain visible while
  successful directories continue to return their cards.
- Consume `sos-data-utils-ts@0.6.21` and `sos-sdk-core-ts@0.5.4`, the exact
  published provider-discovery contracts validated by this release.

## 0.1.17 - 2026-10-22

- Consume the shared historical NCBI OBO taxonomy read compatibility used by
  provider-authorized animal-card discovery.

## 0.1.16 - 2026-10-22

- Recover checksum-valid historical animal cards through the provider's exact
  stored alias and explicit taxonomy claim, while returning only the current
  species-bound card identity to portals. New writes still reject the retired
  identifier form.

## 0.1.15 - 2026-10-22

- Add product-neutral verification and resolution for an existing professional
  DID, employee-authorization URN or signed professional SHC. Invitation and
  device registration remain separate host-managed operations.

## 0.1.14 - 2026-10-21

- Add a product-neutral server-profile owner assertion for personal passkey
  registration. It binds the selected profile to the authenticated Firebase
  principal without misinterpreting an individual-member actor DID as a
  professional employee identifier; mandatory passkey enrollment after PIN
  verification remains unchanged.
- Accept the browser WebAuthn secure-context exception for local loopback
  origins while continuing to reject plain HTTP origins on remote hosts.

- Adopt the product-neutral secure organization registration runtime previously
  specialized in the clinical Node SDK: reviewed controller bootstrap-wallet
  reconstruction, encrypted verification/reissuance transport, Offer-to-Order
  confirmation and terminal OperationOutcome rejection. Portal forms, sector
  admission policy, profile persistence and deployment values remain outside
  this package.

## 0.1.13 - 2026-10-21

- Add the trusted-BFF host organization directory client. It submits and polls
  the canonical host `org.schema/Organization/_search` route, reads a
  DIDComm-wrapped paginated Bundle, preserves opaque cursors and surfaces
  Bundle `OperationOutcome` failures without accepting browser-selected host
  authority. The same client performs status, suspend, reactivate and purge
  operations and reads their authoritative Bundle results.

## 0.1.12 - 2026-10-21

- Add the product-neutral server passkey state machine used by SOSChain, UHC
  and Vet BFFs. It requires platform user verification, binds credentials to
  one verified login and profile, and releases a sealed profile-unlock secret
  only through a short-lived, one-time server grant.

## 0.1.11 - 2026-10-20

- Keep valid owned human cards discoverable when the same verified identity
  also has active profile or controller licenses whose authorized subject is
  not a card DID; malformed card-shaped DIDs still fail closed.

## 0.1.10 - 2026-10-20

- Discover canonical animal cards through any governed `animal-*` sector,
  including `animal-research`, instead of treating `animal-care` as the only
  animal subject directory.

- Send authorized-subject directory submit and poll envelopes with the
  canonical `application/didcomm-plain+json` media type so compat-mode SOS
  gateways do not reject card discovery as legacy JSON.
- Add the shared trusted-BFF authorized-subject directory client with canonical
  SOS GW Organization/License routes, real submit/poll HTTP coverage,
  independent `sameAs` alias matching and fail-closed animal-card DID
  validation.
- Document multiple-controller ownership and future explicit principal
  controller promotion without changing the child or animal subject identity.
- Add the 2026 development-owner notice and re-establish the public repository
  from a clean source snapshot while
  retaining this changelog as the package release record.

## 0.1.7 - 2026-10-05

- Add a short-lived HMAC-protected email assertion for exact BFF-to-BFF
  audiences and purposes. It normalizes the authenticated email and fails
  closed for weak secrets, altered payloads, expiry and cross-audience reuse;
  it is not a browser-selected mode or an authorization capability.

## 0.1.6 - 2026-10-04

- Add one atomic accepted-handover persistence boundary for the
  Encounter/EncounterHistory projection, future professional Group audience
  revision and family-safe journey event.

## 0.1.5 - 2026-10-04

- Add the product-neutral confidential channel cache shared by SOSChain,
  VetChain and UHC Next.js BFFs. One profile-and-channel document stores
  materialized FHIR Communication messages behind the unlocked profile's
  confidential-storage adapter, skips already opened source JWEs and keeps
  subject, channel, recipients and payload out of cleartext persistence.

## 0.1.4 - 2026-10-04

- Add the injectable protected Bundle-sync service used by trusted runtimes for
  clinical documents, Consent, emergency contacts and Encounter transfers.
  It persists the exact retryable draft, enforces idempotency and confirms a
  mutation only after authoritative provider readback.
- Pin `sos-sdk-core-ts@0.5.1`, which owns the portable synchronization state
  and response reconciliation contract.

- Link the coordinated clinical accessor adoption boundary and keep optional
  portal/assistant editor work out of the Node adapter until runtime behavior
  is actually required.

## 0.1.3 - 2026-09-27

- Serialize Node test files so package and publication gates cannot exhaust a
  shared developer workstation with parallel workers.
- Require one version change only after grouped changes are merged and tested,
  and preserve every exact published version on an immutable stable branch.

- Add the product-neutral immutable prompt-audio Node runtime with stable
  SHA-256 object keys, durable filesystem storage, concurrent-miss coalescing,
  sequential prewarming and an ElevenLabs multilingual-v2 adapter.
- Correct the package boundary: SOSChain, Vet and UHC may reuse this Node
  runtime while keeping their sector policy in their own SDKs.
- Add a product-neutral, create-only GCS prompt store so identical reviewed
  assets can be reused across Vet, UHC and Connect ICA without sharing live
  OTPs, personalized speech or clinical data.

## 0.1.2

- Add the Node CSPRNG adapter and factory for the shared multi-recipient ML-KEM
  secure-message core used by written and binary-audio payloads.
- Keep Node limited to validated `node:crypto.randomBytes` output; ML-KEM, KDF,
  CEK wrapping and AES content protection remain in runtime-neutral core.

## 0.1.1

- Apply the blocking main-before-publish release contract to the SOSChain Node SDK documentation and repository skills.

## 0.1.0

- Initialize the SOSChain-specific Node SDK above `sos-sdk-core-ts@0.2.0`.
- Add fail-closed authenticated emergency dispatch with HTTPS enforcement,
  idempotency and acknowledgement validation.
