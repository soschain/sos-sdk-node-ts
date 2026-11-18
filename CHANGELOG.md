# Changelog

## 0.6.0

- Preserve access for existing individual-member profiles carrying their own
  protected presentation. Reopen and forward that exact presentation for
  gateway verification, retaining member scope and current consent checks;
  do not issue a credential, register another device or infer controller rights.

- Correlate SMART issuance through the signed response's request identifier
  and thread while validating the JWT's independent token identifier. Preserve
  pinned keys, signatures, issuer, audience, actor, time and scope checks.

- Add optional encrypted-host checkpoint persistence to device enrollment.
  Save the exact operation and custody binding before submission; recover an
  uncertain acknowledgement by polling that operation, preserving both device
  keys and the existing installation. Consumed or unavailable results require
  explicit recovery instead of another registration.

- Accept governed research and emergency ISCO-08 occupations in workforce
  provisioning and recipient enrollment, using the shared classification
  catalogue. Preserve current contact, role, device and licence bindings;
  unknown codes and unrelated namespaces remain invalid.

- Include the owned public KEM reply key in the protected transport header and
  bind its existing thumbprint in the inner signed header. Preserve key
  derivation and custody while allowing the gateway to validate the intended
  encrypted response recipient before device registration.

- Classify malformed clinical inputs and missing current custody/Consent evidence
  as owned admission denials while preserving operational key/storage failures.
  Keep registered profile/session return declarations portable across coherent
  Antifraud dependency versions without changing their emitted JavaScript.

- Bind the operational Encounter Consent group independently of the
  department triage queue. Require its explicit trusted-host reference;
  neither group may substitute for the other during admission or Task updates.

- Add a purpose-fixed registered employee Task triage client. Reopen current
  PIN/DCR-bound custody, require independent active Encounter Consent, and
  bind clinical creator, group and both Encounter capabilities. Keep Task
  search and conditional updates claims-first; verify signed/encrypted GW
  issuer, audience and thread, and reject asynchronous revocation or version
  conflicts. GW remains authoritative for clinical permissions and licences;
  this client does not expose a general transport or migrate other care flows.

### Planned 0.5.5 cohort (unpublished)

- Validate the accumulated runtime contracts with the private Antifraud Data
  0.3.4, SOS Data 0.8.3, SOS Core 0.7.2 and FHIR Data 0.7.2 cohort: compile,
  all 408 native tests and typed controls pass. Keep the owner manifest and
  lockfile on the matching public cohort until upstream publication permits
  normal release alignment. The private 0.5.5 archive is not a registry release.

- Add the shared Madrid public dental-registry reader and authenticated read-only
  HTTP composition for all portal modes. Bound downloads, coalesce daily source
  reads, reject conflicting registrations and keep NIF indexes server-side.
  Unlabelled source X/Y values are not treated as GPS; radius searches require
  explicit reviewed WGS84 enrichment. On 2026-11-17, the complete Node 26.13.0
  SDK build and all 387 tests passed with immutable local Antifraud/SOS Data
  packages. A compatible exact public-registry release cohort is still pending.

- Resolve the public requester of a draft permission proposal from current
  PIN-sealed custody and the exact completed employee-enrollment record.
  Bind verified phone/email, role, provider, route and installation; retain
  completed enrollment evidence after invitation expiry and reject stale
  sessions or changes during key opening. Bind organizations to the configured
  enrollment host without requiring a subject-directory catalog entry.
  Require a nonempty persisted tenant issuer on both completed-enrollment
  records before comparing their exact values.

- Sign one admitted stored-profile payload through fixed individual VP or
  organization detached ES384 profiles. Preserve existing seed derivation,
  session AAD, public keys and revision-zero rows; recheck current profile and
  session state after unsealing before returning a public-only signature result.
  Reject selected-session rows with missing or unknown relationship modes.

## 0.5.4

- Accept an optional trusted `plannedEncounter` in
  `PortalEmergencyRequestInput`. Commit it with ServiceRequest, triage Task,
  optional Communication, notice and operation receipt in one read-before-write
  vault transaction. Return only that operation's stored graph. Same-intent
  server-clock retries preserve the first stored timestamps; caller Encounter
  periods, coding, message, service and actor remain bound. Existing planned
  Encounter validation, resource authorization and ordinary Encounter lifecycle
  behavior remain in force.

- Add `PortalCareVaultProvider.requestEmergency`, a purpose-fixed emergency
  request vault transaction using the shared Core
  ServiceRequest/triage plan and optional literal patient Communication. Keep
  actor-bound retry receipts, subject equivalence, access callbacks and atomic
  rollback; preserve existing Encounter transactions and authorized links.
- Apply the Core triage lifecycle through `transitionEmergencyTriage`, an
  atomic transition operation.
  Retain ServiceRequest focus, deny generic-save/profile-downgrade bypasses,
  and update a real linked Encounter and its history in the same transaction.
- Name selected SMART-session return fields through public owned contracts so
  mixed compatible FHIR versions produce portable declarations. Preserve exact
  registered-access runtime bytes and authority checks.
- Pin verified public FHIR 0.7.1 and SOS Core 0.7.1. Preserve all other direct
  versions and lock entries apart from the required nested historical FHIR
  0.7.0 copies. Fresh registry installation, strict compilation and all 352
  native cases pass with one worker and zero skips. The cumulative planned
  Encounter correction passes all 358 cases, including public typed consumers.

## 0.5.3

- Pin verified Antifraud 0.3.3 and SOS Data 0.8.2 registry contracts while
  preserving every other dependency, public export and compiled output.
  Fresh registry installation, strict compilation and all 342 native cases
  pass with one memory-bounded worker and zero skips. All 32 public loaders,
  exact upstream package bytes and the production dependency closure pass.

- Preserve the existing trial offer as a once-only vault allocation, keeping
  Demo self-invitation and activation independent of manual capacity additions.
  Persist an explicit installation limit and browser registration atomically
  with one-use activation when the host selects that policy. Exact registration
  revocation and role suspension invalidate current installation checks.
  Reactivation requires a fresh PIN-opened session generation and does not
  restore an explicitly revoked browser.

- Persist organization workforce capacity and operation-bound allocation retries.
  Read actual inventory, reserve seats atomically, and let hosts require managed
  capacity before invitations while retaining existing provider behavior.

- Clarify jurisdiction-scoped integration acceptance: unrelated Demo and
  general technology-sector lifecycles remain independent, and affected
  regressions remain mandatory without converting failures to skips or green.

- Accept UN M49 host coverage, including World (`001`), when submitting
  organization verification, credential reissuance and Order requests. Preserve
  ISO-style host routes, tenant jurisdiction, encryption and response binding.
  Two genuine failures now pass with malformed-route and retained auth controls;
  16 focused transport/authentication cases, all 329 native cases and strict
  compilation pass, with zero skips or retries.

## 0.5.2

- Support an explicit host-only notification policy for workforce invitations:
  seal pending activation codes for authorized controller retrieval while
  preserving failed delivery, single-use activation and required-delivery defaults.
  Legacy hash-only invitations require an explicit reissue.

## 0.5.1

- Pin the verified Antifraud 0.3.2 and SOS Data 0.8.1 registry contracts while
  retaining Core 0.7.0 and all other direct runtime dependency versions.

- Read the current signed authorized-subject directory without mutating profile
  metadata or a selected SMART context; recheck the exact current actor session
  before transport and before returning accepted subjects.

- Add sealed controller-owned pending evidence with current transactional
  custody resolution, independent document slots, opaque protected downloads,
  immutable retries and exact-card reset/expiry cleanup. Reuse the same vault
  usecase across host-selected Demo and Network adapters.

- Submit purpose-fixed workflow Group/Consent entries through the existing
  registered workforce transport. Preserve provider/caller/thread binding and
  actual acknowledgements without exposing a generic gateway batch method.

- Allow initial recovery-code redelivery only for the same generation-one
  identity and seed after host current-profile PIN/revision checks; preserve
  the original code without another write or rotation.

- Coordinate controller recovery through owned share/ciphertext and atomic
  generation ports. Preserve historical email record/AAD/code bytes, bind
  phones separately, and return recovery codes without returning wallet seeds.
  Reuse managed PIN preparation so a host can atomically join recovery/outbox
  writes to exact-profile revocation in both configured session families.
  Share configured Google KMS HTTP custody with a binary 32-byte recovery port
  while retaining the existing UTF-8 profile-sealer behavior.

- Add registered workforce inventory and lifecycle transport with validated
  phone/email DTOs, exact seat/device selectors, explicit Offer/Order evidence,
  and separately configured host-registry status/purge readback.

- Support client-bound controller presentations with the existing profile actor
  key and embedded own public JWK, preserving the distinct runtime VP purpose.

- Share explicit encrypted pre-DCR Token/Device transport below domain admission
  for controller and employee enrollment. Preserve employee grant checks, exact
  key purposes, optional registration token and trusted reply bindings; snapshot
  configured identity and request material for stable-installation retries.

## 0.5.0 - 2026-11-15

- Accept device enrollment responses without an optional registration management
  token, matching the gateway's actual response. Reject malformed tokens when
  present; retain contact, route, public-key and verified-response admission.

- Expose the existing frozen registered-client transport profile through the
  public SDK root, preserving the original form media value and implementation.

- Preserve actual registered SMART r/rs/cruds grants and independently configured
  ES384, explicit ES256 or PQC token verification without weakening outer PQC
  transport. Select token keys from trusted provider authentication methods and
  retain narrower granted actions/sections exactly.

- Compose registered individual-controller custody, encrypted subject discovery
  and verified SMART selection in one host-only access use case. Keep normal
  runtime ES384 client assertions distinct from actor/VP signing, and bind
  sealed clinical grants to the unchanged provider, profile and session.

- Rewrap authorized profile PINs while atomically revoking every host-configured
  owner/profile session family. Validate historical stored key subsets by full
  public material without fabricating keys or granting strict registered custody.

- Add separate fixed-purpose controller governance ML-DSA-65 detached signing
  and runtime ML-DSA-44 access-token signing, retaining derivation/key identities
  and wire profiles without changing normal profile keys or host authority.

- Add registered confidential document custody over the existing compact-JWE
  profile, preserving document-key and effective-owner bindings, historical
  protected headers and outer row metadata without returning private keys.

- Add purpose-separated registered actor detached credential signing and exact
  identity-presentation VP signing while retaining strict client-bound APIs,
  original public keys and caller-provided claim values.

- Add registered-profile custody sessions over the transactional vault, retaining
  existing protected envelopes, AAD and registered keys. Bind account, profile
  and routed provider context; commit authenticated PIN failures separately
  from host outages and atomically revoke sessions on authorized PIN rewrap.

## 0.4.0 - 2026-11-14

- Pin the published independent Antifraud, FHIR, SOS Data and Core contracts.
  Remove GDC from the resolved registry graph and use only the committed registry
  lockfile in CI, retaining Node.js 26.13.0. All 242 native checks pass, including
  strict source, emitted-module, registry and public-runtime dependency guards.

- Authenticate organization bootstrap receipts with the configured Gateway's
  inner JWS and exact issuer, caller and thread binding before exposing tenant
  authority; retain the Individual client's public verification API.
- Preserve all five existing workforce DCR key purposes through the six-key
  custody projection, keeping document storage material separate and rejecting
  contradictory public-key algorithm/use descriptors.

- Recover the existing six purpose-separated profile/runtime public keys from
  unlocked custody, retain all five DCR keys and keep the document key separate.
  Bind registered material exactly and expose distinct actor and VP ES384
  signing with explicit client binding, without rotating keys or issuing roles.

- Protect and open persisted server-profile secrets through the SOS-owned
  envelope contract, PIN-derived scrypt key and independent host sealer. Retain
  existing ciphertext and purpose-specific AAD without replacing wallet seeds;
  reject malformed parameters and distinguish PIN rejection from host failure.

- Add contact-generic staff provisioning and recipient Token/DCR transport over
  shared registered submit/poll handling. Bind employee and seat receipts to the
  selected contact, role and actual resource UUID; keep commercial seat Orders
  explicit. Keep configured signature trust separate from each manager's
  expected response issuer, and preserve existing individual-registration rules.
  Distinguish registered administration from explicit pre-DCR key-possession
  bootstrap, retain the governed actor-signing public key and permit local HTTP
  callback URIs only through a host-selected loopback option.
- Resolve configured did:web communication keys through their exact local DID
  relationships, with bounded transport and rejection of foreign identities,
  redirects, private material and ambiguous methods.

- Provide host-selected AES-GCM and Google KMS profile sealers over the existing
  Core port. Preserve existing ciphertext envelopes and AAD without choosing a
  runtime mode, replacing a custody key or rotating stored wallet seeds.

- Submit individual registration and recipient Order confirmation through owned
  bootstrap or registered signed/encrypted transport. Bind actual gateway
  identities, Offers, response signatures and separate controller assignments.
- Recover the exact registered communication pair from an unlocked profile,
  rejecting mismatched derivation context or public material without rotating keys.

- Stage actual pending identity-document bytes as immutable scoped vault chunks,
  verify SHA3-384 CIDs by readback and publish metadata only in a small atomic
  finalization. Resume interrupted uploads without rewriting committed chunks;
  reject expired creator admission, corruption and rebound subject references.
- Carry the existing three-file, 10 MiB-per-file policy through a separately
  bounded authenticated evidence envelope while retaining the ordinary 32 KiB
  peer limit. Preserve distinct subject, controller and relationship slots and
  pending-only receipts without issuing a signature or identity verification.

- Read immutable registration creation receipts through the same authenticated
  peer transport, restricted to the admitted creator organization. Later
  controller claim does not invalidate that historical receipt or turn its
  pending-at-creation fields into live ownership status.

- Persist provisional subject registrations and pending responsible-party
  invitations atomically through the existing transactional vault. Retain exact
  request replay after later claim; reject changed requests and other creator
  organizations without registering an owned or discoverable card.
- Extend the authenticated portal peer transport with an injected registration
  provider and preserve its explicit conflict and admission errors.

- Replace direct imports from <https://github.com/Global-DataCare/gdc-common-utils-ts>
  with SOS storage, workforce, Consent and Communication contracts plus FHIR and
  Antifraud utilities.
- Own encrypted organization verification, reissuance and Order submit/poll.
  Reconstruct the exact existing communication keys and key identifiers using
  independent cryptography; reject plaintext terminal responses and rejected
  submits without polling. Real loopback HTTP and cryptography checks pass.
- Implement the process-owned transactional memory adapter without a legacy
  delegate, preserving atomic commit/rollback and isolated record custody.


## 0.3.1 - 2026-11-13

- Pin Common Utilities 2.9.31 and SOS Data 0.6.35, retaining the runtime and declaration bytes from the cumulative local proof.

- Propagate trusted resource-instance context through Consent evaluation so coded emergency-only grants cannot authorize unclassified or unrelated encounter history.

- Add injected-vault workforce and organization-catalog providers: one-use invitation activation, delivery status, licence lifecycle, group memberships and revision-checked publication. Add the authorized peer catalog port and host-validated permission audit labels for private organization identities; keep authentication and sector policy in the host.

- Add recipient care-inbox subject discovery to the authenticated Demo peer transport through an injected host authorization provider. Expose the canonical care-resource collection name for that scope query without introducing another store or product policy.
- Transport a BFF-verified canonical E164 telephone as `PortalDemoCareParticipant.verifiedPhone`, independently of email. Reject malformed/noncanonical peer assertions before invoking care/Consent factories and bind telephone request targets using canonical `tel:` Consent identifiers. The owning host factory still verifies profile authority and constructs `actor.phone`. Six real peer/vault regressions produced two expected failures before implementation; the cumulative local check passes all 148 tests before release.

## 0.3.0 - 2026-11-13

- Allow an authorized Consent replacement to commit related changes through the same supplied vault transaction. Authorization and revision checks precede the callback; failure rolls back both the Consent and related writes. The callback performs vault operations only, never external delivery.

## 0.2.5 - 2026-11-12

- Evaluate the shared professional treatment/emergency hierarchy in the Consent vault. Persist and expose controller-only requesting-organization audit context separately from the requested audience; draft requests remain non-authorizing and atomic with their Communication.

## 0.2.4 - 2026-11-11

- Persist each professional permission request as one Communication carrying its draft Consent Bundle in the same transaction. Bind retries to the requesting actor, retain one receipt and roll back both records if audit persistence fails.

- Invoke one delivery wake-up for each atomic Task/Encounter operation so Firestore never reads again after the callback starts writing; both resource notices remain persisted.

- Commit linked assistance Tasks with Encounter changes, history, notices and retry receipts in one vault transaction. Preserve rollback and reject collisions or updates against hidden foreign-provider records.

- Add a separate subject/generation-scoped Consent collection on the injected
  transactional vault. Controller edits use optimistic revisions; reads and
  access evaluation consume current rules through the canonical consent engine.

- Persist authorized Encounter transitions, paired service transfers and immutable
  EncounterHistory milestones in one vault transaction with Communication
  notices and a restart-safe retry receipt. Reject stale revisions and changed
  replays; retain provider resource boundaries in reads and writes. The peer
  transport carries the same operation over authenticated BFF HTTP.

## 0.2.3 - 2026-11-10

- Prepare `PortalCareVaultProvider` for scoped Appointment, Encounter and Task
  claims, with atomic Communication notices and the existing Tasks SDK engine.
  Add optional peer care operations, revision checks, read acknowledgement and
  explicit due-job dispatch. The host must supply BFF-validated section access;
  actual CH provider composition, persistent shared UI, closed-browser delivery
  and coordinated registry release remain incomplete. No GW/Chat protocol changes.

- Resolve Demo cards from displayed card numbers (spaces or hyphens) and exact
  registered card DID/subject aliases in the owning BFF's existing directory.
  Retain scope and expiry checks, reject ambiguous aliases and never fetch
  user-supplied URLs. Separate Firebase account stores do not require a second
  Demo card directory. This source fix still requires release and deployment.

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
