# sos-sdk-node-ts

Copyright 2026 Connecting Solution & Applications Ltd.
Licensed under the Apache License, Version 2.0; see [`NOTICE`](NOTICE).

## Public source history

The public repository begins from a clean 2026 source snapshot. The retained
[`CHANGELOG.md`](CHANGELOG.md) records package releases without republishing
the former Git push history.

Accepted Encounter handover persistence and future channel-audience
reconciliation are documented in
[`docs/ENCOUNTER_TRANSFER_AUDIENCE_PERSISTENCE.md`](docs/ENCOUNTER_TRANSFER_AUDIENCE_PERSISTENCE.md).
## Blocking local-first SDK release

The canonical contract is [`SDK_LAYERING.md`](https://github.com/soschain/sos-data-utils-ts/blob/main/docs/SDK_LAYERING.md). Its
indivisible order is **local packages -> full local test matrix -> merge every
validated branch to `main` -> publish bottom-up -> install exact registry
versions and commit lockfiles on `main` -> staging**. Never publish to discover
deterministic failures and never commit a local package reference. Staging
begins only after exact registry packages are installed and verified.


Product-neutral Node adapters for trusted SOSCHAIN runtimes.

## BFF-owned synthetic Demo exchange

`PortalDemoExchange` receives the existing transactional Confidential Storage
vault. It stores synthetic card discovery records and call events as
Communications, enforces expiry/generation, participant and state-transition
checks, and never contacts GW, Chat or a media provider. Call IDs are bound
across the selected scope; retries cannot overwrite another subject or replay
a terminal transition.

One owning BFF injects memory locally or its configured durable adapter.
`PortalDemoExchangeClient` lets another trusted BFF use that same state through
`createPortalDemoExchangeHandler`, rather than creating a second process-local
store. The handler requires a private service credential, compares it in
constant time, rejects placeholder credentials, bounds requests to 32 KiB and
locks requests to its configured non-production Demo scope. Credentials never
enter browser props. The caller BFF must first verify the account, PIN profile,
sector/role capability and subject scope; a service credential does not prove
professional authority. Normal Test Network use cases retain their GW path.

LiveKit receives separate short-lived participant grants. RTC credentials,
tokens, signaling and media do not belong in Communication history. Optional
Terminology, media and assistant services remain independent use-case gates.

`secure-organization-registration` owns the trusted Node transport used after
an application has been reviewed: deterministic reconstruction of the exact
controller bootstrap wallet, encrypted organization verification or credential
reissuance, and confirmation of the exact accepted Offer through Order. It
does not own portal forms, admission policy, user authentication, application
storage, payment policy or professional operations.
The capability-by-capability source decision is recorded in
[`docs/ORGANIZATION_REGISTRATION_SOURCE_EVALUATION.md`](docs/ORGANIZATION_REGISTRATION_SOURCE_EVALUATION.md).

```text
gdc-* frozen
    ↓
sos-data-utils-ts
    ↓
sos-sdk-core-ts
    ↓
sos-sdk-node-ts
```

This package owns reusable server-side Node transport, credentials,
persistence, jobs and prompt-audio runtime behavior. It does not own
deterministic data contracts, common authorization or sector policy. Downstream
applications consume it without creating dependencies between one another.

`TransactionalVaultRepository` extends the existing Confidential Storage port
with atomic operations without changing the frozen base interface. All-local
BFFs inject `TransactionalMemoryVaultRepository`; durable composition roots
implement the same capability with their database's native transaction.
Callbacks must use their supplied transaction port and perform reads before
writes. A failed operation commits nothing, and competing claims serialize.
Memory is process-owned, disposable and unsuitable for production persistence.

`createVaultServerPasskeyStore` stores credentials, ceremonies and one-use
access through that port. The host provides logical collection names and the
adapter provides deployment/network/host isolation. No account use case should
select Firestore directly merely because the deployed adapter is Firestore.
WebAuthn verification, ownership checks and secret sealing remain in the
existing server passkey service; this store provides atomic persistence.

`BundleSyncDraftService` is the trusted-runtime adapter for the shared durable
editor outbox. The application injects protected storage, payload protection
and the real provider executor. The service stores no clear clinical Bundle,
reuses the same idempotent draft after transient failures, and does not report
confirmation until the provider write has been followed by authoritative
readback.

It also does not duplicate the typed clinical Bundle editors exposed by the
GDC Node SDK. Add a SOS Node adapter only when a real shared channel workflow
requires runtime behavior, following the
[clinical accessor adoption matrix](https://github.com/soschain/sos-data-utils-ts/blob/main/docs/CLINICAL_TYPED_ACCESSOR_ADOPTION.md).
Portals and assistants without that editor remain on their verified versions.

The first adapter, `SosEmergencyDispatchClient`, sends an already-authorized
emergency request over HTTPS with a stable idempotency key and validates the
provider acknowledgement. The bearer credential remains only in the trusted
Node runtime.

`sos-sdk-node-ts/bff-email-assertion` lets one authenticated BFF present a
normalized email to one exact receiving BFF for a short-lived, named purpose.
The receiving application still authorizes the operation and should reject
replay where it matters. Never expose the shared secret or let a browser set
the trusted issuer, audience, purpose or identity claims.

`sos-sdk-node-ts/subject-card-directory-client` owns the complete asynchronous
SOS GW Organization/License search and polling protocol used by every portal
BFF. It matches exact aliases inside `Organization.sameAs` CSV values and
rejects removed animal-card DID layouts before UI mapping. See
[the authorized subject directory contract](docs/AUTHORIZED_SUBJECT_DIRECTORY.md).

`sos-sdk-node-ts/portable-professional-evidence` lets a trusted BFF discover
existing professional roles from an exact configured provider using country,
optional ISO 3166-2 region, organization legal identifier, sector and one
BFF-verified contact. Supply `verifiedContact: { contactKind: 'phone', contact }`
for a phone, or the corresponding `email` channel. The previous `verifiedEmail`
input remains supported separately; supplying both identities fails. The BFF,
not this data argument, verifies the identity-provider token and contact binding.
The shared Antifraud identity builder preserves the existing actor hash/DID.
It derives candidate employee DIDs only from the governed role catalog
and returns a role only when the authoritative employee DID document binds the
expected authorization URN. These routing inputs and a later browser role
choice grant no authority by themselves.

These identifiers have distinct jobs:

- The stable actor `urn:multibase:...` hashes a normalized contact with SHA3-256.
- The operational employee `did:web:...:employee:...:<role>` uses that contact
  hash and a separate role.
- The host-independent CDS authorization URN's `member` component encodes the
  employee UUID's 16 raw bytes as base58btc. It is **not** the contact hash.

For an existing fetched employee DID, resolution requires the selected contact's
operational DID and the alias's organization, jurisdiction and role to agree.
Direct UUID authorization-URN resolution remains routing before DCR and performs
no employee-DID fetch. It does not verify a signature, licence existence or the
UUID's ownership by the selected contact. The owning profile manager calls
`Token/_exchange`, where GW resolves the issued licence and verifies its contact,
organization, employee UUID and role before consuming activation and issuing a
DCR token. Requiring an employee DID earlier would block legitimate enrollment
before that operational DID is published.
Technical-sector role catalogues remain unchanged in this resolver batch.
Phone routing support does not close the gateway's remaining email-only
portable licence-resolution guard or the portal's email-only enrollment APIs.
Those authority paths require their own implementation and real-boundary proof.

`sos-sdk-node-ts/host-organization-directory-client` is the separate trusted-
BFF client for a host operator's organization directory. It sends the
canonical `org.schema/Organization/_search` request, polls the matching
response route and returns the privacy-minimized, paginated Bundle projection.
The host jurisdiction and network come from trusted server configuration;
they are never browser-selected authority.

## Secure-message CSPRNG adapter

`sos-sdk-node-ts/secure-message-crypto` exports `NodeSecureRandomSource` and
`createNodeSecureMessageCrypto()`. Node supplies only bytes from
`node:crypto.randomBytes`; the runtime-neutral `sos-sdk-core-ts` package owns
ML-KEM, key derivation, recipient CEK wrapping and AES content encryption.

The factory handles UTF-8 text and binary audio through the same byte-oriented
API. Applications select the protected `contentType`, apply their own upload or
audio-duration limits, and authorize every recipient change before calling the
shared core. See [docs/SECURE_MESSAGES.md](docs/SECURE_MESSAGES.md).

## Immutable prompt audio

`sos-sdk-node-ts/prompt-audio-runtime` hashes the canonical descriptor produced
by `sos-data-utils-ts/prompt-audio`, coalesces concurrent misses, persists the
audio and prewarms prompts sequentially. It includes a filesystem adapter for
local execution and an ElevenLabs multilingual-v2 synthesizer. A production
runtime supplies its approved durable-object-store adapter. Complete live OTPs
are never cache entries; ICA composes static prefix and digit assets. See
[docs/PROMPT_AUDIO_RUNTIME.md](docs/PROMPT_AUDIO_RUNTIME.md).

```bash
npm ci
npm run check
```
