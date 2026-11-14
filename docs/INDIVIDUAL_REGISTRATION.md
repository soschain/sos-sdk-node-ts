# Individual registration transport

`IndividualRegistrationClient` submits the existing GW individual Organization
transaction and polls its result. It consumes the request-bound receipt from
SOS Data: the stored Organization UUID, canonical subject DID, public card
alias, provider and Offer remain separate values. It does not derive a
controller actor from a proposed contact or grant access to a subject.

The host chooses one explicit transport profile:

- `registered-didcomm-encrypted` signs the opened profile's `client_id` with
  the request and encrypts both submission and polling. A professional creating
  a subject for another controller needs this profile and current GW admission.
- `oidc-bootstrap-json` uses the existing narrow, verified-account bootstrap
  route. It does not confer professional authority over another controller.

For the registered profile, `openRegisteredCommunicationWallet` recovers the
existing communication pair from an approved, server-unlocked profile seed and
its exact stored derivation identity. It compares both key identifiers and all
public key material with the stored registration. A mismatch fails; it never
registers replacement keys or rotates a device. The seed stays in the trusted
host and must not be accepted from a browser registration request.

`createIndividualRegistrationSecureAdapter` receives callbacks for that opened
wallet's packing and decryption. Its own verification resolves a public signing
key for the configured gateway identity, checks the protected algorithm and key
identifier, verifies the signature through Antifraud cryptography and parses the
verified payload. Decoded callback content is not signature evidence. The client
also binds the signed response issuer, audience and thread, and never downgrades
an encrypted terminal response to plaintext. Caller-supplied flags cannot create
GW transport provenance or replace the gateway's DCR, licence and group checks.

Subject demographics and the proposed responsible party remain distinct. The
low-level client preserves the supplied claims and does not insert a self-role
for a child or dependent. Uploading an unsigned photo or PDF as pending evidence
does not make it a signed onboarding document or a verified identity check.

After professional registration, an explicit Personal recipient acceptance is a
separate operation. Only that authenticated recipient's server context confirms
the exact Offer through `confirmIndividualOrganizationOrder`, using the stored,
validated subject identity. The returned activation credential and active
RelatedPerson assignment describe an issued invitation/seat. They do not prove
recipient acceptance, device registration, controller responsibility or Consent
approval. The professional creator must not consume the recipient's activation
credential. Existing Personal activation, DCR and explicit permission approval
remain separate use cases.

These APIs provide transport and registered-key recovery. A real portal host
must still compose its owner/profile/PIN checks, route and application identity,
verified account bearer, configured gateway keys and current authority records.
Transport integration tests do not replace the real portal, GW or ledger journey.
