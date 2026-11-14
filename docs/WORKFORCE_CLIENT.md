# Staff provisioning and recipient installation

`sos-sdk-node-ts/workforce-client` exports `WorkforceClient`,
`WorkforceSubmitError` and `WorkforceSeatOfferRequiredError`.

The trusted BFF constructs the client from a previously opened profile and its
registered communication wallet. Use the existing verified encrypted-response
adapter with keys resolved from the configured gateway. The adapter's signing
identity and the response envelope issuer are separate configuration:

| Operation | Expected envelope issuer |
| --- | --- |
| Employee creation | Configured tenant identifier URN |
| License issue and Token exchange | Configured provider DID |
| Device DCR | Explicit configured `dcrResponseIssuer` host DID |

Every encrypted result must also address the original caller and retain the
request thread. No returned field selects the signing key or expected issuer.
Individual registration uses the same internal transport while retaining its
existing narrower issuer policy.

`provisionEmployee` accepts an explicit operation UUID, one Antifraud
`ActorContactInput` and one canonical occupation/role. It creates or resolves the
Employee first, checks the returned contact, role, UUID and actor alias, then
requests a seat for that exact returned Employee. A returned seat must repeat
the contact, role and Employee binding. An actual no-seat Offer throws
`WorkforceSeatOfferRequiredError` with the Offer ID and receipt: commercial
payment and Order confirmation remain an explicit controller workflow.
The current role validator is the SOS healthcare/emergency catalog. The host
keeps the sector-specific role filter and GW policy; this client does not
establish a general Antifraud workforce catalog for education or other sectors.

The client's explicit `transportProfile` is `registered-didcomm-encrypted` for
controller staff administration and `pre-dcr-didcomm-encrypted` for recipient
installation. The latter cannot provision staff, even if an untrusted caller
supplies a controller client ID. There is no automatic JSON fallback.
Only registered administration requires the authoritative `tenantIssuer`;
recipient installation obtains its provider/route from the persisted grant
and does not supply or invent a tenant issuer URN.

For the new installation, import the existing
`sos-sdk-node-ts/organization-registration-wallet` and explicitly use
`packBootstrapForRecipientWithContext`. It signs and encrypts using that
installation's provisioned pair and embeds only its actual public signing JWK.
Registered packing remains unchanged and omits the embedded JWK. The gateway
uses the bootstrap key as possession proof only; verified bearer and activation
credential remain separate requirements.

`enrollEmployeeDevice` accepts the persisted SOS activation routing grant, the
BFF-selected verified contact, activation credential and installation's public
keys. It checks contact, route, provider, actor/role and grant expiry before
Token exchange, then sends Device DCR with the returned initial-access token.
Recipient enrollment never calls Employee mutation and never uses the creating
controller's registered client ID. The gateway validates the actual activation
credential, employee assignment, licensed role and bounded device allowance.
The BFF owns profile persistence, PIN protection and one-use installation
redemption. No local grant or successful HTTP orchestration establishes those
postconditions by itself. Existing registered wallet keys are never rotated.
The public key set retains the communication signing/KEM pair and can include
one distinct existing actor-signing ES384/P-384 public key used by current
professional enrollment. Duplicate key IDs, private/symmetric material and
unknown extra keys are rejected. The document-at-rest key stays local. Storing
the actor public key does not prove an evidence signature or authorize evidence
attestation; those remain separately verified operations.
Redirect URIs require HTTPS by default. A trusted host can explicitly set
`allowLoopbackRedirectUris: true` for its local portal callbacks. This permits
HTTP only on `localhost`, `127.0.0.1` and `[::1]`, retaining the configured ports
and paths. Credentials, fragments and remote HTTP remain rejected. The SDK
does not infer this opt-in from environment variables or an execution mode.

The focused loopback tests prove request/receipt orchestration and rejection
propagation. Retained cryptographic tests exercise actual signed/encrypted
response verification. A connected portal-to-GW journey, durable profile
readback and ledger acceptance are additional integration gates.
