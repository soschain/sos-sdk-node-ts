# Public did:web agreement-key resolution

Import `resolveDidWebKeyAgreementJwk` from
`sos-sdk-node-ts/did-web-key-agreement`. It fetches the canonical HTTPS DID
document and returns the first supported public JWK in `keyAgreement` order.
The default `publicationProfile: 'did-web'` uses `/path/did.json` for hosted
DIDs. A trusted caller integrating the existing hosted publication convention
can explicitly select `publicationProfile: 'hosted-well-known'`, which uses
`/path/.well-known/did.json`. Both use `/.well-known/did.json` for a host DID.
These are fixed HTTPS paths on the DID's origin, with no fallback or arbitrary
path override; all identity, relationship and key checks remain mandatory.
Methods declaring a use other than `enc` are skipped. An agreement key does
not require an unrelated authentication or signing key.
Distinct EC and ML-KEM methods can coexist; duplicate or conflicting method
definitions are rejected.

The returned document must identify the requested DID. Each selected method
must be explicitly authorized by `keyAgreement`, have a local method ID and
the exact DID controller, and contain public asymmetric JWK material. Private
or symmetric parameters are rejected. Existing public `kid`, `alg`, `use` and
`key_ops` metadata is preserved; an absent or empty `kid` is inferred from the
selected method's fragment. An opaque existing `kid` need not equal that
fragment: the DID relationship binds the verification method itself.
The existing Antifraud `PublicJwk` contract
supports EC P-256/P-384/secp256k1 and ML-KEM-512/768/1024 here. This leaf does
not support X25519 or RSA. Its EC algorithm labels are those represented by
that public contract: ES256, ES384 and ES256K; an unrepresented label is an
explicit incompatibility rather than a type assertion.

Only the canonical document is fetched. Remote verification-method references
are rejected rather than followed. Requests omit credentials, send an Accept
header, reject redirects and use a bounded timeout and one-MiB response limit.
`requestTimeoutMs` defaults to 15000 and must be between 1 and 120000.

For an isolated local integration test, a trusted host can supply both
`didDocumentUrl` and the literal capability `allowTestLoopbackDocument: true`.
The override must be HTTP(S) on localhost, 127.0.0.1 or IPv6 loopback, without
credentials, query, fragment or traversal. A URL alone cannot enable this
transport. Keep the expected external DID unchanged and set the capability
only under the host's existing all-local test guard. Do not forward either
option from browser input or production configuration.
Canonical production resolution rejects IP-address DIDs. An exact loopback-IP
DID is allowed only with both test options, and its host and declared port
must match the loopback override. Nonloopback IPs remain rejected.

`fetchImpl` is also a privileged host/test dependency. With either injected
transport, matching document and controller strings validate the expected
test fixture; they do not establish public HTTPS domain ownership.

This API is a bounded JSON/JWK resolver, not a JSON-LD processor or a role,
registration, Consent or custody authorization service. The operational
`registered-did-keys` resolver keeps its stricter registered PQC profile.

The resolution and relationship rules follow the
[did:web method specification](https://w3c-ccg.github.io/did-method-web/) and
[DID Core key agreement relationship](https://www.w3.org/TR/did-core/#key-agreement).
The selected EC/ML-KEM algorithms and trusted local-test capability are this
SDK's explicit supported profile.

This is not an unrestricted replacement for a permissive historical resolver.
The historical hosted path requires the explicit fixed publication profile
above. There is no remote URL override or automatic fallback. No caller fixture
establishes that all previous keys exclude X25519/RSA or unrepresented EC
algorithm labels; the supported subset above is a deliberate restriction.
