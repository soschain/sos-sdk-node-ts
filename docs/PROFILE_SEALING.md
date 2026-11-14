# Profile sealing adapters

Import `createAesGcmProfileSealer` or `createGoogleKmsProfileSealer` from
`sos-sdk-node-ts/profile-sealer`. Both implement the existing Core
`ServerProfileSealer` capability. The trusted host chooses custody and supplies
the key configuration; these adapters do not inspect environment variables,
select Demo or Network behavior, create wallet seeds or rotate stored keys.

The AES adapter snapshots the supplied 32-byte key and preserves the existing
`local-test-v1.` base64url envelope: twelve IV bytes, sixteen authentication-tag
bytes and ciphertext. Cleartext and additional authenticated data use UTF-8.
Unsealing requires the same key and exact AAD; malformed or modified envelopes
fail. This adapter does not establish that a caller has passed PIN or profile
ownership checks.

The Google KMS adapter keeps ciphertext in the original raw Cloud KMS format.
It sends UTF-8 plaintext and AAD as base64 through the official symmetric
[encrypt](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt)
and [decrypt](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt)
operations. The host supplies a configured key resource and may inject an
access-token provider and HTTP transport. Otherwise a token is requested lazily
from the fixed [workload metadata endpoint](https://docs.cloud.google.com/compute/docs/access/authenticate-workloads).
Requests are bounded and do not follow redirects. IAM, runtime service identity
and authorization to use the configured key remain deployment responsibilities.
KMS or metadata failures do not fall back to a different key or local encryption.

Existing owners must preserve their key configuration and exact AAD when moving
to these factories. Their ciphertext can then be read without re-encrypting or
changing a profile seed. Native AES compatibility tests and an injected KMS HTTP
contract verify the adapter boundaries; they do not prove live Google IAM/KMS
access or replace the real profile-unlock journey.
