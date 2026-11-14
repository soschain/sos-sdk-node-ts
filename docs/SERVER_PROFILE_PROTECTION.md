# Server profile secret protection

`sos-sdk-node-ts/server-profile-protection` exports
`protectServerProfileSecret`, `openServerProfileSecret` and
`ProfilePinRejectedError`. Its persisted envelope types are re-exported from
`sos-data-utils-ts/server-profile-secret-contract`; the host sealing capability
is the existing `sos-sdk-core-ts/profile-sealer` port.

The host supplies the existing secret, PIN and purpose-specific AAD. Protection
creates a fresh random data encryption key, wraps it through the host sealer,
and protects the host-wrapped value with a scrypt PIN key. Both ciphertext
layers use AES-256-GCM. Opening authenticates the PIN layer before calling the
host. Host failures remain separate from `ProfilePinRejectedError`.

The persisted `gdc-pin-host-envelope-v1` marker remains unchanged solely for
existing ciphertext compatibility. This implementation has no dependency on
the former runtime. Existing `:wallet-seed`, `:vp-token` and initial-wallet AAD
are caller-owned and must be retained exactly. Internal AAD suffixes are `:dek`,
`:payload` and `:host-wrapped-dek`.

New envelopes default to scrypt cost 16384, block size 8, parallelization 1,
with a random 16-byte salt and 32-byte key. Persisted parameters are validated
before derivation: power-of-two cost 2 through 262144, block size 1 through 32,
parallelization 1 through 16, and their product at most 1048576. The host owns
PIN policy, rate limits, account/profile scope, storage and lockout. This codec
does not create actor identities, derive actor/communication/storage keys,
rotate wallet material, enroll a device or authorize a profile.

Compatibility tests open a synthetic stored envelope from a read-only oracle
and independently decode newly written ciphertext with native cryptographic
primitives. They do not use a legacy SDK at runtime or prove cloud IAM access.
