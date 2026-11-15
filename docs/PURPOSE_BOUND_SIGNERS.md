# Separate governance and runtime signing

`sos-sdk-node-ts/controller-governance-signer` exposes
`openControllerGovernanceSigner({keyDerivationId, unlockedWalletSeed})`.
It derives the existing extra ML-DSA-65 `actor-signing` key under
`profile:<keyDerivationId>:controller-signing-pqc-v1`. Its public key can be
prepared for ICA publication; `signDetachedCredential({payload})` signs exact
string/byte content with `application/vc+ld+json`, `b64:false` and `crit:['b64']`.
The host independently admits the controller, checks publication/authority and
constructs the canonical credential and its proof metadata.

`sos-sdk-node-ts/runtime-access-token-signer` exposes
`openRuntimeAccessTokenSigner({runtimeId, seedMaterial})`.
It retains the runtime-only ML-DSA-44 `openid-id-token-signing` key under
`runtime:<runtimeId>:default`. `signAccessToken({claims})` emits `at+jwt` with
the supplied JSON claims unchanged. Issuer, client, audience, account facts and
time policy remain with the hosting service. Signing is not authentication or
proof that a receiving service trusts that issuer.

Each capability returns its public JWK and a single managed signing operation.
Input identity/seed strings are snapshotted at opening without trimming or
substitution. Claims are snapshotted before asynchronous signing without
executing accessors or coercion. Temporary private byte material is derived
only for each signing operation and wiped afterward; no raw key or seed is
returned. Public key identifiers preserve the existing RFC7638 thumbprint URN.

These are separate from the normal six-key profile factory: its actor/VP and
ID-token ES384 keys and communication ML-DSA-44 key remain unchanged. Neither
capability enrolls a person, manages sessions or substitutes one purpose's key
for another.

The static test baseline is newly generated synthetic output from the verified
historical published runtime, with public key/context vectors and signatures
independently checked through Antifraud cryptography. It is not an old persisted
or production credential. Package tests import only the static bytes and owned
Antifraud/SOS modules. Original read-only sources:

- [Wallet derivation and signing](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/node-managed-wallet.ts).
- [Signing JWK and identifier construction](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/main/src/utils/jwt-signer.ts).
