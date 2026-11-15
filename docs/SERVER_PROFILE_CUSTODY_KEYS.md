# Purpose-separated profile custody

`sos-sdk-node-ts/server-profile-custody-keys` exports
`openServerProfileCustodyKeys` and the public `ServerProfileKeyDescriptor` type.
The host supplies the existing unlocked 32-byte seed and the exact stored
`walletKeyDerivationId`. An explicit enrollment binding prepares public keys;
a registered binding requires every existing DCR and document public key to
match. Neither mode creates an actor or proves account, employee, role, licence
or controller authority.

The helper preserves these existing derivation namespaces and algorithms:

| Scope | Purpose | Algorithm | DCR |
| --- | --- | --- | --- |
| Profile | actor-signing | ES384 | Yes |
| Profile | document-at-rest | ML-KEM-768 | No |
| Runtime | openid-id-token-signing | ES384 | Yes |
| Runtime | vp-token-signing | ES384 | Yes |
| Runtime | comm-signing | ML-DSA-44 | Yes |
| Runtime | comm-encryption | ML-KEM-768 | Yes |

The profile namespace is `profile:<walletKeyDerivationId>:default`; runtime is
`runtime:<walletKeyDerivationId>:server-runtime:default`. Public descriptors
retain each purpose, scope, algorithm and key identifier. `publicJwks` contains
the five DCR keys, while `storagePublicJwk` remains separate. Descriptor labels
are selection metadata and never confer authorization.

`signActorJws` and `signVpJws` use distinct existing ES384 keys and fixed owned
algorithm/key headers. Both require the actual returned client identifier to
match `payload.client_id`. The VP closure embeds its public JWK. The caller
still builds the correct canonical payload and checks the selected profile,
subject and role; no credential authority is inferred or granted by signing.

`signActorDetachedJws` signs the caller's exact credential string or byte payload
with the actor key and the existing detached `application/vc+ld+json` profile:
`b64:false` and `crit:['b64']`. `signIdentityPresentationJws` signs the caller's
unchanged identity-presentation claims with the separate VP key and fixed
`application/vp+jwt` type, without inserting `client_id` or an embedded key.
These operations do not weaken the two client-bound methods above. The host
still owns holder, audience, nonce, credential and responsibility checks.

Private material is never returned. This helper does not replace the existing
communication wallet, perform DCR, encrypt documents or establish evidence
readiness. Its document public key is a compatibility descriptor, not proof
that document storage or synchronization has run.
