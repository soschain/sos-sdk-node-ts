# Registered gateway communication keys

`resolveRegisteredDidWebKeys` from `sos-sdk-node-ts/registered-did-keys` fetches
the configured gateway DID document and returns its ML-DSA authentication key,
ML-KEM agreement key and their separate verification-method identifiers. It is
a resolver for this operational communication profile, not proof of employee,
tenant or subject authority.

The default URL preserves the DID's path case and uses its canonical `did.json`
location; an authority-only DID uses `/.well-known/did.json`. A configured host
document URL may override that authority-only location on the same origin.
Plain HTTP requires explicit loopback opt-in. Requests use a deadline, reject
redirects and cap the actual streamed document at one MiB, including responses
without a declared length.

The document must identify the exact requested DID. Communication signing keys
come from `authentication`, and encryption keys come from `keyAgreement`.
These are distinct [DID verification relationships](https://www.w3.org/TR/did-core/#verification-relationships);
an assertion-only key is not selected as the gateway communication signer.
References must resolve inside the same document, with exact method/controller
binding. Duplicate identifiers, conflicting embedded methods, private key
material and ambiguous applicable keys fail. Key references never select a
different network fetch target.

The host supplies the resulting signing key to
`createIndividualRegistrationSecureAdapter` for actual response-signature
verification and the agreement key to its opened wallet for encryption. The
resolver preserves published key identifiers and method identifiers separately.
It does not infer authority from a key identifier or a proposed controller contact.
