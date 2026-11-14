# Organization registration response authentication

`SecureOrganizationRegistrationRuntime` requires the host to supply
`resolveGatewaySigningJwk(gatewayDid)` in addition to its encryption-key resolver.
The signing resolver is called with the configured `hostContext.hostDid`; a
response header or returned organization claim never selects the trusted signer.

The runtime decrypts the response, verifies its inner compact JWS with that
configured public key, and consumes the verified payload only. It then requires
its issuer to equal the configured host DID, its audience to equal the original
controller DID, and its thread to equal the request thread. This applies to
verification, credential reissuance and Offer-to-Order confirmation.

An authenticated receipt may carry the organization identifier used by the host
for subsequent tenant routing. These checks establish response authenticity and
request binding; they do not replace Gateway admission, controller consent,
licence, commercial Order or device-enrollment policy.

The lower-level `OrganizationRegistrationClient` remains an injected transport
boundary. Callers of that lower-level API own their adapter's authentication;
the high-level runtime always supplies the verified adapter and strict response
binding. The Individual registration adapter reuses the same owned verification
implementation and retains its existing public API and error identifiers.
