# Resolve the requester of a draft permission proposal

Call `resolveRegisteredEmployeeDraftRequester` from
`sos-sdk-node-ts/registered-employee-draft-requester` after the host verifies
the Firebase account and its sign-in contact. Supply the account UID, selected
profile ID, existing PIN-session token and that verified contact. A browser's
chosen role, email, provider or route is not an authority input.

The host options contain its transactional vault, profile sealer, three exact
collections, configured provider catalog and expected authority DID. Select
these from server configuration. The operation compares the provider namespace
with an exact authority delimiter and matches the route against that catalog;
it does not reconstruct or claim to validate the full organization-DID profile.

## Completed enrollment and current custody

The employee enrollment use case verifies the returned DCR role and route,
then atomically stores the profile and the grant's existing
`consumedEnrollments` tuple: owner, profile and client installation. The
requester operation requires exactly one matching completed tuple, identical
profile/grant provider, route and issuer, and the canonical employee DID for
the recorded role and verified contact.

Invitation `createdAt` and `expiresAt` retain their original meaning: they
bounded admission to enrollment. Expiring the invitation does not expire an
already completed enrollment. The operation instead checks the current sealed
PIN session, profile revision and lock state. It reconstructs and verifies all
registered purpose keys, including the PQC storage key, under the existing
`confidential-pqc-v1` profile. It retains existing envelope AAD and revision-zero
compatibility and never resets PIN failure counters.

All profile, session and consumed-record reads occur before any writes. This
operation writes nothing. It repeats the reads after host unsealing and full
key verification and rejects a changed or revoked record before returning.
Host key-service or datastore outages remain operational errors rather than
being relabeled as credential failures.

## Use the public result

The result contains the owner/profile binding, actor DID, provider and route,
client and installation IDs, and `recordedRole`. It contains no seed, raw
session token, ciphertext, private key or reusable wallet handle.

The host maps `recordedRole` to its existing proposal policy and validates the
requested target and sections. This is recorded enrollment identity, not proof
of current employment, licence, SMART permission or active Consent. A proposal
remains pending; the receiving gateway and subject controller retain their
existing admission and approval responsibilities.

Keep completed consumption records available while enrolled profiles depend
on them. If evidence is missing, ambiguous or inconsistent, the operation
denies the projection; it does not infer a role from an actor-kind label or
request body or create a replacement enrollment record.
