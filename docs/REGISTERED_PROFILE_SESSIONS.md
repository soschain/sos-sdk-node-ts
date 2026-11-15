# Registered profile custody sessions

`sos-sdk-node-ts/registered-profile-sessions` exposes
`RegisteredProfileSessions` and `RegisteredProfileSessionsOptions`. Persisted
record and account-binding types belong to
`sos-data-utils-ts/registered-profile-contract`.

The trusted host supplies its transactional vault, distinct profile/session
collections, `ServerProfileSealer`, and authenticated account/profile/provider
route binding. Collections select the deployment namespace. The runtime checks
the binding against the stored profile before opening custody. It accepts only
the stored registered public material through the existing six-purpose custody
helper. Missing historical document-key metadata produces an explicit migration
error; this API does not invent replacement keys or enrollment.

`unlock` opens the original PIN-plus-host envelope and creates a short host-sealed
session. `resolve` checks account, route, expiry and credential revision again,
reopens the same registered key purposes, and returns host-only custody.
`lock` removes the exact owned session. These returned records and managed
custody capabilities stay in the server process; a browser receives only the
host's public projection and opaque session reference.

Authenticated PIN rejection commits a failure counter and bounded lockout.
Operational KMS/host failures retain their original error and do not count as
wrong PINs. The defaults are five failures, a 300-second lock, and a 300-second
session lifetime. The host can supply bounded explicit policy values.

After independently authorizing recovery or passkey custody, the host may call
`replacePin` with the authorized original seed and any separately protected VP.
The runtime verifies the existing public key material, rewraps the original
seed using the original profile AAD, and atomically replaces the protected
record and deletes its owned sessions. Cryptography runs outside the storage
transaction; a snapshot comparison inside it rejects a concurrent reassignment
or rewrap. An optional credential revision invalidates stale sessions while
historical records without a revision retain revision-zero interpretation.

This API covers persisted custody and session lifetime. Gateway enrollment,
controller/employee admission, recipient acceptance, subject-directory selection,
SMART tokens, device replacement and clinical permissions remain separate
authoritative operations. It does not implement the complete legacy profile
facade or treat local custody as a role or access grant.

The existing persisted shape was inspected as read-only evidence at
[the original profile runtime source](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/server-profile-session.ts).
The implementation uses SOS-owned codecs, custody and transactional storage;
it imports no legacy runtime.
