# Pre-DCR device enrollment

`DeviceEnrollmentClient` submits the existing encrypted Token exchange and Device
registration protocol below domain admission. A host first verifies its actual
Organization receipt/licence or employee grant, the authenticated recipient, and
the exact actor/profile/provider/tenant bindings. The client does not invent an
employee grant for an organization controller, acquire a seat, consume a local
grant, or persist a local profile.

The constructor snapshots trusted `expectedProfile` actor/profile/contact and
route configuration. `enroll` checks the explicitly verified contact and snapshots
the installation, five-purpose public DCR material and redirects before transport.
The distinct sixth document-at-rest public key stays outside DCR. Existing two-
and three-key compatibility is retained; purpose-labelled five-key registration
continues to require its existing custody descriptors.

The host supplies the existing explicit bootstrap packing capability and a
configured-GW verifying adapter. The encrypted outer signature and each operation's
issuer, audience and correlation are independently checked. HTTPS redirects remain
the default; loopback HTTP requires the existing explicit opt-in. A registration
access token is optional because the current GW does not necessarily return one.

`WorkforceClient.enrollEmployeeDevice` retains its contact, role, grant expiry,
provider and route checks before delegating to the same transport. Its existing
error prefixes and submit-error class remain compatible.

For durable enrollment, pass a third argument to `enroll` containing the last
`checkpoint` and an awaited `saveCheckpoint` callback. The host seals the entire
checkpoint in the same owner/profile-bound grant as the original wallet seed,
derivation identifier and `clientInstanceId`. Never expose this state to a
browser or logs: a checkpoint includes the short-lived initial access token and
verified response receipts. Load it only from trusted, integrity-protected
server persistence, not from caller input.

The SDK awaits persistence before each Token or Device submission. A resumed
pending operation polls its original correlation identifier; it never submits a
second registration. Its binding digest rejects a changed actor, provider,
route, activation code, installation, public custody or redirect URI. A completed
checkpoint returns the original enrollment receipt without another mutation.
That receipt records enrollment; current access still requires the normal
session, device and authorization checks.

```ts
import {
  DeviceEnrollmentClient,
  type DeviceEnrollmentInput,
  type DeviceEnrollmentCheckpoint,
} from 'sos-sdk-node-ts/device-enrollment-client'

export function enrollFromStoredGrant(
  client: DeviceEnrollmentClient,
  input: DeviceEnrollmentInput,
  checkpoint: DeviceEnrollmentCheckpoint | undefined,
  saveCheckpoint: (value: DeviceEnrollmentCheckpoint) => Promise<void>,
) {
  return client.enroll(input, undefined, {checkpoint, saveCheckpoint})
}
```

The callback uses the host's existing encrypted, owner/profile-bound
persistence adapter. It must preserve the same seed and installation before the
first network call and compare/update the checkpoint atomically so competing callers cannot start
a second operation. A persistence failure
before submission prevents that network mutation.

A lost submit acknowledgement can be recovered while its original result
remains available. The current GW consumes a completed result when it serves the
poll response. If that response is lost, already consumed, expired or no longer
authorized, resumption fails with `DeviceEnrollmentRecoveryRequiredError`.
The host keeps the sealed grant for explicit recovery rather than repeating DCR,
replacing a device or generating new custody. Two-argument enrollment remains
available for existing callers; it does not provide durable retry protection.
Actual GW manager and authenticated online tests remain separate evidence from
the SDK's encrypted transport-peer tests.
