# Publish a tenant catalogue from a registered controller

Run this code in the portal backend after the organization controller approves
a batch of products or services. The controller must already have a registered
profile on the destination gateway. Select that profile from the authenticated
backend session and retain the same listing IDs and operation ID on retries.

## Open the existing profile and publish

```ts
import { readPublicOfferingDraftDocument } from 'antifraud-data-utils-ts/public-offering-catalog'
import { openRegisteredWorkforceController } from 'sos-sdk-node-ts/workforce-client'

type ControllerOptions = Parameters<typeof openRegisteredWorkforceController>[0]
type ControllerSession = Parameters<typeof openRegisteredWorkforceController>[1]

export async function publishTenantOfferings(input: {
  gatewayBaseUrl: string
  readUnlockedProfile: ControllerOptions['readUnlockedProfile']
  controllerSession: ControllerSession
  reviewedEntries: unknown
  operationId: string
}) {
  const document = readPublicOfferingDraftDocument({ data: input.reviewedEntries })
  const client = await openRegisteredWorkforceController({
    gatewayBaseUrl: input.gatewayBaseUrl,
    readUnlockedProfile: input.readUnlockedProfile,
  }, input.controllerSession)

  const receipt = await client.publishOfferingBatch({
    document,
    operationId: input.operationId,
  })
  const publishedOfferings = await client.getPublishedOfferings()
  const expected = new Set(document.data.map(entry => JSON.stringify([entry.type, entry.id])))
  const confirmed = publishedOfferings.filter(item => expected.has(JSON.stringify([item.type, item.id])))
  if (confirmed.length !== expected.size) {
    throw new Error('The tenant public catalogue does not include the complete batch.')
  }
  return { receipt, publishedOfferings: confirmed }
}
```

- `gatewayBaseUrl` is the server-configured gateway origin for the selected tenant.
- `controllerSession.ownerId` and `bearerToken` come from the authenticated account
  and its fresh signed ID token. `verifiedContact` is the email or telephone verified
  by the backend. `profileId` selects that account's registered controller profile.
- `readUnlockedProfile` opens the portal's protected profile store for the supplied
  account and profile IDs. It returns the enrolled `profile` and its
  `unlockedWalletSeed` under the backend's existing unlock policy. Store the
  encrypted seed and its original derivation context together. Keep the seed in
  the backend and use it only to reconstruct the registered keys.
- `reviewedEntries` is the approved list of JSON:API resources with stable IDs
  and public Schema.org attributes. Submit one type per batch. `operationId`
  is the backend's persisted identifier for the approved change.
- Compare the changed public fields in `publishedOfferings` with the submitted
  values before reporting the update complete. The public tenant DCAT links the
  offering feed at `/dsp/catalog/offerings.json` under the tenant base URL.

The Node SDK binds the profile to the gateway and tenant, restores and checks
the registered keys, then builds and sends the signed, encrypted DIDComm
message. SOS SDK Core owns the publication plan and receipt validation.

## Prepare an external dataset from Ocean metadata

Install `antifraud-data-utils-ts@0.4.5` in the portal backend for this example.
Use a trusted and resolved DDO with its public landing page if available.

```ts
import {
  buildCataloguePrimaryDocument,
  projectOceanDatasetEntries,
} from 'antifraud-data-utils-ts/ocean-catalogue'

export function prepareExternalDataset(ddo: unknown, landingPage?: string) {
  return buildCataloguePrimaryDocument(projectOceanDatasetEntries({ ddo, landingPage }))
}
```

The result contains `Dataset` and linked `DataService` resources with the
external asset DID. Sending it to a tenant requires a dataset receiver. The
commercial method above accepts `Product` or `Service`.

For a HealthDCAT research dataset, use `client.publishResearchStudyDataset(...)`
with the authorized study, dataset, distribution, access service and
Provenance. The SDK validates the complete graph before sending its ordered
writes and publishes the CatalogRecord last. Verify the dataset in the tenant
DCAT and use `client.archiveResearchStudyDataset(...)` to retire the record.
