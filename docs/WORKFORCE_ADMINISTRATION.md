# Registered workforce administration

The existing `WorkforceClient` requires registered encrypted controller transport
for administration. The BFF separately verifies the current owner, controller
profile, wallet session, configured tenant issuer and each selected target. The
GW remains authoritative for controller, licence, role and lifecycle admission.
Pre-DCR key possession enables none of these operations.

`submitWorkflowAccess({resourceType, entries, operationId})` accepts only the
existing Data-owned `OrganizationWorkflowFlatEntry` shape for Group or Consent.
It submits fixed tenant FHIR routes and POST/PATCH relative resource selectors;
it cannot address arbitrary managers or providers. The host still resolves the
controller, employee Occupation and governed capabilities before building a plan,
and saves local authorization only after terminal signed acknowledgements.

Actual Group and Consent replies use the tenant provider issuer and original
caller/thread. The organization route returns versioned `Group-v5.0.0` and
`Consent-v5.0.0` entries with the requested resource type, ID and normalized
claims. The client rejects the unrelated generic Consent acknowledgement and
substituted requested claims. Group accepts POST/PATCH; the routed Consent
owner preserves POST and stored-original inactive PATCH, with full-resource
inactive PUT for explicit original-resource submissions. The gateway retains
current controller, membership and capability admission; Group membership alone
does not confer Consent authority.

`getAdministration` submits fixed Employee and Licence searches, then validates
the response claims into the Data-owned contact union and seven numeric licence
totals. Phone rows contain `telephone`, without an invented email. Both existing
occupation claim keys are recognized deliberately; conflicting roles, foreign
seat/contact links and ambiguous contained Occupations fail closed. The optional
`occupationResourceId` is the actual correlated document ID, not an inferred
FHIR PractitionerRole. Both primary rows and the existing nested search envelope
are supported. The returned evidence remains server-side protocol evidence.

`changeEmployee` preserves current DELETE/POST batch and explicit purge paths.
`revokeDevice` targets one exact licence and client. Neither expands a wildcard
or silently releases another seat. Terminal acknowledgements must identify the
requested employee or revoked device.

`requestEmployeeLicenseOffer` requests a priced, quantity-bound quotation. It
never confirms payment. `confirmLicenseOrder` is a separate host-registry call
with an exact accepted Offer and caller-supplied verified payment evidence. It
does not invent a zero price, bypass paid-provider proof or invoke `_add`.

Host registry routing is explicit constructor configuration:
`hostRegistry: {hostDid, jurisdiction, hostNetwork, responseIssuer,
secureTransportAdapter}`. Its independently configured gateway keys and response
issuer stay separate from the durable tenant provider. A tenant-routed Offer is
host-issued; Employee replies use the tenant issuer, Licence replies the tenant
provider, and host Order/lifecycle replies the configured host issuer.

`organizationLifecycle` returns authoritative status snapshots after status,
disable or enable. Successful purge instead returns a validated purge receipt;
it neither queries a deleted registry nor fabricates zero descendant counters.
Operation references identify acknowledgements and are not blockchain proof.

Read-only historical wire references:

- [resource operations](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/resource-operations.ts)
- [route construction](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/runtime-client-paths.ts)
- [explicit licence Order](https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/organization-license-order.ts)

No production import or dependency on those sources is introduced. Synthetic
real-crypto peer tests establish protocol binding, not deployed GW authorization,
cloud persistence, Fabric acceptance or a completed portal journey.
