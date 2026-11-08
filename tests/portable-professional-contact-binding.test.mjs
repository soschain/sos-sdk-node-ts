// Flow contract: a BFF supplies one verified contact; published employee DIDs bind that contact while an employee UUID authorization URN remains pre-DCR routing evidence, never a licence, profile, verified contact binding or device grant.
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildStableActorIdentifier, buildPortalActorDidWeb } from 'gdc-common-utils-ts/utils/actor-identifier'
import { HealthcareActorRoles } from 'gdc-common-utils-ts/constants/healthcare'
import { buildOrganizationAuthorizationUrnCds, buildOrganizationEmployeeAuthorizationUrnCds } from 'gdc-common-utils-ts/utils/organization-authorization-urn'
import { REPOSITORY_SAFE_EXAMPLES } from 'sos-data-utils-ts/repository-privacy'
import { resolvePortableProfessionalEnrollment, resolvePortableProfessionalOrganizationEnrollments } from '../dist/portable-professional-evidence.js'

const fixture = Object.freeze({
  provider: { baseUrl: 'https://gateway.example.invalid', tenantId: 'Example-Phone', jurisdiction: 'CA-BC', sector: 'animal-tech' },
  providerDid: 'did:web:authority.example.invalid:Example-Phone:cds-CA-BC:v1:animal-tech',
  phone: REPOSITORY_SAFE_EXAMPLES.phoneE164,
  email: REPOSITORY_SAFE_EXAMPLES.individualEmail,
  otherEmail: REPOSITORY_SAFE_EXAMPLES.firstContactEmail,
  role: HealthcareActorRoles.Receptionist,
  employeeUuid: REPOSITORY_SAFE_EXAMPLES.resourceUuid,
  otherEmployeeUuid: REPOSITORY_SAFE_EXAMPLES.demoOrganizationUuids.animalTech,
})

function identity(contactKind, contact, role = fixture.role, employeeUuid = fixture.employeeUuid) {
  const actorIdentifier = buildStableActorIdentifier({ contactKind, contact })
  return {
    professionalDid: buildPortalActorDidWeb({ portalDidWeb: fixture.providerDid, actorIdentifier, role }),
    // The authorization member is the 16-byte employee UUID encoded as base58;
    // the operational employee DID uses the separate SHA3-256 contact hash.
    authorizationUrn: buildOrganizationEmployeeAuthorizationUrnCds({
      organizationUrn: buildOrganizationAuthorizationUrnCds({ jurisdiction: fixture.provider.jurisdiction, identifierType: 'bn', identifierValue: fixture.provider.tenantId }),
      employeeUuid,
      roleCode: role.split('|')[1],
    }),
  }
}

function providerFetch(person, aliases = [person.authorizationUrn]) {
  return async url => {
    if (String(url).endsWith('/.well-known/did.json')) return Response.json({
      id: fixture.providerDid,
      service: [{ type: 'JsonWebKeyService2020', serviceEndpoint: 'https://authority.example.invalid/jwks.json' }],
    })
    const role = person.professionalDid.split(':employee:')[1].split(':').slice(1).join(':')
    if (String(url).endsWith(`/${encodeURIComponent(role)}/did.json`)) {
      return Response.json({ id: person.professionalDid, alsoKnownAs: aliases })
    }
    return new Response('', { status: 404 })
  }
}

function directInput(person) {
  return { professionalIdentifier: person.authorizationUrn, sectorHint: fixture.provider.sector,
    providers: [fixture.provider], fetchImpl: providerFetch(person) }
}

test('routes a real UUID authorization URN before DCR without requiring an employee DID or email', async () => {
  const person = identity('phone', fixture.phone)
  const requested = []
  const result = await resolvePortableProfessionalEnrollment({ ...directInput(person),
    verifiedContact: { contactKind: 'phone', contact: fixture.phone }, fetchImpl: async url => {
      requested.push(String(url))
      assert.equal(String(url).includes('/employee/'), false)
      return providerFetch(person)(url)
    } })
  assert.equal(result.professionalDid, person.professionalDid)
  assert.equal(result.employeeAuthorizationUrn, person.authorizationUrn)
  assert.equal(requested.length, 1)
  assert.notEqual(person.authorizationUrn.split(':member:')[1].split(':')[0], buildStableActorIdentifier({ contactKind: 'phone', contact: fixture.phone }).slice('urn:multibase:'.length))
  assert.equal(Object.hasOwn(result, 'licenseId'), false)
  assert.equal(Object.hasOwn(result, 'accessToken'), false)
})

test('resolves an existing phone employee DID without substituting its identity', async () => {
  const person = identity('phone', fixture.phone)
  const result = await resolvePortableProfessionalEnrollment({ ...directInput(person), professionalIdentifier: person.professionalDid,
    verifiedContact: { contactKind: 'phone', contact: fixture.phone } })
  assert.equal(result.professionalDid, person.professionalDid)
})

test('discovers the existing phone role in a technical-sector organization', async () => {
  const person = identity('phone', fixture.phone)
  const results = await resolvePortableProfessionalOrganizationEnrollments({
    country: 'CA', region: fixture.provider.jurisdiction, organizationIdentifier: fixture.provider.tenantId,
    sector: fixture.provider.sector, providers: [fixture.provider], fetchImpl: providerFetch(person),
    verifiedContact: { contactKind: 'phone', contact: fixture.phone },
  })
  assert.equal(results.length, 1)
  assert.equal(results[0].professionalDid, person.professionalDid)
  assert.equal(results[0].employeeAuthorizationUrn, person.authorizationUrn)
})

test('does not interpret an opaque employee UUID as proof of the selected contact', async () => {
  const other = identity('email', fixture.otherEmail, fixture.role, fixture.otherEmployeeUuid)
  const selected = identity('email', fixture.email)
  const result = await resolvePortableProfessionalEnrollment({ ...directInput(other), verifiedEmail: fixture.email })
  assert.equal(result.employeeAuthorizationUrn, other.authorizationUrn)
  assert.equal(result.professionalDid, selected.professionalDid)
  assert.notEqual(result.professionalDid, other.professionalDid)
  // Token/_exchange must still verify the UUID's issued licence against the
  // fresh account contact. Routing metadata is not that authorization result.
  assert.equal(Object.hasOwn(result, 'authorized'), false)
  assert.equal(Object.hasOwn(result, 'profile'), false)
})

test('rejects a fetched employee DID belonging to another verified contact', async () => {
  const other = identity('email', fixture.otherEmail)
  await assert.rejects(resolvePortableProfessionalEnrollment({ ...directInput(other), professionalIdentifier: other.professionalDid,
    verifiedEmail: fixture.email }), /professional_credential_binding_invalid/)
})

test('rejects a role mismatch between the fetched DID and its authorization alias', async () => {
  const person = identity('email', fixture.email)
  const otherRole = identity('email', fixture.email, HealthcareActorRoles.Veterinarian)
  await assert.rejects(resolvePortableProfessionalEnrollment({ ...directInput(person), professionalIdentifier: person.professionalDid,
    verifiedEmail: fixture.email, fetchImpl: providerFetch(person, [otherRole.authorizationUrn]) }), /professional_credential_binding_invalid/)
})

test('rejects organization discovery whose authorization alias has the wrong role', async () => {
  const person = identity('email', fixture.email)
  const other = identity('email', fixture.email, HealthcareActorRoles.Veterinarian)
  await assert.rejects(resolvePortableProfessionalOrganizationEnrollments({
    country: 'CA', region: fixture.provider.jurisdiction, organizationIdentifier: fixture.provider.tenantId,
    sector: fixture.provider.sector, providers: [fixture.provider], fetchImpl: providerFetch(person, [other.authorizationUrn]),
    verifiedEmail: fixture.email,
  }), /professional_credential_binding_invalid/)
})

test('rejects ambiguous verified-contact inputs before querying a provider', async () => {
  const person = identity('email', fixture.email)
  let requested = false
  await assert.rejects(resolvePortableProfessionalEnrollment({ ...directInput(person), verifiedEmail: fixture.email,
    verifiedContact: { contactKind: 'phone', contact: fixture.phone }, fetchImpl: async () => { requested = true; throw new Error('unexpected_fetch') } }), /professional_verified_contact_ambiguous/)
  assert.equal(requested, false)
})
