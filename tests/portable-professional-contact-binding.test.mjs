// Flow contract: a BFF supplies one verified contact to existing portable resolution APIs; the returned organization, employee DID, authorization URN and role must identify that same contact, while discovery alone never grants a licence, profile or device.
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildStableActorIdentifier, buildPortalActorDidWeb } from 'gdc-common-utils-ts/utils/actor-identifier'
import { HealthcareActorRoles } from 'gdc-common-utils-ts/constants/healthcare'
import { REPOSITORY_SAFE_EXAMPLES } from 'sos-data-utils-ts/repository-privacy'
import { resolvePortableProfessionalEnrollment, resolvePortableProfessionalOrganizationEnrollments } from '../dist/portable-professional-evidence.js'

const fixture = Object.freeze({
  provider: { baseUrl: 'https://gateway.example.invalid', tenantId: 'Example-Phone', jurisdiction: 'CA-BC', sector: 'animal-tech' },
  providerDid: 'did:web:authority.example.invalid:Example-Phone:cds-CA-BC:v1:animal-tech',
  phone: REPOSITORY_SAFE_EXAMPLES.phoneE164,
  email: REPOSITORY_SAFE_EXAMPLES.individualEmail,
  otherEmail: REPOSITORY_SAFE_EXAMPLES.firstContactEmail,
  role: HealthcareActorRoles.Receptionist,
})

function identity(contactKind, contact, role = fixture.role) {
  const actorIdentifier = buildStableActorIdentifier({ contactKind, contact })
  return {
    professionalDid: buildPortalActorDidWeb({ portalDidWeb: fixture.providerDid, actorIdentifier, role }),
    authorizationUrn: `urn:cds-ca-bc:v1:organization:bn:${fixture.provider.tenantId}:member:${actorIdentifier.slice('urn:multibase:'.length)}:${role.split('|')[1]}`,
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

test('resolves a phone-bound authorization URN without an email', async () => {
  const person = identity('phone', fixture.phone)
  const result = await resolvePortableProfessionalEnrollment({ ...directInput(person),
    verifiedContact: { contactKind: 'phone', contact: fixture.phone } })
  assert.equal(result.professionalDid, person.professionalDid)
  assert.equal(result.employeeAuthorizationUrn, person.authorizationUrn)
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

test('rejects an authorization URN for another contact even with the right organization and role', async () => {
  const other = identity('email', fixture.otherEmail)
  await assert.rejects(resolvePortableProfessionalEnrollment({ ...directInput(other), verifiedEmail: fixture.email }), /professional_credential_binding_invalid/)
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

test('rejects organization discovery whose alias names a different contact', async () => {
  const person = identity('email', fixture.email)
  const other = identity('email', fixture.otherEmail)
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
