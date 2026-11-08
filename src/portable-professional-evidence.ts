import { createPublicKey, verify } from 'node:crypto'
import { inflateRawSync } from 'node:zlib'
import { buildOrganizationEmployeeDidWeb, buildStableActorIdentifier, normalizeActorContact, type ActorContactInput } from 'antifraud-data-utils-ts/organization-identity'
import { getHealthcareProfessionalRolesBySector } from 'gdc-common-utils-ts/constants/healthcare'
import type { DataspaceSector } from 'gdc-common-utils-ts/constants/sectors'

export type PortableProfessionalProvider = Readonly<{
  baseUrl: string
  tenantId: string
  jurisdiction: string
  sector: string
}>

export type PortableProfessionalEnrollment = Readonly<{
  sector: string
  employeeAuthorizationUrn: string
  professionalDid: string
  providerDid: string
  gatewayBaseUrl: string
  tenantId: string
  jurisdiction: string
  role: string
}>

/** The owning BFF verifies possession; this SDK input does not verify an ID token. */
export type PortableProfessionalVerifiedContactInput = Readonly<{
  verifiedContact?: ActorContactInput
  /** Retained email-only caller compatibility; do not supply both inputs. */
  verifiedEmail?: unknown
}>

function verifiedContact(input: PortableProfessionalVerifiedContactInput): ActorContactInput {
  if (input.verifiedEmail !== undefined && input.verifiedEmail !== null && typeof input.verifiedEmail !== 'string') {
    throw new TypeError('professional_verified_contact_invalid')
  }
  const legacyEmail = text(input.verifiedEmail)
  if (input.verifiedContact !== undefined) {
    if (legacyEmail) throw new TypeError('professional_verified_contact_ambiguous')
    if (!input.verifiedContact || typeof input.verifiedContact !== 'object') throw new TypeError('professional_verified_contact_invalid')
    return { contactKind: input.verifiedContact.contactKind, contact: normalizeActorContact(input.verifiedContact) }
  }
  if (!legacyEmail) throw new TypeError('verified_email_required')
  return { contactKind: 'email', contact: normalizeActorContact({ contactKind: 'email', contact: legacyEmail }) }
}

const EMPLOYEE_AUTHORIZATION_URN_PATTERN =
  /^urn:cds-([a-z]{2}(?:-[a-z0-9]{2,3})?):v[1-9][0-9]*:organization:([a-z][a-z0-9-]*):([^:]+):member:(z[1-9A-HJ-NP-Za-km-z]+):([0-9]+)$/i

type JsonRecord = Record<string, unknown>

function record(value: unknown): JsonRecord {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {}
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function identifiers(resource: JsonRecord): string[] {
  return (Array.isArray(resource.identifier) ? resource.identifier : [])
    .map(item => text(record(item).value))
    .filter(Boolean)
}

function providerIssuer(provider: PortableProfessionalProvider): string {
  return `${new URL(provider.baseUrl).origin}/${encodeURIComponent(provider.tenantId)}/cds-${encodeURIComponent(provider.jurisdiction)}/v1/${encodeURIComponent(provider.sector)}`
}

async function resolveProviderDid(provider: PortableProfessionalProvider, fetchImpl: typeof fetch): Promise<string> {
  const response = await fetchImpl(`${providerIssuer(provider)}/.well-known/did.json`, {
    headers: { accept: 'application/did+json, application/json' },
  })
  if (!response.ok) throw new TypeError('professional_tenant_did_unavailable')
  const document = record(await response.json())
  const providerDid = text(document.id)
  const expectedContext = `:${provider.tenantId}:cds-${provider.jurisdiction}:v1:${provider.sector}`
  const services = Array.isArray(document.service) ? document.service : []
  const hasJwks = services.some(service => text(record(service).type) === 'JsonWebKeyService2020'
    && /^https:\/\//i.test(text(record(service).serviceEndpoint)))
  if (!providerDid.startsWith('did:web:') || !providerDid.endsWith(expectedContext) || !hasJwks) {
    throw new TypeError('professional_tenant_did_invalid')
  }
  return providerDid
}

/**
 * Finds the signed professional DID documents already published beneath one
 * exact organization. Country, optional region, legal identifier and sector
 * only reconstruct routing; the authoritative employee DID and authorization
 * URN still determine every returned role.
 */
export async function resolvePortableProfessionalOrganizationEnrollments(input: PortableProfessionalVerifiedContactInput & Readonly<{
  country: unknown
  region?: unknown
  organizationIdentifier: unknown
  sector: unknown
  providers: readonly PortableProfessionalProvider[]
  fetchImpl?: typeof fetch
}>): Promise<readonly PortableProfessionalEnrollment[]> {
  const country = text(input.country).toUpperCase()
  const region = text(input.region).toUpperCase()
  const jurisdiction = region || country
  const organizationIdentifier = text(input.organizationIdentifier)
  const sector = text(input.sector).toLowerCase()
  if (!/^[A-Z]{2}$/.test(country)) throw new TypeError('professional_country_invalid')
  if (region && (!new RegExp(`^${country}-[A-Z0-9]{1,3}$`).test(region))) {
    throw new TypeError('professional_region_country_mismatch')
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/.test(organizationIdentifier)) {
    throw new TypeError('professional_organization_identifier_invalid')
  }
  const contact = verifiedContact(input)
  const expectedMemberId = buildStableActorIdentifier(contact).slice('urn:multibase:'.length)
  const roleCatalog = getHealthcareProfessionalRolesBySector(sector as DataspaceSector)
  const roles = Object.values(roleCatalog).filter(role => role.claim.startsWith('ISCO-08|'))
  if (!roles.length) throw new TypeError('professional_sector_not_allowed')
  const providers = input.providers.filter(provider => provider.tenantId === organizationIdentifier
    && provider.jurisdiction.toUpperCase() === jurisdiction
    && provider.sector.toLowerCase() === sector)
  if (providers.length === 0) throw new TypeError('professional_provider_not_found')
  if (providers.length > 1) throw new TypeError('multiple_professional_providers_found')

  const provider = providers[0]
  const fetchImpl = input.fetchImpl ?? fetch
  const providerDid = await resolveProviderDid(provider, fetchImpl)
  const results: PortableProfessionalEnrollment[] = []
  for (const role of roles) {
    const professionalDid = buildOrganizationEmployeeDidWeb({
      organizationDidWeb: providerDid,
      ...contact,
      role: role.claim,
    })
    const memberPath = professionalDid.slice(`${providerDid}:employee:`.length)
    const memberId = memberPath.slice(0, memberPath.indexOf(':'))
    const didUrl = `${providerIssuer(provider)}/employee/${encodeURIComponent(memberId)}/${encodeURIComponent(role.claim)}/did.json`
    const response = await fetchImpl(didUrl, { headers: { accept: 'application/did+json, application/json' } })
    if (response.status === 404) continue
    if (!response.ok) throw new TypeError('professional_directory_unavailable')
    const document = record(await response.json())
    if (text(document.id) !== professionalDid) throw new TypeError('professional_did_invalid')
    const employeeAuthorizationUrn = (Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs : [])
      .map(String).find(value => EMPLOYEE_AUTHORIZATION_URN_PATTERN.test(value)) || ''
    const authorization = EMPLOYEE_AUTHORIZATION_URN_PATTERN.exec(employeeAuthorizationUrn)
    if (!authorization
      || authorization[1].toUpperCase() !== jurisdiction
      || authorization[3] !== organizationIdentifier
      || authorization[4] !== expectedMemberId
      || authorization[5] !== role.code) {
      throw new TypeError('professional_credential_binding_invalid')
    }
    results.push(Object.freeze({
      sector: provider.sector,
      employeeAuthorizationUrn,
      professionalDid,
      providerDid,
      gatewayBaseUrl: new URL(provider.baseUrl).origin,
      tenantId: provider.tenantId,
      jurisdiction,
      role: role.claim,
    }))
  }
  if (!results.length) throw new TypeError('professional_profile_not_found')
  return Object.freeze(results)
}

function decodeShcQr(value: unknown): string {
  const normalized = text(value)
  if (!/^shc:\/\d+$/.test(normalized)) throw new TypeError('professional_credential_shc_required')
  const digits = normalized.slice('shc:/'.length)
  if (!digits || digits.length % 2 !== 0) throw new TypeError('professional_credential_shc_invalid')
  let compact = ''
  for (let index = 0; index < digits.length; index += 2) {
    const pair = Number(digits.slice(index, index + 2))
    if (pair > 77) throw new TypeError('professional_credential_shc_invalid')
    compact += String.fromCharCode(pair + 45)
  }
  return compact
}

/**
 * Derives routing candidates only from evidence shape plus a server-owned host
 * and sector allowlist. The returned candidate grants no authority: the signed
 * credential or authoritative DID documents are still verified by the
 * resolution functions below.
 */
export function derivePortableProfessionalProviderCandidates(input: Readonly<{
  professionalCredential?: unknown
  professionalIdentifier?: unknown
  sectorHint?: unknown
  trustedGatewayBaseUrls: readonly string[]
  allowedSectors: readonly string[]
}>): PortableProfessionalProvider[] {
  const hasCredential = Boolean(text(input.professionalCredential))
  const professionalIdentifier = text(input.professionalIdentifier)
  if (hasCredential === Boolean(professionalIdentifier)) throw new TypeError('professional_evidence_path_invalid')

  let tenantId = ''
  let jurisdiction = ''
  let sector = text(input.sectorHint).toLowerCase()
  let issuerOrigin = ''
  if (hasCredential) {
    const parts = decodeShcQr(input.professionalCredential).split('.')
    if (parts.length !== 3) throw new TypeError('professional_credential_shc_invalid')
    let payload: JsonRecord
    try {
      payload = record(JSON.parse(inflateRawSync(Buffer.from(parts[1], 'base64url')).toString('utf8')))
    } catch {
      throw new TypeError('professional_credential_shc_invalid')
    }
    const issuer = new URL(text(payload.iss))
    const match = issuer.pathname.match(/^\/([^/]+)\/cds-([^/]+)\/v[1-9][0-9]*\/([a-z][a-z0-9-]*)\/?$/i)
    if (!match) throw new TypeError('professional_credential_issuer_invalid')
    tenantId = decodeURIComponent(match[1])
    jurisdiction = decodeURIComponent(match[2])
    sector = decodeURIComponent(match[3]).toLowerCase()
    issuerOrigin = issuer.origin
  } else {
    const authorization = EMPLOYEE_AUTHORIZATION_URN_PATTERN.exec(professionalIdentifier)
    const did = professionalIdentifier.match(/:([^:]+):cds-([^:]+):v[1-9][0-9]*:([a-z][a-z0-9-]*):employee:/i)
    if (authorization) {
      jurisdiction = authorization[1]
      tenantId = authorization[3]
    } else if (did) {
      tenantId = did[1]
      jurisdiction = did[2]
      if (sector && sector !== did[3].toLowerCase()) throw new TypeError('professional_sector_mismatch')
      sector = did[3].toLowerCase()
    } else {
      throw new TypeError('professional_credential_invalid')
    }
  }

  const allowedSectors = new Set(input.allowedSectors.map(value => text(value).toLowerCase()).filter(Boolean))
  if (!sector || !allowedSectors.has(sector)) throw new TypeError('professional_sector_not_allowed')
  const origins = [...new Set(input.trustedGatewayBaseUrls.map(value => new URL(value).origin))]
    .filter(origin => !issuerOrigin || origin === issuerOrigin)
  if (origins.length === 0) throw new TypeError('professional_provider_not_allowed')
  return origins.map(baseUrl => Object.freeze({ baseUrl, tenantId, jurisdiction: jurisdiction.toUpperCase(), sector }))
}

/**
 * Verifies one signed professional SHC and returns only its existing
 * organization-issued authorization reference. It creates neither an
 * invitation nor a device registration.
 */
export async function resolveProfessionalShcEnrollment(input: Readonly<{
  credential: unknown
  providers: readonly PortableProfessionalProvider[]
  fetchImpl?: typeof fetch
  nowSeconds?: number
}>): Promise<Readonly<{ professionalIdentifier: string; sectorHint: string }>> {
  const compact = decodeShcQr(input.credential)
  const parts = compact.split('.')
  if (parts.length !== 3) throw new TypeError('professional_credential_shc_invalid')

  let header: JsonRecord
  let payload: JsonRecord
  try {
    header = record(JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')))
    payload = record(JSON.parse(inflateRawSync(Buffer.from(parts[1], 'base64url')).toString('utf8')))
  } catch {
    throw new TypeError('professional_credential_shc_invalid')
  }
  if (header.alg !== 'ES256' || header.zip !== 'DEF' || !text(header.kid)) {
    throw new TypeError('professional_credential_header_invalid')
  }
  const issuer = text(payload.iss)
  const notBefore = Number(payload.nbf)
  if (!issuer.startsWith('https://') || !Number.isInteger(notBefore)
    || notBefore > (input.nowSeconds ?? Math.floor(Date.now() / 1000))) {
    throw new TypeError('professional_credential_time_or_issuer_invalid')
  }

  const provider = input.providers.find(candidate => providerIssuer(candidate) === issuer)
  if (!provider) throw new TypeError('professional_credential_provider_not_allowed')
  const jwksResponse = await (input.fetchImpl ?? fetch)(`${issuer}/.well-known/jwks.json`, {
    headers: { accept: 'application/jwk-set+json, application/json' },
  })
  if (!jwksResponse.ok) throw new TypeError('professional_credential_jwks_unavailable')
  const jwks = record(await jwksResponse.json())
  const key = (Array.isArray(jwks.keys) ? jwks.keys : []).map(record)
    .find(candidate => candidate.kid === header.kid && candidate.kty === 'EC' && candidate.crv === 'P-256')
  if (!key) throw new TypeError('professional_credential_key_not_found')
  let valid = false
  try {
    valid = verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), {
      key: createPublicKey({ key: key as import('node:crypto').JsonWebKey, format: 'jwk' }),
      dsaEncoding: 'ieee-p1363',
    }, Buffer.from(parts[2], 'base64url'))
  } catch {
    valid = false
  }
  if (!valid) throw new TypeError('professional_credential_signature_invalid')

  const credentialSubject = record(record(payload.vc).credentialSubject)
  const bundle = record(credentialSubject.fhirBundle)
  if (bundle.resourceType !== 'Bundle') throw new TypeError('professional_credential_bundle_invalid')
  const resources = (Array.isArray(bundle.entry) ? bundle.entry : [])
    .map(entry => record(record(entry).resource))
  const organization = resources.find(resource => resource.resourceType === 'Organization')
  const practitioner = resources.find(resource => resource.resourceType === 'Practitioner')
  const practitionerRole = resources.find(resource => resource.resourceType === 'PractitionerRole')
  if (!organization || !practitioner || !practitionerRole || practitionerRole.active === false) {
    throw new TypeError('professional_credential_resources_required')
  }
  const authorizationUrn = identifiers(practitionerRole)
    .find(value => EMPLOYEE_AUTHORIZATION_URN_PATTERN.test(value))
  const authorization = authorizationUrn
    ? EMPLOYEE_AUTHORIZATION_URN_PATTERN.exec(authorizationUrn)
    : undefined
  if (!authorization || !authorizationUrn) throw new TypeError('professional_credential_authorization_missing')
  const [, jurisdiction, , organizationOfficialId] = authorization
  if (jurisdiction.toLowerCase() !== provider.jurisdiction.toLowerCase()
    || organizationOfficialId !== provider.tenantId
    || !identifiers(organization).includes(provider.tenantId)
    || identifiers(practitioner).length === 0
    || text(record(practitionerRole.organization).reference) !== 'resource:0'
    || text(record(practitionerRole.practitioner).reference) !== 'resource:1') {
    throw new TypeError('professional_credential_binding_invalid')
  }
  return Object.freeze({ professionalIdentifier: authorizationUrn, sectorHint: provider.sector })
}

/**
 * Resolves one organization-issued DID or authorization URN through
 * server-owned provider configuration. The result still requires the host
 * profile manager to perform licence, contact and device-registration checks.
 */
export async function resolvePortableProfessionalEnrollment(input: PortableProfessionalVerifiedContactInput & Readonly<{
  professionalIdentifier: unknown
  sectorHint: unknown
  providers: readonly PortableProfessionalProvider[]
  fetchImpl?: typeof fetch
}>): Promise<PortableProfessionalEnrollment> {
  const professionalIdentifier = text(input.professionalIdentifier)
  const sectorHint = text(input.sectorHint).toLowerCase()
  if (!/^[a-z][a-z0-9-]*$/.test(sectorHint)) throw new TypeError('professional_sector_hint_required')
  const contact = verifiedContact(input)
  const expectedMemberId = buildStableActorIdentifier(contact).slice('urn:multibase:'.length)

  const fetchImpl = input.fetchImpl ?? fetch
  let employeeAuthorizationUrn = professionalIdentifier
  let authorization = EMPLOYEE_AUTHORIZATION_URN_PATTERN.exec(employeeAuthorizationUrn)
  if (!authorization && professionalIdentifier.startsWith('did:web:')) {
    const didMatches = input.providers.flatMap(provider => {
      const context = `:${provider.tenantId}:cds-${provider.jurisdiction}:v1:${provider.sector}:employee:`
      if (provider.sector.toLowerCase() !== sectorHint || !professionalIdentifier.includes(context)) return []
      const employeePath = professionalIdentifier.slice(professionalIdentifier.indexOf(context) + context.length)
      const [memberId, ...roleParts] = employeePath.split(':')
      const role = roleParts.join(':')
      return memberId && role ? [{ provider, memberId, role }] : []
    })
    if (didMatches.length === 0) throw new TypeError('professional_provider_not_found')
    if (didMatches.length > 1) throw new TypeError('multiple_professional_providers_found')
    const { provider, memberId, role } = didMatches[0]
    const didUrl = `${providerIssuer(provider)}/employee/${encodeURIComponent(memberId)}/${encodeURIComponent(role)}/did.json`
    const didResponse = await fetchImpl(didUrl, { headers: { accept: 'application/did+json, application/json' } })
    if (!didResponse.ok) throw new TypeError('professional_did_unavailable')
    const didDocument = record(await didResponse.json())
    if (text(didDocument.id) !== professionalIdentifier) throw new TypeError('professional_did_invalid')
    employeeAuthorizationUrn = (Array.isArray(didDocument.alsoKnownAs) ? didDocument.alsoKnownAs : [])
      .map(String).find(value => EMPLOYEE_AUTHORIZATION_URN_PATTERN.test(value)) || ''
    authorization = EMPLOYEE_AUTHORIZATION_URN_PATTERN.exec(employeeAuthorizationUrn)
  }
  if (!authorization) throw new TypeError('professional_credential_invalid')
  if (authorization[4] !== expectedMemberId) throw new TypeError('professional_credential_binding_invalid')

  const [, authorizationJurisdiction, , organizationOfficialId, , authorizationRoleCode] = authorization
  const matches = input.providers.filter(provider => provider.tenantId === organizationOfficialId
    && provider.jurisdiction.toLowerCase() === authorizationJurisdiction.toLowerCase()
    && provider.sector.toLowerCase() === sectorHint)
  if (matches.length === 0) throw new TypeError('professional_provider_not_found')
  if (matches.length > 1) throw new TypeError('multiple_professional_providers_found')

  const provider = matches[0]
  const gatewayBaseUrl = new URL(provider.baseUrl).origin
  const providerDid = await resolveProviderDid(provider, fetchImpl)
  const role = `ISCO-08|${authorizationRoleCode}`
  const professionalDid = buildOrganizationEmployeeDidWeb({ organizationDidWeb: providerDid, ...contact, role })
  if (professionalIdentifier.startsWith('did:web:') && professionalIdentifier !== professionalDid) {
    throw new TypeError('professional_credential_binding_invalid')
  }
  return Object.freeze({
    sector: provider.sector,
    employeeAuthorizationUrn,
    professionalDid,
    providerDid,
    gatewayBaseUrl,
    tenantId: provider.tenantId,
    jurisdiction: provider.jurisdiction.toUpperCase(),
    role,
  })
}
