import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { verifyPinnedJwt } from 'antifraud-data-utils-ts/clearing-house'
import { CryptographyService, type PublicJwk } from 'antifraud-data-utils-ts/cryptography'
import { CommunicationCategoryCodes, CommunicationClaim, FhirCodeSystems, HealthcareConsentPurposes } from 'fhir-data-utils-ts'
import { buildFhirParametersResourceFromSearchParams } from 'fhir-data-utils-ts/fhir-parameters'
import { ResearchStudyClaim } from 'fhir-data-utils-ts/research-study-r5'
import { buildProfessionalIdentityVpPayload } from 'sos-data-utils-ts/professional-smart'
import type { AppInfo, PollOptions, RouteContext } from 'sos-data-utils-ts/gateway-transport-contract'
import { buildResearchStudyProfessionalSmartRequest } from 'sos-sdk-core-ts/research-study'
import type { RegisteredSmartTokenAlgorithm } from './registered-did-keys.js'
import { RegisteredGatewayTransport, type VerifiedGatewaySecureAdapter } from './registered-gateway-transport.js'
import type { openServerProfileCustodyKeys } from './server-profile-custody-keys.js'

type Custody = Awaited<ReturnType<typeof openServerProfileCustodyKeys>>
type Options = Readonly<{
  baseUrl: string
  ctx: RouteContext
  actorDid: string
  providerDid: string
  clientId: string
  role: string
  bearerToken: string
  secureTransportAdapter: VerifiedGatewaySecureAdapter
  smartTokenVerification: Readonly<{
    algorithm: RegisteredSmartTokenAlgorithm
    resolveSigningJwk(providerDid: string): Promise<PublicJwk>
  }>
  appInfo?: AppInfo
  fetchImpl?: typeof fetch
  now?: () => Date
}> & Pick<Custody, 'signClientAssertion' | 'signIdentityPresentationJws'>

const invalidGrant = () => new Error('registered_research_study_grant_invalid')
const object = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined
const cryptography = new CryptographyService({
  getRandomBytes: async length => randomBytes(length), randomUUID,
  digestString: async (value, algorithm) => createHash(algorithm.replaceAll('-', '').toLowerCase()).update(value).digest('hex'),
})

export class RegisteredResearchStudyGatewayError extends Error {
  constructor(readonly status: number) { super(`registered_research_study_gateway_failed:${status}`) }
}

/** Requests one study grant through already opened registered employee custody. */
export class RegisteredResearchStudyClient {
  private readonly baseUrl: string
  private readonly tenantPath: string
  private readonly transport: RegisteredGatewayTransport

  constructor(private readonly options: Options) {
    const url = new URL(options.baseUrl)
    const loopback = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
    const { tenantId, jurisdiction, sector } = options.ctx
    if ((url.protocol !== 'https:' && !loopback) || url.username || url.password || url.search || url.hash || url.pathname !== '/'
      || !/^[A-Za-z0-9-]+$/u.test(tenantId) || tenantId.toLowerCase() === 'host'
      || !/^[A-Za-z]{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(jurisdiction) || !/^[a-z0-9-]+$/u.test(sector)
      || !options.actorDid.startsWith('did:web:') || !options.clientId.trim() || !options.role.trim()
      || !options.providerDid.startsWith('did:web:') || options.secureTransportAdapter.gatewayDid !== options.providerDid
      || !options.bearerToken.trim()) throw new TypeError('registered_research_study_context_invalid')
    this.baseUrl = url.origin
    this.tenantPath = `/${tenantId}/cds-${jurisdiction}/v1/${sector}`
    this.transport = new RegisteredGatewayTransport({ ...options, baseUrl: this.baseUrl, errorPrefix: 'registered_research_study',
      submitError: status => new RegisteredResearchStudyGatewayError(status) })
  }

  /** Searches the governed research inbox for the bound assignment. */
  async readStudyInvitationCommunications(party: string, pollOptions?: PollOptions) {
    requirePractitionerRole(party)
    const parameters = buildFhirParametersResourceFromSearchParams({
      [CommunicationClaim.Category]: CommunicationCategoryCodes.Notification.attributeValue,
      [CommunicationClaim.Topic]: `${FhirCodeSystems.ActReason}|${HealthcareConsentPurposes.Research}`,
      recipient: party,
    })
    return this.searchInvitations('/individual/org.hl7.fhir.r4/Communication/_search', {
      resourceType: 'Bundle', type: 'search', entry: [{ request: { method: 'POST', url: 'Communication/_search' }, resource: parameters }],
    }, pollOptions)
  }

  /** Resolves assignments that still exist in the tenant ResearchStudy collection. */
  async readInvitedResearchStudies(party: string, pollOptions?: PollOptions) {
    requirePractitionerRole(party)
    return this.searchInvitations('/organization/org.hl7.fhir.r5/ResearchStudy/_search', {
      resourceType: 'Bundle', type: 'batch', data: [{ resource: { resourceType: 'Parameters', meta: { claims: { [ResearchStudyClaim.Party]: [party] } } } }],
    }, pollOptions)
  }

  private searchInvitations(path: string, body: Record<string, unknown>, pollOptions?: PollOptions) {
    const { actorDid, providerDid, clientId } = this.options
    const thid = randomUUID()
    return this.transport.exchange(`${this.tenantPath}${path}`, {
      thid, jti: thid, iss: actorDid, aud: providerDid, client_id: clientId, body,
    }, providerDid, pollOptions)
  }

  async requestStudyAccess(studyId: string, pollOptions?: PollOptions) {
    const { purpose, scopes: [scope] } = buildResearchStudyProfessionalSmartRequest(studyId)
    const reference = `ResearchStudy/${studyId.trim()}`
    const { actorDid, clientId, providerDid, role } = this.options
    const issuedAt = this.now()
    const thid = randomUUID()
    const path = `${this.tenantPath}/identity/openid/smart/token`
    const audience = `${this.baseUrl}${path}`
    const [assertion, vpToken] = await Promise.all([
      this.options.signClientAssertion({ clientId, audience, issuedAt, jti: randomUUID() }),
      this.options.signIdentityPresentationJws({ claims: buildProfessionalIdentityVpPayload({
        clientId, actorDid, role, additionalPayload: { iss: clientId, sub: actorDid, aud: providerDid, iat: issuedAt, exp: issuedAt + 300, jti: randomUUID() },
      }) }),
    ])
    const result = await this.transport.exchange(path, {
      thid, jti: thid, iss: actorDid, aud: audience, client_id: clientId,
      body: { client_id: clientId, sub: actorDid, id_token: this.options.bearerToken, client_assertion: assertion,
        client_assertion_type: 'private_key_jwt', vp_token: vpToken, acr_values: 'urn:antifraud:acr:openid4vp:employee',
        purpose, scope, expires_in: 300, token_type: 'Bearer' },
    }, providerDid, pollOptions)
    const envelope = object(result.poll.body)
    const body = object(envelope?.body)
    const token = body?.access_token
    if (envelope?.jti !== thid || typeof token !== 'string' || body?.token_type !== 'Bearer'
      || body.subject !== reference || body.scope !== scope) throw invalidGrant()
    const { algorithm, resolveSigningJwk } = this.options.smartTokenVerification
    const key = await resolveSigningJwk(providerDid)
    if (!('alg' in key) || key.alg !== algorithm) throw invalidGrant()
    const now = this.now()
    const claims = await verifyPinnedJwt(token, { keys: [key] }, providerDid, now, { audience: providerDid, cryptography })
    if (claims.aud !== providerDid || claims.sub !== actorDid || claims.client_id !== clientId
      || claims.purpose !== purpose || claims.scope !== scope || claims.study !== reference
      || typeof claims.jti !== 'string' || !claims.jti || typeof claims.iat !== 'number' || !Number.isSafeInteger(claims.iat)
      || claims.iat < issuedAt - 60 || typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp)
      || claims.exp > claims.iat + 300) throw invalidGrant()
    return { status: 'fetched' as const, accessToken: token, studyReference: reference, scope }
  }

  private now() {
    const seconds = Math.floor((this.options.now?.() ?? new Date()).getTime() / 1000)
    if (!Number.isSafeInteger(seconds) || seconds < 0) throw new TypeError('registered_research_study_clock_invalid')
    return seconds
  }
}

function requirePractitionerRole(value: string) {
  if (typeof value !== 'string' || !/^PractitionerRole\/[A-Za-z0-9.-]{1,64}$/u.test(value)) {
    throw new TypeError('registered_research_party_invalid')
  }
}
