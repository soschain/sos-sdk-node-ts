import { randomUUID } from 'node:crypto'
import {readIndividualOrganizationIdentity} from 'sos-data-utils-ts/individual-registration-contract'

import {
  migrateHistoricalAnimalCardDidWeb,
  parseAnimalCardDidWeb,
  parseNcbiTaxonomyUri,
} from 'sos-data-utils-ts/animal-card-interoperability'
import { buildGatewayApplicationHeaders } from 'sos-data-utils-ts/gateway-application-identity'

const CLAIM_AUDIENCE_TYPE = 'org.schema.IndividualProduct.audience.audienceType'
const CLAIM_ITEM_CONDITION = 'org.schema.IndividualProduct.itemCondition'
const CLAIM_PERSON_EMAIL = 'org.schema.Person.email'
const CLAIM_PERSON_TELEPHONE = 'org.schema.Person.telephone'
const CLAIM_ORGANIZATION_SAME_AS = 'org.schema.Organization.sameAs'
const CLAIM_ORGANIZATION_OWNER_EMAIL = 'org.schema.Organization.owner.email'
const CLAIM_ORGANIZATION_OWNER_TELEPHONE = 'org.schema.Organization.owner.telephone'
const CLAIM_ORGANIZATION_OWNER_IDENTIFIER = 'org.schema.Organization.owner.identifier.value'
const CLAIM_ORGANIZATION_MEMBER_ROLE = 'org.schema.Organization.member.role'
const CLAIM_ORGANIZATION_MEMBER_ADDITIONAL_TYPE = 'org.schema.Organization.member.additionalType'
const CLAIM_RELATED_PERSON_ROLE = 'RelatedPerson.role'
const CLAIM_OCCUPATION_IDENTIFIER = 'org.schema.Person.hasOccupation.identifier.value'

export type SosGatewayRouteContext = Readonly<{
  tenantId: string
  jurisdiction: string
  sector: string
}>

export type AuthorizedSubjectVerifiedContact = Readonly<{
  email?: string
  telephone?: string
}>

export type AuthorizedIndividualSubjectDirectoryInput = Readonly<{
  verifiedContact: AuthorizedSubjectVerifiedContact
  requestThid?: string
  pollOptions?: Readonly<{ timeoutMs?: number; intervalMs?: number }>
  /** Trusted registered provider, enabling strict row UUID/canonical subject binding. */
  expectedProviderDid?: string
}>

export type AuthorizedIndividualSubject = Readonly<{
  subjectDid: string
  /** Historical provider lookup alias retained only while its record is migrated. */
  sourceSubjectDid?: string
  organizationId?: string
  role?: string
  grantClaims: Readonly<Record<string, unknown>>
  authorizationEvidenceId?: string
  relatedPersonId?: string
  issuerDid?: string
  subjectClaims: Readonly<Record<string, unknown>>
}>

export type SosGatewaySubjectDirectoryClientOptions = Readonly<{
  baseUrl: string
  bearerToken?: string
  appId?: string
  appVersion?: string
  defaultHeaders?: Readonly<Record<string, string>>
  requestTimeoutMs?: number
  fetchImpl?: typeof fetch
  /** Explicit encrypted registered transport. No plaintext fallback is attempted. */
  registeredExchange?: (path:string,payload:Readonly<Record<string,unknown>> & Readonly<{thid:string}>,options?:Readonly<{timeoutMs?:number;intervalMs?:number}>)=>Promise<Readonly<{status:number;body:unknown}>>
}>

type GatewayResponse = Readonly<{ status: number; body: unknown }>

type AcceptedLicenseRow = Readonly<{
  subjectDid: string
  role?: string
  grantClaims: Readonly<Record<string, unknown>>
  authorizationEvidenceId?: string
  relatedPersonId?: string
  issuerDid?: string
}>

/**
 * Shared trusted-BFF client for the canonical asynchronous SOS GW subject
 * directory. The verified contact is discovery evidence only; results never
 * grant a protected clinical or emergency action.
 */
export class SosGatewaySubjectDirectoryClient {
  private readonly baseUrl: string
  private readonly headers: Readonly<Record<string, string>>
  private readonly requestTimeoutMs: number
  private readonly fetchImpl: typeof fetch

  public constructor(private readonly options: SosGatewaySubjectDirectoryClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl)
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs ?? 15_000, 'request_timeout_invalid')
    this.fetchImpl = options.fetchImpl ?? fetch
    this.headers = Object.freeze({
      // The shared GW contract identifies this existing thid/body envelope as
      // DIDComm plaintext. Compat and strict deployments must never receive it
      // under the ambiguous legacy application/json media type.
      'Content-Type': 'application/didcomm-plain+json',
      Accept: 'application/didcomm-plain+json',
      ...(requiredOptional(options.bearerToken) ? { Authorization: `Bearer ${requiredOptional(options.bearerToken)}` } : {}),
      ...(requiredOptional(options.appId)
        ? buildGatewayApplicationHeaders({
          appId: requiredOptional(options.appId)!,
          appVersion: options.appVersion,
        })
        : {}),
      ...(options.defaultHeaders ?? {}),
    })
  }

  public async listAuthorizedIndividualSubjects(
    routeContext: SosGatewayRouteContext,
    input: AuthorizedIndividualSubjectDirectoryInput,
  ): Promise<AuthorizedIndividualSubject[]> {
    const context = normalizeRouteContext(routeContext)
    const email = String(input.verifiedContact?.email || '').trim().toLowerCase()
    const telephone = String(input.verifiedContact?.telephone || '').trim()
    if (!email && !telephone) throw new Error('verified_contact_required')

    const organizationPath = gatewayPath(context, 'Organization', '_search')
    const organizationPollPath = gatewayPath(context, 'Organization', '_search-response')
    const ownerResult = await this.submitAndPoll(
      organizationPath,
      organizationPollPath,
      {
        thid: input.requestThid || threadId('authorized-subject-owner'),
        body: searchBundle('Family-search-v1.0', {
          '@context': 'org.schema',
          ...(email ? { [CLAIM_ORGANIZATION_OWNER_EMAIL]: email } : {}),
          ...(telephone ? { [CLAIM_ORGANIZATION_OWNER_TELEPHONE]: telephone } : {}),
        }),
      },
      input.pollOptions,
    )
    const ownedSubjects = readOwnedSubjects(ownerResult.body, context, { email, telephone },input.expectedProviderDid)
    if(input.expectedProviderDid){
      const patientsByAlias=new Map<string,unknown>()
      for(const subject of ownedSubjects){
        const patient=subject.subjectClaims['org.schema.Organization.did']
        for(const alias of publicAliases(subject.subjectClaims[CLAIM_ORGANIZATION_SAME_AS]).filter(value=>registeredAlias(value,input.expectedProviderDid!))){
          if(patientsByAlias.has(alias)&&patientsByAlias.get(alias)!==patient)throw new Error('registered_directory_alias_ambiguous')
          patientsByAlias.set(alias,patient)
        }
      }
    }
    const subjectsByDid = new Map(ownedSubjects.map((subject) => [subject.subjectDid, subject]))

    const licensePath = gatewayPath(context, 'License', '_search')
    const licensePollPath = gatewayPath(context, 'License', '_search-response')
    const licenseResult = await this.submitAndPoll(
      licensePath,
      licensePollPath,
      {
        thid: input.requestThid || threadId('authorized-subject-license'),
        body: {
          resourceType: 'Bundle',
          type: 'batch',
          data: [{
            request: { method: 'POST' },
            resource: { meta: { status: 'active', claims: {
              '@context': 'org.schema',
              [CLAIM_AUDIENCE_TYPE]: 'Individual',
              [CLAIM_ITEM_CONDITION]: 'https://schema.org/UsedCondition',
              ...(email ? { [CLAIM_PERSON_EMAIL]: email } : {}),
              ...(telephone ? { [CLAIM_PERSON_TELEPHONE]: telephone } : {}),
            } } },
          }],
        },
      },
      input.pollOptions,
    )
    const licenses = readAcceptedLicenses(licenseResult.body, context,input.expectedProviderDid)

    for (const license of licenses) {
      if (subjectsByDid.has(license.subjectDid)) continue
      const organizationResult = await this.submitAndPoll(
        organizationPath,
        organizationPollPath,
        {
          thid: threadId('authorized-subject-record'),
          body: searchBundle('Family-search-v1.0', {
            '@context': 'org.schema',
            [CLAIM_ORGANIZATION_SAME_AS]: license.subjectDid,
          }),
        },
        input.pollOptions,
      )
      const organization = readFirstOrganization(organizationResult.body)
      if (!publicAliases(organization.claims[CLAIM_ORGANIZATION_SAME_AS]).includes(license.subjectDid)) continue
      if(input.expectedProviderDid)assertRegisteredSubject(organization.claims,organization.organizationId,license.subjectDid,input.expectedProviderDid)
      const resolvedDid:Readonly<{subjectDid:string;sourceSubjectDid?:string}> = input.expectedProviderDid?{subjectDid:license.subjectDid}:resolveSubjectCardDid(license.subjectDid, context, organization.claims)
      subjectsByDid.set(resolvedDid.subjectDid, Object.freeze({
        subjectDid: resolvedDid.subjectDid,
        ...(resolvedDid.sourceSubjectDid ? { sourceSubjectDid: resolvedDid.sourceSubjectDid } : {}),
        ...(organization.organizationId ? { organizationId: organization.organizationId } : {}),
        ...(license.role ? { role: license.role } : {}),
        grantClaims: license.grantClaims,
        ...(license.authorizationEvidenceId ? { authorizationEvidenceId: license.authorizationEvidenceId } : {}),
        ...(license.relatedPersonId ? { relatedPersonId: license.relatedPersonId } : {}),
        ...(license.issuerDid ? { issuerDid: license.issuerDid } : {}),
        subjectClaims: organization.claims,
      }))
    }
    return [...subjectsByDid.values()]
  }

  private async submitAndPoll(
    submitPath: string,
    pollPath: string,
    payload: Readonly<Record<string, unknown>> & Readonly<{ thid: string }>,
    options?: Readonly<{ timeoutMs?: number; intervalMs?: number }>,
  ): Promise<GatewayResponse> {
    if(this.options.registeredExchange)return this.options.registeredExchange(submitPath,payload,options)
    const submit = await this.post(submitPath, payload)
    requireSuccessfulResponse(submit, 'gateway_submit_failed')
    const timeoutMs = positiveInteger(options?.timeoutMs ?? 30_000, 'poll_timeout_invalid')
    const intervalMs = positiveInteger(options?.intervalMs ?? 250, 'poll_interval_invalid')
    const started = Date.now()
    for (;;) {
      const poll = await this.post(pollPath, { thid: payload.thid })
      if (poll.status !== 202) {
        requireSuccessfulResponse(poll, 'gateway_poll_failed')
        return poll
      }
      if (Date.now() - started >= timeoutMs) throw new Error('gateway_poll_timeout')
      await new Promise((resolve) => setTimeout(resolve, intervalMs))
    }
  }

  private async post(path: string, payload: unknown): Promise<GatewayResponse> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs)
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      })
      const raw = await response.text()
      let body: unknown = {}
      if (raw) {
        try { body = JSON.parse(raw) } catch { body = raw }
      }
      return { status: response.status, body }
    } finally {
      clearTimeout(timeout)
    }
  }
}

function searchBundle(type: string, claims: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return {
    resourceType: 'Bundle',
    type: 'batch',
    data: [{ type, request: { method: 'POST' }, resource: { meta: { claims } } }],
  }
}

function registeredAlias(value:string,provider:string):boolean{
  return value.startsWith(`${provider}:card:`)&&!/[\s?#]/u.test(value)&&value.length>provider.length+6
}
function assertRegisteredSubject(claims:Readonly<Record<string,unknown>>,id:unknown,alias:string,provider:string):void{
  if(!registeredAlias(alias,provider))throw new Error('registered_directory_subject_binding_invalid')
  readIndividualOrganizationIdentity({organizationId:id,providerDid:provider,canonicalSubjectIdentifier:claims['org.schema.Organization.did'],publicCardAlias:alias})
}

function readOwnedSubjects(
  body: unknown,
  context: SosGatewayRouteContext,
  verified: Readonly<{ email: string; telephone: string }>,
  expectedProviderDid?:string,
): AuthorizedIndividualSubject[] {
  const resources = readData(body).flatMap((entry: any) =>
    entry?.resource?.resourceType === 'Bundle' && Array.isArray(entry.resource.entry)
      ? entry.resource.entry.map((item: any) => item?.resource).filter(Boolean)
      : [])
  return resources.flatMap((resource: any) => {
    const claims = objectRecord(resource?.meta?.claims)
    const ownerEmail = String(claims[CLAIM_ORGANIZATION_OWNER_EMAIL] || '').trim().toLowerCase()
    const ownerTelephone = String(claims[CLAIM_ORGANIZATION_OWNER_TELEPHONE] || '').trim()
    if (!((verified.email && ownerEmail === verified.email) || (verified.telephone && ownerTelephone === verified.telephone))) return []
    const sourceSubjectDid = expectedProviderDid?publicAliases(claims[CLAIM_ORGANIZATION_SAME_AS]).find(alias=>registeredAlias(alias,expectedProviderDid)):selectSubjectCardAlias(claims[CLAIM_ORGANIZATION_SAME_AS], context)
    if (!sourceSubjectDid) return []
    if(expectedProviderDid)assertRegisteredSubject(claims,resource.id,sourceSubjectDid,expectedProviderDid)
    const resolvedDid:Readonly<{subjectDid:string;sourceSubjectDid?:string}> = expectedProviderDid?{subjectDid:sourceSubjectDid}:resolveSubjectCardDid(sourceSubjectDid, context, claims)
    const role = isAnimalSector(context.sector)
      ? 'RESPRSN'
      : String(claims[CLAIM_ORGANIZATION_MEMBER_ROLE] || '').trim()
    const relatedPersonId = String(claims[CLAIM_ORGANIZATION_OWNER_IDENTIFIER] || '').trim()
    return [Object.freeze({
      subjectDid: resolvedDid.subjectDid,
      ...(resolvedDid.sourceSubjectDid ? { sourceSubjectDid: resolvedDid.sourceSubjectDid } : {}),
      ...(String(resource?.id || '').trim() ? { organizationId: String(resource.id).trim() } : {}),
      ...(role ? { role } : {}),
      ...(relatedPersonId ? { relatedPersonId } : {}),
      grantClaims: Object.freeze({}),
      subjectClaims: claims,
    })]
  })
}

function readAcceptedLicenses(body: unknown, context: SosGatewayRouteContext,expectedProviderDid?:string): AcceptedLicenseRow[] {
  const rows = (readData(body)[0] as any)?.resource?.data
  if (!Array.isArray(rows)) return []
  return rows.flatMap((row: any) => {
    const meta = objectRecord(row?.meta || row?.resource?.meta)
    const subjectDid = String(meta.authorizedSubjectDid || '').trim()
    if (!subjectDid) return []
    if (!(expectedProviderDid?registeredAlias(subjectDid,expectedProviderDid):isSubjectCardCandidate(subjectDid, context))) return []
    const claims = objectRecord(meta.claims)
    const relatedRoles = String(claims[CLAIM_RELATED_PERSON_ROLE] || '')
      .split(',').map((value) => value.trim().toUpperCase()).filter(Boolean)
    const occupation = String(claims[CLAIM_OCCUPATION_IDENTIFIER] || '').trim()
    const role = relatedRoles.includes('CAREGIVER') ? 'CAREGIVER' : relatedRoles[0] || occupation
    return [Object.freeze({
      subjectDid,
      ...(role ? { role } : {}),
      grantClaims: claims,
      ...(requiredOptional(meta.identifier) ? { authorizationEvidenceId: requiredOptional(meta.identifier)! } : {}),
      ...(requiredOptional(meta.relatedPersonId) ? { relatedPersonId: requiredOptional(meta.relatedPersonId)! } : {}),
      ...(requiredOptional(meta.issuerDid) ? { issuerDid: requiredOptional(meta.issuerDid)! } : {}),
    })]
  })
}

function readFirstOrganization(body: unknown): Readonly<{ claims: Record<string, unknown>; organizationId?: string }> {
  const entry = readData(body)[0] as any
  const claims = objectRecord(entry?.resource?.meta?.claims || entry?.meta?.claims)
  const organizationId = String(entry?.resource?.id || entry?.id || '').trim()
  return { claims, ...(organizationId ? { organizationId } : {}) }
}

function readData(body: unknown): any[] {
  const root = objectRecord(body)
  const payload = objectRecord(root.body || root)
  return Array.isArray(payload.data) ? payload.data : []
}

function selectSubjectCardAlias(value: unknown, context: SosGatewayRouteContext): string | undefined {
  const aliases = publicAliases(value)
  const candidate = aliases.find((alias) => isAnimalSector(context.sector)
    ? alias.includes(':card:vetchain:')
    : alias.includes(':card:uhc:'))
  if (!candidate) return undefined
  if (!isAnimalSector(context.sector)) requireCanonicalSubjectDid(candidate, context)
  return candidate
}

function resolveSubjectCardDid(
  sourceSubjectDid: string,
  context: SosGatewayRouteContext,
  claims: Readonly<Record<string, unknown>>,
): Readonly<{ subjectDid: string; sourceSubjectDid?: string }> {
  if (!isAnimalSector(context.sector)) {
    requireCanonicalSubjectDid(sourceSubjectDid, context)
    return Object.freeze({ subjectDid: sourceSubjectDid })
  }
  if (parseAnimalCardDidWeb(sourceSubjectDid)) {
    return Object.freeze({ subjectDid: sourceSubjectDid })
  }
  const taxonomyId = parseNcbiTaxonomyUri(claims[CLAIM_ORGANIZATION_MEMBER_ADDITIONAL_TYPE])
  const migrated = taxonomyId
    ? migrateHistoricalAnimalCardDidWeb(sourceSubjectDid, taxonomyId)
    : undefined
  if (!migrated) throw new Error('animal_card_did_invalid')
  return Object.freeze({
    subjectDid: migrated.cardDid,
    sourceSubjectDid: migrated.sourceCardDid,
  })
}

function requireCanonicalSubjectDid(subjectDid: string, context: SosGatewayRouteContext): void {
  if (isAnimalSector(context.sector) && !parseAnimalCardDidWeb(subjectDid)) {
    throw new Error('animal_card_did_invalid')
  }
  if (!isAnimalSector(context.sector) && !/^did:web:[^\s]+:card:uhc:(?:personal|professional):[^\s]+$/i.test(subjectDid)) {
    throw new Error('human_card_did_invalid')
  }
}

function isSubjectCardCandidate(subjectDid: string, context: SosGatewayRouteContext): boolean {
  return isAnimalSector(context.sector)
    ? subjectDid.toLowerCase().includes(':card:vetchain:')
    : subjectDid.toLowerCase().includes(':card:uhc:')
}

function isAnimalSector(sector: string): boolean {
  return sector.toLowerCase().startsWith('animal-')
}

function publicAliases(value: unknown): string[] {
  const values = Array.isArray(value) ? value : String(value ?? '').split(',')
  return [...new Set(values.map((alias) => String(alias).trim()).filter(Boolean))]
}

function gatewayPath(context: SosGatewayRouteContext, resource: 'Organization' | 'License', action: string): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/individual/org.schema/${resource}/${action}`
}

function normalizeRouteContext(value: SosGatewayRouteContext): SosGatewayRouteContext {
  const segment = (input: unknown): string => {
    const normalized = String(input ?? '').trim()
    if (!normalized || normalized.includes('/') || normalized === '.' || normalized === '..') throw new Error('gateway_route_context_invalid')
    return normalized
  }
  return Object.freeze({
    tenantId: segment(value.tenantId),
    jurisdiction: segment(value.jurisdiction),
    sector: segment(value.sector),
  })
}

function normalizeBaseUrl(value: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new Error('gateway_base_url_insecure')
  }
  return url.href.replace(/\/$/, '')
}

function requireSuccessfulResponse(response: GatewayResponse, code: string): void {
  if (response.status >= 200 && response.status < 300) return
  const issue = objectRecord(response.body)
  const diagnostics = Array.isArray(issue.issue)
    ? issue.issue.map((entry) => String(objectRecord(entry).diagnostics || '').trim()).find(Boolean)
    : undefined
  throw new Error(`${code}:${response.status}${diagnostics ? `:${diagnostics}` : ''}`)
}

function objectRecord(value: unknown): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : {}
}

function requiredOptional(value: unknown): string | undefined {
  const normalized = String(value ?? '').trim()
  return normalized || undefined
}

function positiveInteger(value: number, code: string): number {
  if (!Number.isInteger(value) || value < 1) throw new Error(code)
  return value
}

function threadId(prefix: string): string {
  return `${prefix}-${randomUUID()}`
}
