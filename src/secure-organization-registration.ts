// Copyright 2026 Connecting Solution & Applications Ltd under the Apache License, Version 2.0.
import {
  OrganizationRegistrationClient, TransportProfiles,
  type AppInfo, type HostRouteContext, type LegalOrganizationOrderInput,
  type NodeLegalOrganizationVerificationTransactionInput, type PollOptions,
  type RouteContext, type SubmitAndPollResult,
} from './organization-registration-client.js'
import {OrganizationRegistrationWallet} from './organization-registration-wallet.js'
import {buildAuthorityDidWeb,resolveDidWebKeyAgreementJwk} from './did-web-recipient.js'

type PublicJwk = Readonly<Record<string, unknown>>
export type HostScopedDidWebResolverOptions = Readonly<{
  gatewayBaseUrl: string; hostCoverageScope: string; version: string; hostNetwork: string; fetchImpl?: typeof fetch
}>

export function buildHostScopedDidDocumentUrl(options: Omit<HostScopedDidWebResolverOptions, 'fetchImpl'>): string {
  const gatewayOrigin = secureOrigin(options.gatewayBaseUrl, 'host_did_gateway_url_required')
  const coverage = routeSegment(options.hostCoverageScope, 'host_did_coverage_scope_required').toUpperCase()
  const version = routeSegment(options.version, 'host_did_version_required')
  const network = routeSegment(options.hostNetwork, 'host_did_network_required')
  return `${gatewayOrigin}/host/cds-${coverage}/${version}/${network}/.well-known/did.json`
}

export function createHostScopedDidWebKeyAgreementResolver(
  options: HostScopedDidWebResolverOptions,
): (recipientDid: string) => ReturnType<typeof resolveDidWebKeyAgreementJwk> {
  const gatewayOrigin = secureOrigin(options.gatewayBaseUrl, 'host_did_gateway_url_required')
  const hostDid = buildAuthorityDidWeb({ authority: gatewayOrigin }).toLowerCase()
  const didDocumentUrl = buildHostScopedDidDocumentUrl(options)
  return recipientDid => resolveDidWebKeyAgreementJwk(recipientDid, {
    fetchImpl: options.fetchImpl,
    ...(String(recipientDid || '').trim().toLowerCase() === hostDid ? { didDocumentUrl } : {}),
  })
}

export type SecureOrganizationRegistrationRuntimeOptions = Readonly<{
  gatewayBaseUrl: string
  appInfo?: AppInfo
  resolveRecipientJwk(recipientDid: string): Promise<PublicJwk>
  fetchImpl?: typeof fetch
  requestTimeoutMs?: number
}>
type SecureOrganizationBootstrapInput = Readonly<{
  walletSeed: string; walletKeyDerivationId: string; bearerToken: string; providerDid: string
  routeContext: RouteContext; hostContext: HostRouteContext; pollOptions?: PollOptions
}>
export type SecureOrganizationRegistrationInput = SecureOrganizationBootstrapInput & Readonly<{
  verificationInput: NodeLegalOrganizationVerificationTransactionInput
}>
export type SecureOrganizationOrderInput = SecureOrganizationBootstrapInput & Readonly<{
  orderInput: LegalOrganizationOrderInput
}>

export function buildOrganizationRegistrationWalletContext(walletKeyDerivationId: string) {
  const id = required(walletKeyDerivationId, 'organization_registration_wallet_context_required')
  return { profile: { profileId: id }, runtime: { runtimeId: `${id}:server-runtime`, runtimeType: 'backend-service' } } as const
}

/** Trusted-server facade for encrypted verification, reissuance and Offer-to-Order confirmation. */
export class SecureOrganizationRegistrationRuntime {
  constructor(private readonly options: SecureOrganizationRegistrationRuntimeOptions) {
    secureOrigin(options.gatewayBaseUrl, 'organization_registration_gateway_url_required')
  }

  async submitVerificationWithBootstrapWallet(input: SecureOrganizationRegistrationInput): Promise<SubmitAndPollResult> {
    const client = await this.createEncryptedClient(input)
    return assertSuccessfulOrganizationRegistrationResult(await client.submitLegalOrganizationVerificationTransaction(
      input.hostContext, input.verificationInput, input.pollOptions,
    ))
  }

  async submitCredentialReissuanceWithBootstrapWallet(input: SecureOrganizationRegistrationInput): Promise<SubmitAndPollResult> {
    const client = await this.createEncryptedClient(input)
    return assertSuccessfulOrganizationRegistrationResult(await client.submitLegalOrganizationCredentialReissuance(
      input.hostContext, input.verificationInput, input.pollOptions,
    ))
  }

  async confirmOrderWithBootstrapWallet(input: SecureOrganizationOrderInput): Promise<SubmitAndPollResult> {
    const client = await this.createEncryptedClient(input)
    return assertSuccessfulOrganizationRegistrationResult(await client.confirmLegalOrganizationOrder(
      input.hostContext, input.orderInput, input.pollOptions,
    ))
  }

  private async createEncryptedClient(input: SecureOrganizationBootstrapInput): Promise<OrganizationRegistrationClient> {
    const walletKeyDerivationId = required(input.walletKeyDerivationId, 'organization_registration_wallet_context_required')
    const walletSeed = required(input.walletSeed, 'organization_registration_wallet_seed_required')
    const providerDid = required(input.providerDid, 'organization_registration_provider_did_required')
    const bearerToken = required(input.bearerToken, 'organization_registration_bearer_required')
    const wallet = new OrganizationRegistrationWallet({ resolveRecipientJwk: this.options.resolveRecipientJwk })
    const context = buildOrganizationRegistrationWalletContext(walletKeyDerivationId)
    await wallet.provisionCommunicationKeys(context,walletSeed)
    return new OrganizationRegistrationClient({
      baseUrl: this.options.gatewayBaseUrl, bearerToken, ctx: input.routeContext,
      appInfo: this.options.appInfo, fetchImpl: this.options.fetchImpl, requestTimeoutMs: this.options.requestTimeoutMs,
      transportProfile: TransportProfiles.DidcommEncryptedForm,
      secureTransportAdapter: {
        pack: message => wallet.packForRecipientWithContext(message, providerDid, { context }),
        unpack: async jwe => (await wallet.unpackWithContext(jwe, { context })).content,
      },
    })
  }
}

export function assertSuccessfulOrganizationRegistrationResult<T extends Readonly<{
  poll: Readonly<{ status: number; body: unknown }>
}>>(result: T): T {
  const failure = findFailedOperationOutcome(result.poll.body)
  if (result.poll.status >= 400 || failure) {
    const code = String(failure?.issue.code || 'operation-outcome').trim() || 'operation-outcome'
    const status = failure?.status || result.poll.status
    throw new Error(`organization_registration_gateway_failed:${status}:${code}`)
  }
  return result
}

function findFailedOperationOutcome(value: unknown): Readonly<{ issue: Record<string, unknown>; status?: number }> | undefined {
  const seen = new WeakSet<object>()
  const visit = (candidate: unknown, inheritedStatus?: number): Readonly<{ issue: Record<string, unknown>; status?: number }> | undefined => {
    if (!candidate || typeof candidate !== 'object' || seen.has(candidate)) return undefined
    seen.add(candidate)
    if (Array.isArray(candidate)) {
      for (const item of candidate) { const failure = visit(item, inheritedStatus); if (failure) return failure }
      return undefined
    }
    const record = asRecord(candidate)
    const responseStatus = parseHttpStatus(asRecord(record.response).status) || inheritedStatus
    if (record.resourceType === 'OperationOutcome') {
      const issues = Array.isArray(record.issue) ? record.issue.map(asRecord) : []
      const issue = issues.find(item => ['error', 'fatal'].includes(String(item.severity || '').toLowerCase()))
      if (issue) return { issue, status: parseHttpStatus(issue.responseStatus) || responseStatus }
    }
    for (const nested of Object.values(record)) { const failure = visit(nested, responseStatus); if (failure) return failure }
    return undefined
  }
  return visit(value)
}

function parseHttpStatus(value: unknown): number | undefined {
  const status = Number.parseInt(String(value ?? ''), 10)
  return Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined
}
function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}
function required(value: unknown, error: string): string {
  const normalized = String(value ?? '').trim(); if (!normalized) throw new TypeError(error); return normalized
}
function routeSegment(value: unknown, error: string): string {
  const normalized = required(value, error); if (!/^[A-Za-z0-9-]+$/u.test(normalized)) throw new TypeError(error); return normalized
}
function secureOrigin(value: unknown, error: string): string {
  const url = new URL(required(value, error))
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(url.hostname))) {
    throw new TypeError('organization_registration_gateway_https_required')
  }
  return url.origin
}
