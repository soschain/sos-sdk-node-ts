import {randomUUID} from 'node:crypto'
import type {RouteContext} from 'sos-data-utils-ts/gateway-transport-contract'
import {buildProfessionalEmployeeCredential} from 'sos-data-utils-ts/professional-smart'
import {getIndividualMemberIdentityVC} from 'sos-data-utils-ts/individual-smart'

export type PreparedProfessionalWalletOffer = Readonly<{offerUri: string; transactionCode: string}>

type WalletOfferOptions = Readonly<{
  gatewayBaseUrl: string
  route: RouteContext
  signPresentation: (input: Readonly<{clientId: string; payload: Record<string, unknown>}>) => Promise<string>
  credentialIssuer?: string
  allowLoopbackHttp?: boolean
  fetch?: typeof globalThis.fetch
}>

export type PrepareProfessionalWalletOfferOptions = WalletOfferOptions & Readonly<{
  profile: Readonly<{clientId: string; actorDid: string; role: string}>
}>

export type PrepareIndividualAgeWalletOfferOptions = WalletOfferOptions & Readonly<{
  profile: Readonly<{clientId: string; actorDid: string; subjectDid: string; relationship: string}>
}>

function walletUrl(options: WalletOfferOptions): URL {
  const base = new URL(options.gatewayBaseUrl)
  const loopback = base.hostname === 'localhost' || base.hostname === '127.0.0.1'
  if ((base.protocol !== 'https:' && !(base.protocol === 'http:' && loopback && options.allowLoopbackHttp))
    || base.username || base.password || base.pathname !== '/' || base.hash || base.search) {
    throw new TypeError('Wallet authorization requires a trusted HTTPS gateway origin')
  }
  const {tenantId, jurisdiction, sector} = options.route
  if (!/^[A-Za-z0-9_-]{1,100}$/u.test(tenantId) || tenantId === 'host'
    || !/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/u.test(jurisdiction) || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(sector)) {
    throw new TypeError('Wallet authorization requires a tenant route')
  }
  return new URL(`/${tenantId}/cds-${jurisdiction}/v1/${sector}/identity/openid/wallet`, base)
}

/** Prepares the wallet offer from an authenticated, unlocked registered professional profile. */
export async function prepareProfessionalWalletOffer(options: PrepareProfessionalWalletOfferOptions): Promise<PreparedProfessionalWalletOffer> {
  const {clientId, actorDid, role} = options.profile
  if (!clientId || !actorDid || !role) throw new TypeError('A registered professional and role are required')
  return prepareRegisteredWalletOffer(options, '_authorize', clientId, buildProfessionalEmployeeCredential({actorDid, role}))
}

/** Authorizes the current member to receive their own age attestation. Evidence is resolved by the issuer. */
export async function prepareIndividualAgeWalletOffer(options: PrepareIndividualAgeWalletOfferOptions): Promise<PreparedProfessionalWalletOffer> {
  const {clientId, actorDid, subjectDid, relationship} = options.profile
  if (!clientId || !actorDid || !subjectDid || !relationship) throw new TypeError('A registered individual member is required')
  return prepareRegisteredWalletOffer(options, '_authorize-proof-of-age', clientId,
    getIndividualMemberIdentityVC({actorDid, subjectDid, relationship}))
}

async function prepareRegisteredWalletOffer(
  options: WalletOfferOptions,
  action: '_authorize' | '_authorize-proof-of-age',
  clientId: string,
  credential: object,
): Promise<PreparedProfessionalWalletOffer> {
  const wallet = walletUrl(options)
  const issuerPath = wallet.pathname
  const endpoint = new URL(`${issuerPath}/${action}`, wallet)
  const issuer = new URL(options.credentialIssuer ?? issuerPath, endpoint)
  const loopback = endpoint.hostname === 'localhost' || endpoint.hostname === '127.0.0.1'
  const localTlsProxy = options.allowLoopbackHttp && loopback && issuer.hostname === endpoint.hostname
  if (issuer.protocol !== 'https:' || issuer.pathname !== issuerPath || issuer.search || issuer.hash
    || issuer.username || issuer.password || (issuer.origin !== endpoint.origin && !localTlsProxy)) {
    throw new TypeError('Wallet offers must use the trusted HTTPS tenant issuer')
  }
  const now = Math.floor(Date.now() / 1000)
  const vpToken = await options.signPresentation({clientId, payload: {
    iss: clientId,
    client_id: clientId,
    aud: endpoint.href,
    jti: randomUUID(),
    iat: now,
    exp: now + 480,
    vp: {holder: clientId, verifiableCredential: [credential]},
  }})
  const response = await (options.fetch ?? fetch)(endpoint, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
    headers: {accept: 'application/json', 'content-type': 'application/json'},
    body: JSON.stringify({client_id: clientId, vp_token: vpToken}),
  })
  if (response.status !== 201) throw new Error(`Wallet authorization failed with HTTP ${response.status}`)
  const result = await response.json() as {offerUri?: unknown; transactionCode?: unknown} | null
  const prefix = issuer.href + '/credential-offers/'
  if (typeof result?.offerUri !== 'string' || !result.offerUri.startsWith(prefix)
    || !/^[A-Za-z0-9_-]{43}$/u.test(result.offerUri.slice(prefix.length))
    || typeof result.transactionCode !== 'string' || !/^\d{6}$/u.test(result.transactionCode)) {
    throw new Error('Invalid wallet offer from the tenant')
  }
  return {offerUri: result.offerUri, transactionCode: result.transactionCode}
}
