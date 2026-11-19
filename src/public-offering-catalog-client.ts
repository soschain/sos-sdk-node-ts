import { readPublicOfferingCatalog, readPublicOfferingCatalogJson } from 'antifraud-data-utils-ts/public-offering-catalog'
import { buildGatewayDataspaceCatalogArtifactPath, buildGatewayDataspaceOfferingCatalogPath } from 'sos-data-utils-ts/gateway-dataspace-routing'

const maximumBytes = 1_000_000
const pathSegment = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u

type OfferingSource = Readonly<{ url: URL; catalogUrl?: URL; publisherId: string; sector: string }>

function readSources(json: string | undefined): readonly OfferingSource[] {
  if (!json?.trim()) return []
  const invalid = () => new TypeError('public_offering_api_source_invalid')
  if (json.length > maximumBytes) throw invalid()
  const items: unknown = JSON.parse(json)
  if (!Array.isArray(items)) throw invalid()
  return items.map(readSource)
}

function readSource(item: unknown): OfferingSource {
  const invalid = () => new TypeError('public_offering_api_source_invalid')
  const source = record(item)
  if (!source || Object.keys(source).some(key =>
    !['gatewayOrigin', 'tenantId', 'jurisdiction', 'sector', 'publisherId', 'discovery'].includes(key))) throw invalid()
  const { gatewayOrigin, tenantId, jurisdiction, sector, publisherId, discovery } = source
  if (typeof gatewayOrigin !== 'string' || typeof tenantId !== 'string' || !pathSegment.test(tenantId)
    || tenantId.toLowerCase() === 'host' || typeof jurisdiction !== 'string' || !pathSegment.test(jurisdiction)
    || typeof sector !== 'string' || !pathSegment.test(sector)
    || typeof publisherId !== 'string' || !publisherId.startsWith('did:web:')
    || (discovery !== undefined && discovery !== 'dcat')) throw invalid()
  const origin = new URL(gatewayOrigin)
  const localHttp = origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
  if ((origin.protocol !== 'https:' && !localHttp) || origin.username || origin.password
    || origin.search || origin.hash || origin.pathname !== '/') throw invalid()
  const scope = { tenantId, jurisdiction, version: 'v1', sector }
  return { url: new URL(buildGatewayDataspaceOfferingCatalogPath(scope), origin), publisherId, sector,
    ...(discovery === 'dcat' ? { catalogUrl: new URL(buildGatewayDataspaceCatalogArtifactPath(scope), origin) } : {}) }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

function advertisesOfferingFeed(value: unknown, source: OfferingSource): boolean {
  const catalog = record(value)
  const services = catalog?.['dcat:service']
  if (catalog?.['@type'] !== 'dcat:Catalog' || !Array.isArray(services)) throw new TypeError('public_offering_dcat_invalid')
  const matching = services.map(record).filter(node => {
    const endpoint = node?.['dcat:endpointURL']
    return node?.['@type'] === 'dcat:DataService' && (endpoint === source.url.href || record(endpoint)?.['@id'] === source.url.href)
  })
  if (matching.some(node => record(node?.['dcterms:publisher'])?.['@id'] !== source.publisherId)) {
    throw new TypeError('public_offering_api_scope_mismatch')
  }
  return matching.length > 0
}

async function fetchPublicJson(request: typeof fetch, url: URL, signal: AbortSignal, accept: string) {
  const response = await request(url, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal, headers: { accept } })
  if (response.ok) return readJson(response)
  await response.body?.cancel()
  if (response.status === 404) return undefined
  throw new Error('public_offering_api_unavailable')
}

async function readJson(response: Response): Promise<unknown> {
  if (!response.body || Number(response.headers.get('content-length')) > maximumBytes) {
    await response.body?.cancel()
    throw new TypeError('public_offering_api_response_invalid')
  }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > maximumBytes) {
        await reader.cancel()
        throw new TypeError('public_offering_api_response_invalid')
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}

/** Reads public Network offerings from host-selected tenant feeds and the existing local catalogue. */
export async function readNetworkPublicOfferingCatalog(input: Readonly<{
  sourcesJson?: string; catalogJson?: string; fetchImpl?: typeof fetch
}>) {
  const local = readPublicOfferingCatalogJson(input.catalogJson, false)
  const sources = readSources(input.sourcesJson)
  const request = input.fetchImpl ?? fetch
  const results = await Promise.all(sources.map(source => readOfferingSource(request, source)))
  return readPublicOfferingCatalog([...local, ...results.flat()])
}

/** Reads the public feed for a known gateway scope, with no controller credentials. */
export function readTenantPublicOfferingCatalog(input: Readonly<{
  gatewayOrigin: string; tenantId: string; jurisdiction: string; sector: string; publisherId: string
}>, fetchImpl: typeof fetch = fetch) {
  return readOfferingSource(fetchImpl, readSource(input))
}

async function readOfferingSource(request: typeof fetch, source: OfferingSource) {
  const signal = AbortSignal.timeout(8_000)
  if (source.catalogUrl) {
    const catalog = await fetchPublicJson(request, source.catalogUrl, signal, 'application/ld+json, application/json')
    if (catalog === undefined || !advertisesOfferingFeed(catalog, source)) return []
  }
  const feed = await fetchPublicJson(request, source.url, signal, 'application/json')
  if (feed === undefined) return []
  const offerings = readPublicOfferingCatalog(feed)
  if (offerings.some(offering => offering.demo || offering.publisher.id !== source.publisherId || offering.sector !== source.sector)) {
    throw new TypeError('public_offering_api_scope_mismatch')
  }
  return offerings
}
