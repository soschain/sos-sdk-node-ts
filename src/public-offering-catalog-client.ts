import { readPublicOfferingCatalog, readPublicOfferingCatalogJson } from 'antifraud-data-utils-ts/public-offering-catalog'
import { buildGatewayDataspaceOfferingCatalogPath } from 'sos-data-utils-ts/gateway-dataspace-routing'

const maximumBytes = 1_000_000
const pathSegment = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u

type OfferingSource = Readonly<{ url: URL; publisherId: string; sector: string }>

function readSources(json: string | undefined): readonly OfferingSource[] {
  if (!json?.trim()) return []
  const invalid = () => new TypeError('public_offering_api_source_invalid')
  if (json.length > maximumBytes) throw invalid()
  const items: unknown = JSON.parse(json)
  if (!Array.isArray(items)) throw invalid()
  return items.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).some(key =>
      !['gatewayOrigin', 'tenantId', 'jurisdiction', 'sector', 'publisherId'].includes(key))) throw invalid()
    const { gatewayOrigin, tenantId, jurisdiction, sector, publisherId } = item
    if (typeof gatewayOrigin !== 'string' || typeof tenantId !== 'string' || !pathSegment.test(tenantId)
      || tenantId.toLowerCase() === 'host' || typeof jurisdiction !== 'string' || !pathSegment.test(jurisdiction)
      || typeof sector !== 'string' || !pathSegment.test(sector)
      || typeof publisherId !== 'string' || !publisherId.startsWith('did:web:')) throw invalid()
    const origin = new URL(gatewayOrigin)
    const localHttp = origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
    if ((origin.protocol !== 'https:' && !localHttp) || origin.username || origin.password
      || origin.search || origin.hash || origin.pathname !== '/') throw invalid()
    const path = buildGatewayDataspaceOfferingCatalogPath({ tenantId, jurisdiction, version: 'v1', sector })
    return { url: new URL(path, origin), publisherId, sector }
  })
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
  const results = await Promise.all(sources.map(async source => {
    const response = await request(source.url, { cache: 'no-store', credentials: 'omit', redirect: 'error',
      signal: AbortSignal.timeout(8_000), headers: { accept: 'application/json' } })
    if (!response.ok) {
      await response.body?.cancel()
      if (response.status === 404) return []
      throw new Error('public_offering_api_unavailable')
    }
    const offerings = readPublicOfferingCatalog(await readJson(response))
    if (offerings.some(offering => offering.demo || offering.publisher.id !== source.publisherId || offering.sector !== source.sector)) {
      throw new TypeError('public_offering_api_scope_mismatch')
    }
    return offerings
  }))
  return readPublicOfferingCatalog([...local, ...results.flat()])
}
