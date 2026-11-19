// Flow contract: server-configured tenant feeds supply public Network offerings without accepting browser endpoints, Demo entries or another publisher's claims.
import assert from 'node:assert/strict'
import test from 'node:test'
import { REPOSITORY_SAFE_EXAMPLES as safe } from 'sos-data-utils-ts/repository-privacy'
import { buildGatewayDataspaceCatalogArtifactPath, buildGatewayDataspaceOfferingCatalogPath } from 'sos-data-utils-ts/gateway-dataspace-routing'
import { readNetworkPublicOfferingCatalog } from '../dist/public-offering-catalog-client.js'

const source = { gatewayOrigin: safe.httpsBaseUrl, tenantId: safe.tenantId,
  jurisdiction: safe.countryIso2, sector: safe.sector, publisherId: safe.didWeb }
const offering = { id: 'tracker', type: 'Product', sector: safe.sector, category: 'devices', name: 'Example tracker',
  description: 'Animal monitoring device', demo: false, publisher: { id: safe.didWeb, name: safe.organizationLegalName }, offers: [] }

test('reads the configured tenant feed and retains the existing static catalogue', async () => {
  const result = await readNetworkPublicOfferingCatalog({ sourcesJson: JSON.stringify([source]),
    catalogJson: JSON.stringify([{ ...offering, id: 'legacy' }]), fetchImpl: async (url, init) => {
      assert.equal(String(url), `${safe.httpsBaseUrl}/${safe.tenantId}/cds-${safe.countryIso2}/v1/${safe.sector}/dsp/catalog/offerings.json`)
      assert.equal(init.redirect, 'error')
      assert.equal(init.credentials, 'omit')
      assert.deepEqual(init.headers, { accept: 'application/json' })
      return Response.json([offering])
    } })
  assert.deepEqual(result.map(item => item.id), ['legacy', 'tracker'])
})

test('discovers the configured tenant endpoint through DCAT without following another URL', async () => {
  const scope = { ...source, version: 'v1' }
  const catalogUrl = new URL(buildGatewayDataspaceCatalogArtifactPath(scope), source.gatewayOrigin).href
  const feedUrl = new URL(buildGatewayDataspaceOfferingCatalogPath(scope), source.gatewayOrigin).href
  const service = { '@type': 'dcat:DataService', 'dcterms:publisher': { '@id': source.publisherId }, 'dcat:endpointURL': feedUrl }
  const subscriptions = [], sourcesJson = JSON.stringify([{ ...source, discovery: 'dcat' }])
  const read = advertised => readNetworkPublicOfferingCatalog({ sourcesJson, fetchImpl: async (url, init) => {
    subscriptions.push(String(url))
    assert.equal(init.redirect, 'error')
    assert.equal(init.credentials, 'omit')
    if (String(url) === catalogUrl) return Response.json({ '@type': 'dcat:Catalog', 'dcat:service': advertised })
    assert.equal(String(url), feedUrl)
    return Response.json([offering])
  } })
  assert.deepEqual(await read([service]), [offering])
  assert.deepEqual(subscriptions.splice(0), [catalogUrl, feedUrl])
  assert.deepEqual(await read([{ ...service, 'dcat:endpointURL': new URL('/other-tenant', source.gatewayOrigin).href }]), [])
  assert.deepEqual(subscriptions.splice(0), [catalogUrl])
  await assert.rejects(read([{ ...service, 'dcterms:publisher': { '@id': `${source.publisherId}:foreign` } }]), /public_offering_api_scope_mismatch/u)
  assert.deepEqual(subscriptions, [catalogUrl])
})

test('drops withdrawn feeds, rejects mismatches and never follows invalid configured endpoints', async () => {
  const sourcesJson = JSON.stringify([source])
  const read = fetchImpl => readNetworkPublicOfferingCatalog({ sourcesJson, fetchImpl })
  assert.deepEqual(await read(async () => new Response(null, { status: 404 })), [])
  for (const invalid of [{ ...offering, demo: true }, { ...offering, sector: 'education' },
    { ...offering, publisher: { ...offering.publisher, id: `${safe.didWeb}:other` } }, { ...offering, privateEvidence: 'private' }]) {
    await assert.rejects(read(async () => Response.json([invalid])))
  }
  await assert.rejects(read(async () => new Response(null, { status: 500 })))
  await assert.rejects(read(async () => new Response('a'.repeat(1_000_001))))
  await assert.rejects(readNetworkPublicOfferingCatalog({ sourcesJson: JSON.stringify([{ ...source, tenantId: '../host' }]),
    fetchImpl: async () => assert.fail('invalid source must never fetch') }))
  await assert.rejects(readNetworkPublicOfferingCatalog({ sourcesJson, catalogJson: JSON.stringify([offering]),
    fetchImpl: async () => Response.json([offering]) }))
})
