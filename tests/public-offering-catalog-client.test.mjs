// Flow contract: server-configured tenant feeds supply public Network offerings without accepting browser endpoints, Demo entries or another publisher's claims.
import assert from 'node:assert/strict'
import test from 'node:test'
import { REPOSITORY_SAFE_EXAMPLES as safe } from 'sos-data-utils-ts/repository-privacy'
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
