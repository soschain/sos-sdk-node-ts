// Flow contract: reuse shared synthetic fixtures. A signed profile proof is sent only to the
// configured tenant. The tenant returns an offer under its own issuer URL.
import assert from 'node:assert/strict'
import {once} from 'node:events'
import {randomBytes} from 'node:crypto'
import {createServer} from 'node:http'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {prepareProfessionalWalletOffer} from '../dist/index.js'

test('authorizes the professional profile at its tenant and accepts only an offer from that same tenant', async t => {
  const route = {tenantId: e.tenantId, jurisdiction: 'EU', sector: 'health-care'}
  const profile = {clientId: e.resourceUuid, actorDid: `${e.didWeb}:employee`,
    role: HealthcareActorRoles.GeneralistMedicalPractitioner}
  const reference = randomBytes(32).toString('base64url')
  const proof = 'synthetic-signed-professional-proof'
  const calls = []
  let accept = true
  let foreign = false
  const server = createServer(async (request, response) => {
    let body = ''
    for await (const chunk of request) body += chunk
    calls.push({method: request.method, path: request.url, body: JSON.parse(body)})
    response.writeHead(accept ? 201 : 403, {'content-type': 'application/json'})
    response.end(JSON.stringify(foreign ? {...result, offerUri: result.offerUri.replace(e.tenantId, "other-tenant")} : result))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => server.close())
  const gatewayBaseUrl = `http://127.0.0.1:${server.address().port}`
  const routePath = `/${route.tenantId}/cds-${route.jurisdiction}/v1/${route.sector}/identity/openid/wallet/_authorize`
  const credentialIssuer = gatewayBaseUrl.replace('http:', 'https:') + routePath.replace(/\/_authorize$/u, '')
  const result = {offerUri: `${credentialIssuer}/credential-offers/${reference}`, transactionCode: '000001'}
  const options = {gatewayBaseUrl, route, profile, allowLoopbackHttp: true,
    signPresentation: async ({clientId, payload}) => {
      assert.equal(clientId, profile.clientId)
      assert.equal(payload.client_id, profile.clientId)
      assert.equal(payload.aud, gatewayBaseUrl + routePath)
      assert.equal(payload.vp.holder, profile.clientId)
      assert.equal(payload.vp.verifiableCredential[0].credentialSubject.id, profile.actorDid)
      assert.equal(payload.vp.verifiableCredential[0].credentialSubject.hasOccupation, profile.role)
      return proof
    },
    credentialIssuer,
  }
  await assert.rejects(prepareProfessionalWalletOffer({...options, allowLoopbackHttp: false}), /https/iu)
  assert.deepEqual(await prepareProfessionalWalletOffer(options), result)
  assert.deepEqual(calls, [{method: 'POST', path: routePath, body: {client_id: profile.clientId, vp_token: proof}}])
  foreign = true
  await assert.rejects(prepareProfessionalWalletOffer(options), /offer/iu)
  accept = false
  await assert.rejects(prepareProfessionalWalletOffer(options), /403/)
})
