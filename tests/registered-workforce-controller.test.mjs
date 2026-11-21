// Flow contract: only the owner of an unlocked registered organization controller can open workforce transport for its configured host and tenant. The stored public keys must match the recovered wallet, and rejected bindings do not resolve remote keys.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {readPublicOfferingDraftDocument} from 'antifraud-data-utils-ts/public-offering-catalog'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {readFile} from 'node:fs/promises'
import test from 'node:test'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import {buildAuthorityDidWeb,buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const wallet = JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json', import.meta.url), 'utf8'))
const { openRegisteredWorkforceController } = await import('../dist/workforce-client.js')
const gatewayBaseUrl = 'https://gateway.example.invalid'
const providerDid = `${buildAuthorityDidWeb({authority:gatewayBaseUrl})}:${safe.tenantId}:cds-ES-MD:v1:health-care`
const verifiedContact = {contactKind:'phone',contact:safe.phoneE164}
const profile = Object.freeze({
  ownerId: safe.resourceUuid,
  profileId: wallet.walletKeyDerivationId,
  actorKind: ActorKinds.OrganizationController,
  actorMode: 'controller',
  actorDid: buildOrganizationEmployeeDidWeb({...verifiedContact,organizationDidWeb:providerDid,role:'RESPRSN'}),
  providerDid,
  clientId: safe.resourceUuid,
  tenantIssuer: providerDid,
  publicJwks: wallet.publicJwks,
  routeContext: {tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'},
})
const session = {ownerId:profile.ownerId,profileId:profile.profileId,verifiedContact,bearerToken:'synthetic-verified-token'}

function makeOptions(stored = profile, seed = wallet.walletSeed) {
  return {
    gatewayBaseUrl,
    appInfo: {appId:'controller-example',appType:'web',sector:profile.routeContext.sector},
    readUnlockedProfile: async ({ownerId,profileId}) => {
      assert.deepEqual({ownerId,profileId},{ownerId:session.ownerId,profileId:session.profileId})
      return {profile:stored,unlockedWalletSeed:seed}
    },
    fetchImpl: async () => { throw new Error('a rejected binding must not access the network') },
  }
}

test('opens existing custody for encrypted employee search and approved catalogue publication',async()=>{
  const options = makeOptions()
  const controllerKey = wallet.publicJwks.find(key => key.kty === 'OKP')
  const gatewayWallet = new OrganizationRegistrationWallet({resolveRecipientJwk:async did=>{
    assert.equal(did,profile.actorDid)
    return controllerKey
  }})
  await gatewayWallet.provisionCommunicationKeys(wallet.context,createHash('sha256').update(wallet.walletSeed).digest('base64url'))
  const keys = gatewayWallet.getPublicJwks(wallet.context)
  const verificationMethod = [
    {id:`${providerDid}#${keys.signing.kid}`,controller:providerDid,type:'JsonWebKey2020',publicKeyJwk:keys.signing},
    {id:`${providerDid}#${keys.encryption.kid}`,controller:providerDid,type:'JsonWebKey2020',publicKeyJwk:keys.encryption},
  ]
  const route = `/${safe.tenantId}/cds-ES-MD/v1/health-care/entity/org.schema/Employee/_search`
  const catalogRoute = `/${safe.tenantId}/cds-ES-MD/v1/health-care/organization/org.schema/Catalog/_upsert`
  const operationId = safe.resourceUuid
  const document = readPublicOfferingDraftDocument({ data: [{
    type:'Product', id:safe.resourceUuid,
    attributes:{name:'Tracker',description:'Test catalogue item',category:'devices',offers:[]},
  }] })
  const requests = []
  let submittedThread
  const fetchImpl = async (input,init) => {
    const target = new URL(input)
    assert.equal(target.origin,gatewayBaseUrl)
    if (target.pathname.endsWith('/did.json')) return Response.json({
      id:providerDid,verificationMethod,authentication:[verificationMethod[0].id],keyAgreement:[verificationMethod[1].id],
    })
    requests.push(target.pathname)
    assert.equal(init.headers.Authorization,`Bearer ${session.bearerToken}`)
    const {content: request} = await gatewayWallet.unpackWithContext(new URLSearchParams(init.body).get('request'),{context:wallet.context})
    assert.equal(request.iss,profile.actorDid)
    assert.equal(request.aud,providerDid)
    assert.equal(request.client_id,profile.clientId)
    if (target.pathname === route || target.pathname === catalogRoute) {
      if (target.pathname === catalogRoute) {
        assert.equal(request.thid,operationId)
        assert.deepEqual(request.body,document)
      }
      submittedThread = request.thid
      return Response.json({}, {status:202})
    }
    assert.equal(request.thid,submittedThread)
    const catalogue = target.pathname === `${catalogRoute}-response`
    const response = await gatewayWallet.packForRecipientWithContext({
      iss:profile.tenantIssuer,aud:profile.actorDid,thid:submittedThread,
      ...(catalogue ? {type:'org.schema.catalog-publication',body:{total:1}} : {body:{data:[]}}),
    },profile.actorDid,{context:wallet.context})
    return Response.json({response})
  }
  const client = await openRegisteredWorkforceController({...options,fetchImpl},session)
  const result = await client.searchEmployees({ email:safe.individualEmail },{intervalMs:0})
  assert.deepEqual(result.poll.body.body.data,[])
  assert.deepEqual(await client.publishOfferingBatch({document,operationId},{intervalMs:0}),{total:1})
  assert.deepEqual(requests,[route,`${route}-response`,catalogRoute,`${catalogRoute}-response`])
})

test('rejects a different verified contact, a foreign owner, a different route or altered key material',async()=>{
  await assert.rejects(openRegisteredWorkforceController(makeOptions(),
    {...session,verifiedContact:{contactKind:'email',contact:safe.individualEmail}}),/workforce_controller_binding_invalid/)
  for (const selection of [
    {...profile,ownerId:profile.tenantIssuer},
    {...profile,actorKind:ActorKinds.OrganizationEmployee},
    {...profile,routeContext:{...profile.routeContext,tenantId:'other'}},
    {...profile,publicJwks:[]},
  ]) await assert.rejects(openRegisteredWorkforceController(makeOptions(selection),session),/workforce_controller_binding_invalid|registered_communication_wallet_binding_invalid/)
})
