// Flow contract: 1) an owned client sends encrypted verification over real loopback HTTP; 2) an independent wallet decodes it; 3) polling preserves thread and actor binding; 4) only an encrypted terminal response completes the exchange. A rejected submit never starts polling. This transport integration does not replace the real portal/GW journey.
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import test from 'node:test'
import {OrganizationRegistrationClient,TransportProfiles} from '../dist/organization-registration-client.js'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {SchemaOrgServiceClaim} from 'antifraud-data-utils-ts/organization-service-catalog'

const context=id=>({runtime:{runtimeId:id,runtimeType:'backend-service'}})
const route={tenantId:safe.tenantId,jurisdiction:'CA-BC',sector:safe.sector}
const host={jurisdiction:'CA-BC',hostNetwork:'test',controllerDid:safe.didWeb,hostDid:`${safe.didWeb}:host`}

for(const jurisdiction of [host.jurisdiction,'001']){
test(`submits and polls protected organization requests under host coverage ${jurisdiction}`,async()=>{
  const scopedHost={...host,jurisdiction}
  const clientContext=context('synthetic-client'),serverContext=context('synthetic-gateway')
  let clientKey
  const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>clientKey})
  await gateway.provisionCommunicationKeys(serverContext,'synthetic-server-seed')
  const wallet=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gateway.getPublicJwks(serverContext).encryption})
  await wallet.provisionCommunicationKeys(clientContext,'synthetic-client-seed')
  clientKey=wallet.getPublicJwks(clientContext).encryption
  const seen=[]
  let polls=0,serverFailure
  const server=createServer(async(request,response)=>{
    try{
      assert.equal(request.headers.authorization,'Bearer synthetic-test-token')
      assert.equal(request.headers['content-type'],TransportProfiles.DidcommEncryptedForm)
      const chunks=[];for await(const chunk of request)chunks.push(chunk)
      const packed=new URLSearchParams(Buffer.concat(chunks).toString('utf8')).get('request')
      const message=(await gateway.unpackWithContext(packed,{context:serverContext})).content
      seen.push({path:request.url,message})
      if(request.url.endsWith('_transaction')){response.writeHead(202,{'Content-Type':'application/json'});response.end(JSON.stringify({thid:message.thid}));return}
      assert.equal(message.thid,seen[0].message.thid)
      assert.equal(message.iss,host.controllerDid)
      assert.equal(message.aud,host.hostDid)
      if(++polls===1){response.writeHead(202);response.end();return}
      const result=await gateway.packForRecipientWithContext({accepted:true},safe.didWeb,{context:serverContext})
      response.writeHead(200,{'Content-Type':TransportProfiles.DidcommEncryptedForm})
      response.end(`response=${encodeURIComponent(result)}`)
    }catch(error){serverFailure=error;response.writeHead(500);response.end()}
  })
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
  try{
    const baseUrl=`http://127.0.0.1:${server.address().port}`
    const client=new OrganizationRegistrationClient({baseUrl,bearerToken:'synthetic-test-token',ctx:route,transportProfile:TransportProfiles.DidcommEncryptedForm,secureTransportAdapter:{pack:message=>wallet.packForRecipientWithContext(message,safe.didWeb,{context:clientContext}),unpack:async value=>(await wallet.unpackWithContext(value,{context:clientContext})).content}})
    const result=await client.submitLegalOrganizationVerificationTransaction(scopedHost,{claims:{[SchemaOrgServiceClaim.Category]:safe.sector},controller:{did:safe.didWeb},attachments:[{id:'synthetic-evidence'}]},{intervalMs:0,timeoutMs:5000})
    assert.equal(serverFailure,undefined)
    assert.deepEqual(result.poll.body,{accepted:true})
    assert.equal(result.poll.attempts,2)
    assert.equal(seen[0].path,`/host/cds-${jurisdiction}/v1/test/registry/org.schema/Organization/_transaction`)
    assert.deepEqual(seen[0].message.attachments,[{id:'synthetic-evidence'}])
    assert.equal(Object.hasOwn(seen[0].message.body,'attachments'),false)
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
})
}

test('uses the global host coverage for Order and credential reissuance without changing the tenant route',async()=>{
 const paths=[]
 const client=new OrganizationRegistrationClient({baseUrl:safe.httpsBaseUrl,bearerToken:'synthetic-test-token',ctx:route,transportProfile:TransportProfiles.DidcommEncryptedForm,secureTransportAdapter:{pack:async()=> 'synthetic.protected.key.ciphertext.tag',unpack:async()=>{throw new Error('must_not_decode')}},fetchImpl:async url=>{paths.push(new URL(url).pathname);return new Response('{}',{status:403})}})
 await assert.rejects(client.confirmLegalOrganizationOrder({...host,jurisdiction:'001'},{offerId:'synthetic-offer'}),error=>error.status===403)
 await assert.rejects(client.submitLegalOrganizationCredentialReissuance({...host,jurisdiction:'001'},{claims:{[SchemaOrgServiceClaim.Category]:safe.sector},controller:{did:safe.didWeb}}),error=>error.status===403)
 assert.deepEqual(paths,['/host/cds-001/v1/test/registry/org.schema/Order/_batch','/host/cds-001/v1/test/registry/org.schema/Organization/_issue'])
 assert.equal(route.jurisdiction,'CA-BC')
})

test('rejects malformed host scopes and network selectors before encryption or HTTP',async()=>{
 let requests=0,encryptions=0
 const client=new OrganizationRegistrationClient({baseUrl:safe.httpsBaseUrl,bearerToken:'synthetic-test-token',ctx:route,transportProfile:TransportProfiles.DidcommEncryptedForm,secureTransportAdapter:{pack:async()=>{encryptions++;return 'synthetic.protected.key.ciphertext.tag'},unpack:async()=>({})},fetchImpl:async()=>{requests++;return new Response('{}',{status:403})}})
 for(const jurisdiction of ['001/../CA','001?x','1','0001','../001'])assert.throws(()=>client.confirmLegalOrganizationOrder({...host,jurisdiction},{offerId:'synthetic-offer'}),/organization_registration_host_route_invalid/u)
 assert.throws(()=>client.confirmLegalOrganizationOrder({...host,jurisdiction:'001',hostNetwork:'test-network/../network'},{offerId:'synthetic-offer'}),/organization_registration_host_route_invalid/u)
 assert.equal(requests,0);assert.equal(encryptions,0)
})

test('a rejected submit is terminal and cannot poll or downgrade to plaintext success',async()=>{
  let requests=0
  const client=new OrganizationRegistrationClient({baseUrl:safe.httpsBaseUrl,bearerToken:'synthetic-test-token',ctx:route,transportProfile:TransportProfiles.DidcommEncryptedForm,secureTransportAdapter:{pack:async()=> 'synthetic.protected.key.ciphertext.tag',unpack:async()=>{throw new Error('must_not_decode')}},fetchImpl:async()=>{requests++;return new Response(JSON.stringify({resourceType:'OperationOutcome'}),{status:403})}})
  await assert.rejects(client.confirmLegalOrganizationOrder(host,{offerId:'synthetic-offer'}),error=>error.status===403)
  assert.equal(requests,1)
})
