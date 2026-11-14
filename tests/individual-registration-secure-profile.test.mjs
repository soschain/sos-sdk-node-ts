// Flow contract: an already opened employee wallet signs and encrypts registration and polling over real HTTP; only a response signed by the configured GW key with matching issuer/audience/thread becomes a bound receipt. Missing or false signatures and decryption failures cannot downgrade to decoded plaintext. This does not replace live GW employee/group admission or the Personal recipient acceptance journey.
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {createHash,randomBytes} from 'node:crypto'
import test from 'node:test'
import * as api from '../dist/individual-registration-client.js'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {encodeMultibaseSha3} from 'antifraud-data-utils-ts/encoding'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const context=id=>({runtime:{runtimeId:id,runtimeType:'backend-service'}})
const employeeDid=`${safe.didWeb}:employee:synthetic-dentist`
const providerDid=safe.didWeb
const route={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'}
const clientId='synthetic-active-client'
const bytes=Uint8Array.from(safe.resourceUuid.replaceAll('-','').match(/../gu),value=>Number.parseInt(value,16))
const subjectDid=`${providerDid}:individual:multibase:${encodeMultibaseSha3(bytes,384)}`
const claims={'@context':'org.schema','Organization.identifier.value':safe.resourceUuid,'Organization.alternateName':'Dependent subject','Organization.owner.email':safe.firstContactEmail,'Service.category':'health-care'}

async function exercise(mode,run){
 const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),digestString:async(data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data).digest('hex'),randomUUID:()=>globalThis.crypto.randomUUID()})
 const clientContext=context('synthetic-opened-employee'),gatewayContext=context('synthetic-registered-gateway'),rogueContext=context('synthetic-untrusted-signer')
 let clientPublic
 const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>clientPublic.encryption})
 await gateway.provisionCommunicationKeys(gatewayContext,'synthetic-gateway-keys')
 const gatewayPublic=gateway.getPublicJwks(gatewayContext)
 const employee=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gatewayPublic.encryption})
 await employee.provisionCommunicationKeys(clientContext,'synthetic-existing-employee-keys')
 clientPublic=employee.getPublicJwks(clientContext)
 const rogue=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>clientPublic.encryption})
 await rogue.provisionCommunicationKeys(rogueContext,'synthetic-untrusted-keys')
 const headerSigner=await crypto.generateKeyPairMlDsa(randomBytes(32),'ML-DSA-44')
 const headerPublic={...headerSigner.publicJWKey,kid:`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${headerSigner.publicJWKey.kid}`}
 const requests=[];let serverFailure
 const server=createServer(async(request,response)=>{
  try{
   assert.equal(request.headers.authorization,'Bearer synthetic-verified-professional-token')
   assert.equal(request.headers['content-type'],'application/x-www-form-urlencoded')
   const chunks=[];for await(const chunk of request)chunks.push(chunk)
   const packed=new URLSearchParams(Buffer.concat(chunks).toString()).get('request')
   assert.ok(packed)
   const decoded=await gateway.unpackWithContext(packed,{context:gatewayContext})
   assert.equal(await crypto.verifyJws(decoded.meta.jws.compact,clientPublic.signing),true)
   const message=decoded.content
   assert.equal(message.client_id,clientId)
   assert.equal(message.iss,employeeDid);assert.equal(message.aud,providerDid)
   requests.push(message)
   if(request.url.endsWith('/_transaction')){
    assert.deepEqual(message.body.data[0].resource.meta.claims,claims)
    assert.equal(Object.hasOwn(message.body.data[0].resource.meta.claims,'Organization.member.role'),false)
    assert.equal(Object.hasOwn(message,'authenticatedTransport'),false)
    response.writeHead(202,{'Content-Type':'application/json'});response.end('{}');return
   }
   assert.equal(message.thid,requests[0].thid)
   const result={iss:mode==='foreign-issuer'?`${providerDid}:foreign`:providerDid,aud:mode==='wrong-audience'?`${employeeDid}:foreign`:employeeDid,thid:mode==='wrong-thread'?'synthetic-foreign-thread':message.thid,body:{resourceType:'Bundle',type:'collection',data:[{type:'Family-registration-offer-v1.0',resource:{resourceType:'Organization',id:safe.resourceUuid,meta:{claims:{'org.schema.Organization.did':subjectDid,'org.schema.Organization.sameAs':`${providerDid}:card:synthetic-dependent`,'org.schema.Offer.identifier':'synthetic-offer','org.schema.Offer.offeredBy':providerDid}}},response:{status:'201'}}]}}
   let reply=mode==='wrong-signer'?await rogue.packForRecipientWithContext(result,employeeDid,{context:rogueContext}):await gateway.packForRecipientWithContext(result,employeeDid,{context:gatewayContext})
   if(mode==='unsigned'){
    const ephemeral=await crypto.generateKeyPairMlKem(randomBytes(64),'ML-KEM-768')
    reply=await crypto.encryptJweToCompact(JSON.stringify(result),{enc:'A256GCM',skid:ephemeral.publicJWKey.kid,cty:'application/json'},{...ephemeral.publicJWKey,dBytes:ephemeral.secretKeyBytes},clientPublic.encryption)
   }
   if(mode==='missing-signature'){
    const compact=`${Buffer.from(JSON.stringify({alg:'ML-DSA-44',kid:gatewayPublic.signing.kid})).toString('base64url')}.${Buffer.from(JSON.stringify(result)).toString('base64url')}.`
    const ephemeral=await crypto.generateKeyPairMlKem(randomBytes(64),'ML-KEM-768')
    reply=await crypto.encryptJweToCompact(compact,{enc:'A256GCM',skid:ephemeral.publicJWKey.kid,cty:'JWS'},{...ephemeral.publicJWKey,dBytes:ephemeral.secretKeyBytes},clientPublic.encryption)
   }
   if(mode==='missing-kid'||mode==='alg-none'){
    const header=mode==='missing-kid'?{alg:'ML-DSA-44'}:{alg:'none',kid:headerPublic.kid}
    const protectedPart=Buffer.from(JSON.stringify(header)).toString('base64url'),payloadPart=Buffer.from(JSON.stringify(result)).toString('base64url')
    const signature=await crypto.signBytes(Buffer.from(`${protectedPart}.${payloadPart}`),headerSigner.secretKeyBytes,'ML-DSA-44')
    const compact=`${protectedPart}.${payloadPart}.${Buffer.from(signature).toString('base64url')}`
    assert.equal(await crypto.verifyJws(compact,headerPublic),true,'signature is mathematically valid; header policy must still reject it')
    const ephemeral=await crypto.generateKeyPairMlKem(randomBytes(64),'ML-KEM-768')
    reply=await crypto.encryptJweToCompact(compact,{enc:'A256GCM',skid:ephemeral.publicJWKey.kid,cty:'JWS'},{...ephemeral.publicJWKey,dBytes:ephemeral.secretKeyBytes},clientPublic.encryption)
   }
   if(mode==='tampered'){
    const parts=reply.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);reply=parts.join('.')
   }
   response.writeHead(200,{'Content-Type':'application/x-www-form-urlencoded'})
   response.end(`response=${encodeURIComponent(reply)}`)
  }catch(error){serverFailure=error;response.writeHead(500);response.end()}
 })
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{
  assert.equal(typeof api.createIndividualRegistrationSecureAdapter,'function','owned signature-verifying adapter is required')
  const adapter=api.createIndividualRegistrationSecureAdapter({
   gatewayDid:providerDid,
   pack:message=>employee.packForRecipientWithContext(message,providerDid,{context:clientContext}),
   decrypt:async packed=>{
    const decoded=await employee.unpackWithContext(packed,{context:clientContext})
    if(mode==='decoded-without-signature')return {content:decoded.content,meta:{}}
    if(mode==='decoded-content-replaced')return {...decoded,content:{forged:true}}
    return decoded
   },
   resolveGatewaySigningJwk:async did=>{assert.equal(did,providerDid);if(mode==='wrong-key-material')return {...rogue.getPublicJwks(rogueContext).signing,kid:gatewayPublic.signing.kid};return mode==='missing-kid'||mode==='alg-none'?headerPublic:gatewayPublic.signing},
  })
  const client=new api.IndividualRegistrationClient({baseUrl:`http://127.0.0.1:${server.address().port}`,bearerToken:'synthetic-verified-professional-token',ctx:route,issuerDid:employeeDid,recipientDid:providerDid,clientId,transportProfile:'registered-didcomm-encrypted',secureTransportAdapter:adapter})
  await run(client,requests)
  assert.equal(serverFailure,undefined)
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
}

test('uses a real signed/encrypted employee exchange and ignores unverified decoded callback content',async()=>{
 for(const mode of ['valid','decoded-content-replaced'])await exercise(mode,async(client,requests)=>{
  const result=await client.registerIndividualOrganization({claims},{intervalMs:0,timeoutMs:5000})
  assert.equal(result.identity.canonicalSubjectIdentifier,subjectDid)
  assert.equal(result.offerId,'synthetic-offer');assert.equal(requests.length,2)
 })
})

test('rejects a wrong registered signer, tampered ciphertext, unsigned reply and unverified decoded content',async()=>{
 for(const mode of ['wrong-signer','wrong-key-material','tampered','unsigned','missing-signature','decoded-without-signature','missing-kid','alg-none'])await exercise(mode,async client=>{
  await assert.rejects(client.registerIndividualOrganization({claims},{intervalMs:0,timeoutMs:5000}))
 })
})

test('rejects an authenticated but misbound issuer, audience or thread after signature verification',async()=>{
 for(const mode of ['foreign-issuer','wrong-audience','wrong-thread'])await exercise(mode,async client=>{
  await assert.rejects(client.registerIndividualOrganization({claims},{intervalMs:0,timeoutMs:5000}),/binding/)
 })
})
