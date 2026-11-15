// Flow contract: trusted host actor/profile/contact and provider configuration drive pre-DCR encrypted Token then Device operations without an employee grant. Real PQC packing/verifying preserves six custody purposes, stable installation and five public DCR keys through an uncertain acknowledgement. This simulated transport peer does not establish GW authorization or online enrollment; actual manager replay has a separate persisted regression.
import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {openServerProfileCustodyKeys} from '../dist/server-profile-custody-keys.js'
import {createVerifiedGatewaySecureAdapter} from '../dist/registered-gateway-transport.js'
const owned=await import('../dist/device-enrollment-client.js').catch(error=>{
 if(error.code==='ERR_MODULE_NOT_FOUND')return {}
 throw error
})
function need(){assert.equal(typeof owned.DeviceEnrollmentClient,'function','missing owned DeviceEnrollmentClient');return owned.DeviceEnrollmentClient}
const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),randomUUID,
 digestString:async(s,a)=>createHash(a.replaceAll('-','').toLowerCase()).update(s).digest('hex')})
const seed=JSON.parse(readFileSync(new URL('./fixtures/registered-communication-wallet.json',import.meta.url),'utf8'))
const ctx={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'}
const gatewayDid=safe.didWeb,providerDid=`${gatewayDid}:${ctx.tenantId}:cds-es-md:v1:${ctx.sector}`
const actorDid=`${providerDid}:controller`,contact={contactKind:'phone',contact:safe.phoneE164}
const walletContext=id=>({profile:{profileId:id},runtime:{runtimeId:`${id}:server-runtime`,runtimeType:'backend-service'}})
async function fixture({lostAck=false,foreignReply=false}={}){
 const recipientContext=walletContext(seed.walletKeyDerivationId),gatewayContext=walletContext('synthetic-enrollment-gateway')
 let recipientPublic
 const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>recipientPublic.encryption})
 await gateway.provisionCommunicationKeys(gatewayContext,'synthetic-enrollment-peer-seed')
 const gatewayPublic=gateway.getPublicJwks(gatewayContext)
 const recipient=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gatewayPublic.encryption})
 await recipient.provisionCommunicationKeys(recipientContext,seed.walletSeed)
 recipientPublic=recipient.getPublicJwks(recipientContext)
 const custody=await openServerProfileCustodyKeys({walletKeyDerivationId:seed.walletKeyDerivationId,unlockedWalletSeed:seed.walletSeed,binding:{kind:'enrollment'}})
 assert.deepEqual(custody.publicJwks.find(key=>key.kty==='AKP'),{...recipientPublic.signing,use:'sig'})
 assert.deepEqual(custody.publicJwks.find(key=>key.kty==='OKP'),recipientPublic.encryption)
 const adapter=createVerifiedGatewaySecureAdapter({gatewayDid,
  pack:message=>recipient.packBootstrapForRecipientWithContext(message,providerDid,{context:recipientContext}),
  decrypt:packed=>recipient.unpackWithContext(packed,{context:recipientContext}),resolveGatewaySigningJwk:async did=>{
   assert.equal(did,gatewayDid);return gatewayPublic.signing
  }})
 const replies=new Map(),messages=[],registrations=[]
 let lose=lostAck
 const fetchImpl=async(url,init)=>{
  const packed=new URLSearchParams(init.body).get('request')
  const decrypted=await gateway.unpackWithContext(packed,{context:gatewayContext})
  const compact=decrypted.meta.jws.compact
  const header=JSON.parse(Buffer.from(compact.split('.')[0],'base64url'))
  assert.deepEqual(header.jwk,recipientPublic.signing)
  assert.equal(await crypto.verifyJws(compact,recipientPublic.signing),true)
  const message=decrypted.content
  messages.push({path:new URL(url).pathname,message})
  assert.equal(message.iss,actorDid);assert.equal(message.aud,providerDid)
  if(!new URL(url).pathname.endsWith('-response')){
   let body,iss
   if(new URL(url).pathname.includes('/Token/')){
    assert.equal(init.headers.Authorization,'Bearer synthetic-verified-phone-token')
    assert.equal(message.body.subject_token,'synthetic-controller-activation-code')
    body={initial_access_token:'synthetic-host-initial-token',token_type:'Bearer',scope:'dcr:register',expires_in:300};iss=providerDid
   }else{
    assert.equal(init.headers.Authorization,'Bearer synthetic-host-initial-token')
    assert.equal(message.body.actor_did,actorDid);assert.equal(message.body.profile_did,actorDid)
    assert.equal(message.body.ext_device_info.device_id,'synthetic-stable-installation')
    assert.deepEqual(message.body.jwks.keys,custody.publicJwks)
    assert.equal(message.body.jwks.keys.some(key=>key.kid===custody.storagePublicJwk.kid),false)
    if(registrations.length)assert.deepEqual(message.body,registrations[0])
    else registrations.push(message.body)
    body={data:[{response:{status:'201'},resource:{resourceType:'Device',id:'synthetic-stable-client',client_id:'synthetic-stable-client',registration_client_uri:'https://example.invalid/clients/synthetic-stable-client'}}]};iss=gatewayDid
    if(lose){lose=false;throw new Error('synthetic_dcr_ack_lost')}
   }
   replies.set(message.thid,{jti:randomUUID(),iss:foreignReply?`did:web:foreign.example.invalid`:iss,aud:actorDid,thid:message.thid,body})
   return new Response('{}',{status:202,headers:{'content-type':'application/json'}})
  }
  const response=await gateway.packForRecipientWithContext(replies.get(message.thid),actorDid,{context:gatewayContext})
  return new Response(JSON.stringify({response}),{status:200,headers:{'content-type':'application/json'}})
 }
 const options={baseUrl:'https://example.invalid',ctx:{...ctx},providerDid,gatewayDid,dcrResponseIssuer:gatewayDid,
  expectedProfile:{actorDid,profileDid:actorDid,contact:{...contact}},bearerToken:'synthetic-verified-phone-token',
  transportProfile:'pre-dcr-didcomm-encrypted',secureTransportAdapter:adapter,fetchImpl,allowLoopbackRedirectUris:true}
 const input={verifiedContact:contact,activationCode:'synthetic-controller-activation-code',clientInstanceId:'synthetic-stable-installation',
  publicJwks:custody.publicJwks,enrollmentKeyDescriptors:custody.descriptors,redirectUris:['http://localhost:4338/__/auth/handler']}
 return {options,input,messages,registrations,custody}
}
test('enrolls a host-bound phone controller through real encrypted exchange without an employee grant',async()=>{
 const Client=need(),f=await fixture()
 const result=await new Client(f.options).enroll(f.input,{intervalMs:0})
 assert.equal(result.clientId,'synthetic-stable-client')
 assert.equal(result.actorDid,actorDid);assert.equal(result.profileDid,actorDid)
 assert.deepEqual(result.routeContext,ctx);assert.equal(f.messages.length,4)
 assert.equal(f.custody.descriptors.length,6)
})
test('uncertain DCR acknowledgement retry keeps identical installation and public keys with new correlation threads',async()=>{
 const Client=need(),f=await fixture({lostAck:true}),client=new Client(f.options)
 await assert.rejects(client.enroll(f.input,{intervalMs:0}),/synthetic_dcr_ack_lost/u)
 const result=await client.enroll(f.input,{intervalMs:0})
 assert.equal(result.clientId,'synthetic-stable-client');assert.equal(f.registrations.length,1)
 const attempts=f.messages.filter(row=>row.path.endsWith('/Device/_dcr'))
 assert.equal(attempts.length,2);assert.notEqual(attempts[0].message.thid,attempts[1].message.thid)
 assert.deepEqual(attempts[0].message.body,attempts[1].message.body)
})
test('rejects a different verified contact before transport and a signed foreign reply issuer',async()=>{
 const Client=need(),f=await fixture(),client=new Client(f.options)
 await assert.rejects(client.enroll({...f.input,verifiedContact:{contactKind:'email',contact:safe.firstContactEmail}}))
 assert.equal(f.messages.length,0)
 const foreign=await fixture({foreignReply:true})
 await assert.rejects(new Client(foreign.options).enroll(foreign.input,{intervalMs:0}),/binding_invalid/u)
})
test('snapshots host actor/profile/contact and tenant configuration before later caller mutations',async()=>{
 const Client=need(),f=await fixture(),client=new Client(f.options)
 f.options.expectedProfile.actorDid='did:web:foreign.example.invalid:controller'
 f.options.expectedProfile.profileDid=f.options.expectedProfile.actorDid
 f.options.expectedProfile.contact={contactKind:'email',contact:safe.firstContactEmail}
 f.options.ctx.tenantId='foreign-tenant'
 const result=await client.enroll(f.input,{intervalMs:0})
 assert.equal(result.actorDid,actorDid);assert.deepEqual(result.routeContext,ctx)
 assert.ok(f.messages.every(row=>row.path.startsWith(`/${ctx.tenantId}/`)))
})
