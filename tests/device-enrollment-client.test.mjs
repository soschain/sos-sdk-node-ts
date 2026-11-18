// Flow contract: trusted host actor/profile/contact and provider configuration drive pre-DCR encrypted Token then Device operations without an employee grant. Await sealed operation checkpoints before mutations; recover lost submit acknowledgements only by polling the original operation and fail closed when its consumed result is unavailable. Real PQC custody, identity bindings and legacy two-argument enrollment remain intact. This simulated encrypted peer does not establish online GW authorization.
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
async function fixture({lostAck=false,lostTokenAck=false,lostDcrPoll=false,foreignReply=false}={}){
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
 let lose=lostAck,loseToken=lostTokenAck,losePoll=lostDcrPoll
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
   }
   replies.set(message.thid,{jti:randomUUID(),iss:foreignReply?`did:web:foreign.example.invalid`:iss,aud:actorDid,thid:message.thid,body})
   if(new URL(url).pathname.includes('/Token/')&&loseToken){loseToken=false;throw new Error('synthetic_token_ack_lost')}
   if(new URL(url).pathname.includes('/Device/')&&lose){lose=false;throw new Error('synthetic_dcr_ack_lost')}
   return new Response('{}',{status:202,headers:{'content-type':'application/json'}})
  }
  if(!replies.has(message.thid))return new Response('{}',{status:404})
  const response=await gateway.packForRecipientWithContext(replies.get(message.thid),actorDid,{context:gatewayContext})
  replies.delete(message.thid)
  if(new URL(url).pathname.includes('/Device/')&&losePoll){losePoll=false;throw new Error('synthetic_dcr_poll_response_lost')}
  return new Response(JSON.stringify({response}),{status:200,headers:{'content-type':'application/json'}})
 }
 const options={baseUrl:'https://example.invalid',ctx:{...ctx},providerDid,gatewayDid,dcrResponseIssuer:gatewayDid,
  expectedProfile:{actorDid,profileDid:actorDid,contact:{...contact}},bearerToken:'synthetic-verified-phone-token',
  transportProfile:'pre-dcr-didcomm-encrypted',secureTransportAdapter:adapter,fetchImpl,allowLoopbackRedirectUris:true}
 const input={verifiedContact:contact,activationCode:'synthetic-controller-activation-code',clientInstanceId:'synthetic-stable-installation',
  publicJwks:custody.publicJwks,enrollmentKeyDescriptors:custody.descriptors,redirectUris:['http://localhost:4338/__/auth/handler']}
 return {options,input,messages,registrations,custody,dropReplies:()=>replies.clear()}
}
test('enrolls a host-bound phone controller through real encrypted exchange without an employee grant',async()=>{
 const Client=need(),f=await fixture()
 const result=await new Client(f.options).enroll(f.input,{intervalMs:0})
 assert.equal(result.clientId,'synthetic-stable-client')
 assert.equal(result.actorDid,actorDid);assert.equal(result.profileDid,actorDid)
 assert.deepEqual(result.routeContext,ctx);assert.equal(f.messages.length,4)
 assert.equal(f.custody.descriptors.length,6)
})
test('resumes an uncertain DCR submit acknowledgement by polling its persisted operation without registering again',async()=>{
 const Client=need(),f=await fixture({lostAck:true})
 let saved
 const control=()=>({checkpoint:saved,saveCheckpoint:async checkpoint=>{saved=structuredClone(checkpoint)}})
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},control()),/synthetic_dcr_ack_lost/u)
 assert.equal(saved?.phase,'registration-pending','save original DCR operation before any uncertain network mutation')
 const result=await new Client(f.options).enroll(f.input,{intervalMs:0},control())
 assert.equal(result.clientId,'synthetic-stable-client')
 const submits=f.messages.filter(row=>!row.path.endsWith('-response'))
 assert.equal(submits.filter(row=>row.path.endsWith('/Device/_dcr')).length,1)
 assert.equal(submits.filter(row=>row.path.endsWith('/Token/_exchange')).length,1)
 const original=submits.find(row=>row.path.endsWith('/Device/_dcr'))
 assert.equal(f.messages.at(-1).message.thid,original.message.thid)
 assert.equal(saved.phase,'complete')
 const messageCount=f.messages.length
 assert.equal((await new Client(f.options).enroll(f.input,{intervalMs:0},control())).clientId,result.clientId)
 assert.equal(f.messages.length,messageCount,'completed sealed receipt prevents a second mutation')
})
test('resumes a lost Token submit acknowledgement using its original operation before registering once',async()=>{
 const Client=need(),f=await fixture({lostTokenAck:true})
 let saved
 const control=()=>({checkpoint:saved,saveCheckpoint:async checkpoint=>{saved=structuredClone(checkpoint)}})
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},control()),/synthetic_token_ack_lost/u)
 assert.equal(saved?.phase,'token-pending')
 assert.equal((await new Client(f.options).enroll(f.input,{intervalMs:0},control())).clientId,'synthetic-stable-client')
 assert.equal(f.messages.filter(row=>row.path.endsWith('/Token/_exchange')).length,1)
 assert.equal(f.messages.filter(row=>row.path.endsWith('/Device/_dcr')).length,1)
})
test('requires checkpoint persistence before Token or DCR submission',async()=>{
 const Client=need(),f=await fixture()
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},{saveCheckpoint:async()=>{throw new Error('synthetic_storage_unavailable')}}),/synthetic_storage_unavailable/u)
 assert.equal(f.messages.length,0)
 const g=await fixture()
 await assert.rejects(new Client(g.options).enroll(g.input,{intervalMs:0},{saveCheckpoint:async checkpoint=>{
  if(checkpoint.phase==='registration-pending')throw new Error('synthetic_storage_unavailable')
 }}),/synthetic_storage_unavailable/u)
 assert.equal(g.messages.filter(row=>row.path.endsWith('/Token/_exchange')).length,1)
 assert.equal(g.messages.filter(row=>row.path.endsWith('/Device/_dcr')).length,0)
})
test('binds a sealed checkpoint to the exact installation, public custody, code, redirects and trusted actor/provider',async()=>{
 const Client=need(),f=await fixture({lostAck:true})
 let saved
 const saveCheckpoint=async checkpoint=>{saved=structuredClone(checkpoint)}
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},{saveCheckpoint}),/synthetic_dcr_ack_lost/u)
 const before=f.messages.length
 for(const input of [
  {...f.input,clientInstanceId:'synthetic-second-installation'},
  {...f.input,activationCode:'synthetic-other-activation-code'},
  {...f.input,redirectUris:['https://example.invalid/other-callback']},
  {...f.input,publicJwks:f.input.publicJwks.map((key,index)=>index?key:{...key,pub:key.pub+'A'})},
 ])await assert.rejects(new Client(f.options).enroll(input,{intervalMs:0},{checkpoint:saved,saveCheckpoint}),/checkpoint_binding_invalid|key_purpose_binding_invalid/u)
 await assert.rejects(new Client({...f.options,providerDid:f.options.providerDid+':other'}).enroll(f.input,{intervalMs:0},{checkpoint:saved,saveCheckpoint}),/checkpoint_binding_invalid/u)
 await assert.rejects(new Client({...f.options,expectedProfile:{...f.options.expectedProfile,profileDid:actorDid+':other'}}).enroll(f.input,{intervalMs:0},{checkpoint:saved,saveCheckpoint}),/checkpoint_binding_invalid/u)
 assert.equal(f.messages.length,before)
})
test('unavailable original DCR result requires explicit recovery and never resubmits or replaces a device',async()=>{
 const Client=need(),f=await fixture({lostAck:true})
 let saved
 const control=()=>({checkpoint:saved,saveCheckpoint:async checkpoint=>{saved=structuredClone(checkpoint)}})
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},control()),/synthetic_dcr_ack_lost/u)
 f.dropReplies()
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},control()),error=>{
  assert.equal(error.name,'DeviceEnrollmentRecoveryRequiredError')
  assert.match(error.message,/recovery_required/u)
  return true
 })
 assert.equal(f.messages.filter(row=>row.path.endsWith('/Device/_dcr')).length,1)
 assert.equal(saved.phase,'registration-pending')
})
test('a consumed DCR poll response lost in transit is explicit recovery, not a second registration',async()=>{
 const Client=need(),f=await fixture({lostDcrPoll:true})
 let saved
 const control=()=>({checkpoint:saved,saveCheckpoint:async checkpoint=>{saved=structuredClone(checkpoint)}})
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},control()),/synthetic_dcr_poll_response_lost/u)
 assert.equal(saved.phase,'registration-pending')
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},control()),error=>error.name==='DeviceEnrollmentRecoveryRequiredError')
 assert.equal(f.messages.filter(row=>row.path.endsWith('/Device/_dcr')).length,1)
})
test('resumes after persistence stopped before DCR submission without exchanging another token',async()=>{
 const Client=need(),f=await fixture()
 let saved
 await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},{saveCheckpoint:async checkpoint=>{
  if(checkpoint.phase==='registration-pending')throw new Error('synthetic_storage_unavailable')
  saved=structuredClone(checkpoint)
 }}),/synthetic_storage_unavailable/u)
 assert.equal(saved.phase,'token-complete')
 assert.equal((await new Client(f.options).enroll(f.input,{intervalMs:0},{checkpoint:saved,saveCheckpoint:async checkpoint=>{saved=structuredClone(checkpoint)}})).clientId,'synthetic-stable-client')
 assert.equal(f.messages.filter(row=>row.path.endsWith('/Token/_exchange')).length,1)
 assert.equal(f.messages.filter(row=>row.path.endsWith('/Device/_dcr')).length,1)
})
test('rejects malformed checkpoint states before any network request',async()=>{
 const Client=need(),f=await fixture()
 for(const checkpoint of [null,{}, {version:1,phase:'complete'}, {version:1,phase:'registration-pending',bindingDigest:'invalid'}]){
  await assert.rejects(new Client(f.options).enroll(f.input,{intervalMs:0},{checkpoint,saveCheckpoint:async()=>{}}),/checkpoint_invalid/u)
 }
 assert.equal(f.messages.length,0)
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
