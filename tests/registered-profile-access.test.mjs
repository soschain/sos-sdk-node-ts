// Flow contract: one existing actor unlocks registered custody, discovers only provider-confirmed subjects through real encrypted HTTP protocol bytes, obtains exact subject-bound SMART authorization using its normal ES384 client-assertion key, and resolves/reset/revokes the same sealed session. The signed response correlates its request while each SMART JWT retains its independent identifier. The HTTP peer is synthetic protocol evidence, not online GW acceptance.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash,createPublicKey,generateKeyPairSync,randomBytes,randomUUID,sign,verify} from 'node:crypto'
import test from 'node:test'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {encodeMultibaseSha3} from 'antifraud-data-utils-ts/encoding'
import {HL7_CODING_SYSTEM_V3_ROLE_CODE} from 'fhir-data-utils-ts'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {buildScopeSmartCompositionAccess} from 'sos-data-utils-ts/consent-smart-scopes'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
import {protectServerProfileSecret} from '../dist/server-profile-protection.js'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {openRegisteredCommunicationWallet} from '../dist/registered-communication-wallet.js'
const load=()=>import('../dist/registered-profile-access.js')
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const oracle=JSON.parse(await readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)))
const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value,'utf8').digest('hex'),randomUUID})
const profiles='synthetic_access_profiles',sessions='synthetic_access_sessions',pin='synthetic-access-pin'
const providerDid=safe.didWeb,actorDid=`${safe.didWeb}:actor:synthetic-controller`,clientId='synthetic-access-client'
const route={tenantId:safe.tenantId,jurisdiction:safe.countryIso2,sector:'health-tech'}
const binding={ownerId:'synthetic-access-owner',profileId:seed.walletKeyDerivationId,actorDid,providerDid,routeContext:route}
const alias=`${providerDid}:card:synthetic-dependent`
const uuidBytes=Uint8Array.from(safe.resourceUuid.replaceAll('-','').match(/../gu),pair=>Number.parseInt(pair,16))
const patient=`${providerDid}:individual:multibase:${encodeMultibaseSha3(uuidBytes,384)}`
const secondAlias=`${providerDid}:card:synthetic-self`
const secondUuid=safe.demoOrganizationUuids.healthCare
const secondBytes=Uint8Array.from(secondUuid.replaceAll('-','').match(/../gu),pair=>Number.parseInt(pair,16))
const secondPatient=`${providerDid}:individual:multibase:${encodeMultibaseSha3(secondBytes,384)}`
const requestedScope=buildScopeSmartCompositionAccess({subjectDid:alias,accessVerb:'rs'})
const canonicalScope=buildScopeSmartCompositionAccess({subjectDid:patient,accessVerb:'rs'})
const requestedCrud=buildScopeSmartCompositionAccess({subjectDid:alias,accessVerb:'cruds'})
const canonicalCrud=buildScopeSmartCompositionAccess({subjectDid:patient,accessVerb:'cruds'})
const baseUrl=safe.httpsBaseUrl,smartPath=`/${route.tenantId}/cds-${route.jurisdiction}/v1/${route.sector}/identity/openid/smart/token`
const accountToken='synthetic-host-verified-account-token'

async function fixture(t,{smartAlg='ML-DSA-44',policyAlg=smartAlg}={}){
 const vault=new TransactionalMemoryVaultRepository(),sealer=createAesGcmProfileSealer(Buffer.alloc(32,19))
 const publicJwks=oracle.descriptors.filter(d=>d.purpose!=='document-at-rest').map(d=>structuredClone(d.publicJwk))
 const storagePublicJwk=structuredClone(oracle.descriptors.find(d=>d.purpose==='document-at-rest').publicJwk)
 const profile={id:binding.profileId,...binding,actorKind:'individual_controller',actorMode:'controller',profileDid:actorDid,allowedSubjectDids:[],clientId,deviceDid:`${actorDid}:device`,publicJwks,storagePublicJwk,protectedWalletSeed:await protectServerProfileSecret(seed.walletSeed,pin,`${binding.profileId}:wallet-seed`,sealer,{cost:1024}),failedUnlocks:0,createdAt:'2026-01-01T00:00:00Z',updatedAt:'2026-01-01T00:00:00Z'}
 await vault.put(profiles,profile)
 const clientSigning=oracle.descriptors.find(d=>d.purpose==='comm-signing').publicJwk
 const clientEncryption=oracle.descriptors.find(d=>d.purpose==='comm-encryption').publicJwk
 const assertionKey=oracle.descriptors.find(d=>d.purpose==='openid-id-token-signing').publicJwk
 const peerSeed=Buffer.alloc(32,17).toString('base64url'),runtimeId='synthetic-gateway-access-runtime'
 const peerContext={runtime:{runtimeId,runtimeType:'backend-service'}}
 const peer=new OrganizationRegistrationWallet({resolveRecipientJwk:async did=>{assert.equal(did,actorDid);return clientEncryption}})
 await peer.provisionCommunicationKeys(peerContext,peerSeed)
 const peerPublic=peer.getPublicJwks(peerContext)
 const material=createHash('sha512').update(`${peerSeed}:runtime:${runtimeId}:default:comm-signing:0`,'utf8').digest().subarray(0,32)
 const signing=await crypto.generateKeyPairMlDsa(material,'ML-DSA-44');material.fill(0)
 assert.equal(signing.publicJWKey.pub,peerPublic.signing.pub)
 const ec=generateKeyPairSync('ec',{namedCurve:smartAlg==='ES256'?'prime256v1':'secp384r1'})
 const ecWrong=generateKeyPairSync('ec',{namedCurve:smartAlg==='ES256'?'prime256v1':'secp384r1'})
 const ecPublic={...ec.publicKey.export({format:'jwk'}),kid:'synthetic-smart-ec-key',alg:smartAlg,use:'sig'}
 t.after(()=>signing.secretKeyBytes.fill(0))
 const client=await openRegisteredCommunicationWallet({walletKeyDerivationId:seed.walletKeyDerivationId,unlockedWalletSeed:seed.walletSeed,registeredPublicJwks:publicJwks,resolveRecipientJwk:async did=>{assert.equal(did,providerDid);return peerPublic.encryption}})
 // Positive crypto setup control before any absent use-case module is loaded.
 const probe=await client.wallet.packForRecipientWithContext({iss:actorDid,aud:providerDid,thid:'synthetic-probe',client_id:clientId,body:{}},providerDid,{context:client.context})
 const openedProbe=await peer.unpackWithContext(probe,{context:peerContext})
 assert.equal(await crypto.verifyJws(openedProbe.meta.jws.compact,clientSigning),true)
 let now=1794614400000,fault='',gate,release,started,directoryGate,releaseDirectory,startedDirectory
 const requests=[],jobs=new Map()
 const state={requests,setFault:value=>{fault=value},advance:ms=>{now+=ms},holdSmart(){gate=new Promise(resolve=>{release=resolve});return new Promise(resolve=>{started=resolve})},releaseSmart(){release?.()},holdDirectory(){directoryGate=new Promise(resolve=>{releaseDirectory=resolve});return new Promise(resolve=>{startedDirectory=resolve})},releaseDirectory(){releaseDirectory?.()}}
 async function fetchImpl(url,options){
  assert.equal(options.method,'POST');assert.equal(options.headers.Authorization,`Bearer ${accountToken}`)
  assert.equal(options.headers['Content-Type'],'application/x-www-form-urlencoded')
  const compact=new URLSearchParams(options.body).get('request');assert.ok(compact)
  const opened=await peer.unpackWithContext(compact,{context:peerContext}),message=opened.content
  assert.equal(await crypto.verifyJws(opened.meta.jws.compact,clientSigning),true)
  assert.equal(message.iss,actorDid);assert.equal(message.client_id,clientId)
  const path=new URL(url).pathname;requests.push({path,message})
  if(!path.endsWith('-response')){
   jobs.set(message.thid,{message,path,polls:0})
   return new Response('{}',{status:202})
  }
  const job=jobs.get(message.thid);assert.ok(job)
  assert.equal(message.aud,job.message.aud);assert.equal(message.client_id,job.message.client_id)
  if(job.polls++===0)return new Response('{}',{status:202})
  let body
  if(job.path===smartPath){
   const request=job.message.body
   assert.equal(job.message.aud,`${baseUrl}${smartPath}`)
   assert.equal(request.client_id,clientId);assert.equal(request.sub,actorDid)
   assert.equal(request.id_token,accountToken);assert.equal('vp_token' in request,false)
   assert.equal(request.client_assertion_type,'private_key_jwt')
   assert.equal(request.acr_values,'urn:antifraud:acr:openid4vp:individual')
   assert.equal(request.purpose,'TREAT')
   assert.ok([canonicalScope,`${canonicalScope} ${canonicalCrud}`,buildScopeSmartCompositionAccess({subjectDid:secondPatient,accessVerb:'rs'})].includes(request.scope))
   const selectedPatient=new URLSearchParams(request.scope.split('?')[1]).get('subject')
   const assertion=request.client_assertion.split('.'),header=JSON.parse(Buffer.from(assertion[0],'base64url')),claims=JSON.parse(Buffer.from(assertion[1],'base64url'))
   assert.equal(header.alg,'ES384');assert.equal(header.kid,assertionKey.kid)
   assert.equal(verify('sha384',Buffer.from(`${assertion[0]}.${assertion[1]}`),{key:createPublicKey({key:assertionKey,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(assertion[2],'base64url')),true)
   assert.equal(claims.iss,clientId);assert.equal(claims.sub,clientId);assert.equal(claims.aud,`${baseUrl}${smartPath}`)
   assert.equal(claims.exp-claims.iat,300);assert.ok(claims.jti)
   started?.();if(gate)await gate
   if(fault==='consent')return new Response(JSON.stringify({error:'consent_missing'}),{status:403})
   const seconds=Math.floor(now/1000),scope=fault==='scope'?`${request.scope} user/Observation.cruds`:fault==='broader-cruds'?`${canonicalScope} ${canonicalCrud}`:fault==='narrow-grant'?canonicalScope:request.scope
   const tokenClaims={iss:providerDid,sub:actorDid,aud:fault==='token-audience'?`${providerDid}:foreign`:providerDid,scope,jti:fault==='independent-token-id'?randomUUID():fault==='missing-token-id'?undefined:fault==='empty-token-id'?'':fault==='invalid-token-id'?7:randomUUID(),iat:seconds,nbf:seconds,exp:fault==='expired-token'?seconds-1:seconds+120}
   let accessToken
   if(smartAlg==='ES384'||smartAlg==='ES256'){
    const header={alg:smartAlg,kid:fault==='smart-header-kid'?'synthetic-foreign-kid':ecPublic.kid,typ:'JWT'}
    const signingInput=`${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(tokenClaims)).toString('base64url')}`
    accessToken=`${signingInput}.${sign(smartAlg==='ES256'?'sha256':'sha384',Buffer.from(signingInput),{key:ec.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')}`
    assert.equal(verify(smartAlg==='ES256'?'sha256':'sha384',Buffer.from(signingInput),{key:ec.publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(accessToken.split('.')[2],'base64url')),true)
   }else{
    const signed=await crypto.signDataJws(tokenClaims,{alg:'ML-DSA-44',kid:peerPublic.signing.kid,typ:'JWT'},signing.secretKeyBytes)
    accessToken=`${signed.protected}.${signed.payload}.${signed.signature}`
   }
   body={access_token:accessToken,token_type:'Bearer',expires_in:120,scope,subject:fault==='patient'?`${selectedPatient}:foreign`:selectedPatient}
  }else if(job.path.includes('/License/'))body={data:[{resource:{data:[]}}]}
  else{
   assert.equal(job.message.aud,providerDid)
   assert.equal(job.message.body.data[0].resource.meta.claims['org.schema.Organization.owner.email'],safe.firstContactEmail)
   const owned={resource:{resourceType:'Organization',id:safe.resourceUuid,meta:{claims:{'org.schema.Organization.sameAs':alias,'org.schema.Organization.did':patient,'org.schema.Organization.owner.email':safe.firstContactEmail,'org.schema.Organization.owner.identifier.value':`urn:uuid:${safe.resourceUuid}`,'org.schema.Organization.member.role':'RESPRSN'}}}}
   const entries=[owned]
   if(fault==='ambiguous-directory'||fault==='repeated-directory'){
    const repeated=structuredClone(owned)
    if(fault==='ambiguous-directory'){
     repeated.resource.id=safe.demoOrganizationUuids.healthCare
     const otherBytes=Uint8Array.from(repeated.resource.id.replaceAll('-','').match(/../gu),pair=>Number.parseInt(pair,16))
     repeated.resource.meta.claims['org.schema.Organization.did']=`${providerDid}:individual:multibase:${encodeMultibaseSha3(otherBytes,384)}`
    }
    entries.push(repeated)
   }
   if(fault==='two-subjects'){
    const second=structuredClone(owned)
    second.resource.id=secondUuid
    Object.assign(second.resource.meta.claims,{'org.schema.Organization.sameAs':secondAlias,'org.schema.Organization.did':secondPatient,'org.schema.Organization.owner.identifier.value':`urn:uuid:${secondUuid}`,'org.schema.Organization.member.role':`${HL7_CODING_SYSTEM_V3_ROLE_CODE}|ONESELF`})
    entries.push(second)
   }
   body={data:[{resource:{resourceType:'Bundle',entry:entries}}]}
  }
  if(!job.path.includes('/License/')&&job.path!==smartPath){startedDirectory?.();if(directoryGate)await directoryGate}
  const response={jti:fault==='response-operation'?'synthetic-other-operation':fault==='missing-response-operation'?undefined:job.message.jti,iss:fault==='provider'?`${providerDid}:foreign`:providerDid,aud:fault==='audience'?`${actorDid}:foreign`:actorDid,thid:fault==='thread'?'synthetic-other-thread':job.message.thid,body}
  const encrypted=await peer.packForRecipientWithContext(response,actorDid,{context:peerContext})
  return new Response(JSON.stringify({response:encrypted}),{status:200})
 }
 const options={vault,sealer,collections:{profiles,sessions},now:()=>new Date(now),gateway:{baseUrl,providerDid,responseIssuer:providerDid,resolveRecipientJwk:async did=>{assert.equal(did,providerDid);return peerPublic.encryption},resolveGatewaySigningJwk:async did=>{assert.equal(did,providerDid);return peerPublic.signing},smartTokenVerification:{algorithm:policyAlg,resolveSigningJwk:async did=>{
  assert.equal(did,providerDid)
  if(smartAlg==='ML-DSA-44')return peerPublic.signing
  if(fault==='smart-wrong-key')return {...ecWrong.publicKey.export({format:'jwk'}),alg:smartAlg,use:'sig',kid:ecPublic.kid}
  if(fault==='smart-private-key')return {...ec.privateKey.export({format:'jwk'}),alg:smartAlg,use:'sig',kid:ecPublic.kid}
  return ecPublic
 }}},fetchImpl,pollOptions:{intervalMs:0,timeoutMs:2000}}
 return {vault,sealer,profile,options,state,readClient:async packed=>{
  const opened=await peer.unpackWithContext(packed,{context:peerContext})
  assert.equal(await crypto.verifyJws(opened.meta.jws.compact,clientSigning),true)
  return opened.content
 },reply:message=>peer.packForRecipientWithContext(message,actorDid,{context:peerContext})}
}
async function begin(t,options){const f=await fixture(t,options),{RegisteredProfileAccess}=await load(),access=new RegisteredProfileAccess(f.options);const actor=await access.unlockActorProfile({...binding,pin});return {...f,access,sessionId:actor.sessionId}}
const request=(sessionId)=>({...binding,sessionId,idToken:accountToken})

test('readAuthorizedSubjects accepts signed current directory rows without changing selected SMART context or profile metadata',async t=>{
 const f=await begin(t)
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})
 const beforeProfile=await f.vault.get(profiles,binding.profileId),beforeSession=await f.vault.get(sessions,f.sessionId)
 assert.ok(beforeSession.sealedAccessToken);assert.equal(beforeSession.selectedSubjectDid,alias)
 f.state.setFault('two-subjects')
 const subjects=await f.access.readAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 assert.deepEqual(subjects.map(subject=>subject.subjectDid).sort(),[alias,secondAlias].sort())
 assert.deepEqual(await f.vault.get(profiles,binding.profileId),beforeProfile)
 assert.deepEqual(await f.vault.get(sessions,f.sessionId),beforeSession)
 assert.equal((await f.access.resolveSession({...binding,sessionId:f.sessionId})).selectedSubjectDid,alias)
 f.state.setFault('provider')
 await assert.rejects(f.access.readAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}}))
 assert.deepEqual(await f.vault.get(sessions,f.sessionId),beforeSession)
})

test('readAuthorizedSubjects denies a revoked lease during a real signed directory response without restoring session state',async t=>{
 const f=await begin(t)
 assert.equal(typeof f.access.readAuthorizedSubjects,'function')
 const beforeProfile=await f.vault.get(profiles,binding.profileId),started=f.state.holdDirectory()
 const pending=f.access.readAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 await started
 await f.access.lock(binding,f.sessionId)
 const afterLock=await f.vault.get(sessions,f.sessionId)
 f.state.releaseDirectory()
 await assert.rejects(pending,/changed|revoked/u)
 assert.deepEqual(await f.vault.get(profiles,binding.profileId),beforeProfile)
 assert.deepEqual(await f.vault.get(sessions,f.sessionId),afterLock)
})

test('drives unlock, registered encrypted discovery, exact-key SMART selection and reset with bounded token lifetime',async t=>{
 const f=await begin(t)
 const profiles=await f.access.listProfiles({ownerId:binding.ownerId,providerDid,routeContext:route})
 assert.equal(profiles.length,1);assert.equal(profiles[0].profileId,binding.profileId)
 assert.equal('protectedWalletSeed' in profiles[0],false);assert.equal('publicJwks' in profiles[0],false)
 await assert.rejects(f.access.resolveSession({...binding,sessionId:f.sessionId}))
 const directory=await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 assert.ok(directory.subjects.some(subject=>subject.subjectDid===alias))
 const selected=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})
 assert.equal(selected.selectedSubjectDid,alias);assert.equal(selected.subjectDid,patient);assert.deepEqual(selected.scopes,[canonicalScope])
 const stored=await f.vault.get(sessions,f.sessionId)
 assert.equal(await f.sealer.unseal(stored.sealedAccessToken,`${f.sessionId}:access-token`),selected.accessToken)
 assert.equal((await f.access.resolveSession({...binding,sessionId:f.sessionId})).subjectDid,patient)
 f.state.advance(121000)
 await assert.rejects(f.access.resolveSession({...binding,sessionId:f.sessionId}),/expired/)
 await f.access.resolveActorSession({...binding,sessionId:f.sessionId})
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 const reset=await f.vault.get(sessions,f.sessionId)
 assert.equal(reset.sealedAccessToken,undefined);assert.equal(reset.subjectDid,undefined);assert.deepEqual(reset.scopes,[])
 assert.equal(f.state.requests.some(item=>item.path.includes('/Device/')||item.path.includes('/_exchange')),false)
})

test('directory discovery grants no clinical token and a foreign selection is denied before HTTP',async t=>{
 const f=await begin(t)
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 const count=f.state.requests.length
 await assert.rejects(f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:`${alias}:unlisted`,scopes:[requestedScope]}))
 assert.equal(f.state.requests.length,count)
 f.state.setFault('consent')
 await assert.rejects(f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]}))
 assert.equal((await f.vault.get(sessions,f.sessionId)).sealedAccessToken,undefined)
})

test('rejects signed foreign envelope and token bindings without persisting access',async t=>{
 for(const fault of ['provider','audience','thread','patient','scope','token-audience','missing-token-id','empty-token-id','invalid-token-id','expired-token']){
  const f=await begin(t)
  await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
  f.state.setFault(fault)
  await assert.rejects(f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]}))
  assert.equal((await f.vault.get(sessions,f.sessionId)).sealedAccessToken,undefined)
 }
})

test('accepts an independently identified ES384 SMART token only inside its signed matching request response',async t=>{
 const f=await begin(t,{smartAlg:'ES384'})
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 f.state.setFault('independent-token-id')
 const selected=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})
 const tokenClaims=JSON.parse(Buffer.from(selected.accessToken.split('.')[1],'base64url'))
 const operation=f.state.requests.find(row=>row.path===smartPath).message.jti
 assert.ok(tokenClaims.jti);assert.notEqual(tokenClaims.jti,operation)
 assert.equal((await f.access.resolveSession({...binding,sessionId:f.sessionId})).accessToken,selected.accessToken)
})
test('rejects a signed SMART response whose operation identifier is missing or belongs to another request',async t=>{
 for(const fault of ['response-operation','missing-response-operation']){
  const f=await begin(t,{smartAlg:'ES384'})
  await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
  f.state.setFault(fault)
  await assert.rejects(f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]}))
  assert.equal((await f.vault.get(sessions,f.sessionId)).sealedAccessToken,undefined)
 }
})

test('revocation during a valid remote SMART result cannot resurrect a session or expose the token',{timeout:10000},async t=>{
 const f=await begin(t)
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 const started=f.state.holdSmart()
 const pending=f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})
 await Promise.race([started,pending.then(()=>{throw new Error('SMART unexpectedly completed before the held response')})])
 await f.access.lock(binding,f.sessionId);f.state.releaseSmart()
 await assert.rejects(pending)
 assert.equal(await f.vault.get(sessions,f.sessionId),undefined)
})

test('strict registered discovery rejects one public alias for different canonical patients but retains repeated same-patient rows',async t=>{
 const f=await begin(t)
 f.state.setFault('ambiguous-directory')
 await assert.rejects(f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}}),/ambiguous/)
 assert.deepEqual((await f.vault.get(sessions,f.sessionId)).authorizedSubjectDids,[])
 f.state.setFault('repeated-directory')
 const directory=await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 assert.equal(directory.subjects.length,1);assert.equal(directory.subjects[0].subjectDid,alias)
})

test('actor and selected sessions provide real bound transport and document capabilities for actual BFF consumers',async t=>{
 const f=await begin(t),actor=await f.access.resolveActorSession({...binding,sessionId:f.sessionId})
 assert.equal(actor.profile.actorDid,actorDid);assert.deepEqual(actor.profile.routeContext,route)
 assert.equal('protectedWalletSeed' in actor.profile,false)
 const thread='synthetic-bff-operation'
 const packed=await actor.secureTransportAdapter.pack({thid:thread,iss:`${actorDid}:foreign`,client_id:'synthetic-foreign-client',aud:providerDid,body:{operation:'synthetic-read'}})
 const read=await f.readClient(packed);assert.equal(read.iss,actorDid);assert.equal(read.client_id,clientId)
 const reply=await f.reply({thid:thread,iss:providerDid,aud:actorDid,body:{result:'synthetic-result'}})
 for(const bindingChange of [{iss:`${providerDid}:foreign`},{aud:`${actorDid}:foreign`},{thid:'synthetic-unopened-thread'}]){
  const foreign=await f.reply({thid:thread,iss:providerDid,aud:actorDid,body:{result:'synthetic-foreign-result'},...bindingChange})
  await assert.rejects(actor.secureTransportAdapter.unpack(foreign))
 }
 assert.equal((await actor.secureTransportAdapter.unpack(reply)).body.result,'synthetic-result')
 await assert.rejects(actor.secureTransportAdapter.unpack(reply))
 const document={id:'synthetic-channel-document',content:{text:'synthetic message'}}
 const sealed=await actor.confidentialStorageAdapter.protect(document)
 assert.deepEqual(await actor.confidentialStorageAdapter.unprotect(sealed),document)
 await f.access.lock(binding,f.sessionId)
 await assert.rejects(actor.secureTransportAdapter.pack({thid:thread,aud:providerDid,body:{}}))
 await assert.rejects(actor.confidentialStorageAdapter.unprotect(sealed))
})

test('directory refresh persists new aliases and selected profile views retain each card personal attester and effective role',async t=>{
 const f=await begin(t);f.state.setFault('two-subjects')
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 const profile=await f.vault.get(profiles,binding.profileId)
 assert.ok(profile.allowedSubjectDids.includes(alias));assert.ok(profile.allowedSubjectDids.includes(secondAlias))
 const controlled=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})
 assert.equal(controlled.actorMode,'controller');assert.equal(controlled.profile.actorMode,'controller')
 assert.deepEqual(controlled.attester,{mode:'personal',party:{reference:`urn:uuid:${safe.resourceUuid}`}})
 const self=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:secondAlias,scopes:[buildScopeSmartCompositionAccess({subjectDid:secondAlias,accessVerb:'rs'})]})
 assert.equal(self.actorMode,'self');assert.equal(self.profile.actorMode,'self')
 assert.deepEqual(self.attester,{mode:'personal',party:{reference:`urn:uuid:${secondUuid}`}})
 assert.deepEqual(self.profile.attester,self.attester);assert.ok(self.profile.allowedSubjectDids.includes(secondAlias))
 assert.deepEqual((await f.access.resolveSession({...binding,sessionId:f.sessionId})).profile.attester,self.attester)
 const packed=await self.secureTransportAdapter.pack({thid:'synthetic-selected-operation',aud:providerDid,body:{subject:secondPatient}})
 assert.equal((await f.readClient(packed)).iss,actorDid)
 const document={id:'synthetic-selected-document',content:{subject:secondPatient}}
 assert.deepEqual(await self.confidentialStorageAdapter.unprotect(await self.confidentialStorageAdapter.protect(document)),document)
 await assert.rejects(controlled.secureTransportAdapter.pack({thid:'synthetic-obsolete-card',aud:providerDid,body:{subject:patient}}))
 assert.equal((await f.vault.get(profiles,binding.profileId)).actorMode,'controller')
})

test('accepts the actual client rs and cruds pair while preserving a narrower signed grant',async t=>{
 const f=await begin(t)
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 const complete=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope,requestedCrud]})
 assert.deepEqual(complete.scopes,[canonicalScope,canonicalCrud])
 f.state.setFault('narrow-grant')
 const selected=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope,requestedCrud]})
 assert.deepEqual(selected.scopes,[canonicalScope])
 assert.deepEqual((await f.access.resolveSession({...binding,sessionId:f.sessionId})).scopes,[canonicalScope])
 f.state.setFault('broader-cruds')
 await assert.rejects(f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]}))
 assert.deepEqual((await f.access.resolveSession({...binding,sessionId:f.sessionId})).scopes,[canonicalScope])
})

test('verifies independently configured ES384 SMART while outer registered transport remains PQC',async t=>{
 const f=await begin(t,{smartAlg:'ES384'})
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 const selected=await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})
 assert.equal(JSON.parse(Buffer.from(selected.accessToken.split('.')[0],'base64url')).alg,'ES384')
 assert.equal((await f.access.resolveSession({...binding,sessionId:f.sessionId})).subjectDid,patient)
})

test('explicit ES256 policy retains compatibility and rejects foreign EC material, private fields, kid and policy mismatch',async t=>{
 const f=await begin(t,{smartAlg:'ES256'})
 await f.access.refreshAuthorizedSubjects({...request(f.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 assert.equal((await f.access.selectAuthorizedSubject({...request(f.sessionId),subjectDid:alias,scopes:[requestedScope]})).subjectDid,patient)
 for(const fault of ['smart-wrong-key','smart-private-key','smart-header-kid']){
  const invalid=await begin(t,{smartAlg:'ES384'})
  await invalid.access.refreshAuthorizedSubjects({...request(invalid.sessionId),verifiedContact:{email:safe.firstContactEmail}})
  invalid.state.setFault(fault)
  await assert.rejects(invalid.access.selectAuthorizedSubject({...request(invalid.sessionId),subjectDid:alias,scopes:[requestedScope]}))
  assert.equal((await invalid.vault.get(sessions,invalid.sessionId)).sealedAccessToken,undefined)
 }
 const wrongPolicy=await begin(t,{smartAlg:'ES256',policyAlg:'ES384'})
 await wrongPolicy.access.refreshAuthorizedSubjects({...request(wrongPolicy.sessionId),verifiedContact:{email:safe.firstContactEmail}})
 await assert.rejects(wrongPolicy.access.selectAuthorizedSubject({...request(wrongPolicy.sessionId),subjectDid:alias,scopes:[requestedScope]}))
})
