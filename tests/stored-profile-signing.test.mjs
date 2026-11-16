// Flow contract: one fixed-profile signature uses exact stored owner/actor/provider/route/session and historical key/AAD bytes, rejects tamper/expiry/revision races before releasing a result, returns public material only and never resets PIN counters or provisions replacement keys.
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {readFileSync} from 'node:fs'
import {createPublicKey,verify} from 'node:crypto'
import * as api from '../dist/index.js'
import * as data from 'sos-data-utils-ts/registered-profile-contract'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

// Pure synthetic recorded data only. The frozen predecessor ran outside SOS;
// its package/module SHA receipt is held privately with the source evidence.
const vector=JSON.parse(readFileSync(new URL('./fixtures/stored-profile-signing-oracle.json',import.meta.url),'utf8'))
const profiles='synthetic-signing-profiles',registeredSessions='synthetic-registered-sessions',walletSessions='synthetic-wallet-sessions'
const subject=safe.subjectCardProviders.animalIndexDid
const now=()=>new Date(vector.now)
const need=()=>{assert.equal(typeof api.signStoredProfilePayload,'function','missing owned signStoredProfilePayload operation');return api.signStoredProfilePayload}

async function setup(kind='individual',contextIndex=0){
 const vault=new api.TransactionalMemoryVaultRepository(),host=api.createAesGcmProfileSealer(Buffer.alloc(32,vector.hostKeyByte)),context=vector.contexts[contextIndex]
 const binding={ownerId:vector.ownerId,profileId:vector.profileId,actorDid:safe.didWeb,providerDid:safe.didWeb,routeContext:{tenantId:safe.tenantId,jurisdiction:'CA-BC',sector:safe.sector}}
 const profile={id:vector.profileId,...binding,walletKeyDerivationId:context.walletKeyDerivationId,actorKind:kind==='individual'?ActorKinds.IndividualController:ActorKinds.OrganizationController,actorMode:'controller',profileDid:safe.didWeb,allowedSubjectDids:[subject],clientId:'synthetic-client',deviceDid:safe.didWeb,publicJwks:context.descriptors.filter(value=>value.purpose!=='document-at-rest').map(value=>value.publicJwk),storagePublicJwk:context.descriptors.find(value=>value.purpose==='document-at-rest').publicJwk,confidentialStorageProfile:'confidential-pqc-v1',protectedWalletSeed:vector.encrypted.protectedWalletSeed,protectedVpToken:vector.encrypted.protectedVpToken,failedUnlocks:2,createdAt:vector.now,updatedAt:vector.now}
 const session={id:vector.sessionId,sessionId:vector.sessionId,ownerId:vector.ownerId,profileId:vector.profileId,subjectDid:subject,selectedSubjectDid:subject,scopes:[`patient/*.read?subject=${encodeURIComponent(subject)}`],authorizedSubjectDids:[subject],authorizedSubjects:[{subjectDid:subject,transportSubjectDid:subject,actorMode:'controller'}],actorMode:'controller',sealedUnlockedWalletSeed:vector.encrypted.registeredSessionSeed,sealedUnlockedVpToken:vector.encrypted.registeredSessionVp,sealedAccessToken:await host.seal('synthetic-accepted-smart-token',`${vector.sessionId}:access-token`),expiresAt:'2099-01-01T00:00:00Z'}
 const wallet={id:vector.walletSessionId,ownerId:vector.ownerId,profileId:vector.profileId,sealedWalletSeed:vector.encrypted.walletSessionSeed,expiresAt:'2099-01-01T00:00:00Z'}
 await vault.put(profiles,profile);await vault.put(registeredSessions,session);await vault.put(walletSessions,wallet)
 const options={vault,sealer:host,profilesCollection:profiles,binding,now,session:kind==='individual'?{format:'registered-profile-session-v1',collection:registeredSessions,sessionId:vector.sessionId}:{format:'sealed-wallet-session-v1',collection:walletSessions,sessionToken:vector.rawWalletSessionToken}}
 return {vault,host,binding,profile,session,wallet,options,context}
}
const presentation=()=>({profile:data.StoredProfileSignatureProfiles.IndividualIdentityPresentation,subjectDid:subject,claims:structuredClone(vector.claims)})
const detached=()=>({profile:data.StoredProfileSignatureProfiles.OrganizationActorDetachedCredential,payload:vector.payload})
function verifySignature(result,payload){
 const parts=result.jws.split('.'),header=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'))
 const bytes=payload===undefined?Buffer.from(`${parts[0]}.${parts[1]}`,'ascii'):Buffer.concat([Buffer.from(`${parts[0]}.`,'ascii'),Buffer.from(payload,'utf8')])
 assert.equal(verify('sha384',bytes,{key:createPublicKey({key:result.publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')),true)
 assert.equal(header.kid,result.publicJwk.kid)
 assert.deepEqual(Object.keys(result).sort(),['jws','publicJwk','verificationMethod'])
 assert.deepEqual(Object.keys(result.publicJwk).sort(),['alg','crv','kid','kty','use','x','y'])
 assert.equal(result.verificationMethod,`${safe.didWeb}#${result.publicJwk.kid}`)
 for(const secret of [vector.seed,vector.rawWalletSessionToken,vector.encrypted.registeredSessionSeed,vector.encrypted.walletSessionSeed])assert.equal(JSON.stringify(result).includes(secret),false)
 return header
}

test('recorded historical PIN envelope opens through the existing owned AES/PIN boundary',async()=>{
 const host=api.createAesGcmProfileSealer(Buffer.alloc(32,vector.hostKeyByte))
 assert.equal(await api.openServerProfileSecret(vector.encrypted.protectedWalletSeed,vector.pin,`${vector.profileId}:wallet-seed`,host),vector.seed)
})

test('signs the exact recorded individual VP input and retains public material/PIN counters',async()=>{
 const s=await setup();const sign=need();const result=await sign(s.options,presentation())
 assert.deepEqual(verifySignature(result),s.context.expectedPresentationHeader)
 assert.equal(result.jws.split('.').slice(0,2).join('.'),s.context.presentation.split('.').slice(0,2).join('.'))
 assert.deepEqual(await s.vault.get(profiles,s.profile.id),s.profile)
 assert.deepEqual(await s.vault.get(registeredSessions,s.session.id),s.session)
})
test('preserves custom derivation and detached Unicode/whitespace bytes with no unrelated storage key',async()=>{
 const s=await setup('organization',1);const sign=need();const {storagePublicJwk:_document,...historical}=s.profile
 await s.vault.put(profiles,historical)
 const result=await sign(s.options,detached())
 assert.deepEqual(verifySignature(result,vector.payload),s.context.expectedDetachedHeader)
 assert.equal(result.jws.split('.')[1],'')
 assert.equal(result.jws.split('.')[0],s.context.detached.split('.')[0])
 assert.equal((await s.vault.get(profiles,historical.id)).storagePublicJwk,undefined)
})
test('denies crossed owner/profile/actor/provider/route before host unseal',async()=>{
 const s=await setup();const sign=need();let calls=0
 const sealer={seal:s.host.seal,unseal:async(...args)=>{calls++;return s.host.unseal(...args)}}
 const bad=[{...s.binding,ownerId:'synthetic-other-owner'},{...s.binding,profileId:'synthetic-other-profile'},{...s.binding,actorDid:safe.subjectCardProviders.humanIndexDid},{...s.binding,providerDid:safe.subjectCardProviders.humanIndexDid},...['tenantId','jurisdiction','sector'].map(field=>({...s.binding,routeContext:{...s.binding.routeContext,[field]:'synthetic-other'}}))]
 for(const binding of bad)await assert.rejects(sign({...s.options,sealer,binding},presentation()))
 assert.equal(calls,0)
})
test('denies malformed/expired/revision-stale sessions and preserves other rows',async()=>{
 const s=await setup();const sign=need();const foreign={...s.session,id:'synthetic-foreign-session',sessionId:'synthetic-foreign-session',ownerId:'synthetic-other-owner'}
 await s.vault.put(registeredSessions,foreign)
 for(const patch of [{expiresAt:'synthetic-invalid-date'},{expiresAt:'2000-01-01T00:00:00Z'},{credentialRevision:1}]){
  await s.vault.put(registeredSessions,{...s.session,...patch});await assert.rejects(sign(s.options,presentation()))
 }
 assert.deepEqual(await s.vault.get(registeredSessions,foreign.id),foreign)
})
test('denies wrong holder/issuer/subject/scope and signing profile substitution',async()=>{
 const s=await setup();const sign=need();const original=presentation()
 for(const claims of [{...original.claims,iss:safe.subjectCardProviders.humanIndexDid},{...original.claims,sub:safe.subjectCardProviders.humanIndexDid},{...original.claims,vp:{...original.claims.vp,holder:safe.subjectCardProviders.humanIndexDid}}])await assert.rejects(sign(s.options,{...original,claims}))
 await assert.rejects(sign(s.options,{...original,subjectDid:safe.subjectCardProviders.secondAnimalIndexDid}))
 await s.vault.put(registeredSessions,{...s.session,scopes:[`patient/*.read?subject=${encodeURIComponent(safe.subjectCardProviders.secondAnimalIndexDid)}`]})
 await assert.rejects(sign(s.options,original))
 await assert.rejects(sign(s.options,detached()))
})
test('rejects key-material tamper under an unchanged kid and never returns private material',async()=>{
 const s=await setup();const sign=need();const kid=s.context.expectedPresentationHeader.kid
 const changed=s.profile.publicJwks.map(key=>key.kid===kid?{...key,x:'synthetic-wrong-public-material'}:key)
 await s.vault.put(profiles,{...s.profile,publicJwks:changed});await assert.rejects(sign(s.options,presentation()))
 await s.vault.put(profiles,{...s.profile,publicJwks:s.profile.publicJwks.map(key=>key.kid===kid?{...key,d:'synthetic-private-member'}:key)})
 await assert.rejects(sign(s.options,presentation()))
})
test('denies revocation/ciphertext changes during host unseal and time expiry before result release',async()=>{
 const s=await setup();const sign=need()
 const revoked={...s.options,sealer:{seal:s.host.seal,unseal:async(...args)=>{const seed=await s.host.unseal(...args);await s.vault.delete(registeredSessions,s.session.id);return seed}}}
 await assert.rejects(sign(revoked,presentation()))
 await s.vault.put(registeredSessions,s.session)
 const changed={...s.options,sealer:{seal:s.host.seal,unseal:async(...args)=>{const seed=await s.host.unseal(...args);await s.vault.put(profiles,{...s.profile,protectedWalletSeed:{...s.profile.protectedWalletSeed,payload:{...s.profile.protectedWalletSeed.payload,tagBase64Url:'synthetic-changed-tag'}}});return seed}}}
 await assert.rejects(sign(changed,presentation()))
 await s.vault.put(profiles,s.profile);let clock=new Date(vector.now)
 await s.vault.put(registeredSessions,{...s.session,expiresAt:'2026-01-01T00:00:01Z'})
 const expired={...s.options,now:()=>clock,sealer:{seal:s.host.seal,unseal:async(...args)=>{const seed=await s.host.unseal(...args);clock=new Date('2026-01-01T00:00:02Z');return seed}}}
 await assert.rejects(sign(expired,presentation()))
})
test('committed PIN failures remain enforced by the existing owned unlock path',async()=>{
 const s=await setup();need();const sessions=new api.RegisteredProfileSessions({vault:s.vault,sealer:s.host,collections:{profiles,sessions:registeredSessions},now,maxFailedUnlocks:3,lockSeconds:300})
 await assert.rejects(sessions.unlock({...s.binding,pin:'fixture-wrong'}),api.ProfilePinRejectedError)
 const current=await s.vault.get(profiles,s.profile.id);assert.equal(current.failedUnlocks,3);assert.ok(Date.parse(current.lockedUntil)>now().getTime())
})
test('concurrent independent signing requests retain the exact session and profile',async()=>{
 const s=await setup();const sign=need();const results=await Promise.all([sign(s.options,presentation()),sign(s.options,presentation())])
 for(const result of results)verifySignature(result)
 assert.deepEqual(await s.vault.get(profiles,s.profile.id),s.profile)
 assert.deepEqual(await s.vault.get(registeredSessions,s.session.id),s.session)
})
