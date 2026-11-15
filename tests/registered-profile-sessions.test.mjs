// Flow contract: reopen an existing registered profile with its original PIN/host envelope and key purposes, bind sessions to the exact account/profile/provider/route, commit real PIN failures without penalizing host failures, and atomically revoke sessions when authorized custody is rewrapped. No onboarding, role admission or remote authorization is implied.
// Read-only historical shape evidence: https://github.com/Global-DataCare/gdc-sdk-node-ts/blob/main/src/server-profile-session.ts
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
import {protectServerProfileSecret,openServerProfileSecret,ProfilePinRejectedError} from '../dist/server-profile-protection.js'
const load=()=>import('../dist/registered-profile-sessions.js')
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const oracle=JSON.parse(await readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)))
const pin='synthetic-profile-pin',newPin='synthetic-replacement-pin'
const profileId=seed.walletKeyDerivationId,ownerId='synthetic-profile-owner'
const routeContext={tenantId:safe.tenantId,jurisdiction:safe.countryIso2,sector:'health-tech'}
const binding={ownerId,profileId,actorDid:safe.didWeb,providerDid:safe.didWeb,routeContext}
async function setup(){
 const vault=new TransactionalMemoryVaultRepository(),host=createAesGcmProfileSealer(createHash('sha256').update('synthetic profile session host').digest())
 const profile={...binding,walletKeyDerivationId:profileId,actorKind:'organization_employee',actorMode:'member',profileDid:safe.didWeb,allowedSubjectDids:[],clientId:'synthetic-registered-client',deviceDid:safe.didWeb,
  publicJwks:oracle.descriptors.filter(d=>d.purpose!=='document-at-rest').map(d=>d.publicJwk),storagePublicJwk:oracle.descriptors.find(d=>d.purpose==='document-at-rest').publicJwk,
  protectedWalletSeed:await protectServerProfileSecret(seed.walletSeed,pin,`${profileId}:wallet-seed`,host,{cost:1024}),failedUnlocks:0,createdAt:'2026-01-01T00:00:00.000Z',updatedAt:'2026-01-01T00:00:00.000Z'}
 await vault.put('synthetic_profiles',{...profile,id:profileId})
 let now=new Date('2026-01-01T00:00:00.000Z')
 const options={vault,collections:{profiles:'synthetic_profiles',sessions:'synthetic_sessions'},sealer:host,now:()=>new Date(now),maxFailedUnlocks:2,lockSeconds:300,sessionTtlSeconds:300,protection:{cost:1024}}
 const runtime=async(overrides={})=>new (await load()).RegisteredProfileSessions({...options,...overrides})
 return {vault,host,profile,runtime,advance:ms=>{now=new Date(now.getTime()+ms)}}
}
test('reopens persisted envelope after runtime restart with the exact six key purposes and no stored plaintext',async()=>{
 const f=await setup(),before=await f.vault.get('synthetic_profiles',profileId),first=await f.runtime()
 const opened=await first.unlock({...binding,pin})
 assert.deepEqual(opened.custody.publicJwks,f.profile.publicJwks)
 assert.deepEqual(opened.custody.storagePublicJwk,f.profile.storagePublicJwk)
 assert.equal(opened.custody.descriptors.length,6)
 const resumed=await (await f.runtime()).resolve(binding,opened.session.sessionId)
 assert.deepEqual(resumed.custody.descriptors,opened.custody.descriptors)
 assert.deepEqual((await f.vault.get('synthetic_profiles',profileId)).protectedWalletSeed,before.protectedWalletSeed)
 const stored=await f.vault.get('synthetic_sessions',opened.session.sessionId)
 assert.equal(await f.host.unseal(stored.sealedUnlockedWalletSeed,`${stored.sessionId}:unlocked-wallet-seed`),seed.walletSeed)
 assert.equal(JSON.stringify(stored).includes(seed.walletSeed),false)
})
test('denies wrong account/profile/provider/tenant and expired or explicitly locked sessions',async()=>{
 const f=await setup(),runtime=await f.runtime(),opened=await runtime.unlock({...binding,pin})
 for(const changed of [{ownerId:'foreign-owner'},{profileId:'foreign-profile'},{providerDid:`${safe.didWeb}:foreign`},{routeContext:{...routeContext,tenantId:'foreign-tenant'}}]){
  await assert.rejects(runtime.resolve({...binding,...changed},opened.session.sessionId))
  await assert.rejects(runtime.unlock({...binding,...changed,pin}))
 }
 await runtime.lock(binding,opened.session.sessionId)
 await assert.rejects(runtime.resolve(binding,opened.session.sessionId))
 const next=await runtime.unlock({...binding,pin});f.advance(300001)
 await assert.rejects(runtime.resolve(binding,next.session.sessionId))
 assert.equal(await f.vault.get('synthetic_sessions',next.session.sessionId),undefined)
})
test('commits authenticated PIN failures and bounded lockout while preserving operational host failures',async()=>{
 const f=await setup(),runtime=await f.runtime()
 await assert.rejects(runtime.unlock({...binding,pin:'synthetic-wrong-pin'}),ProfilePinRejectedError)
 assert.equal((await f.vault.get('synthetic_profiles',profileId)).failedUnlocks,1)
 const outage=await f.runtime({sealer:{seal:f.host.seal,unseal:async()=>{throw new Error('synthetic-host-unavailable')}}})
 await assert.rejects(outage.unlock({...binding,pin}),/synthetic-host-unavailable/)
 assert.equal((await f.vault.get('synthetic_profiles',profileId)).failedUnlocks,1)
 await assert.rejects(runtime.unlock({...binding,pin:'synthetic-wrong-pin'}),ProfilePinRejectedError)
 assert.equal((await f.vault.get('synthetic_profiles',profileId)).failedUnlocks,2)
 await assert.rejects(runtime.unlock({...binding,pin}),/locked/i)
 f.advance(300001);await runtime.unlock({...binding,pin})
 assert.equal((await f.vault.get('synthetic_profiles',profileId)).failedUnlocks,0)
})
test('authorized same-seed PIN rewrap revokes exact profile sessions atomically and retains unrelated sessions',async()=>{
 const f=await setup(),runtime=await f.runtime(),opened=await runtime.unlock({...binding,pin})
 await f.vault.put('synthetic_sessions',{id:'synthetic-other-session',sessionId:'synthetic-other-session',ownerId:'other-owner',profileId:'other-profile'})
 const updated=await runtime.replacePin({...binding,authorizedWalletSeed:seed.walletSeed,newPin})
 assert.deepEqual(updated.publicJwks,f.profile.publicJwks)
 assert.equal(await openServerProfileSecret(updated.protectedWalletSeed,newPin,`${profileId}:wallet-seed`,f.host),seed.walletSeed)
 await assert.rejects(openServerProfileSecret(updated.protectedWalletSeed,pin,`${profileId}:wallet-seed`,f.host),ProfilePinRejectedError)
 await assert.rejects(runtime.resolve(binding,opened.session.sessionId))
 assert.ok(await f.vault.get('synthetic_sessions','synthetic-other-session'))
 await assert.rejects(runtime.replacePin({...binding,authorizedWalletSeed:Buffer.alloc(32,7).toString('base64url'),newPin}))
})
test('an unlock prepared before PIN replacement cannot commit a stale unlocked session afterward',async()=>{
 const f=await setup();let release,entered
 const unblocked=new Promise(resolve=>{release=resolve}),started=new Promise(resolve=>{entered=resolve})
 const paused=await f.runtime({sealer:{seal:f.host.seal,unseal:async(value,aad)=>{const clear=await f.host.unseal(value,aad);entered();await unblocked;return clear}}})
 const pending=paused.unlock({...binding,pin});await started
 await (await f.runtime()).replacePin({...binding,authorizedWalletSeed:seed.walletSeed,newPin});release()
 await assert.rejects(pending,/changed|stale|revoked/i)
 assert.deepEqual(await f.vault.query('synthetic_sessions',{}),[])
 await (await f.runtime()).unlock({...binding,pin:newPin})
})
test('PIN rewrap rollback leaves original envelope and sessions usable when the transaction fails',async()=>{
 const f=await setup(),runtime=await f.runtime(),opened=await runtime.unlock({...binding,pin})
 const failing={...f.vault,runTransaction:operation=>f.vault.runTransaction(async port=>{await operation(port);throw new Error('synthetic-commit-rejected')})}
 // Explicitly retain the vault methods: class prototype methods are not object-spread properties.
 for(const method of ['initialize','get','put','query','delete'])failing[method]=f.vault[method].bind(f.vault)
 await assert.rejects((await f.runtime({vault:failing})).replacePin({...binding,authorizedWalletSeed:seed.walletSeed,newPin}),/synthetic-commit-rejected/)
 assert.equal(await openServerProfileSecret((await f.vault.get('synthetic_profiles',profileId)).protectedWalletSeed,pin,`${profileId}:wallet-seed`,f.host),seed.walletSeed)
 assert.deepEqual((await runtime.resolve(binding,opened.session.sessionId)).custody.publicJwks,f.profile.publicJwks)
})
