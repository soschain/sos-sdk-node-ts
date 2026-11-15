// Flow contract: authorized same-seed PIN rewrap atomically revokes all host-configured owner/profile session families with reads before writes, preserves actually stored legacy public-key subsets and absent metadata, and never grants strict registered custody from PIN-only compatibility.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {RegisteredProfileSessions} from '../dist/registered-profile-sessions.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
import {protectServerProfileSecret,openServerProfileSecret} from '../dist/server-profile-protection.js'
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const oracle=JSON.parse(await readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)))
const profiles='synthetic_pin_profiles',primary='synthetic_pin_sdk_sessions',product='synthetic_pin_product_sessions',unconfigured='synthetic_pin_unconfigured_sessions'
const oldPin='synthetic-previous-pin',newPin='synthetic-replacement-pin'
const binding={ownerId:'synthetic-pin-owner',profileId:seed.walletKeyDerivationId,actorDid:safe.didWeb,providerDid:safe.didWeb,routeContext:{tenantId:safe.tenantId,jurisdiction:safe.countryIso2,sector:'health-tech'}}
function transactionProbe(vault,{failProductDelete=false}={}){
 return {
  initialize:vault.initialize.bind(vault),get:vault.get.bind(vault),put:vault.put.bind(vault),query:vault.query.bind(vault),delete:vault.delete.bind(vault),
  runTransaction:operation=>vault.runTransaction(async transaction=>{
   let wrote=false
   const read=method=>(...args)=>{assert.equal(wrote,false,'Durable transaction read occurred after a write');return method(...args)}
   return operation({get:read(transaction.get.bind(transaction)),query:read(transaction.query.bind(transaction)),put:async(...args)=>{wrote=true;return transaction.put(...args)},delete:async(collection,id)=>{wrote=true;if(failProductDelete&&collection===product)throw new Error('synthetic-product-session-delete-failed');return transaction.delete(collection,id)}})
  }),
 }
}
async function setup({legacy=false,failProductDelete=false}={}){
 const vault=new TransactionalMemoryVaultRepository(),sealer=createAesGcmProfileSealer(createHash('sha256').update('synthetic PIN compatibility host').digest())
 const descriptors=oracle.descriptors.filter(entry=>entry.purpose!=='document-at-rest')
 const profile={id:binding.profileId,...binding,actorKind:'organization_controller',actorMode:'controller',profileDid:safe.didWeb,allowedSubjectDids:[],clientId:'synthetic-pin-client',deviceDid:safe.didWeb,publicJwks:descriptors.filter(entry=>!legacy||['actor-signing','comm-signing','comm-encryption'].includes(entry.purpose)).map(entry=>structuredClone(entry.publicJwk)),...(!legacy?{storagePublicJwk:structuredClone(oracle.descriptors.find(entry=>entry.purpose==='document-at-rest').publicJwk)}:{}),protectedWalletSeed:await protectServerProfileSecret(seed.walletSeed,oldPin,`${binding.profileId}:wallet-seed`,sealer,{cost:1024}),failedUnlocks:0,createdAt:'2026-01-01T00:00:00Z',updatedAt:'2026-01-01T00:00:00Z'}
 await vault.put(profiles,profile)
 for(const collection of [primary,product,unconfigured]){
  await vault.put(collection,{id:`owned-${collection}`,ownerId:binding.ownerId,profileId:binding.profileId})
  await vault.put(collection,{id:`foreign-${collection}`,ownerId:'synthetic-foreign-owner',profileId:binding.profileId})
  await vault.put(collection,{id:`other-${collection}`,ownerId:binding.ownerId,profileId:'synthetic-other-profile'})
 }
 const additionalSessionCollections=[product]
 const options={vault:transactionProbe(vault,{failProductDelete}),collections:{profiles,sessions:primary},additionalSessionCollections,sealer,protection:{cost:1024}}
 const runtime=new RegisteredProfileSessions(options)
 return {vault,sealer,profile,runtime,options,additionalSessionCollections}
}
const replacement=()=>({...binding,authorizedWalletSeed:seed.walletSeed,newPin})

test('revokes exact owner/profile sessions from both trusted factory collections atomically and ignores caller mutation',async()=>{
 const f=await setup()
 f.additionalSessionCollections[0]=unconfigured
 const updated=await f.runtime.replacePin({...replacement(),additionalSessionCollections:[unconfigured]})
 assert.equal(await openServerProfileSecret(updated.protectedWalletSeed,newPin,`${binding.profileId}:wallet-seed`,f.sealer),seed.walletSeed)
 for(const collection of [primary,product]){
  assert.equal(await f.vault.get(collection,`owned-${collection}`),undefined)
  assert.ok(await f.vault.get(collection,`foreign-${collection}`));assert.ok(await f.vault.get(collection,`other-${collection}`))
 }
 assert.ok(await f.vault.get(unconfigured,`owned-${unconfigured}`))
 assert.deepEqual(updated.publicJwks,f.profile.publicJwks)
 for(const additionalSessionCollections of [[profiles],[primary],[product,product]])assert.throws(()=>new RegisteredProfileSessions({...f.options,additionalSessionCollections}),/session_collections_invalid/)
})

test('rolls back the protected profile and both session families when product-session deletion fails',async()=>{
 const f=await setup({failProductDelete:true})
 await assert.rejects(f.runtime.replacePin(replacement()),/synthetic-product-session-delete-failed/)
 assert.deepEqual(await f.vault.get(profiles,binding.profileId),f.profile)
 for(const collection of [primary,product])assert.ok(await f.vault.get(collection,`owned-${collection}`))
 assert.equal(await openServerProfileSecret(f.profile.protectedWalletSeed,oldPin,`${binding.profileId}:wallet-seed`,f.sealer),seed.walletSeed)
})

test('rewraps a known legacy subset without fabricating registered keys, storage metadata or strict custody',async()=>{
 const f=await setup({legacy:true}),updated=await f.runtime.replacePin(replacement())
 assert.deepEqual(updated.publicJwks,f.profile.publicJwks)
 assert.equal('storagePublicJwk' in updated,false);assert.equal('confidentialStorageProfile' in updated,false)
 for(const key of ['custody','secureTransportAdapter','confidentialStorageAdapter','wallet','privateKey'])assert.equal(key in updated,false)
 assert.equal(await openServerProfileSecret(updated.protectedWalletSeed,newPin,`${binding.profileId}:wallet-seed`,f.sealer),seed.walletSeed)
 await assert.rejects(f.runtime.unlock({...binding,pin:newPin}),/migration|binding/)
 for(const collection of [primary,product])assert.equal(await f.vault.get(collection,`owned-${collection}`),undefined)
})

test('rejects forged full public material, private keys, ambiguous subsets and wrong seeds before any rewrap',async()=>{
 const changes=[
  profile=>{profile.publicJwks[0].x='synthetic-wrong-public-coordinate'},
  profile=>{profile.publicJwks[1].pub='synthetic-wrong-public-material'},
  profile=>{profile.publicJwks.push(structuredClone(profile.publicJwks[0]))},
  profile=>{profile.publicJwks[0].d='synthetic-private-field'},
  profile=>{profile.publicJwks[0].kid='synthetic-unknown-key'},
  profile=>{delete profile.publicJwks[0].x},
  profile=>{profile.publicJwks=[]},
 ]
 for(const change of changes){
  const f=await setup({legacy:true});change(f.profile);await f.vault.put(profiles,f.profile)
  await assert.rejects(f.runtime.replacePin(replacement()))
  assert.deepEqual(await f.vault.get(profiles,binding.profileId),f.profile)
  for(const collection of [primary,product])assert.ok(await f.vault.get(collection,`owned-${collection}`))
 }
 const f=await setup({legacy:true})
 await assert.rejects(f.runtime.replacePin({...replacement(),authorizedWalletSeed:Buffer.alloc(32,3).toString('base64url')}))
 assert.deepEqual(await f.vault.get(profiles,binding.profileId),f.profile)
})
