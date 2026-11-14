// Flow contract: recover the exact existing profile/runtime key purposes from an already unlocked governed seed, keep document keys outside DCR, and sign through distinct actor/VP ES384 keys after client binding; wrong stored material never rotates or grants authority. The oracle is synthetic public material only and no legacy dependency runs in these tests.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createPublicKey,verify} from 'node:crypto'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
const load=()=>import('../dist/server-profile-custody-keys.js')
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const fixture=()=>readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url),'utf8').then(JSON.parse)
const base=()=>({walletKeyDerivationId:seed.walletKeyDerivationId,unlockedWalletSeed:seed.walletSeed})
const keys=async()=>{const {descriptors}=await fixture();return {descriptors,publicJwks:descriptors.filter(d=>d.purpose!=='document-at-rest').map(d=>d.publicJwk),storagePublicJwk:descriptors.find(d=>d.purpose==='document-at-rest').publicJwk}}

test('recovers all six original public descriptors and excludes the distinct document key from five DCR keys',async()=>{
 const {openServerProfileCustodyKeys}=await load(),expected=await keys(),opened=await openServerProfileCustodyKeys({...base(),binding:{kind:'enrollment'}})
 assert.deepEqual(opened.descriptors,expected.descriptors)
 assert.deepEqual(opened.publicJwks,expected.publicJwks);assert.deepEqual(opened.storagePublicJwk,expected.storagePublicJwk)
 assert.equal(opened.publicJwks.length,5);assert.equal(opened.descriptors.length,6)
 assert.equal(opened.publicJwks.some(key=>key.kid===opened.storagePublicJwk.kid),false)
 assert.notEqual(opened.storagePublicJwk.x,opened.descriptors.find(d=>d.purpose==='comm-encryption').publicJwk.x)
 for(const descriptor of opened.descriptors){for(const secret of ['d','dBytes','privateKey','secretKeyBytes'])assert.equal(secret in descriptor.publicJwk,false)}
 assert.equal(Object.isFrozen(opened.descriptors),true)
})
test('opens an existing registered five-key profile only when every stored public material and document key matches',async()=>{
 const {openServerProfileCustodyKeys}=await load(),expected=await keys(),binding={kind:'registered',publicJwks:expected.publicJwks,storagePublicJwk:expected.storagePublicJwk}
 assert.deepEqual((await openServerProfileCustodyKeys({...base(),binding})).publicJwks,expected.publicJwks)
 for(const changed of [
  {...binding,publicJwks:binding.publicJwks.slice(1)},
  {...binding,publicJwks:[...binding.publicJwks,binding.publicJwks[0]]},
  {...binding,publicJwks:binding.publicJwks.map((key,i)=>i===0?{...key,x:binding.publicJwks.find(k=>k.kty==='OKP').x}:key)},
  {...binding,storagePublicJwk:binding.publicJwks.find(key=>key.kty==='OKP')},
  {...binding,publicJwks:binding.publicJwks.map((key,i)=>i===0?{...key,d:'synthetic-private-field'}:key)},
  {kind:'registered'},
 ])await assert.rejects(openServerProfileCustodyKeys({...base(),binding:changed}))
 await assert.rejects(openServerProfileCustodyKeys({...base(),walletKeyDerivationId:`${seed.walletKeyDerivationId}-foreign`,binding}))
 await assert.rejects(openServerProfileCustodyKeys({...base(),unlockedWalletSeed:Buffer.alloc(32,4).toString('base64url'),binding}))
})
test('signs real ES384 compact JWS with separate owned actor and VP keys and rejects missing or mismatched client binding',async()=>{
 const {openServerProfileCustodyKeys}=await load(),opened=await openServerProfileCustodyKeys({...base(),binding:{kind:'enrollment'}})
 const clientId='synthetic-registered-client',payload={client_id:clientId,sub:safe.didWeb,vp:{holder:clientId}}
 for(const [method,purpose] of [['signActorJws','actor-signing'],['signVpJws','vp-token-signing']]){
  const compact=await opened[method]({clientId,payload}),parts=compact.split('.'),header=JSON.parse(Buffer.from(parts[0],'base64url'))
  const descriptor=opened.descriptors.find(d=>d.purpose===purpose)
  assert.equal(header.alg,'ES384');assert.equal(header.kid,descriptor.kid)
  assert.deepEqual(JSON.parse(Buffer.from(parts[1],'base64url')),payload)
  assert.equal(Buffer.from(parts[2],'base64url').length,96)
  assert.equal(verify('sha384',Buffer.from(`${parts[0]}.${parts[1]}`),{key:createPublicKey({key:descriptor.publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')),true)
  const other=opened.descriptors.find(d=>d.purpose===(purpose==='actor-signing'?'vp-token-signing':'actor-signing'))
  assert.equal(verify('sha384',Buffer.from(`${parts[0]}.${parts[1]}`),{key:createPublicKey({key:other.publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')),false)
  await assert.rejects(opened[method]({clientId:'',payload}));await assert.rejects(opened[method]({clientId,payload:{...payload,client_id:'foreign-client'}}))
 }
})
