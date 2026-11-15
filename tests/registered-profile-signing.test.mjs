// Flow contract: sign existing detached credential bytes with the registered actor key and identity-presentation claims with the distinct registered VP key, preserving exact wire headers/claims, original public material and stricter client-bound signing APIs. Foreign contexts and opposite-purpose keys never substitute for the owned key. No legacy runtime executes.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createPublicKey,verify} from 'node:crypto'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {openServerProfileCustodyKeys} from '../dist/server-profile-custody-keys.js'
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const oracle=JSON.parse(await readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)))
const publicJwks=oracle.descriptors.filter(d=>d.purpose!=='document-at-rest').map(d=>d.publicJwk)
const storagePublicJwk=oracle.descriptors.find(d=>d.purpose==='document-at-rest').publicJwk
const input={walletKeyDerivationId:seed.walletKeyDerivationId,unlockedWalletSeed:seed.walletSeed,binding:{kind:'registered',publicJwks,storagePublicJwk}}
const descriptor=purpose=>oracle.descriptors.find(d=>d.purpose===purpose)
const verifies=(bytes,signature,purpose)=>verify('sha384',bytes,{key:createPublicKey({key:descriptor(purpose).publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url'))
const claims=()=>({iss:safe.didWeb,sub:safe.didWeb,aud:safe.httpsBaseUrl,nonce:'synthetic-presentation-nonce',state:'synthetic-presentation-state',iat:1794614400,exp:1794614700,jti:`urn:uuid:${safe.resourceUuid}`,vp:{'@context':['https://www.w3.org/ns/credentials/v2'],type:['VerifiablePresentation'],holder:safe.didWeb,verifiableCredential:[{type:['VerifiableCredential'],issuer:safe.didWeb,credentialSubject:{id:safe.didWeb}}]}})

test('signs exact detached credential bytes with RFC7797 headers and the registered actor ES384 key',async()=>{
 const opened=await openServerProfileCustodyKeys(input)
 const payload=JSON.stringify({type:['VerifiableCredential'],issuer:safe.didWeb,credentialSubject:{id:safe.didWeb,display:'Synthetic subject'}})
 const compact=await opened.signActorDetachedJws({payload}),parts=compact.split('.')
 assert.equal(parts.length,3);assert.equal(parts[1],'')
 assert.deepEqual(JSON.parse(Buffer.from(parts[0],'base64url')),{typ:'application/vc+ld+json',alg:'ES384',kid:descriptor('actor-signing').kid,b64:false,crit:['b64']})
 const signingBytes=Buffer.concat([Buffer.from(`${parts[0]}.`,'ascii'),Buffer.from(payload,'utf8')])
 assert.equal(verifies(signingBytes,parts[2],'actor-signing'),true)
 assert.equal(verifies(signingBytes,parts[2],'vp-token-signing'),false)
 assert.equal(verifies(Buffer.concat([signingBytes,Buffer.from(' altered')]),parts[2],'actor-signing'),false)
 const binary=Buffer.from('Synthetic credential bytes: é\n','utf8')
 const second=(await opened.signActorDetachedJws({payload:binary})).split('.')
 assert.equal(verifies(Buffer.concat([Buffer.from(`${second[0]}.`,'ascii'),binary]),second[2],'actor-signing'),true)
})

test('signs the existing identity presentation typ and claims with the VP key without adding client claims or embedded keys',async()=>{
 const opened=await openServerProfileCustodyKeys(input),payload=claims(),before=structuredClone(payload)
 const compact=await opened.signIdentityPresentationJws({claims:payload}),parts=compact.split('.')
 assert.equal(parts.length,3)
 assert.deepEqual(JSON.parse(Buffer.from(parts[0],'base64url')),{typ:'application/vp+jwt',alg:'ES384',kid:descriptor('vp-token-signing').kid})
 assert.deepEqual(JSON.parse(Buffer.from(parts[1],'base64url')),before);assert.deepEqual(payload,before)
 assert.equal('client_id' in payload,false)
 const signingBytes=Buffer.from(`${parts[0]}.${parts[1]}`,'ascii')
 assert.equal(verifies(signingBytes,parts[2],'vp-token-signing'),true)
 assert.equal(verifies(signingBytes,parts[2],'actor-signing'),false)
 const changed=Buffer.from(JSON.stringify({...payload,nonce:'synthetic-foreign-nonce'}),'utf8').toString('base64url')
 assert.equal(verifies(Buffer.from(`${parts[0]}.${changed}`,'ascii'),parts[2],'vp-token-signing'),false)
})

test('retains public key parity, rejects foreign derivation contexts and returns no raw private custody',async()=>{
 const opened=await openServerProfileCustodyKeys(input)
 assert.deepEqual(opened.publicJwks,publicJwks);assert.deepEqual(opened.storagePublicJwk,storagePublicJwk)
 assert.deepEqual(opened.descriptors,oracle.descriptors)
 for(const name of ['seed','walletSeed','unlockedWalletSeed','privateKey','secretKeyBytes'])assert.equal(name in opened,false)
 for(const changed of [{walletKeyDerivationId:`${seed.walletKeyDerivationId}-foreign`},{unlockedWalletSeed:Buffer.alloc(32,9).toString('base64url')}])await assert.rejects(openServerProfileCustodyKeys({...input,...changed}))
 const swapped=publicJwks.map(key=>key.kid===descriptor('actor-signing').kid?{...descriptor('vp-token-signing').publicJwk,kid:key.kid}:key)
 await assert.rejects(openServerProfileCustodyKeys({...input,binding:{...input.binding,publicJwks:swapped}}))
})

test('keeps both existing client-bound signing methods strict and purpose-separated',async()=>{
 const opened=await openServerProfileCustodyKeys(input),payload=claims()
 for(const [name,purpose] of [['signActorJws','actor-signing'],['signVpJws','vp-token-signing']]){
  await assert.rejects(opened[name]({clientId:'synthetic-client',payload}),/client_binding/)
  await assert.rejects(opened[name]({clientId:'synthetic-client',payload:{...payload,client_id:'synthetic-foreign-client'}}),/client_binding/)
  const parts=(await opened[name]({clientId:'synthetic-client',payload:{...payload,client_id:'synthetic-client'}})).split('.')
  assert.equal(verifies(Buffer.from(`${parts[0]}.${parts[1]}`,'ascii'),parts[2],purpose),true)
 }
})
