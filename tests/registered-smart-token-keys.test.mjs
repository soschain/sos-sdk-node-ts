// Flow contract: SMART has a separately configured signing algorithm/published authentication method, while outer registered transport stays PQC. Only keys from the expected provider document are returned; JWT headers never select a resolver target, policy or key URL.
import assert from 'node:assert/strict'
import {generateKeyPairSync} from 'node:crypto'
import {readFile} from 'node:fs/promises'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
const load=()=>import('../dist/registered-did-keys.js')
function document(algorithm='ES384'){
 const pair=generateKeyPairSync('ec',{namedCurve:algorithm==='ES384'?'secp384r1':'prime256v1'})
 const key={...pair.publicKey.export({format:'jwk'}),alg:algorithm,kid:'synthetic-smart-signing',use:'sig'}
 const id=`${safe.didWeb}#${key.kid}`
 return {id:safe.didWeb,verificationMethod:[{id,controller:safe.didWeb,type:'JsonWebKey2020',publicKeyJwk:key}],authentication:[id],assertionMethod:[id]}
}
const options=(doc,algorithm='ES384',extra={})=>({algorithm,...extra,fetchImpl:async url=>{assert.equal(new URL(url).origin,new URL(safe.httpsBaseUrl).origin);return new Response(JSON.stringify(doc),{status:200})}})

test('resolves configured ES384/ES256 authentication methods independently from the PQC communication selection',async()=>{
 const {resolveRegisteredSmartTokenSigningJwk}=await load()
 assert.equal(typeof resolveRegisteredSmartTokenSigningJwk,'function')
 for(const algorithm of ['ES384','ES256']){
  const doc=document(algorithm),key=await resolveRegisteredSmartTokenSigningJwk(safe.didWeb,options(doc,algorithm))
  assert.deepEqual(key,doc.verificationMethod[0].publicKeyJwk)
 }
 const oracle=JSON.parse(await readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)))
 const key=oracle.descriptors.find(item=>item.purpose==='comm-signing').publicJwk,id=`${safe.didWeb}#${key.kid}`
 const pqc={id:safe.didWeb,verificationMethod:[{id,controller:safe.didWeb,type:'JsonWebKey2020',publicKeyJwk:key}],authentication:[id]}
 assert.deepEqual(await resolveRegisteredSmartTokenSigningJwk(safe.didWeb,options(pqc,'ML-DSA-44')),key)
})

test('denies foreign or ambiguous methods, private keys, wrong curve and unconfigured algorithms without trusting header data',async()=>{
 const {resolveRegisteredSmartTokenSigningJwk}=await load()
 assert.equal(typeof resolveRegisteredSmartTokenSigningJwk,'function')
 const doc=document(),variants=[]
 const foreign=structuredClone(doc);foreign.id=`${safe.didWeb}:foreign`;variants.push(foreign)
 const controller=structuredClone(doc);controller.verificationMethod[0].controller=`${safe.didWeb}:foreign`;variants.push(controller)
 const relationship=structuredClone(doc);relationship.authentication=[];variants.push(relationship)
 const privateKey=structuredClone(doc);privateKey.verificationMethod[0].publicKeyJwk.d='synthetic-private-field';variants.push(privateKey)
 const mismatch=structuredClone(doc);mismatch.verificationMethod[0].publicKeyJwk.kid='synthetic-foreign-kid';variants.push(mismatch)
 const wrongCurve=structuredClone(doc);wrongCurve.verificationMethod[0].publicKeyJwk.crv='P-256';variants.push(wrongCurve)
 const duplicate=structuredClone(doc),other=document().verificationMethod[0]
 other.id=`${safe.didWeb}#synthetic-other-key`;other.publicKeyJwk.kid='synthetic-other-key'
 duplicate.verificationMethod.push(other);duplicate.authentication.push(other.id);variants.push(duplicate)
 for(const value of variants)await assert.rejects(resolveRegisteredSmartTokenSigningJwk(safe.didWeb,options(value)))
 await assert.rejects(resolveRegisteredSmartTokenSigningJwk(safe.didWeb,options(doc,'RS256')))
 assert.deepEqual(await resolveRegisteredSmartTokenSigningJwk(safe.didWeb,options(duplicate,'ES384',{verificationMethodId:doc.verificationMethod[0].id})),doc.verificationMethod[0].publicKeyJwk)
})
