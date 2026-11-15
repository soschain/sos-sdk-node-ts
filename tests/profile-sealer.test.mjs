// Flow contract: preserve existing sealed profile ciphertext/UTF-8 AAD and raw recovery-share bytes with binary AAD using host-selected custody, reject tampering/custody failures, and never select an environment, seed or replacement key. KMS tests cross real loopback HTTP with injected cloud transport; they do not claim live Google IAM/KMS verification.
import assert from 'node:assert/strict'
import {createCipheriv,createDecipheriv,createHash} from 'node:crypto'
import {createServer} from 'node:http'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const load=()=>import('../dist/profile-sealer.js')
const key=createHash('sha256').update('synthetic existing profile key').digest()
const cleartext='synthetic existing profile seed',aad='synthetic-owner:synthetic-profile:wallet-session-seed'
const keyName=`projects/${safe.tenantId}/locations/global/keyRings/synthetic-profile/cryptoKeys/profile-sealer`
function priorEnvelope(){const iv=Buffer.alloc(12,7),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(aad));const data=Buffer.concat([cipher.update(cleartext,'utf8'),cipher.final()]);return `local-test-v1.${Buffer.concat([iv,cipher.getAuthTag(),data]).toString('base64url')}`}
function nativeUnseal(value){const packed=Buffer.from(value.slice('local-test-v1.'.length),'base64url'),decipher=createDecipheriv('aes-256-gcm',key,packed.subarray(0,12));decipher.setAAD(Buffer.from(aad));decipher.setAuthTag(packed.subarray(12,28));return Buffer.concat([decipher.update(packed.subarray(28)),decipher.final()]).toString('utf8')}

test('reads the existing AES envelope and produces ciphertext consumable by the original native codec',async()=>{
 const {createAesGcmProfileSealer}=await load()
 const suppliedKey=Buffer.from(key),sealer=createAesGcmProfileSealer(suppliedKey)
 suppliedKey.fill(0)
 assert.equal(await sealer.unseal(priorEnvelope(),aad),cleartext)
 const sealed=await sealer.seal(cleartext,aad)
 assert.match(sealed,/^local-test-v1\./)
 assert.equal(nativeUnseal(sealed),cleartext)
})

test('rejects wrong AAD, ciphertext tampering, malformed envelopes and a non-256-bit AES key',async()=>{
 const {createAesGcmProfileSealer}=await load()
 const sealer=createAesGcmProfileSealer(key),packed=Buffer.from(priorEnvelope().slice('local-test-v1.'.length),'base64url')
 packed[12]^=1
 for(const [value,binding] of [[priorEnvelope(),`${aad}:foreign`],[`local-test-v1.${packed.toString('base64url')}`,aad],['local-test-v1.invalid',aad],['wrong-profile.ciphertext',aad]])await assert.rejects(sealer.unseal(value,binding))
 assert.throws(()=>createAesGcmProfileSealer(Buffer.alloc(31)))
 await assert.rejects(createAesGcmProfileSealer(Buffer.alloc(32)).unseal(priorEnvelope(),aad))
})

test('preserves raw Google KMS ciphertext and exact base64 plaintext/AAD through real HTTP',async()=>{
 const {createGoogleKmsProfileSealer}=await load()
 const opaque=Buffer.from('synthetic opaque cloud ciphertext').toString('base64'),seen=[];let failure
 const server=createServer(async(request,response)=>{
  try{
   const chunks=[];for await(const chunk of request)chunks.push(chunk)
   const body=JSON.parse(Buffer.concat(chunks).toString());seen.push({path:request.url,body})
   assert.equal(request.headers.authorization,'Bearer synthetic-workload-access-token')
   assert.equal(body.additionalAuthenticatedData,Buffer.from(aad).toString('base64'))
   response.writeHead(200,{'Content-Type':'application/json'})
   if(request.url.endsWith(':encrypt')){assert.equal(body.plaintext,Buffer.from(cleartext).toString('base64'));response.end(JSON.stringify({ciphertext:opaque}))}
   else{assert.equal(body.ciphertext,opaque);response.end(JSON.stringify({plaintext:Buffer.from(cleartext).toString('base64')}))}
  }catch(error){failure=error;response.writeHead(500);response.end()}
 })
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{
  const sealer=createGoogleKmsProfileSealer({keyName,accessToken:async()=> 'synthetic-workload-access-token',fetchImpl:(url,init)=>{
   assert.equal(new URL(url).origin,'https://cloudkms.googleapis.com')
   return fetch(`http://127.0.0.1:${server.address().port}${new URL(url).pathname}`,init)
  }})
  assert.equal(await sealer.seal(cleartext,aad),opaque)
  assert.equal(await sealer.unseal(opaque,aad),cleartext)
  assert.deepEqual(seen.map(item=>item.path),[`/v1/${keyName}:encrypt`,`/v1/${keyName}:decrypt`]);assert.equal(failure,undefined)
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
})

test('requests workload metadata lazily with the required Google header instead of importing a cloud SDK',async()=>{
 const {createGoogleKmsProfileSealer}=await load()
 const seen=[]
 const sealer=createGoogleKmsProfileSealer({keyName,fetchImpl:async(url,init)=>{
  seen.push({url:String(url),init})
  if(String(url).startsWith('http://metadata.google.internal/')){
   assert.equal(new Headers(init.headers).get('Metadata-Flavor'),'Google')
   return Response.json({access_token:'synthetic-workload-access-token'})
  }
  assert.equal(new Headers(init.headers).get('authorization'),'Bearer synthetic-workload-access-token')
  return Response.json({ciphertext:Buffer.from('synthetic opaque cloud ciphertext').toString('base64')})
 }})
 assert.equal(seen.length,0)
 await sealer.seal(cleartext,aad)
 assert.equal(seen[0].url,'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token')
 assert.equal(seen.length,2)
})

test('rejects KMS or metadata failure and malformed successful responses without falling back to local encryption',async()=>{
 const {createGoogleKmsProfileSealer}=await load()
 for(const result of [new Response('',{status:403}),Response.json({}),Response.json({ciphertext:42})]){
  const sealer=createGoogleKmsProfileSealer({keyName,accessToken:async()=> 'synthetic-workload-access-token',fetchImpl:async()=>result})
  await assert.rejects(sealer.seal(cleartext,aad))
 }
 let requests=0
 const sealer=createGoogleKmsProfileSealer({keyName,fetchImpl:async()=>{requests++;return Response.json({})}})
 await assert.rejects(sealer.seal(cleartext,aad));assert.equal(requests,1)
 assert.throws(()=>createGoogleKmsProfileSealer({keyName:`${keyName}?untrusted-route`}))
})

test('recovery KMS port preserves all 32 share bytes and binary AAD over actual HTTP without UTF-8 conversion',async()=>{
 const {createGoogleKmsProfileRecovery}=await load()
 const share=Uint8Array.from({length:32},(_,index)=>(index*37)&255),binding=Uint8Array.from([0,255,10,128]),seen=[]
 const opaque=Buffer.from('synthetic opaque recovery ciphertext').toString('base64');let failure
 const server=createServer(async(request,response)=>{
  try{
   const chunks=[];for await(const chunk of request)chunks.push(chunk)
   const body=JSON.parse(Buffer.concat(chunks).toString());seen.push(request.url)
   assert.equal(request.headers.authorization,'Bearer synthetic-workload-access-token')
   assert.equal(body.additionalAuthenticatedData,Buffer.from(binding).toString('base64'))
   response.writeHead(200,{'Content-Type':'application/json'})
   if(request.url.endsWith(':encrypt')){assert.equal(body.plaintext,Buffer.from(share).toString('base64'));response.end(JSON.stringify({ciphertext:opaque}))}
   else{assert.equal(body.ciphertext,opaque);response.end(JSON.stringify({plaintext:Buffer.from(share).toString('base64')}))}
  }catch(error){failure=error;response.writeHead(500);response.end()}
 })
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{
  const adapter=createGoogleKmsProfileRecovery({keyName,accessToken:async()=> 'synthetic-workload-access-token',fetchImpl:(url,init)=>{
   assert.equal(new URL(url).origin,'https://cloudkms.googleapis.com')
   return fetch(`http://127.0.0.1:${server.address().port}${new URL(url).pathname}`,init)
  }})
  assert.equal(adapter.keyName,keyName)
  assert.equal(await adapter.encrypt(share,binding),opaque)
  assert.deepEqual(await adapter.decrypt(opaque,binding),share)
  assert.deepEqual(seen,[`/v1/${keyName}:encrypt`,`/v1/${keyName}:decrypt`]);assert.equal(failure,undefined)
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
})

test('recovery KMS rejects coerced or malformed shares and operational failures without a local fallback',async()=>{
 const {createGoogleKmsProfileRecovery}=await load()
 const share=new Uint8Array(32),binding=Uint8Array.from([1,2,3]);let requests=0
 const adapter=createGoogleKmsProfileRecovery({keyName,accessToken:async()=> 'synthetic-workload-access-token',fetchImpl:async()=>{requests++;return new Response('',{status:403})}})
 await assert.rejects(adapter.encrypt('synthetic-string',binding));await assert.rejects(adapter.encrypt(new Uint8Array(31),binding));assert.equal(requests,0)
 await assert.rejects(adapter.encrypt(share,binding));assert.equal(requests,1)
 for(const plaintext of ['!!!!',Buffer.alloc(31).toString('base64'),'',42]){
  const malformed=createGoogleKmsProfileRecovery({keyName,accessToken:async()=> 'synthetic-workload-access-token',fetchImpl:async()=>Response.json({plaintext})})
  await assert.rejects(malformed.decrypt('synthetic-ciphertext',binding))
 }
})
