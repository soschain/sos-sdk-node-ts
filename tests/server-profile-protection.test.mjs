// Flow contract: retain persisted PIN-plus-host profile envelopes and purpose-specific AAD without changing seeds or keys; reject wrong PIN before host access and keep host outages distinct. A synthetic read-only compatibility oracle provides the existing ciphertext, and a native codec independently opens newly written envelopes.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash,createDecipheriv,scryptSync} from 'node:crypto'
import test from 'node:test'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
const load=()=>import('../dist/server-profile-protection.js')
const wallet=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const fixture=()=>readFile(new URL('./fixtures/server-profile-protection.json',import.meta.url),'utf8').then(JSON.parse)
const pin='synthetic-profile-pin',aad=`${wallet.walletKeyDerivationId}:wallet-seed`
const host=()=>createAesGcmProfileSealer(createHash('sha256').update('synthetic existing profile key').digest())
function decrypt(value,key,aad){const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(value.ivBase64Url,'base64url'));decipher.setAAD(Buffer.from(aad));decipher.setAuthTag(Buffer.from(value.tagBase64Url,'base64url'));return Buffer.concat([decipher.update(Buffer.from(value.ciphertextBase64Url,'base64url')),decipher.final()])}

test('opens the actual stored synthetic envelope and preserves all original ciphertext fields',async()=>{
 const {openServerProfileSecret}=await load(),{envelope}=await fixture(),before=structuredClone(envelope)
 assert.equal(await openServerProfileSecret(envelope,pin,aad,host()),wallet.walletSeed)
 assert.deepEqual(envelope,before)
})
test('writes a fresh envelope readable by an independent native decoder with the exact existing AAD',async()=>{
 const {protectServerProfileSecret}=await load(),sealer=host(),calls=[]
 const envelope=await protectServerProfileSecret(wallet.walletSeed,pin,aad,{seal:async(value,binding)=>{calls.push(binding);return sealer.seal(value,binding)},unseal:sealer.unseal},{cost:1024})
 assert.equal(envelope.version,(await fixture()).envelope.version)
 assert.deepEqual(Object.keys(envelope).sort(),['kdf','payload','pinWrappedHostDek','version'])
 const k=envelope.kdf,key=scryptSync(pin,Buffer.from(k.saltBase64Url,'base64url'),32,{N:k.cost,r:k.blockSize,p:k.parallelization,maxmem:64*1024*1024})
 const wrapped=decrypt(envelope.pinWrappedHostDek,key,`${aad}:host-wrapped-dek`).toString('utf8'),dek=Buffer.from(await sealer.unseal(wrapped,`${aad}:dek`),'base64url')
 assert.equal(decrypt(envelope.payload,dek,`${aad}:payload`).toString('utf8'),wallet.walletSeed)
 assert.deepEqual(calls,[`${aad}:dek`]);assert.equal(k.keyLength,32);assert.equal(Buffer.from(k.saltBase64Url,'base64url').length,16)
 const second=await protectServerProfileSecret(wallet.walletSeed,pin,aad,sealer,{cost:1024});assert.notDeepEqual(envelope,second)
 const defaults=await protectServerProfileSecret(wallet.walletSeed,pin,aad,sealer);assert.deepEqual({cost:defaults.kdf.cost,blockSize:defaults.kdf.blockSize,parallelization:defaults.kdf.parallelization},{cost:16384,blockSize:8,parallelization:1})
})
test('wrong PIN and purpose AAD reject before host unseal without masking host availability failures',async()=>{
 const {openServerProfileSecret,ProfilePinRejectedError}=await load(),{envelope}=await fixture();let calls=0
 const unavailable={seal:host().seal,unseal:async()=>{calls++;throw new Error('synthetic-host-unavailable')}}
 for(const [supplied,binding] of [['incorrect-profile-pin',aad],[pin,`${aad}:vp-token`]])await assert.rejects(openServerProfileSecret(envelope,supplied,binding,unavailable),ProfilePinRejectedError)
 assert.equal(calls,0);await assert.rejects(openServerProfileSecret(envelope,pin,aad,unavailable),/synthetic-host-unavailable/);assert.equal(calls,1)
})
test('rejects tampered payload and an invalid host DEK without returning plaintext',async()=>{
 const {openServerProfileSecret,ProfilePinRejectedError}=await load(),{envelope}=await fixture(),changed=structuredClone(envelope)
 const tag=Buffer.from(changed.payload.tagBase64Url,'base64url');tag[0]^=1;changed.payload.tagBase64Url=tag.toString('base64url')
 await assert.rejects(openServerProfileSecret(changed,pin,aad,host()),error=>!(error instanceof ProfilePinRejectedError))
 await assert.rejects(openServerProfileSecret(envelope,pin,aad,{seal:host().seal,unseal:async()=>Buffer.alloc(31).toString('base64url')}),/invalid.*DEK/i)
})
test('fails closed on malformed or resource-exhausting envelope parameters without calling the host',async()=>{
 const {openServerProfileSecret,protectServerProfileSecret}=await load(),{envelope}=await fixture();let calls=0
 const guarded={seal:async()=>{calls++;return ''},unseal:async()=>{calls++;return ''}}
 for(const update of [{version:'unknown'},{kdf:{...envelope.kdf,cost:2**30}},{kdf:{...envelope.kdf,cost:16385}},{kdf:{...envelope.kdf,blockSize:0}},{kdf:{...envelope.kdf,keyLength:16}},{payload:{...envelope.payload,ivBase64Url:'bad'}},{pinWrappedHostDek:{...envelope.pinWrappedHostDek,tagBase64Url:'bad'}}])await assert.rejects(openServerProfileSecret({...envelope,...update},pin,aad,guarded))
 await assert.rejects(protectServerProfileSecret(wallet.walletSeed,'short',aad,guarded));assert.equal(calls,0)
})
