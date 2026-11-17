// Flow contract: real ML-DSA/ML-KEM requests carry only the exact sender public KEM key in the authenticated protected header; an independent peer replies to that key, while header tampering fails before decryption and never changes wallet custody.
import assert from 'node:assert/strict'
import test from 'node:test'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'

const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),randomUUID,
 digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value).digest('hex')})
const context=id=>({profile:{profileId:id},runtime:{runtimeId:`${id}:server-runtime`,runtimeType:'backend-service'}})
async function fixture(){
 const senderContext=context('synthetic-reply-sender'),gatewayContext=context('synthetic-reply-gateway')
 let verifiedSenderEncryption
 const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>verifiedSenderEncryption})
 await gateway.provisionCommunicationKeys(gatewayContext,'synthetic-reply-gateway-seed')
 const gatewayPublic=gateway.getPublicJwks(gatewayContext)
 const sender=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gatewayPublic.encryption})
 await sender.provisionCommunicationKeys(senderContext,'synthetic-reply-sender-seed')
 const senderPublic=sender.getPublicJwks(senderContext)
 return {sender,gateway,senderContext,gatewayContext,senderPublic,gatewayPublic,setVerifiedSender:key=>{verifiedSenderEncryption=key}}
}
for(const method of ['packBootstrapForRecipientWithContext','packForRecipientWithContext']){
 test(`${method} authenticates its public reply key and accepts a pinned signed response for that same key`,async()=>{
  const f=await fixture()
  const message={iss:'did:web:example.invalid:employee',aud:'did:web:example.invalid',jti:randomUUID(),thid:randomUUID(),body:{subject_token_type:'synthetic-activation-contract'}}
  const packed=await f.sender[method](message,message.aud,{context:f.senderContext})
  const header=JSON.parse(Buffer.from(packed.split('.')[0],'base64url'))
  assert.deepEqual(header.jwk,f.senderPublic.encryption,'request must advertise the exact owned sender KEM public key')
  assert.equal(header.skid,header.jwk.kid)
  assert.equal(Object.keys(header.jwk).some(key=>['d','dBytes','k','priv','secretKey','secretKeyBytes'].includes(key)),false)
  const incoming=await f.gateway.unpackWithContext(packed,{context:f.gatewayContext})
  assert.equal(await crypto.verifyJws(incoming.meta.jws.compact,f.senderPublic.signing),true)
  const signedHeader=JSON.parse(Buffer.from(incoming.meta.jws.compact.split('.')[0],'base64url'))
  assert.equal(signedHeader.skid,header.skid,'the signed sender KEM thumbprint must bind the advertised reply key')
  assert.deepEqual(incoming.content,message)
  f.setVerifiedSender(incoming.meta.jwe.protected.jwk)
  const response={iss:message.aud,aud:message.iss,jti:randomUUID(),thid:message.thid,body:{status:'synthetic-response'}}
  const reply=await f.gateway.packForRecipientWithContext(response,message.iss,{context:f.gatewayContext})
  const decoded=await f.sender.unpackWithContext(reply,{context:f.senderContext})
  assert.equal(await crypto.verifyJws(decoded.meta.jws.compact,f.gatewayPublic.signing),true)
  assert.deepEqual(decoded.content,response)
  assert.deepEqual(f.sender.getPublicJwks(f.senderContext),f.senderPublic)
 })
}
test('a changed reply-key protected header is rejected by real authenticated decryption',async()=>{
 const f=await fixture(),message={iss:'did:web:example.invalid:employee',aud:'did:web:example.invalid',jti:randomUUID(),thid:randomUUID(),body:{}}
 const packed=await f.sender.packBootstrapForRecipientWithContext(message,message.aud,{context:f.senderContext})
 const parts=packed.split('.'),header=JSON.parse(Buffer.from(parts[0],'base64url'))
 assert.deepEqual(header.jwk,f.senderPublic.encryption,'request must contain its authenticated public reply key')
 header.jwk=f.gatewayPublic.encryption;parts[0]=Buffer.from(JSON.stringify(header)).toString('base64url')
 await assert.rejects(f.gateway.unpackWithContext(parts.join('.'),{context:f.gatewayContext}))
 assert.deepEqual(f.sender.getPublicJwks(f.senderContext),f.senderPublic)
})

test('pre-DCR proof signs the exact existing sender KEM thumbprint independently from outer encryption metadata',async()=>{
 const f=await fixture();const message={iss:'did:web:example.invalid:employee',aud:'did:web:example.invalid',jti:randomUUID(),thid:randomUUID(),body:{}}
 const packed=await f.sender.packBootstrapForRecipientWithContext(message,message.aud,{context:f.senderContext})
 const incoming=await f.gateway.unpackWithContext(packed,{context:f.gatewayContext})
 assert.equal(await crypto.verifyJws(incoming.meta.jws.compact,f.senderPublic.signing),true)
 const signedHeader=JSON.parse(Buffer.from(incoming.meta.jws.compact.split('.')[0],'base64url'))
 assert.equal(signedHeader.skid,f.senderPublic.encryption.kid)
})
