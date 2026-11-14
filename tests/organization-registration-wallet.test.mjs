// Flow contract: the trusted server reconstructs scoped communication keys, signs and encrypts with independent cryptography, rejects tampering and never exposes a plaintext transport fallback.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'

const context={profile:{profileId:'synthetic-profile'},runtime:{runtimeId:'synthetic-runtime:server-runtime',runtimeType:'backend-service'}}
const seed='synthetic-wallet-seed-for-independent-crypto-test'

test('reconstructs the same scoped keys and performs authenticated encrypted round trips',async()=>{
  const recipient=new OrganizationRegistrationWallet()
  await recipient.provisionCommunicationKeys(context,seed)
  assert.equal(recipient.getPublicJwks(context).signing.kid,'urn:ietf:params:oauth:jwk-thumbprint:sha-256:gPkgp0xVTBDV3PZ6cBpaZzss_EKT0AiGYaeNbHmb9KU')
  assert.equal(recipient.getPublicJwks(context).encryption.kid,'7Xm9LvSN8jNPfncq7pt1kNh2VYBBYNGOWOR2wUCfMaA')
  const repeated=new OrganizationRegistrationWallet()
  await repeated.provisionCommunicationKeys(context,seed)
  assert.deepEqual(repeated.getPublicJwks(context),recipient.getPublicJwks(context))
  const sender=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>recipient.getPublicJwks(context).encryption})
  await sender.provisionCommunicationKeys(context,'another-synthetic-wallet-seed')
  const message={thid:'synthetic-thread',iss:'synthetic-sender',body:{data:[{type:'Organization'}]}}
  const packed=await sender.packForRecipientWithContext(message,'did:web:example.invalid',{context})
  assert.equal(packed.split('.').length,5)
  assert.equal(packed.includes('synthetic-thread'),false)
  assert.deepEqual((await recipient.unpackWithContext(packed,{context})).content,message)
  const pieces=packed.split('.')
  pieces[3]=(pieces[3][0]==='A'?'B':'A')+pieces[3].slice(1)
  await assert.rejects(recipient.unpackWithContext(pieces.join('.'),{context}))
  await assert.rejects(recipient.unpackWithContext(packed,{context:{...context,runtime:{...context.runtime,runtimeId:'another-runtime'}}}))
})
