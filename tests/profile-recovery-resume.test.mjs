// Flow contract: after the host proves CURRENT profile PIN and revision, initial recovery delivery may resume generation one with identical code and no writes; foreign bindings, changed material and recovered generations never disclose it.
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy'
import assert from 'node:assert/strict'
import {createCipheriv,createDecipheriv} from 'node:crypto'
import {readFileSync} from 'node:fs'
const fixture=JSON.parse(readFileSync(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const identity={profileId:fixture.walletKeyDerivationId,ownerId:'synthetic-resume-owner',controllerKind:'organization-controller',contactKind:'phone',contact:SAFE.phoneE164}
const seed=()=>Buffer.from(fixture.walletSeed,'base64url')
async function setup(){
 const {ProfileRecoveryService}=await import('../dist/profile-recovery-service.js')
 const key=Buffer.alloc(32,7);let record,writes=0,decryptions=0,fail=false
 const service=new ProfileRecoveryService({environment:'staging',repository:{async get(){return structuredClone(record)},async put(value){record=structuredClone(value);writes++},async rotate(value){record=structuredClone(value);writes++}},kms:{keyName:'synthetic://resume-key',async encrypt(bytes,aad){
  const iv=Buffer.alloc(12,9),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aad)
  return Buffer.concat([iv,cipher.update(bytes),cipher.final(),cipher.getAuthTag()]).toString('base64url')
 },async decrypt(value,aad){
  decryptions++;if(fail)throw new Error('synthetic-kms-unavailable')
  const bytes=Buffer.from(value,'base64url'),cipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));cipher.setAAD(aad);cipher.setAuthTag(bytes.subarray(-16))
  return Uint8Array.from(Buffer.concat([cipher.update(bytes.subarray(12,-16)),cipher.final()]))
 }}})
 return {service,record:()=>structuredClone(record),writes:()=>writes,decryptions:()=>decryptions,change:change=>{record={...record,...change}},fail:()=>{fail=true}}
}
test('resumes the exact generation-one phone code without persistence, generation change or mutation of caller seed',async()=>{
 const f=await setup(),first=await f.service.enroll(identity,seed()),before=f.record(),opened=seed(),copy=Buffer.from(opened)
 assert.equal(typeof f.service.resumeEnrollment,'function')
 assert.deepEqual(await f.service.resumeEnrollment(identity,opened),first)
 assert.deepEqual(opened,copy);assert.deepEqual(f.record(),before);assert.equal(f.writes(),1)
})
test('denies foreign identity, changed material and generations other than one before KMS',async()=>{
 const f=await setup();await f.service.enroll(identity,seed())
 assert.equal(typeof f.service.resumeEnrollment,'function')
 for(const change of [{ownerId:'foreign'},{profileId:'foreign'},{contact:SAFE.secondContactPhoneE164},{controllerKind:'individual-controller'}])await assert.rejects(f.service.resumeEnrollment({...identity,...change},seed()))
 await assert.rejects(f.service.resumeEnrollment(identity,Buffer.alloc(32,99)))
 f.change({generation:2});await assert.rejects(f.service.resumeEnrollment(identity,seed()))
 assert.equal(f.decryptions(),0);assert.equal(f.writes(),1)
})
test('preserves operational KMS failures and persisted recovery state',async()=>{
 const f=await setup();await f.service.enroll(identity,seed());const before=f.record();f.fail()
 assert.equal(typeof f.service.resumeEnrollment,'function')
 await assert.rejects(f.service.resumeEnrollment(identity,seed()),/synthetic-kms-unavailable/u)
 assert.deepEqual(f.record(),before);assert.equal(f.writes(),1)
})
