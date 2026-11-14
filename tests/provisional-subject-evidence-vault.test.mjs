// Flow contract: actual evidence bytes stage as immutable bounded chunks in the existing vault, with canonical SHA3-384 CIDs, separate subject/controller/relationship slots and a small atomic pending-receipt publication only after full readback. Interrupted uploads resume idempotently; creator scope, expiry and integrity remain enforced without verification or signatures.
import test from 'node:test'
import assert from 'node:assert/strict'
import {randomUUID,createHash} from 'node:crypto'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {ProvisionalSubjectRegistrationVault} from '../dist/provisional-subject-registration-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {buildSha3_384EvidenceContentIdFromDigest} from 'antifraud-data-utils-ts/identity-assurance'

const creator={organizationReference:`Organization/${safe.demoOrganizationUuids.animalCare}`,actorIdentifier:`urn:uuid:${safe.resourceUuid}`,expiresAt:Date.now()+60_000}
const document=(slot='subject',bytes=Buffer.from('%PDF-1.7\nSynthetic pending document\n%%EOF'))=>({slot,fileName:`${slot}.pdf`,mediaType:'application/pdf',bytes:new Uint8Array(bytes)})
class InstrumentedVault extends TransactionalMemoryVaultRepository{
 failChunkIndex;failFinal=false;largestTransactionBytes=0;committedChunks=new Map();afterChunksCommitted
 async runTransaction(operation){
  let bytes=0;const chunks=[]
  const result=await super.runTransaction(transaction=>operation({...transaction,put:async(collection,input)=>{
   const values=Array.isArray(input)?input:[input]
   for(const row of values){
    bytes+=Buffer.byteLength(JSON.stringify(row))
    if(collection.endsWith('__evidence-chunks')){
     if(row.index===this.failChunkIndex){this.failChunkIndex=undefined;throw new Error('injected_chunk_failure')}
     chunks.push(row.id)
    }
    if(collection.endsWith('__pending-evidence-records')&&this.failFinal){this.failFinal=false;throw new Error('injected_final_failure')}
   }
   return transaction.put(collection,input)
  }}))
  this.largestTransactionBytes=Math.max(bytes,this.largestTransactionBytes)
  for(const id of chunks)this.committedChunks.set(id,(this.committedChunks.get(id)??0)+1)
  if(chunks.length)this.afterChunksCommitted?.()
  return result
 }
}
async function setup(kind='animal'){
 const {ProvisionalSubjectEvidenceVault,pendingSubjectEvidenceCollections}=await import('../dist/provisional-subject-evidence-vault.js')
 const store=new InstrumentedVault(),clock={now:Date.now()}
 const assertCreator=async participant=>participant?.other?{...creator,organizationReference:`Organization/${safe.demoOrganizationUuids.healthCare}`}:creator
 const registration=new ProvisionalSubjectRegistrationVault({store,scopeKey:safe.tenantId,assertCreator,now:()=>clock.now})
 const subject=kind==='human'?{kind:'human',alternateName:'Dependent subject',birthDate:'2015-01-01'}:{kind:'animal',alternateName:'Pending subject',ncbiTaxonomyId:'9615'}
 const created=await registration.register({participant:{},command:{operationId:randomUUID(),subject,controller:{legalName:'Proposed controller',contact:{kind:'telephone',value:safe.firstContactPhoneE164},relationship:'RESPRSN'}}})
 const provider=new ProvisionalSubjectEvidenceVault({store,scopeKey:safe.tenantId,assertCreator,now:()=>clock.now})
 const command={operationId:randomUUID(),registrationId:created.registrationId,verificationMethod:'sripp',subject:{identifier:{system:'urn:synthetic:subject-identifier',value:'subject-document-number'}},controller:{identifier:{type:'passport',value:'controller-document-number',country:'CA'}}}
 return {provider,registration,store,clock,created,command,names:pendingSubjectEvidenceCollections(safe.tenantId)}
}
test('stores actual bytes with independent slots and canonical CIDs, leaving all evidence pending',async()=>{
 const {provider,store,command,names,created}=await setup()
 const documents=[document(),document('controller'),document('relationship')]
 const receipt=await provider.submit({participant:{},command,documents})
 assert.equal(receipt.status,'pending');assert.equal(receipt.registrationId,created.registrationId)
 assert.deepEqual(receipt.documents.map(item=>item.slot),['subject','controller','relationship'])
 for(const item of documents){
  const expected=buildSha3_384EvidenceContentIdFromDigest(createHash('sha3-384').update(item.bytes).digest())
  assert.equal(receipt.documents.find(entry=>entry.slot===item.slot).contentId,expected)
  assert.deepEqual(await provider.readDocument({participant:{},registrationId:created.registrationId,slot:item.slot}),item.bytes)
 }
 assert.deepEqual(await provider.read({participant:{},registrationId:created.registrationId}),receipt)
 const records=await store.query(names.evidence,{})
 assert.equal(records[0].subjectReference,created.subjectIdentifier)
 assert.equal(records[0].controllerInvitationId,created.controllerInvitation.invitationId)
 assert.equal(Object.hasOwn(records[0],'controllerActorIdentifier'),false)
 assert.equal(Object.hasOwn(records[0],'signature'),false)
})
test('stores a human dependent subject document without inventing issued identifiers or animal taxonomy',async()=>{
 const {provider,command,created}=await setup('human'),documents=[document()]
 const receipt=await provider.submit({participant:{},command:{...command,subject:{},controller:{}},documents})
 assert.equal(receipt.status,'pending')
 assert.deepEqual(await provider.readDocument({participant:{},registrationId:created.registrationId,slot:'subject'}),documents[0].bytes)
})
test('resumes interrupted immutable chunks without exposing a partial pending receipt or rewriting committed bytes',async()=>{
 const {provider,store,command,names,created}=await setup()
 const documents=[document('subject',Buffer.alloc(3*1024*1024,65))]
 store.failChunkIndex=8
 await assert.rejects(provider.submit({participant:{},command,documents}),/injected_chunk_failure/)
 const before=await store.query(names.chunks,{})
 assert.ok(before.length>0)
 await assert.rejects(provider.read({participant:{},registrationId:created.registrationId}),/not_found/)
 assert.equal((await store.query(names.evidence,{})).length,0)
 const receipt=await provider.submit({participant:{},command,documents})
 assert.equal(receipt.status,'pending')
 for(const row of before)assert.equal(store.committedChunks.get(row.id),1)
 for(const row of await store.query(names.chunks,{}))assert.ok(Buffer.byteLength(JSON.stringify(row))<1024*1024)
 assert.ok(store.largestTransactionBytes<8*1024*1024)
 assert.deepEqual(await provider.readDocument({participant:{},registrationId:created.registrationId,slot:'subject'}),documents[0].bytes)
})
test('rolls back failed receipt publication and finalizes the same staged upload on retry',async()=>{
 const {provider,store,command,names,created}=await setup()
 store.failFinal=true
 await assert.rejects(provider.submit({participant:{},command,documents:[document()]}),/injected_final_failure/)
 assert.equal((await store.query(names.evidence,{})).length,0)
 await assert.rejects(provider.read({participant:{},registrationId:created.registrationId}),/not_found/)
 const receipt=await provider.submit({participant:{},command,documents:[document()]})
 assert.deepEqual(await provider.read({participant:{},registrationId:created.registrationId}),receipt)
})
test('keeps identical operation replay stable and rejects changed bytes or metadata',async()=>{
 const {provider,command}=await setup(),documents=[document()]
 const original=await provider.submit({participant:{},command,documents})
 assert.deepEqual(await provider.submit({participant:{},command,documents}),original)
 await assert.rejects(provider.submit({participant:{},command,documents:[document('subject',Buffer.from('changed'))]}),/conflict/)
 await assert.rejects(provider.submit({participant:{},command,documents:[{...document(),fileName:'changed.pdf'}]}),/conflict/)
})
test('denies wrong creator organization, unknown registration and forged target or controller authority',async()=>{
 const {provider,command,created}=await setup()
 await assert.rejects(provider.submit({participant:{other:true},command,documents:[document()]}),/forbidden/)
 await assert.rejects(provider.submit({participant:{},command:{...command,registrationId:randomUUID()},documents:[document()]}),/not_found/)
 await assert.rejects(provider.submit({participant:{},command:{...command,controllerActorIdentifier:creator.actorIdentifier},documents:[document()]}))
 await provider.submit({participant:{},command,documents:[document()]})
 await assert.rejects(provider.readDocument({participant:{other:true},registrationId:created.registrationId,slot:'subject'}),/forbidden/)
})
test('rejects invalid file policies and missing/duplicate subject slots before staging',async()=>{
 const {provider,store,command,names}=await setup()
 for(const documents of [[],[document('controller')],[document(),document()],[{...document(),mediaType:'text/html'}],[document('subject',new Uint8Array())],[document('subject',new Uint8Array(10*1024*1024+1))]])await assert.rejects(provider.submit({participant:{},command,documents}))
 assert.equal((await store.query(names.stages,{})).length,0)
})
test('detects corrupted stored chunks and refuses expired staged uploads',async()=>{
 const {provider,store,clock,command,names,created}=await setup()
 await provider.submit({participant:{},command,documents:[document()]})
 const row=(await store.query(names.chunks,{}))[0]
 await store.put(names.chunks,{...row,dataBase64:Buffer.from('corrupted').toString('base64')})
 await assert.rejects(provider.readDocument({participant:{},registrationId:created.registrationId,slot:'subject'}),/integrity/)
 clock.now+=24*60*60*1000+1
 await assert.rejects(provider.submit({participant:{},command,documents:[document()]}),/expired|not_found|forbidden/)
})
test('does not publish evidence if creator admission expires while bytes are staging',async()=>{
 const {provider,store,clock,command,names}=await setup()
 store.afterChunksCommitted=()=>{store.afterChunksCommitted=undefined;clock.now+=61_000}
 await assert.rejects(provider.submit({participant:{},command,documents:[document()]}),/forbidden|expired/)
 assert.equal((await store.query(names.evidence,{})).length,0)
})
test('rejects a stored stage pointer rebound to a different subject registration',async()=>{
 const {provider,registration,store,command,names,created}=await setup()
 const first=await provider.submit({participant:{},command,documents:[document()]})
 const other=await registration.register({participant:{},command:{operationId:randomUUID(),subject:{kind:'animal',alternateName:'Other pending subject',ncbiTaxonomyId:'9615'},controller:{legalName:'Proposed controller',contact:{kind:'telephone',value:safe.firstContactPhoneE164},relationship:'RESPRSN'}}})
 const second=await provider.submit({participant:{},command:{...command,operationId:randomUUID(),registrationId:other.registrationId},documents:[document('subject',Buffer.from('other-subject-bytes'))]})
 const record=await store.get(names.evidence,first.evidenceId),replacement=await store.get(names.evidence,second.evidenceId)
 await store.put(names.evidence,{...record,stageId:replacement.stageId})
 await assert.rejects(provider.readDocument({participant:{},registrationId:created.registrationId,slot:'subject'}),/integrity/)
})
test('rejects corrupted existing final records on upload replay and ignores harmless object key order',async()=>{
 const {provider,store,command,names}=await setup(),documents=[document(),document('controller')]
 const receipt=await provider.submit({participant:{},command,documents})
 const original=await store.get(names.evidence,receipt.evidenceId)
 const corruptions=[
  {...original,scopeKey:'other-scope'},
  {...original,creatorOrganizationReference:`Organization/${safe.demoOrganizationUuids.healthCare}`},
  {...original,registrationId:randomUUID()},
  {...original,stageId:'wrong-stage'},
  {...original,subjectReference:`urn:uuid:${randomUUID()}`},
  {...original,controllerInvitationId:randomUUID()},
  {...original,expiresAt:0},
  {...original,receipt:{...receipt,evidenceId:randomUUID()}},
  {...original,receipt:{...receipt,registrationId:randomUUID()}},
  {...original,receipt:{...receipt,status:'verified'}},
  {...original,receipt:{...receipt,documents:receipt.documents.map(item=>item.slot==='subject'?{...item,fileName:'different.pdf'}:item)}},
  {...original,command:{...command,verificationMethod:'pipp'}},
 ]
 for(const corrupted of corruptions){
  await store.put(names.evidence,corrupted)
  await assert.rejects(provider.submit({participant:{},command,documents}),error=>error.status===409&&/integrity/.test(error.message))
 }
 const reordered={documents:[...receipt.documents].reverse().map(item=>({size:item.size,fileName:item.fileName,mediaType:item.mediaType,contentId:item.contentId,slot:item.slot})),status:receipt.status,registrationId:receipt.registrationId,evidenceId:receipt.evidenceId}
 await store.put(names.evidence,{...original,receipt:reordered,command:{controller:command.controller,subject:command.subject,verificationMethod:command.verificationMethod,registrationId:command.registrationId,operationId:command.operationId}})
 assert.deepEqual(await provider.submit({participant:{},command,documents}),reordered)
})
