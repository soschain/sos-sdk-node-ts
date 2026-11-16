// Flow contract: one controller evidence usecase seals private media/metadata in the real transactional vault, re-resolves current account/card/controller authority across awaits, exposes opaque pending files only, and preserves unrelated cards on retry/reset/expiry. No professional creator or provisional registration is invented.
import assert from 'node:assert/strict'
import test from 'node:test'
import {createHash,randomUUID} from 'node:crypto'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {buildSha3_384EvidenceContentIdFromDigest} from 'antifraud-data-utils-ts/identity-assurance'

const load=()=>import('../dist/controller-identity-evidence-vault.js')
const CARDS='synthetic_controller_cards',ownerId='synthetic-controller-owner',foreignOwner='synthetic-foreign-owner'
const cardId=safe.resourceUuid,otherCardId=safe.demoOrganizationUuids.healthCare
const command=()=>({operationId:randomUUID(),verificationMethod:'sripp',subject:{},controller:{}})
const document=(slot='controller',size=100)=>{const bytes=Buffer.alloc(size,65);bytes.set(Buffer.from('%PDF-1.7\n'));return {slot,fileName:`private-${slot}.pdf`,mediaType:'application/pdf',bytes:new Uint8Array(bytes)}}
class AuditVault extends TransactionalMemoryVaultRepository{
 collections=new Set();failCommitOrdinal;commits=0;inside=false
 async runTransaction(operation){
  return super.runTransaction(async port=>{
   this.inside=true;let writing=false,touched=false,totalBytes=0
   const observed={
    get:(...args)=>{assert.equal(writing,false,'read after write');return port.get(...args)},
    query:(...args)=>{assert.equal(writing,false,'query after write');return port.query(...args)},
    put:(collection,values)=>{writing=true;touched=true;this.collections.add(collection);totalBytes+=Buffer.byteLength(JSON.stringify(values));assert.ok(totalBytes<700_000,'bounded evidence transaction');return port.put(collection,values)},
    delete:(collection,id)=>{writing=true;touched=true;this.collections.add(collection);return port.delete(collection,id)},
   }
   try{const result=await operation(observed);if(touched&&++this.commits===this.failCommitOrdinal)throw new Error('synthetic-evidence-commit-rejected');return result}
   finally{this.inside=false}
  })
 }
 async evidenceRows(){const rows=[];for(const collection of this.collections)if(collection!==CARDS)for(const value of await this.query(collection,{}))rows.push({collection,value});return rows}
}
async function setup(){
 const {ControllerIdentityEvidenceVault}=await load()
 const store=new AuditVault(),clock={now:Date.parse('2026-11-15T00:00:00.000Z')},calls=[],sealed=[]
 const base=createAesGcmProfileSealer(createHash('sha256').update('synthetic controller evidence host').digest())
 let afterSeal,afterUnseal
 const sealer={async seal(clear,aad){assert.equal(store.inside,false,'custody outside transaction');assert.ok(Buffer.byteLength(clear)<64*1024,'bounded KMS plaintext');sealed.push(clear);const result=await base.seal(clear,aad);await afterSeal?.();return result},
  async unseal(value,aad){assert.equal(store.inside,false,'custody outside transaction');const result=await base.unseal(value,aad);await afterUnseal?.();return result}}
 const card=id=>({id,ownerId,subjectIdentifier:`urn:uuid:${id}`,controllerActorIdentifier:`${safe.didWeb}:controller`,relationshipReference:`RelatedPerson/${id}`,generationId:'synthetic-generation-one',revision:'synthetic-authority-one',authorizationExpiresAt:clock.now+600_000,permittedSlots:['subject','controller','relationship'],canManage:true})
 await store.put(CARDS,[card(cardId),card(otherCardId)])
 const resolveCustody=async(participant,id,action,transaction)=>{
  calls.push({action,transaction:Boolean(transaction)})
  const current=await (transaction??store).get(CARDS,id)
  if(!participant||!current||current.ownerId!==participant.uid||current.canManage!==true||current.authorizationExpiresAt<=clock.now)throw Object.assign(new Error('controller-evidence-forbidden'),{status:403})
  const {canManage:_permission,id:_id,...binding}=current
  return {...binding,cardId:id}
 }
 const options={store,scopeKey:safe.tenantId,sealer,resolveCustody,retention:{stageTtlMs:60_000,evidenceTtlMs:120_000},now:()=>clock.now}
 const open=()=>new ControllerIdentityEvidenceVault(options)
 return {store,clock,calls,sealed,open,provider:open(),participant:{uid:ownerId},afterSeal:value=>{afterSeal=value},afterUnseal:value=>{afterUnseal=value}}
}

test('seals independent controller/relationship media and private metadata, resumes after restart and returns protected bytes only to the current card',async()=>{
 const f=await setup(),input=command(),documents=[document('controller'),document('relationship',150)],before=structuredClone(documents)
 const pending=f.provider.upload({participant:f.participant,cardId,command:input,documents})
 documents[0].bytes.fill(0);documents[0].fileName='changed-after-submit.pdf'
 const receipt=await pending
 assert.equal(receipt.status,'pending');assert.deepEqual(receipt.files.map(file=>file.slot),['controller','relationship'])
 for(const file of receipt.files){
  assert.deepEqual(Object.keys(file).sort(),['fileId','slot'])
  const source=before.find(document=>document.slot===file.slot),download=await f.open().download({participant:f.participant,cardId,fileId:file.fileId})
  assert.deepEqual(download.bytes,source.bytes);assert.equal(download.fileName,source.fileName);assert.equal(download.mediaType,source.mediaType)
  const cid=buildSha3_384EvidenceContentIdFromDigest(createHash('sha3-384').update(source.bytes).digest())
  assert.ok(f.sealed.some(value=>value.includes(cid)),'canonical media CID stays in sealed metadata')
 }
 assert.deepEqual(await f.open().list({participant:f.participant,cardId}),[receipt])
 const stored=JSON.stringify(await f.store.evidenceRows())
 for(const forbidden of [ownerId,cardId,safe.didWeb,before[0].fileName,Buffer.from(before[0].bytes).toString('base64')])assert.equal(stored.includes(forbidden),false,'no private plaintext in evidence rows')
 assert.ok(f.calls.some(call=>call.action==='upload'&&call.transaction))
})

test('foreign owner/card, forbidden slots and native spoofed document types deny before protected download or sealing',async()=>{
 const f=await setup()
 await assert.rejects(f.provider.upload({participant:{uid:foreignOwner,canManage:true},cardId,command:command(),documents:[document()]}),/forbidden/u)
 assert.equal(f.sealed.length,0)
 const row=await f.store.get(CARDS,cardId);await f.store.put(CARDS,{...row,permittedSlots:['controller']})
 await assert.rejects(f.provider.upload({participant:f.participant,cardId,command:command(),documents:[document('relationship')]}))
 assert.equal(f.sealed.length,0)
 await assert.rejects(f.provider.upload({participant:f.participant,cardId,command:command(),documents:[{...document(),mediaType:'image/png'}]}))
 const receipt=await f.provider.upload({participant:f.participant,cardId,command:command(),documents:[document()]})
 await assert.rejects(f.provider.download({participant:f.participant,cardId:otherCardId,fileId:receipt.files[0].fileId}))
 await assert.rejects(f.provider.download({participant:{uid:foreignOwner},cardId,fileId:receipt.files[0].fileId}))
})

test('revocation during seal or unseal rechecks current transactional custody and never commits or returns stale evidence',async()=>{
 const upload=await setup();let changed=false
 upload.afterSeal(async()=>{if(changed)return;changed=true;const card=await upload.store.get(CARDS,cardId);await upload.store.put(CARDS,{...card,canManage:false,revision:'synthetic-revoked-authority'})})
 await assert.rejects(upload.provider.upload({participant:upload.participant,cardId,command:command(),documents:[document()]}),/forbidden|changed|stale/u)
 assert.deepEqual(await upload.store.evidenceRows(),[])
 const download=await setup(),receipt=await download.provider.upload({participant:download.participant,cardId,command:command(),documents:[document()]});changed=false
 download.afterUnseal(async()=>{if(changed)return;changed=true;const card=await download.store.get(CARDS,cardId);await download.store.put(CARDS,{...card,canManage:false,revision:'synthetic-revoked-authority'})})
 await assert.rejects(download.provider.download({participant:download.participant,cardId,fileId:receipt.files[0].fileId}),/forbidden|changed|stale/u)
})

test('interrupted immutable chunks and completed lost-response retries preserve one receipt, while conflicting retry cannot overwrite evidence',async()=>{
 const f=await setup(),input=command(),documents=[document('controller',2*1024*1024)]
 f.store.failCommitOrdinal=4
 await assert.rejects(f.provider.upload({participant:f.participant,cardId,command:input,documents}),/synthetic-evidence-commit-rejected/u)
 assert.deepEqual(await f.provider.list({participant:f.participant,cardId}),[])
 const before=(await f.store.evidenceRows()).filter(row=>Number.isInteger(row.value.index))
 assert.ok(before.length>0,'some sealed chunks committed before interruption')
 f.store.failCommitOrdinal=undefined
 const receipt=await f.open().upload({participant:f.participant,cardId,command:input,documents})
 const replay=await f.open().upload({participant:f.participant,cardId,command:input,documents})
 assert.deepEqual(replay,receipt)
 const after=await f.store.evidenceRows()
 for(const row of before)assert.deepEqual(after.find(value=>value.collection===row.collection&&value.value.id===row.value.id)?.value,row.value)
 await assert.rejects(f.provider.upload({participant:f.participant,cardId,command:input,documents:[document('controller',200)]}),/conflict/u)
 assert.deepEqual((await f.open().download({participant:f.participant,cardId,fileId:receipt.files[0].fileId})).bytes,documents[0].bytes)
})

test('ciphertext, slot or digest tampering cannot expose bytes through an opaque download',async()=>{
 const f=await setup(),receipt=await f.provider.upload({participant:f.participant,cardId,command:command(),documents:[document()]})
 const rows=await f.store.evidenceRows(),chunk=rows.find(row=>Number.isInteger(row.value.index)&&typeof row.value.ciphertext==='string')
 assert.ok(chunk,'sealed indexed chunk exists')
 const changed=chunk.value.ciphertext.endsWith('A')?'B':'A'
 await f.store.put(chunk.collection,{...chunk.value,ciphertext:chunk.value.ciphertext.slice(0,-1)+changed})
 await assert.rejects(f.open().download({participant:f.participant,cardId,fileId:receipt.files[0].fileId}))
})

test('exact card reset and bounded expiry cleanup preserve unrelated active cards and their protected files',async()=>{
 const f=await setup(),first=await f.provider.upload({participant:f.participant,cardId,command:command(),documents:[document()]}),second=await f.provider.upload({participant:f.participant,cardId:otherCardId,command:command(),documents:[document('relationship')]})
 const reset=await f.provider.reset({participant:f.participant,cardId})
 assert.equal(reset.deletedEvidence,1);assert.equal(reset.deletedFiles,1)
 assert.deepEqual(await f.provider.list({participant:f.participant,cardId}),[])
 await assert.rejects(f.provider.download({participant:f.participant,cardId,fileId:first.files[0].fileId}))
 assert.deepEqual(await f.provider.list({participant:f.participant,cardId:otherCardId}),[second])
 const g=await setup();await g.provider.upload({participant:g.participant,cardId,command:command(),documents:[document()]})
 g.clock.now+=90_000
 const live=await g.provider.upload({participant:g.participant,cardId:otherCardId,command:command(),documents:[document('relationship')]})
 g.clock.now+=40_000
 const cleanup=await g.provider.cleanupExpired({limit:100})
 assert.ok(cleanup.deletedEvidence>=1)
 assert.deepEqual(await g.provider.list({participant:g.participant,cardId}),[])
 assert.deepEqual(await g.provider.list({participant:g.participant,cardId:otherCardId}),[live])
 assert.equal((await g.provider.download({participant:g.participant,cardId:otherCardId,fileId:live.files[0].fileId})).mediaType,'application/pdf')
})
