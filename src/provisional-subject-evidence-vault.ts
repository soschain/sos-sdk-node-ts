import {createHash,randomUUID} from 'node:crypto'
import {buildSha3_384EvidenceContentIdFromDigest,toSchemaOrgEvidenceMediaFlatClaims,type SchemaOrgEvidenceMediaAttachment} from 'antifraud-data-utils-ts/identity-assurance'
import {normalizePendingSubjectEvidenceCommand,assertPendingSubjectEvidenceReceipt,PendingSubjectEvidencePolicy,type PendingSubjectEvidenceCommand,type PendingSubjectEvidenceReceipt,type PendingSubjectEvidenceSlot} from 'sos-data-utils-ts/provisional-subject-evidence'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import {provisionalSubjectRegistrationCollections,type ProvisionalSubjectRegistrationRecord,type TrustedSubjectRegistrationCreator} from './provisional-subject-registration-vault.js'

export type PendingSubjectEvidenceUploadDocument=Readonly<{slot:PendingSubjectEvidenceSlot;fileName:string;mediaType:string;bytes:Uint8Array}>
type Descriptor=Readonly<{slot:PendingSubjectEvidenceSlot;fileName:string;mediaType:string;size:number;digest:string;contentId:string;chunkCount:number}>
type Stage=Readonly<{id:string;scopeKey:string;registrationId:string;creatorOrganizationReference:string;requestHash:string;evidenceId:string;command:PendingSubjectEvidenceCommand;documents:readonly Descriptor[];expiresAt:number;status:'staging'|'complete'}>
type Chunk=Readonly<{id:string;stageId:string;scopeKey:string;slot:PendingSubjectEvidenceSlot;index:number;dataBase64:string;digest:string;size:number;expiresAt:number}>
type CompletedFile=Readonly<{id:string;stageId:string;scopeKey:string;slot:PendingSubjectEvidenceSlot;digest:string;contentId:string;size:number;expiresAt:number}>
type EvidenceRecord=Readonly<{id:string;scopeKey:string;registrationId:string;creatorOrganizationReference:string;subjectReference:string;controllerInvitationId:string;stageId:string;command:PendingSubjectEvidenceCommand;receipt:PendingSubjectEvidenceReceipt;mediaClaims:readonly Readonly<Record<string,string>>[];expiresAt:number}>
const CHUNK_BYTES=192*1024,CHUNKS_PER_TRANSACTION=8
const hash=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex')
const digest=(bytes:Uint8Array)=>createHash('sha3-384').update(bytes).digest()
const fail=(code:string,status=400)=>Object.assign(new Error(`subject_registration_evidence_${code}`),{status})
function evidenceRequestHash(command:unknown,documents:readonly Descriptor[]):string{
 const canonical=[...documents].sort((left,right)=>['subject','controller','relationship'].indexOf(left.slot)-['subject','controller','relationship'].indexOf(right.slot))
 return hash(JSON.stringify({command:normalizePendingSubjectEvidenceCommand(command),documents:canonical.map(document=>({slot:document.slot,fileName:document.fileName,mediaType:document.mediaType,size:document.size,digest:document.digest,contentId:document.contentId,chunkCount:document.chunkCount}))}))
}
export function pendingSubjectEvidenceCollections(scopeKey:string){
 if(typeof scopeKey!=='string'||!scopeKey||scopeKey.length>2048)throw fail('scope_invalid')
 const prefix=`provisional-v1__${hash(scopeKey)}`
 return Object.freeze({stages:`${prefix}__evidence-stages`,chunks:`${prefix}__evidence-chunks`,files:`${prefix}__evidence-completed-files`,evidence:`${prefix}__pending-evidence-records`})
}

/** Upload staging uses the existing vault; published receipts contain no verification or signature. */
export class ProvisionalSubjectEvidenceVault{
 constructor(private readonly options:Readonly<{store:TransactionalVaultRepository;scopeKey:string;assertCreator:(participant:unknown)=>Promise<TrustedSubjectRegistrationCreator>;now?:()=>number}>){pendingSubjectEvidenceCollections(options.scopeKey)}
 private now(){return (this.options.now??Date.now)()}
 private async creator(participant:unknown){
  const creator=await this.options.assertCreator(participant)
  if(!creator||typeof creator.organizationReference!=='string'||!/^Organization\/[A-Za-z0-9.-]{1,64}$/u.test(creator.organizationReference)||typeof creator.actorIdentifier!=='string'||!creator.actorIdentifier||!Number.isFinite(creator.expiresAt)||creator.expiresAt<=this.now())throw fail('forbidden',403)
  return creator
 }
 private async registration(store:IVaultRepository,id:string,creator:TrustedSubjectRegistrationCreator){
  if(creator.expiresAt<=this.now())throw fail('forbidden',403)
  const record=await store.get<ProvisionalSubjectRegistrationRecord>(provisionalSubjectRegistrationCollections(this.options.scopeKey).registrations,id)
  if(!record||record.expiresAt<=this.now())throw fail('not_found',404)
  if(record.scopeKey!==this.options.scopeKey||record.creatorOrganizationReference!==creator.organizationReference)throw fail('forbidden',403)
  return record
 }
 private documents(input:readonly PendingSubjectEvidenceUploadDocument[]){
  if(!Array.isArray(input)||input.length<1||input.length>PendingSubjectEvidencePolicy.maxFiles)throw fail('documents_invalid')
  const slots=new Set<string>()
  const documents=input.map(raw=>{
   if(!raw||typeof raw!=='object')throw fail('document_invalid')
   const descriptors=Object.getOwnPropertyDescriptors(raw),item:Record<string,unknown>=Object.create(null)
   for(const key of Reflect.ownKeys(descriptors)){
    if(typeof key!=='string'||!['slot','fileName','mediaType','bytes'].includes(key)||!('value' in descriptors[key]!))throw fail('document_invalid')
    item[key]=descriptors[key]!.value
   }
   if(typeof item.slot!=='string'||!['subject','controller','relationship'].includes(item.slot)||slots.has(item.slot))throw fail('slot_invalid')
   slots.add(item.slot)
   if(typeof item.fileName!=='string'||!item.fileName.trim()||item.fileName.length>180||/[\\/\u0000-\u001f]/u.test(item.fileName)||typeof item.mediaType!=='string'||!PendingSubjectEvidencePolicy.mediaTypes.some(type=>type===item.mediaType)||!(item.bytes instanceof Uint8Array)||item.bytes.byteLength<1||item.bytes.byteLength>PendingSubjectEvidencePolicy.maxFileBytes)throw fail('document_invalid')
   const bytes=Uint8Array.from(item.bytes),hashed=digest(bytes)
   const descriptor:Descriptor={slot:item.slot as PendingSubjectEvidenceSlot,fileName:item.fileName.trim(),mediaType:item.mediaType,size:bytes.byteLength,digest:hashed.toString('base64'),contentId:buildSha3_384EvidenceContentIdFromDigest(hashed),chunkCount:Math.ceil(bytes.byteLength/CHUNK_BYTES)}
   return {descriptor,bytes}
  }).sort((left,right)=>['subject','controller','relationship'].indexOf(left.descriptor.slot)-['subject','controller','relationship'].indexOf(right.descriptor.slot))
  if(!slots.has('subject'))throw fail('subject_document_required')
  return documents
 }
 async submit(input:Readonly<{participant:unknown;command:unknown;documents:readonly PendingSubjectEvidenceUploadDocument[]}>):Promise<PendingSubjectEvidenceReceipt>{
  const command=normalizePendingSubjectEvidenceCommand(input.command),creator=await this.creator(input.participant)
  await this.registration(this.options.store,command.registrationId,creator)
  const documents=this.documents(input.documents),names=pendingSubjectEvidenceCollections(this.options.scopeKey)
  const id=hash(`${this.options.scopeKey}\0${creator.organizationReference}\0${command.registrationId}\0${command.operationId}`)
  const requestHash=evidenceRequestHash(command,documents.map(item=>item.descriptor))
  const stage=await this.options.store.runTransaction(async transaction=>{
   const registration=await this.registration(transaction,command.registrationId,creator)
   const prior=await transaction.get<Stage>(names.stages,id)
   if(prior){
    if(prior.scopeKey!==this.options.scopeKey||prior.creatorOrganizationReference!==creator.organizationReference||prior.requestHash!==requestHash)throw fail('request_conflict',409)
    if(prior.expiresAt<=this.now())throw fail('expired',410)
    return prior
   }
   const next:Stage={id,scopeKey:this.options.scopeKey,registrationId:command.registrationId,creatorOrganizationReference:creator.organizationReference,requestHash,evidenceId:randomUUID(),command,documents:documents.map(item=>item.descriptor),expiresAt:Math.min(registration.expiresAt,this.now()+24*60*60*1000),status:'staging'}
   await transaction.put(names.stages,next)
   return next
  })
  for(const document of documents){
   for(let first=0;first<document.descriptor.chunkCount;first+=CHUNKS_PER_TRANSACTION){
    await this.options.store.runTransaction(async transaction=>{
     if(creator.expiresAt<=this.now())throw fail('forbidden',403)
     const active=await transaction.get<Stage>(names.stages,stage.id)
     if(!active||active.expiresAt<=this.now()||active.requestHash!==requestHash)throw fail('expired',410)
     const pending:Chunk[]=[]
     for(let index=first;index<Math.min(first+CHUNKS_PER_TRANSACTION,document.descriptor.chunkCount);index++){
      const bytes=document.bytes.subarray(index*CHUNK_BYTES,(index+1)*CHUNK_BYTES)
      const chunk:Chunk={id:`${stage.id}:${document.descriptor.slot}:${index}`,stageId:stage.id,scopeKey:this.options.scopeKey,slot:document.descriptor.slot,index,dataBase64:Buffer.from(bytes).toString('base64'),digest:digest(bytes).toString('base64'),size:bytes.length,expiresAt:stage.expiresAt}
      const existing=await transaction.get<Chunk>(names.chunks,chunk.id)
      if(existing){if(existing.scopeKey!==chunk.scopeKey||existing.stageId!==chunk.stageId||existing.slot!==chunk.slot||existing.index!==chunk.index||existing.digest!==chunk.digest||existing.size!==chunk.size||existing.dataBase64!==chunk.dataBase64)throw fail('integrity',409)}else pending.push(chunk)
     }
     // Finish every read before the first write for durable transactional adapters.
     for(const chunk of pending)await transaction.put(names.chunks,chunk)
    })
   }
   await this.bytes(stage,document.descriptor)
   await this.options.store.runTransaction(async transaction=>{
    if(creator.expiresAt<=this.now())throw fail('forbidden',403)
    const active=await transaction.get<Stage>(names.stages,stage.id)
    const id=`${stage.id}:${document.descriptor.slot}`
    const prior=await transaction.get<CompletedFile>(names.files,id)
    if(!active||active.expiresAt<=this.now())throw fail('expired',410)
    if(prior){if(prior.digest!==document.descriptor.digest||prior.contentId!==document.descriptor.contentId||prior.size!==document.descriptor.size)throw fail('integrity',409);return}
    await transaction.put<CompletedFile>(names.files,{id,stageId:stage.id,scopeKey:this.options.scopeKey,slot:document.descriptor.slot,digest:document.descriptor.digest,contentId:document.descriptor.contentId,size:document.descriptor.size,expiresAt:stage.expiresAt})
   })
  }
  return this.options.store.runTransaction(async transaction=>{
   const registration=await this.registration(transaction,command.registrationId,creator)
   const active=await transaction.get<Stage>(names.stages,stage.id)
   const existing=await transaction.get<EvidenceRecord>(names.evidence,stage.evidenceId)
   if(!active||active.expiresAt<=this.now()||active.requestHash!==requestHash)throw fail('expired',410)
   for(const document of stage.documents){
    const completed=await transaction.get<CompletedFile>(names.files,`${stage.id}:${document.slot}`)
    if(!completed||completed.scopeKey!==this.options.scopeKey||completed.stageId!==stage.id||completed.digest!==document.digest||completed.contentId!==document.contentId||completed.size!==document.size)throw fail('integrity',409)
   }
   if(existing)return this.validatedReceipt(existing,active,registration,creator)
   const receipt:PendingSubjectEvidenceReceipt={evidenceId:stage.evidenceId,registrationId:command.registrationId,status:'pending',documents:stage.documents.map(({slot,contentId,mediaType,fileName,size})=>({slot,contentId,mediaType,fileName,size}))}
   assertPendingSubjectEvidenceReceipt(receipt)
   const mediaClaims=stage.documents.map(document=>{
    const attachment:SchemaOrgEvidenceMediaAttachment={id:`urn:sos:pending-evidence:${stage.evidenceId}:${document.slot}`,mediaType:document.mediaType,contentUrl:`urn:sos:pending-evidence:${stage.evidenceId}:${document.slot}`,contentSize:document.size,contentId:document.contentId,digestAlgorithm:'sha3-384',digest:document.digest}
    return toSchemaOrgEvidenceMediaFlatClaims(attachment)
   })
   const record:EvidenceRecord={id:stage.evidenceId,scopeKey:this.options.scopeKey,registrationId:command.registrationId,creatorOrganizationReference:creator.organizationReference,subjectReference:registration.receipt.subjectIdentifier,controllerInvitationId:registration.receipt.controllerInvitation.invitationId,stageId:stage.id,command,receipt,mediaClaims,expiresAt:stage.expiresAt}
   await transaction.put(names.evidence,record)
   await transaction.put(provisionalSubjectRegistrationCollections(this.options.scopeKey).registrations,{...registration,pendingEvidenceId:stage.evidenceId})
   await transaction.put(names.stages,{...stage,status:'complete'})
   return receipt
  })
 }
 private async bytes(stage:Stage,document:Descriptor):Promise<Uint8Array>{
  if(!Number.isSafeInteger(document.size)||document.size<1||document.size>PendingSubjectEvidencePolicy.maxFileBytes||document.chunkCount!==Math.ceil(document.size/CHUNK_BYTES))throw fail('integrity',409)
  const names=pendingSubjectEvidenceCollections(this.options.scopeKey),chunks:Uint8Array[]=[]
  for(let index=0;index<document.chunkCount;index++){
   const chunk=await this.options.store.get<Chunk>(names.chunks,`${stage.id}:${document.slot}:${index}`)
   if(!chunk||chunk.scopeKey!==this.options.scopeKey||chunk.stageId!==stage.id||chunk.slot!==document.slot||chunk.index!==index||chunk.expiresAt<=this.now())throw fail('integrity',409)
   const bytes=Buffer.from(chunk.dataBase64,'base64')
   if(bytes.toString('base64')!==chunk.dataBase64||bytes.length!==chunk.size||digest(bytes).toString('base64')!==chunk.digest)throw fail('integrity',409)
   chunks.push(bytes)
  }
  const bytes=Buffer.concat(chunks)
  if(bytes.length!==document.size||digest(bytes).toString('base64')!==document.digest||buildSha3_384EvidenceContentIdFromDigest(digest(bytes))!==document.contentId)throw fail('integrity',409)
  return Uint8Array.from(bytes)
 }
 private validatedReceipt(record:EvidenceRecord,stage:Stage,registration:ProvisionalSubjectRegistrationRecord,creator:TrustedSubjectRegistrationCreator):PendingSubjectEvidenceReceipt{
  try{
   assertPendingSubjectEvidenceReceipt(record.receipt)
   if(record.id!==stage.evidenceId||record.scopeKey!==this.options.scopeKey||record.creatorOrganizationReference!==creator.organizationReference||record.registrationId!==registration.id||record.stageId!==stage.id||record.subjectReference!==registration.receipt.subjectIdentifier||record.controllerInvitationId!==registration.receipt.controllerInvitation.invitationId||record.expiresAt!==stage.expiresAt||record.expiresAt<=this.now()
    ||stage.scopeKey!==this.options.scopeKey||stage.registrationId!==registration.id||stage.creatorOrganizationReference!==creator.organizationReference||stage.status!=='complete'||record.receipt.evidenceId!==record.id||record.receipt.registrationId!==registration.id
    ||evidenceRequestHash(stage.command,stage.documents)!==stage.requestHash||evidenceRequestHash(record.command,stage.documents)!==stage.requestHash||new Set(stage.documents.map(document=>document.slot)).size!==stage.documents.length||record.receipt.documents.length!==stage.documents.length)throw new Error()
   for(const document of stage.documents){
    const stored=record.receipt.documents.find(item=>item.slot===document.slot)
    if(!stored||stored.contentId!==document.contentId||stored.fileName!==document.fileName||stored.mediaType!==document.mediaType||stored.size!==document.size)throw new Error()
   }
   return record.receipt
  }catch{throw fail('integrity',409)}
 }
 private async evidence(input:Readonly<{participant:unknown;registrationId:string}>){
  const creator=await this.creator(input.participant),registration=await this.registration(this.options.store,input.registrationId,creator)
  const evidenceId=registration.pendingEvidenceId
  if(!evidenceId)throw fail('not_found',404)
  const names=pendingSubjectEvidenceCollections(this.options.scopeKey),record=await this.options.store.get<EvidenceRecord>(names.evidence,evidenceId)
  if(!record||record.expiresAt<=this.now())throw fail('not_found',404)
  if(record.id!==evidenceId)throw fail('integrity',409)
  const stage=await this.options.store.get<Stage>(names.stages,record.stageId)
  if(!stage)throw fail('integrity',409)
  this.validatedReceipt(record,stage,registration,creator)
  return record
 }
 async read(input:Readonly<{participant:unknown;registrationId:string}>):Promise<PendingSubjectEvidenceReceipt>{return (await this.evidence(input)).receipt}
 async readDocument(input:Readonly<{participant:unknown;registrationId:string;slot:PendingSubjectEvidenceSlot}>):Promise<Uint8Array>{
  const record=await this.evidence(input),stage=await this.options.store.get<Stage>(pendingSubjectEvidenceCollections(this.options.scopeKey).stages,record.stageId)
  if(!stage||stage.expiresAt<=this.now())throw fail('not_found',404)
  if(stage.id!==record.stageId||stage.scopeKey!==this.options.scopeKey||stage.registrationId!==record.registrationId||stage.creatorOrganizationReference!==record.creatorOrganizationReference||stage.evidenceId!==record.id||stage.status!=='complete')throw fail('integrity',409)
  const document=stage.documents.find(document=>document.slot===input.slot),expected=record.receipt.documents.find(document=>document.slot===input.slot)
  if(!document||!expected)throw fail('not_found',404)
  if(document.contentId!==expected.contentId||document.size!==expected.size||document.fileName!==expected.fileName||document.mediaType!==expected.mediaType)throw fail('integrity',409)
  return this.bytes(stage,document)
 }
}
