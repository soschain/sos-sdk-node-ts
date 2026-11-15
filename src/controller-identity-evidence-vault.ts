import {createHash,randomUUID} from 'node:crypto'
import {assertSha3_384EvidenceContentId,buildSha3_384EvidenceContentIdFromDigest,toSchemaOrgEvidenceMediaFlatClaims} from 'antifraud-data-utils-ts/identity-assurance'
import {ControllerIdentityEvidencePolicy,normalizeControllerIdentityEvidenceCommand,assertControllerIdentityEvidenceReceipt,type ControllerIdentityEvidenceCommand,type ControllerIdentityEvidenceReceipt,type ControllerIdentityEvidenceSlot} from 'sos-data-utils-ts/controller-identity-evidence'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type ControllerIdentityEvidenceBinding=Readonly<{
 ownerId:string;cardId:string;subjectIdentifier:string;controllerActorIdentifier:string;relationshipReference?:string
 generationId:string;revision:string;authorizationExpiresAt:number;permittedSlots:readonly ControllerIdentityEvidenceSlot[]
}>
export type ControllerIdentityEvidenceUploadDocument=Readonly<{slot:ControllerIdentityEvidenceSlot;fileName:string;mediaType:string;bytes:Uint8Array}>
export type ControllerIdentityEvidenceAction='upload'|'read'|'download'|'reset'
export type ControllerIdentityEvidenceVaultOptions=Readonly<{
 store:TransactionalVaultRepository;scopeKey:string;sealer:ServerProfileSealer
 resolveCustody:(participant:unknown,cardId:string,action:ControllerIdentityEvidenceAction,transaction?:IVaultRepository)=>Promise<ControllerIdentityEvidenceBinding>
 retention:Readonly<{stageTtlMs:number;evidenceTtlMs:number}>;now?:()=>number
}>
type Header={id:string;scopeHash:string;ownerKey:string;kind:'stage'|'chunk'|'file'|'evidence'|'epoch'|'tombstone';expiresAt:number;ciphertext?:string;stageId?:string;fileId?:string;index?:number;epoch?:number;state?:'staging'|'complete'|'active'|'resetting'}
type Descriptor={slot:ControllerIdentityEvidenceSlot;fileId:string;fileName:string;mediaType:string;size:number;digest:string;contentId:string;chunkCount:number}
type Stage={binding:ControllerIdentityEvidenceBinding;command:ControllerIdentityEvidenceCommand;requestHash:string;evidenceId:string;documents:Descriptor[];stageExpiresAt:number;evidenceExpiresAt:number;epoch:number}
type FileMetadata={binding:ControllerIdentityEvidenceBinding;stageId:string;evidenceId:string;descriptor:Descriptor}
type Evidence={binding:ControllerIdentityEvidenceBinding;stageId:string;requestHash:string;receipt:ControllerIdentityEvidenceReceipt;documents:Descriptor[];mediaClaims:readonly Readonly<Record<string,string>>[]}
const CHUNK_BYTES=24*1024,BATCH_SIZE=8
const SLOTS:readonly ControllerIdentityEvidenceSlot[]=['subject','controller','relationship']
const hash=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex')
const digest=(value:Uint8Array)=>createHash('sha3-384').update(value).digest()
const fail=(code:string,status=409)=>Object.assign(new Error('controller_identity_evidence_'+code),{status})
function text(value:unknown,max=2048):string{if(typeof value!=='string'||!value||value.trim()!==value||value.length>max||/[\u0000-\u001f]/u.test(value))throw fail('invalid',400);return value}
function uuid(value:unknown):string{const result=text(value,36);if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(result))throw fail('integrity');return result}
function integer(value:unknown,min=0,max=Number.MAX_SAFE_INTEGER):number{if(typeof value!=='number'||!Number.isSafeInteger(value)||value<min||value>max)throw fail('integrity');return value}
function object(value:unknown,allowed?:readonly string[]):Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw fail('invalid',400)
 const result:Record<string,unknown>=Object.create(null),fields=Object.getOwnPropertyDescriptors(value)
 for(const name of Reflect.ownKeys(fields)){if(typeof name!=='string'||(allowed&&!allowed.includes(name))||!('value'in fields[name]!))throw fail('invalid',400);result[name]=fields[name]!.value}
 return result
}
function array(value:unknown):unknown[]{
 if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype)throw fail('invalid',400)
 const fields=Object.getOwnPropertyDescriptors(value),result:unknown[]=[]
 for(const name of Reflect.ownKeys(fields))if(typeof name!=='string'||(name!=='length'&&!/^(?:0|[1-9][0-9]*)$/u.test(name))||!('value'in fields[name]!))throw fail('invalid',400)
 for(let index=0;index<value.length;index++){const item=fields[String(index)];if(!item||!('value'in item))throw fail('invalid',400);result.push(item.value)}
 return result
}
function slot(value:unknown):ControllerIdentityEvidenceSlot{if(value==='subject'||value==='controller'||value==='relationship')return value;throw fail('invalid',400)}
function mediaType(value:unknown):string{for(const type of ControllerIdentityEvidencePolicy.mediaTypes)if(value===type)return type;throw fail('media_type',400)}
function fileName(value:unknown):string{const result=text(value,180);if(/[\\/]/u.test(result))throw fail('file_name',400);return result}
function binding(value:unknown):ControllerIdentityEvidenceBinding{
 const row=object(value,['ownerId','cardId','subjectIdentifier','controllerActorIdentifier','relationshipReference','generationId','revision','authorizationExpiresAt','permittedSlots'])
 const permitted=array(row.permittedSlots).map(slot)
 if(!permitted.length||new Set(permitted).size!==permitted.length)throw fail('forbidden',403)
 return Object.freeze({ownerId:text(row.ownerId),cardId:text(row.cardId),subjectIdentifier:text(row.subjectIdentifier),controllerActorIdentifier:text(row.controllerActorIdentifier),
  ...(row.relationshipReference===undefined?{}:{relationshipReference:text(row.relationshipReference)}),generationId:text(row.generationId),revision:text(row.revision),authorizationExpiresAt:integer(row.authorizationExpiresAt),permittedSlots:Object.freeze(SLOTS.filter(value=>permitted.includes(value)))})
}
function sameLease(left:ControllerIdentityEvidenceBinding,right:ControllerIdentityEvidenceBinding):void{if(JSON.stringify(left)!==JSON.stringify(right))throw fail('authority_changed',403)}
function sameOwner(left:ControllerIdentityEvidenceBinding,right:ControllerIdentityEvidenceBinding):void{for(const name of ['ownerId','cardId','subjectIdentifier','controllerActorIdentifier','relationshipReference'] as const)if(left[name]!==right[name])throw fail('forbidden',403)}
function permitted(current:ControllerIdentityEvidenceBinding,documents:readonly {slot:ControllerIdentityEvidenceSlot}[]):void{if(documents.some(document=>!current.permittedSlots.includes(document.slot)))throw fail('slot_forbidden',403)}
function descriptor(value:unknown):Descriptor{
 const row=object(value,['slot','fileId','fileName','mediaType','size','digest','contentId','chunkCount']),size=integer(row.size,1,ControllerIdentityEvidencePolicy.maxFileBytes)
 const encoded=text(row.digest,64),bytes=Buffer.from(encoded,'base64')
 if(bytes.length!==48||bytes.toString('base64')!==encoded||row.chunkCount!==Math.ceil(size/CHUNK_BYTES))throw fail('integrity')
 const contentId=text(row.contentId,200);assertSha3_384EvidenceContentId(contentId)
 if(buildSha3_384EvidenceContentIdFromDigest(bytes)!==contentId)throw fail('integrity')
 return {slot:slot(row.slot),fileId:uuid(row.fileId),fileName:fileName(row.fileName),mediaType:mediaType(row.mediaType),size,digest:encoded,contentId,chunkCount:integer(row.chunkCount,1)}
}
function descriptors(value:unknown):Descriptor[]{
 const result=array(value).map(descriptor)
 if(!result.length||result.length>ControllerIdentityEvidencePolicy.maxFiles||new Set(result.map(item=>item.slot)).size!==result.length||new Set(result.map(item=>item.fileId)).size!==result.length)throw fail('integrity')
 return result
}
function requestHash(command:ControllerIdentityEvidenceCommand,documents:readonly Descriptor[]):string{
 return hash(JSON.stringify({command,documents:documents.map(({fileId:_id,...document})=>document)}))
}
function snapshotDocuments(value:readonly ControllerIdentityEvidenceUploadDocument[]){
 const result=array(value).map(value=>{
  const row=object(value,['slot','fileName','mediaType','bytes'])
  if(!(row.bytes instanceof Uint8Array)||!row.bytes.byteLength||row.bytes.byteLength>ControllerIdentityEvidencePolicy.maxFileBytes)throw fail('file_size',413)
  const bytes=Uint8Array.from(row.bytes),type=mediaType(row.mediaType)
  const valid=type==='application/pdf'?Buffer.from(bytes.subarray(0,5)).toString('ascii')==='%PDF-':type==='image/png'?Buffer.from(bytes.subarray(0,8)).equals(Buffer.from([137,80,78,71,13,10,26,10])):bytes[0]===255&&bytes[1]===216&&bytes[2]===255
  if(!valid)throw fail('media_content',400)
  return {slot:slot(row.slot),fileName:fileName(row.fileName),mediaType:type,bytes}
 })
 if(!result.length||result.length>ControllerIdentityEvidencePolicy.maxFiles||new Set(result.map(item=>item.slot)).size!==result.length)throw fail('files_invalid',400)
 return result.sort((left,right)=>SLOTS.indexOf(left.slot)-SLOTS.indexOf(right.slot))
}

/** Trusted lifecycle code can clear these exact scoped collections without a removed workspace resolver. */
export function controllerIdentityEvidenceCollections(scopeKey:string){
 const prefix='controller-evidence-v1__'+hash(text(scopeKey))
 return Object.freeze({stages:prefix+'__stages',chunks:prefix+'__chunks',evidence:prefix+'__evidence'})
}

/** Identical controller evidence usecase across host-selected memory/durable vault and custody adapters. */
export class ControllerIdentityEvidenceVault{
 private readonly store:TransactionalVaultRepository
 private readonly sealer:ServerProfileSealer
 private readonly resolve:ControllerIdentityEvidenceVaultOptions['resolveCustody']
 private readonly clock:()=>number
 private readonly names:ReturnType<typeof controllerIdentityEvidenceCollections>
 private readonly scopeHash:string
 private readonly stageTtl:number
 private readonly evidenceTtl:number
 constructor(options:ControllerIdentityEvidenceVaultOptions){
  this.names=controllerIdentityEvidenceCollections(options.scopeKey);this.scopeHash=hash(options.scopeKey)
  this.store=options.store;this.sealer=Object.freeze({seal:options.sealer.seal.bind(options.sealer),unseal:options.sealer.unseal.bind(options.sealer)})
  this.resolve=options.resolveCustody;this.clock=options.now??Date.now
  this.stageTtl=integer(options.retention.stageTtlMs,1);this.evidenceTtl=integer(options.retention.evidenceTtlMs,this.stageTtl)
 }
 private now():number{return integer(this.clock())}
 private ownerKey(current:ControllerIdentityEvidenceBinding):string{return hash(JSON.stringify([this.scopeHash,current.ownerId,current.cardId]))}
 private aad(kind:string,ownerKey:string,id:string,detail=''):string{return JSON.stringify(['controller-identity-evidence-v1',this.scopeHash,ownerKey,kind,id,detail])}
 private async authority(participant:unknown,cardId:string,action:ControllerIdentityEvidenceAction,port?:IVaultRepository){
  const current=binding(await this.resolve(participant,cardId,action,port))
  if(current.cardId!==cardId||current.authorizationExpiresAt<=this.now())throw fail('forbidden',403)
  return current
 }
 private guard(participant:unknown,cardId:string,start:ControllerIdentityEvidenceBinding,action:ControllerIdentityEvidenceAction){return async()=>{sameLease(start,await this.authority(participant,cardId,action))}}
 private header(row:Header|undefined,ownerKey?:string):Header{
  if(!row||row.scopeHash!==this.scopeHash||!row.id||!row.ownerKey||(ownerKey!==undefined&&row.ownerKey!==ownerKey))throw fail('not_found',404)
  integer(row.expiresAt)
  return row
 }
 private async epoch(port:IVaultRepository,ownerKey:string){
  const id=hash(JSON.stringify([ownerKey,'epoch'])),row=await port.get<Header>(this.names.stages,id)
  if(!row)return {id,revision:0,state:'active' as const}
  this.header(row,ownerKey)
  if(row.kind!=='epoch'||(row.state!=='active'&&row.state!=='resetting'))throw fail('integrity')
  return {id,revision:integer(row.epoch),state:row.state}
 }
 private async active(port:IVaultRepository,ownerKey:string,expected?:number){
  const epoch=await this.epoch(port,ownerKey)
  if(epoch.state!=='active'||(expected!==undefined&&epoch.revision!==expected))throw fail('reset_or_changed')
  return epoch
 }
 private async seal(value:unknown,aad:string,recheck:()=>Promise<void>):Promise<string>{
  const clear=JSON.stringify(value)
  if(Buffer.byteLength(clear)>48*1024)throw fail('metadata_size',413)
  const result=await this.sealer.seal(clear,aad);await recheck();return result
 }
 private async open(row:Header,kind:string,recheck:()=>Promise<void>):Promise<unknown>{
  let clear:string
  try{clear=await this.sealer.unseal(text(row.ciphertext,128*1024),this.aad(kind,row.ownerKey,row.id))}catch{throw fail('integrity')}
  await recheck()
  try{return JSON.parse(clear)}catch{throw fail('integrity')}
 }
 private parseStage(value:unknown):Stage{
  const row=object(value,['binding','command','requestHash','evidenceId','documents','stageExpiresAt','evidenceExpiresAt','epoch'])
  const stage:Stage={binding:binding(row.binding),command:normalizeControllerIdentityEvidenceCommand(row.command),requestHash:text(row.requestHash,64),evidenceId:uuid(row.evidenceId),documents:descriptors(row.documents),stageExpiresAt:integer(row.stageExpiresAt),evidenceExpiresAt:integer(row.evidenceExpiresAt),epoch:integer(row.epoch)}
  if(stage.requestHash!==requestHash(stage.command,stage.documents)||stage.evidenceExpiresAt<stage.stageExpiresAt)throw fail('integrity')
  return stage
 }
 private async stageRead(participant:unknown,cardId:string,start:ControllerIdentityEvidenceBinding,id:string):Promise<{header:Header;stage:Stage}>{
  const ownerKey=this.ownerKey(start),header=this.header(await this.store.get<Header>(this.names.stages,id),ownerKey)
  if(header.kind!=='stage'||header.expiresAt<=this.now()||(header.state!=='staging'&&header.state!=='complete'))throw fail('expired_or_reset')
  const stage=this.parseStage(await this.open(header,'stage',this.guard(participant,cardId,start,'upload')))
  sameOwner(stage.binding,start)
  if(header.epoch!==stage.epoch||header.stageId!==undefined||header.expiresAt!==(header.state==='complete'?stage.evidenceExpiresAt:stage.stageExpiresAt))throw fail('integrity')
  await this.store.runTransaction(async port=>{
   sameLease(start,await this.authority(participant,cardId,'upload',port));await this.active(port,ownerKey,stage.epoch)
   const current=this.header(await port.get<Header>(this.names.stages,id),ownerKey)
   if(current.ciphertext!==header.ciphertext||current.state!==header.state||current.expiresAt<=this.now())throw fail('changed')
  })
  return {header,stage}
 }
 private chunkId(stageId:string,fileId:string,index:number){return hash(JSON.stringify([stageId,fileId,index]))}
 private chunkAad(ownerKey:string,stageId:string,document:Descriptor,index:number){return this.aad('chunk',ownerKey,stageId,JSON.stringify([document.fileId,document.slot,index,document.digest]))}
 private async chunkBytes(row:Header,ownerKey:string,stageId:string,document:Descriptor,index:number,recheck:()=>Promise<void>):Promise<Uint8Array>{
  this.header(row,ownerKey)
  if(row.kind!=='chunk'||row.stageId!==stageId||row.fileId!==document.fileId||row.index!==index||row.id!==this.chunkId(stageId,document.fileId,index)||row.expiresAt<=this.now())throw fail('integrity')
  let clear:string
  try{clear=await this.sealer.unseal(text(row.ciphertext,128*1024),this.chunkAad(ownerKey,stageId,document,index))}catch{throw fail('integrity')}
  await recheck()
  const result=Buffer.from(clear,'base64'),expected=index===document.chunkCount-1?document.size-index*CHUNK_BYTES:CHUNK_BYTES
  if(result.toString('base64')!==clear||result.length!==expected)throw fail('integrity')
  return Uint8Array.from(result)
 }
 private async checkUpload(port:IVaultRepository,participant:unknown,cardId:string,start:ControllerIdentityEvidenceBinding,stageId:string,stage:Stage){
  const current=await this.authority(participant,cardId,'upload',port)
  sameLease(start,current);sameLease(stage.binding,current);permitted(current,stage.documents)
  await this.active(port,this.ownerKey(current),stage.epoch)
  const header=this.header(await port.get<Header>(this.names.stages,stageId),this.ownerKey(current))
  if(header.kind!=='stage'||header.state!=='staging'||header.expiresAt<=this.now())throw fail('changed')
 }
 private async writeFile(participant:unknown,cardId:string,start:ControllerIdentityEvidenceBinding,stageId:string,stage:Stage,document:Descriptor,bytes:Uint8Array){
  const ownerKey=this.ownerKey(start),recheck=this.guard(participant,cardId,start,'upload')
  for(let offset=0;offset<document.chunkCount;offset+=BATCH_SIZE){
   const indices=Array.from({length:Math.min(BATCH_SIZE,document.chunkCount-offset)},(_,index)=>offset+index)
   const existing=await this.store.runTransaction(async port=>{await this.checkUpload(port,participant,cardId,start,stageId,stage);return Promise.all(indices.map(index=>port.get<Header>(this.names.chunks,this.chunkId(stageId,document.fileId,index))))})
   const prepared:Header[]=[]
   for(let position=0;position<indices.length;position++){
    const index=indices[position]!,part=bytes.subarray(index*CHUNK_BYTES,Math.min(bytes.length,(index+1)*CHUNK_BYTES)),old=existing[position]
    if(old){if(!Buffer.from(await this.chunkBytes(old,ownerKey,stageId,document,index,recheck)).equals(Buffer.from(part)))throw fail('conflict');continue}
    const ciphertext=await this.sealer.seal(Buffer.from(part).toString('base64'),this.chunkAad(ownerKey,stageId,document,index))
    await recheck()
    prepared.push({id:this.chunkId(stageId,document.fileId,index),kind:'chunk',scopeHash:this.scopeHash,ownerKey,stageId,fileId:document.fileId,index,expiresAt:stage.evidenceExpiresAt,ciphertext})
   }
   await this.store.runTransaction(async port=>{
    await this.checkUpload(port,participant,cardId,start,stageId,stage)
    const current=await Promise.all(indices.map(index=>port.get<Header>(this.names.chunks,this.chunkId(stageId,document.fileId,index))))
    for(let position=0;position<indices.length;position++)if(JSON.stringify(current[position])!==JSON.stringify(existing[position]))throw fail('changed')
    for(const row of prepared)await port.put(this.names.chunks,row)
   })
  }
  const restored=await this.readFile(ownerKey,stageId,document,recheck)
  if(!Buffer.from(restored).equals(Buffer.from(bytes)))throw fail('integrity')
  const metadata:FileMetadata={binding:stage.binding,stageId,evidenceId:stage.evidenceId,descriptor:document}
  const ciphertext=await this.seal(metadata,this.aad('file',ownerKey,document.fileId),recheck)
  const previous=await this.store.get<Header>(this.names.evidence,document.fileId)
  if(previous){
   this.header(previous,ownerKey)
   if(previous.kind!=='file'||previous.stageId!==stageId||previous.epoch!==stage.epoch||previous.expiresAt!==stage.evidenceExpiresAt)throw fail('integrity')
   const saved=this.parseFile(await this.open(previous,'file',recheck))
   if(JSON.stringify(saved)!==JSON.stringify(metadata))throw fail('integrity')
  }
  await this.store.runTransaction(async port=>{
   await this.checkUpload(port,participant,cardId,start,stageId,stage)
   const existing=await port.get<Header>(this.names.evidence,document.fileId)
   if(JSON.stringify(existing)!==JSON.stringify(previous))throw fail('changed')
   if(!existing)await port.put(this.names.evidence,{id:document.fileId,kind:'file',scopeHash:this.scopeHash,ownerKey,stageId,expiresAt:stage.evidenceExpiresAt,ciphertext,epoch:stage.epoch})
  })
 }
 private async readFile(ownerKey:string,stageId:string,document:Descriptor,recheck:()=>Promise<void>):Promise<Uint8Array>{
  const parts:Uint8Array[]=[]
  for(let index=0;index<document.chunkCount;index++){const row=await this.store.get<Header>(this.names.chunks,this.chunkId(stageId,document.fileId,index));parts.push(await this.chunkBytes(this.header(row,ownerKey),ownerKey,stageId,document,index,recheck))}
  const bytes=Buffer.concat(parts),actual=digest(bytes)
  if(bytes.length!==document.size||actual.toString('base64')!==document.digest||buildSha3_384EvidenceContentIdFromDigest(actual)!==document.contentId)throw fail('integrity')
  return Uint8Array.from(bytes)
 }
 private parseFile(value:unknown):FileMetadata{const row=object(value,['binding','stageId','evidenceId','descriptor']);return {binding:binding(row.binding),stageId:text(row.stageId,64),evidenceId:uuid(row.evidenceId),descriptor:descriptor(row.descriptor)}}
 private parseEvidence(value:unknown):Evidence{
  const row=object(value,['binding','stageId','requestHash','receipt','documents','mediaClaims']);assertControllerIdentityEvidenceReceipt(row.receipt)
  const documents=descriptors(row.documents),mediaClaims=array(row.mediaClaims).map(value=>{
   const claims=object(value),result:Record<string,string>={}
   for(const [name,value] of Object.entries(claims)){if(typeof value!=='string')throw fail('integrity');result[name]=value}
   return result
  })
  const expected=documents.map(document=>toSchemaOrgEvidenceMediaFlatClaims({id:document.fileId,mediaType:document.mediaType,contentUrl:`urn:sos:identity-evidence:${document.fileId}`,contentSize:document.size,contentId:document.contentId,digestAlgorithm:'sha3-384',digest:document.digest}))
  if(JSON.stringify(mediaClaims)!==JSON.stringify(expected))throw fail('integrity')
  return {binding:binding(row.binding),stageId:text(row.stageId,64),requestHash:text(row.requestHash,64),receipt:structuredClone(row.receipt),documents,mediaClaims}
 }
 private async evidenceRead(participant:unknown,cardId:string,start:ControllerIdentityEvidenceBinding,header:Header,action:'read'|'download'|'upload'){
  this.header(header,this.ownerKey(start))
  if(header.kind!=='evidence'||header.expiresAt<=this.now())throw fail('not_found',404)
  const evidence=this.parseEvidence(await this.open(header,'evidence',this.guard(participant,cardId,start,action)));sameOwner(evidence.binding,start);permitted(start,evidence.documents)
  if(evidence.receipt.evidenceId!==header.id||evidence.stageId!==header.stageId||evidence.stageId!==hash(JSON.stringify([header.ownerKey,evidence.receipt.operationId]))||evidence.receipt.files.length!==evidence.documents.length)throw fail('integrity')
  for(const item of evidence.receipt.files)if(!evidence.documents.some(document=>document.fileId===item.fileId&&document.slot===item.slot))throw fail('integrity')
  await this.store.runTransaction(async port=>{sameLease(start,await this.authority(participant,cardId,action,port));await this.active(port,header.ownerKey,header.epoch);const current=this.header(await port.get<Header>(this.names.evidence,header.id),header.ownerKey);if(current.ciphertext!==header.ciphertext||current.expiresAt<=this.now())throw fail('changed')})
  return evidence
 }
 async upload(input:Readonly<{participant:unknown;cardId:string;command:ControllerIdentityEvidenceCommand;documents:readonly ControllerIdentityEvidenceUploadDocument[]}>):Promise<ControllerIdentityEvidenceReceipt>{
  const cardId=text(input.cardId),command=normalizeControllerIdentityEvidenceCommand(input.command),documents=snapshotDocuments(input.documents),participant=input.participant
  try{
   const start=await this.authority(participant,cardId,'upload');permitted(start,documents)
   const ownerKey=this.ownerKey(start),stageId=hash(JSON.stringify([ownerKey,command.operationId]))
   const proposed=documents.map(document=>{const sum=digest(document.bytes);return {slot:document.slot,fileId:randomUUID(),fileName:document.fileName,mediaType:document.mediaType,size:document.bytes.length,digest:sum.toString('base64'),contentId:buildSha3_384EvidenceContentIdFromDigest(sum),chunkCount:Math.ceil(document.bytes.length/CHUNK_BYTES)}})
   const expectedHash=requestHash(command,proposed)
   let found=await this.store.runTransaction(async port=>{sameLease(start,await this.authority(participant,cardId,'upload',port));const epoch=await this.active(port,ownerKey);return {header:await port.get<Header>(this.names.stages,stageId),epoch:epoch.revision}})
   if(!found.header){
    const now=this.now(),stage:Stage={binding:start,command,requestHash:expectedHash,evidenceId:randomUUID(),documents:proposed,stageExpiresAt:integer(Math.min(now+this.stageTtl,start.authorizationExpiresAt),now+1),evidenceExpiresAt:integer(now+this.evidenceTtl),epoch:found.epoch}
    const ciphertext=await this.seal(stage,this.aad('stage',ownerKey,stageId),this.guard(participant,cardId,start,'upload'))
    found=await this.store.runTransaction(async port=>{sameLease(start,await this.authority(participant,cardId,'upload',port));await this.active(port,ownerKey,stage.epoch);const existing=await port.get<Header>(this.names.stages,stageId);if(existing)return {header:existing,epoch:stage.epoch};const header:Header={id:stageId,kind:'stage',scopeHash:this.scopeHash,ownerKey,expiresAt:stage.stageExpiresAt,state:'staging',epoch:stage.epoch,ciphertext};await port.put(this.names.stages,header);return {header,epoch:stage.epoch}})
   }
   const opened=await this.stageRead(participant,cardId,start,stageId),stage=opened.stage
   if(stage.requestHash!==expectedHash)throw fail('conflict')
   if(opened.header.state==='complete'){const saved=this.header(await this.store.get<Header>(this.names.evidence,stage.evidenceId),ownerKey);return (await this.evidenceRead(participant,cardId,start,saved,'upload')).receipt}
   sameLease(stage.binding,start)
   for(const document of stage.documents){const source=documents.find(value=>value.slot===document.slot);if(!source)throw fail('conflict');await this.writeFile(participant,cardId,start,stageId,stage,document,source.bytes)}
   const receipt:ControllerIdentityEvidenceReceipt={evidenceId:stage.evidenceId,operationId:command.operationId,status:'pending',files:stage.documents.map(document=>({fileId:document.fileId,slot:document.slot}))};assertControllerIdentityEvidenceReceipt(receipt)
   const metadata:Evidence={binding:stage.binding,stageId,requestHash:stage.requestHash,receipt,documents:stage.documents,mediaClaims:stage.documents.map(document=>toSchemaOrgEvidenceMediaFlatClaims({id:document.fileId,mediaType:document.mediaType,contentUrl:`urn:sos:identity-evidence:${document.fileId}`,contentSize:document.size,contentId:document.contentId,digestAlgorithm:'sha3-384',digest:document.digest}))}
   const ciphertext=await this.seal(metadata,this.aad('evidence',ownerKey,stage.evidenceId),this.guard(participant,cardId,start,'upload'))
   await this.store.runTransaction(async port=>{await this.checkUpload(port,participant,cardId,start,stageId,stage);const markers=await Promise.all(stage.documents.map(document=>port.get<Header>(this.names.evidence,document.fileId)));for(const marker of markers){const current=this.header(marker,ownerKey);if(current.kind!=='file'||current.stageId!==stageId)throw fail('integrity')}await port.put(this.names.evidence,{id:stage.evidenceId,kind:'evidence',scopeHash:this.scopeHash,ownerKey,stageId,expiresAt:stage.evidenceExpiresAt,ciphertext,epoch:stage.epoch});await port.put(this.names.stages,{...opened.header,state:'complete',expiresAt:stage.evidenceExpiresAt})})
   return structuredClone(receipt)
  }finally{for(const document of documents)document.bytes.fill(0)}
 }
 async list(input:Readonly<{participant:unknown;cardId:string}>):Promise<readonly ControllerIdentityEvidenceReceipt[]>{
  const cardId=text(input.cardId),start=await this.authority(input.participant,cardId,'read'),ownerKey=this.ownerKey(start)
  const rows=await this.store.query<Header>(this.names.evidence,{where:[{attribute:'ownerKey',equals:ownerKey},{attribute:'kind',equals:'evidence'}]}),result:ControllerIdentityEvidenceReceipt[]=[]
  for(const row of rows)if(row.expiresAt>this.now())result.push((await this.evidenceRead(input.participant,cardId,start,row,'read')).receipt)
  await this.store.runTransaction(async port=>{sameLease(start,await this.authority(input.participant,cardId,'read',port));await this.active(port,ownerKey)})
  return result
 }
 async download(input:Readonly<{participant:unknown;cardId:string;fileId:string}>):Promise<{bytes:Uint8Array;fileName:string;mediaType:string}>{
  const cardId=text(input.cardId),fileId=uuid(input.fileId),start=await this.authority(input.participant,cardId,'download'),ownerKey=this.ownerKey(start)
  const header=this.header(await this.store.get<Header>(this.names.evidence,fileId),ownerKey)
  if(header.kind!=='file'||header.expiresAt<=this.now())throw fail('not_found',404)
  const file=this.parseFile(await this.open(header,'file',this.guard(input.participant,cardId,start,'download')));sameOwner(file.binding,start);permitted(start,[file.descriptor])
  if(file.descriptor.fileId!==fileId||file.stageId!==header.stageId)throw fail('integrity')
  const evidenceHeader=this.header(await this.store.get<Header>(this.names.evidence,file.evidenceId),ownerKey),evidence=await this.evidenceRead(input.participant,cardId,start,evidenceHeader,'download')
  if(evidence.stageId!==file.stageId||!evidence.documents.some(document=>JSON.stringify(document)===JSON.stringify(file.descriptor)))throw fail('integrity')
  const bytes=await this.readFile(ownerKey,file.stageId,file.descriptor,this.guard(input.participant,cardId,start,'download'))
  await this.store.runTransaction(async port=>{sameLease(start,await this.authority(input.participant,cardId,'download',port));await this.active(port,ownerKey,header.epoch);const currentFile=this.header(await port.get<Header>(this.names.evidence,fileId),ownerKey),currentEvidence=this.header(await port.get<Header>(this.names.evidence,file.evidenceId),ownerKey);if(currentFile.ciphertext!==header.ciphertext||currentEvidence.ciphertext!==evidenceHeader.ciphertext||currentFile.expiresAt<=this.now()||currentEvidence.expiresAt<=this.now())throw fail('changed')})
  return {bytes,fileName:file.descriptor.fileName,mediaType:file.descriptor.mediaType}
 }
 async reset(input:Readonly<{participant:unknown;cardId:string}>):Promise<{deletedEvidence:number;deletedFiles:number}>{
  const cardId=text(input.cardId),start=await this.authority(input.participant,cardId,'reset'),ownerKey=this.ownerKey(start)
  const current=await this.store.runTransaction(async port=>{sameLease(start,await this.authority(input.participant,cardId,'reset',port));const previous=await this.epoch(port,ownerKey),revision=previous.state==='resetting'?previous.revision:previous.revision+1;await port.put(this.names.stages,{id:previous.id,kind:'epoch',scopeHash:this.scopeHash,ownerKey,epoch:revision,state:'resetting',expiresAt:Number.MAX_SAFE_INTEGER});return {id:previous.id,revision}})
  let deletedEvidence=0,deletedFiles=0
  for(const collection of [this.names.chunks,this.names.evidence,this.names.stages])for(;;){
   const count=await this.store.runTransaction(async port=>{
    sameLease(start,await this.authority(input.participant,cardId,'reset',port));const epoch=await this.epoch(port,ownerKey);if(epoch.revision!==current.revision||epoch.state!=='resetting')throw fail('changed')
    const rows=await port.query<Header>(collection,{where:[{attribute:'ownerKey',equals:ownerKey},...(collection===this.names.stages?[{attribute:'kind',equals:'stage'}]:[])],limit:64})
    let evidence=0,files=0
    for(const row of rows){this.header(row,ownerKey);if(collection===this.names.stages)await port.put(collection,{id:row.id,kind:'tombstone',scopeHash:this.scopeHash,ownerKey,expiresAt:this.now()+this.stageTtl});else{if(row.kind==='evidence')evidence++;if(row.kind==='file')files++;await port.delete(collection,row.id)}}
    return {rows:rows.length,evidence,files}
   })
   deletedEvidence+=count.evidence;deletedFiles+=count.files
   if(!count.rows)break
  }
  await this.store.runTransaction(async port=>{sameLease(start,await this.authority(input.participant,cardId,'reset',port));const epoch=await this.epoch(port,ownerKey);if(epoch.revision!==current.revision)throw fail('changed');await port.put(this.names.stages,{id:current.id,kind:'epoch',scopeHash:this.scopeHash,ownerKey,epoch:current.revision,state:'active',expiresAt:Number.MAX_SAFE_INTEGER})})
  return {deletedEvidence,deletedFiles}
 }
 /** Trusted scoped maintenance only; public routes must never delegate arbitrary cleanup selectors. */
 async cleanupExpired(input:Readonly<{limit:number}>):Promise<{deletedStages:number;deletedFiles:number;deletedEvidence:number}>{
  const limit=integer(input.limit,1,256),now=this.now();let deletedStages=0,deletedFiles=0,deletedEvidence=0
  const candidates=await this.store.query<Header>(this.names.stages,{orderBy:{attribute:'expiresAt',direction:'asc'},limit})
  for(const candidate of candidates){
   this.header(candidate)
   if(candidate.expiresAt>now||candidate.kind==='epoch')continue
   for(const collection of [this.names.chunks,this.names.evidence])for(;;){
    const count=await this.store.runTransaction(async port=>{
     const stage=this.header(await port.get<Header>(this.names.stages,candidate.id),candidate.ownerKey)
     if(stage.expiresAt>this.now())return {rows:0,files:0,evidence:0}
     const rows=await port.query<Header>(collection,{where:[{attribute:'stageId',equals:candidate.id},{attribute:'ownerKey',equals:candidate.ownerKey}],limit:64})
     let files=0,evidence=0
     for(const row of rows){this.header(row,candidate.ownerKey);if(row.kind==='file')files++;if(row.kind==='evidence')evidence++;await port.delete(collection,row.id)}
     return {rows:rows.length,files,evidence}
    })
    deletedFiles+=count.files;deletedEvidence+=count.evidence
    if(!count.rows)break
   }
   const removed=await this.store.runTransaction(async port=>{const current=await port.get<Header>(this.names.stages,candidate.id);if(current&&current.scopeHash===this.scopeHash&&current.ownerKey===candidate.ownerKey&&current.expiresAt<=this.now()){await port.delete(this.names.stages,current.id);return true}return false})
   if(removed)deletedStages++
  }
  return {deletedStages,deletedFiles,deletedEvidence}
 }
}
