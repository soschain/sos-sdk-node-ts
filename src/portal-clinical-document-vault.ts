import {createHash} from 'node:crypto'
import {canonicalClinicalSubjectReference,validateR4DocumentBundleStructure,type FhirBundle} from 'fhir-data-utils-ts'
import {FhirIpsCreatorKinds} from 'sos-data-utils-ts/clinical-creator-contract'
import {normalizeClinicalCreatorBinding} from 'sos-sdk-core-ts/clinical-creator'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import type {AuthorizedClinicalDocument} from './clinical-document-health-card.js'

export type PortalClinicalDocumentAuthority=Omit<AuthorizedClinicalDocument,'documentReference'|'revision'|'bundle'>
export type PortalClinicalDocumentSave=Readonly<{operationId:string;documentReference:string;expectedRevision?:string;bundle:FhirBundle}>
export type PortalClinicalDocumentOperation=Readonly<{kind:'save';command:PortalClinicalDocumentSave}>|Readonly<{kind:'read';documentReference:string}>
export type PortalClinicalDocumentResult=Readonly<{kind:'document';document:AuthorizedClinicalDocument|undefined}>
export type PortalOriginalClinicalDocument=Pick<AuthorizedClinicalDocument,'documentReference'|'revision'|'bundle'>
export type PortalClinicalDocumentOriginalReadAuthority=Readonly<{authorizationRevision:string;subjectReference:string;readerActorIdentifier:string}>
export type PortalClinicalDocumentOriginalReaderOptions=Readonly<{store:TransactionalVaultRepository;scopeKey:string;subjectIdentifier:string;generationId:string;expiresAt:number;readerActorIdentifier:string;now?:()=>number;authorizeOriginalRead:(transaction:IVaultRepository,documentReference:string)=>Promise<PortalClinicalDocumentOriginalReadAuthority>}>
export type PortalClinicalDocumentVaultOptions=Readonly<{
 store:TransactionalVaultRepository;scopeKey:string;subjectIdentifier:string;generationId:string;expiresAt:number
 organizationReference:string;authorIdentifier:string;now?:()=>number
 readerActorIdentifier?:string;authorizeOriginalRead?:PortalClinicalDocumentOriginalReaderOptions['authorizeOriginalRead']
 /** Current OWNER-LOCAL card/lifecycle and Consent reads use this same transaction before any write. Pro custody/workforce admission is checked separately by its owning host before/after peer transport. */
 authorize:(transaction:IVaultRepository,action:'read'|'write',documentReference:string)=>Promise<PortalClinicalDocumentAuthority>
}>
type StoredDocument={id:string;kind:'document';scopeKey:string;subjectIdentifier:string;generationId:string;expiresAt:number;organizationReference:string;authorIdentifier:string;actorIdentifier:string;documentReference:string;revision:string;bundle:FhirBundle}
type Receipt={id:string;kind:'operation';fingerprint:string;documentId:string;revision:string;bundle:FhirBundle;actorIdentifier:string}
const text=(value:unknown):value is string=>typeof value==='string'&&value.length>0&&value.trim()===value&&value.length<=2048
const object=(value:unknown):value is Record<string,unknown>=>value!==null&&typeof value==='object'&&!Array.isArray(value)
const hash=(value:string)=>createHash('sha256').update(value).digest('hex')
function canonical(value:unknown):string{if(Array.isArray(value))return`[${value.map(canonical).join(',')}]`;if(object(value))return`{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;return JSON.stringify(value)??'null'}
function fail(suffix:string):never{throw new Error('care_document_'+suffix)}
function subjectEqual(a:string,b:string):boolean{try{return canonicalClinicalSubjectReference(a)===canonicalClinicalSubjectReference(b)}catch{return false}}
/** Stores original native documents, never a reconstructed IPS or a persisted authority decision. */
export class PortalClinicalDocumentVaultProvider {
 readonly collectionNames:Readonly<{documents:string;operations:string}>
 private readonly now:()=>number
 constructor(private readonly options:PortalClinicalDocumentVaultOptions){
  for(const value of [options.scopeKey,options.subjectIdentifier,options.generationId,options.organizationReference,options.authorIdentifier])if(!text(value))fail('context_invalid')
  if(!Number.isFinite(options.expiresAt)||typeof options.authorize!=='function'||typeof options.store.runTransaction!=='function')fail('context_invalid')
  this.now=options.now??Date.now;const prefix='portal_clinical_document_'+hash(options.scopeKey);this.collectionNames=Object.freeze({documents:prefix+'_documents',operations:prefix+'_operations'})
 }
 private context(reference:string){if(!text(reference))fail('request_invalid');if(this.options.expiresAt<=this.now())fail('context_expired')}
 private documentId(reference:string){return hash([this.options.subjectIdentifier,this.options.generationId,this.options.organizationReference,reference].join('\0'))}
 private async authority(transaction:IVaultRepository,action:'read'|'write',reference:string):Promise<PortalClinicalDocumentAuthority>{
  const value=await this.options.authorize(transaction,action,reference)
  if(!value||value.licensedClinicalAuthor!==true||!text(value.authorizationRevision)||value.fhirVersion!=='4.0.1'||!Array.isArray(value.permittedResourceTypes)||value.permittedResourceTypes.some(type=>!text(type))||value.organizationReference!==this.options.organizationReference||!subjectEqual(value.subjectReference,this.options.subjectIdentifier))fail('authority_forbidden')
  let binding:ReturnType<typeof normalizeClinicalCreatorBinding>;try{binding=normalizeClinicalCreatorBinding(value.clinicalCreatorBinding)}catch{fail('authority_forbidden')}
  if(binding.kind!==FhirIpsCreatorKinds.Professional||binding.ownerIdentifier!==this.options.organizationReference||binding.authorIdentifier!==this.options.authorIdentifier)fail('authority_forbidden')
  return structuredClone({...value,clinicalCreatorBinding:binding})
 }
 private checkBundle(bundle:FhirBundle,reference:string,authority:PortalClinicalDocumentAuthority):void{
  if(!validateR4DocumentBundleStructure(bundle).ok||Buffer.byteLength(JSON.stringify(bundle))>1024*1024)fail('bundle_invalid')
  const first=bundle.entry?.[0],composition=first?.resource
  if(!composition||composition.resourceType!=='Composition'||!text(composition.id)||(reference!==first?.fullUrl&&reference!==`Composition/${composition.id}`))fail('binding_forbidden')
  if(!object(composition.subject)||typeof composition.subject.reference!=='string'||!subjectEqual(composition.subject.reference,authority.subjectReference)||!Array.isArray(composition.author)||!composition.author.length||!composition.author.every(author=>object(author)&&(author.reference===authority.organizationReference||author.reference===authority.clinicalCreatorBinding.authorIdentifier)))fail('binding_forbidden')
  if(composition.attester!==undefined&&(!Array.isArray(composition.attester)||!composition.attester.every(attester=>object(attester)&&object(attester.party)&&attester.party.reference===authority.clinicalCreatorBinding.authorIdentifier)))fail('binding_forbidden')
  for(const entry of bundle.entry??[]){
   const resource=entry.resource;if(!resource||!authority.permittedResourceTypes.includes(resource.resourceType))fail('resource_forbidden')
   for(const key of ['subject','patient']){const value=resource[key];if(object(value)&&typeof value.reference==='string'&&!subjectEqual(value.reference,authority.subjectReference))fail('binding_forbidden')}
   if(resource.resourceType==='Patient'&&(!text(resource.id)||!subjectEqual(`Patient/${resource.id}`,authority.subjectReference)))fail('binding_forbidden')
   const identifiesAssignment=entry.fullUrl===authority.clinicalCreatorBinding.authorIdentifier||text(resource.id)&&subjectEqual(`PractitionerRole/${resource.id}`,authority.clinicalCreatorBinding.authorIdentifier)
   if(resource.resourceType==='PractitionerRole'&&identifiesAssignment&&(!object(resource.practitioner)||typeof resource.practitioner.reference!=='string'||!subjectEqual(resource.practitioner.reference,authority.clinicalCreatorBinding.actorIdentifier)||!object(resource.organization)||resource.organization.reference!==authority.organizationReference))fail('binding_forbidden')
  }
 }
 private checkedStored(row:StoredDocument|undefined,reference:string,authority:PortalClinicalDocumentAuthority):StoredDocument|undefined{
  if(!row)return undefined
  if(row.kind!=='document'||row.id!==this.documentId(reference)||row.scopeKey!==this.options.scopeKey||row.subjectIdentifier!==this.options.subjectIdentifier||row.generationId!==this.options.generationId||row.organizationReference!==this.options.organizationReference||row.authorIdentifier!==this.options.authorIdentifier||row.actorIdentifier!==authority.clinicalCreatorBinding.actorIdentifier||row.documentReference!==reference||!/^\d+$/u.test(row.revision)||row.expiresAt<=this.now())fail('binding_forbidden')
  this.checkBundle(row.bundle,reference,authority);return row
 }
 private snapshot(row:Pick<StoredDocument,'documentReference'|'revision'|'bundle'>,authority:PortalClinicalDocumentAuthority):AuthorizedClinicalDocument{return structuredClone({...authority,documentReference:row.documentReference,revision:row.revision,bundle:row.bundle})}
 async readOriginalDocument(input:Readonly<{documentReference:string}>):Promise<PortalOriginalClinicalDocument|undefined>{
  if(!this.options.readerActorIdentifier||!this.options.authorizeOriginalRead)fail('original_reader_required')
  return readOriginalDocument({store:this.options.store,scopeKey:this.options.scopeKey,subjectIdentifier:this.options.subjectIdentifier,generationId:this.options.generationId,expiresAt:this.options.expiresAt,readerActorIdentifier:this.options.readerActorIdentifier,authorizeOriginalRead:this.options.authorizeOriginalRead,now:this.now},input)
 }
 async readAuthorizedDocument(input:Readonly<{documentReference:string}>):Promise<AuthorizedClinicalDocument|undefined>{
  this.context(input.documentReference)
  return this.options.store.runTransaction(async transaction=>{const authority=await this.authority(transaction,'read',input.documentReference),row=this.checkedStored(await transaction.get<StoredDocument>(this.collectionNames.documents,this.documentId(input.documentReference)),input.documentReference,authority);return row?this.snapshot(row,authority):undefined})
 }
 async saveDocument(command:PortalClinicalDocumentSave):Promise<AuthorizedClinicalDocument>{
  if(!command||!text(command.operationId)||Object.keys(command).some(key=>!['operationId','documentReference','expectedRevision','bundle'].includes(key))||command.expectedRevision!==undefined&&!/^[1-9]\d*$/u.test(command.expectedRevision))fail('request_invalid')
  this.context(command.documentReference);const copied=structuredClone(command),fingerprint=hash(canonical(copied)),documentId=this.documentId(command.documentReference),operationId=hash([this.options.generationId,this.options.subjectIdentifier,this.options.organizationReference,command.operationId].join('\0'))
  return this.options.store.runTransaction(async transaction=>{
   const authority=await this.authority(transaction,'write',command.documentReference)
   const current=this.checkedStored(await transaction.get<StoredDocument>(this.collectionNames.documents,documentId),command.documentReference,authority),receipt=await transaction.get<Receipt>(this.collectionNames.operations,operationId)
   this.checkBundle(copied.bundle,command.documentReference,authority)
   if(receipt){if(receipt.kind!=='operation'||receipt.fingerprint!==fingerprint||receipt.documentId!==documentId||receipt.actorIdentifier!==authority.clinicalCreatorBinding.actorIdentifier)fail('idempotency_conflict');this.checkBundle(receipt.bundle,command.documentReference,authority);return this.snapshot({documentReference:command.documentReference,revision:receipt.revision,bundle:receipt.bundle},authority)}
   if(current?command.expectedRevision!==current.revision:command.expectedRevision!==undefined)fail('revision_conflict')
   const row:StoredDocument={id:documentId,kind:'document',scopeKey:this.options.scopeKey,subjectIdentifier:this.options.subjectIdentifier,generationId:this.options.generationId,expiresAt:this.options.expiresAt,organizationReference:this.options.organizationReference,authorIdentifier:this.options.authorIdentifier,actorIdentifier:authority.clinicalCreatorBinding.actorIdentifier,documentReference:command.documentReference,revision:String(Number(current?.revision??0)+1),bundle:copied.bundle}
   const operation:Receipt={id:operationId,kind:'operation',fingerprint,documentId,revision:row.revision,bundle:row.bundle,actorIdentifier:row.actorIdentifier}
   await transaction.put(this.collectionNames.documents,row);await transaction.put(this.collectionNames.operations,operation);return this.snapshot(row,authority)
  })
 }
}
export async function executePortalClinicalDocumentOperation(provider:PortalClinicalDocumentVaultProvider,operation:PortalClinicalDocumentOperation):Promise<PortalClinicalDocumentResult>{
 if(!operation||typeof operation!=='object')fail('request_invalid')
 if(operation.kind==='save'&&Object.keys(operation).every(key=>['kind','command'].includes(key)))return {kind:'document',document:await provider.saveDocument(operation.command)}
 if(operation.kind==='read'&&Object.keys(operation).every(key=>['kind','documentReference'].includes(key)))return {kind:'document',document:await provider.readAuthorizedDocument({documentReference:operation.documentReference})}
 return fail('request_invalid')
}

/** Separate owner-read purpose; no licensed-author flag or signing capability is returned. */
async function readOriginalDocument(options:PortalClinicalDocumentOriginalReaderOptions,input:Readonly<{documentReference:string}>):Promise<PortalOriginalClinicalDocument|undefined>{
 for(const value of [options.scopeKey,options.subjectIdentifier,options.generationId,options.readerActorIdentifier,input.documentReference])if(!text(value))fail('original_reader_forbidden')
 const now=options.now??Date.now;if(!Number.isFinite(options.expiresAt)||options.expiresAt<=now())fail('context_expired')
 const collection='portal_clinical_document_'+hash(options.scopeKey)+'_documents'
 return options.store.runTransaction(async transaction=>{
  const permission=await options.authorizeOriginalRead(transaction,input.documentReference)
  if(!permission||!text(permission.authorizationRevision)||permission.readerActorIdentifier!==options.readerActorIdentifier||!subjectEqual(permission.subjectReference,options.subjectIdentifier))fail('original_reader_forbidden')
  const rows=await transaction.query<StoredDocument>(collection,{where:[{attribute:'scopeKey',equals:options.scopeKey},{attribute:'subjectIdentifier',equals:options.subjectIdentifier},{attribute:'generationId',equals:options.generationId},{attribute:'documentReference',equals:input.documentReference}]})
  if(rows.length>1)fail('identity_mismatch');const row=rows[0];if(!row)return undefined
  if(row.kind!=='document'||row.scopeKey!==options.scopeKey||row.subjectIdentifier!==options.subjectIdentifier||row.generationId!==options.generationId||row.documentReference!==input.documentReference||!text(row.organizationReference)||!text(row.authorIdentifier)||!text(row.actorIdentifier)||row.id!==hash([row.subjectIdentifier,row.generationId,row.organizationReference,row.documentReference].join('\0'))||!/^\d+$/u.test(row.revision)||!validateR4DocumentBundleStructure(row.bundle).ok)fail('original_reader_forbidden')
  if(row.expiresAt<=now())fail('context_expired')
  const composition=row.bundle.entry?.[0]?.resource;if(!composition||!object(composition.subject)||typeof composition.subject.reference!=='string'||!subjectEqual(composition.subject.reference,permission.subjectReference))fail('original_reader_forbidden')
  return structuredClone({documentReference:row.documentReference,revision:row.revision,bundle:row.bundle})
 })
}

/** Construct a selected-owner reader without inventing organization or clinical-author context. */
export function createPortalClinicalDocumentOriginalReader(options:PortalClinicalDocumentOriginalReaderOptions):Readonly<{readOriginalDocument:(input:Readonly<{documentReference:string}>)=>Promise<PortalOriginalClinicalDocument|undefined>}>{
 if(!options||typeof options.authorizeOriginalRead!=='function'||typeof options.store?.runTransaction!=='function')fail('original_reader_required')
 return Object.freeze({readOriginalDocument:(input:Readonly<{documentReference:string}>)=>readOriginalDocument(options,input)})
}
