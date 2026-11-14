import {createHash,randomUUID} from 'node:crypto'
import {normalizeSubjectRegistrationCommand,type SubjectRegistrationCommand,type ProvisionalSubjectRegistrationReceipt} from 'sos-data-utils-ts/provisional-subject-registration'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type TrustedSubjectRegistrationCreator=Readonly<{organizationReference:string;actorIdentifier:string;expiresAt:number}>
export type ProvisionalSubjectRegistrationRecord=Readonly<{
 id:string;scopeKey:string;creatorOrganizationReference:string;creatorActorIdentifier:string
 requestKey:string;requestHash:string;command:SubjectRegistrationCommand;receipt:ProvisionalSubjectRegistrationReceipt
 status:'provisional'|'claimed';createdAt:number;expiresAt:number;claimedByOwnerHash?:string
}>
export type PendingSubjectControllerInvitation=Readonly<{
 id:string;scopeKey:string;registrationId:string;recipientKind:'email'|'telephone';recipientHash:string
 status:'pending'|'accepted';expiresAt:number;acceptedByOwnerHash?:string
}>
const hash=(value:string)=>createHash('sha256').update(value).digest('hex')
function scope(value:string):void{if(typeof value!=='string'||!value||value.length>2048)throw new TypeError('subject_registration_scope_invalid')}
export function provisionalSubjectRegistrationCollections(scopeKey:string){
 scope(scopeKey)
 const prefix=`provisional-v1__${hash(scopeKey)}`
 return Object.freeze({registrations:`${prefix}__subject-registrations`,invitations:`${prefix}__subject-registration-invitations`})
}
function failure(code:string,status:number){return Object.assign(new Error(code),{status})}

/** Host admission supplies verified creator context; this provider never infers controller ownership. */
export class ProvisionalSubjectRegistrationVault{
 constructor(private readonly options:Readonly<{
  store:TransactionalVaultRepository;scopeKey:string
  assertCreator:(participant:unknown)=>Promise<TrustedSubjectRegistrationCreator>
  now?:()=>number
 }>){scope(options.scopeKey)}
 private async creator(participant:unknown):Promise<TrustedSubjectRegistrationCreator>{
  const creator=await this.options.assertCreator(participant)
  if(!creator||typeof creator.organizationReference!=='string'||!/^Organization\/[A-Za-z0-9.-]{1,64}$/u.test(creator.organizationReference)
   ||typeof creator.actorIdentifier!=='string'||!creator.actorIdentifier||!Number.isFinite(creator.expiresAt)||creator.expiresAt<=this.now())throw failure('subject_registration_forbidden',403)
  return creator
 }
 private now(){return (this.options.now??Date.now)()}
 async register(input:Readonly<{participant:unknown;command:unknown}>):Promise<ProvisionalSubjectRegistrationReceipt>{
  const command=normalizeSubjectRegistrationCommand(input.command)
  const creator=await this.creator(input.participant),names=provisionalSubjectRegistrationCollections(this.options.scopeKey)
  const requestKey=hash(`${this.options.scopeKey}\0${creator.organizationReference}\0${command.operationId}`),requestHash=hash(JSON.stringify(command))
  return this.options.store.runTransaction(async transaction=>{
   const prior=(await transaction.query<ProvisionalSubjectRegistrationRecord>(names.registrations,{where:[{attribute:'requestKey',equals:requestKey}]}))[0]
   if(prior){
    if(prior.scopeKey!==this.options.scopeKey||prior.creatorOrganizationReference!==creator.organizationReference||prior.requestHash!==requestHash||prior.expiresAt<=this.now())throw failure('subject_registration_request_conflict',409)
    return prior.receipt
   }
   const registrationId=randomUUID(),invitationId=randomUUID(),subjectIdentifier=`urn:uuid:${randomUUID()}`
   const now=this.now(),expiresAt=now+24*60*60*1000
   const receipt:ProvisionalSubjectRegistrationReceipt={registrationId,subjectIdentifier,subjectKind:command.subject.kind,status:'provisional',controllerInvitation:{invitationId,status:'pending'},evidence:{status:'pending'}}
   const record:ProvisionalSubjectRegistrationRecord={id:registrationId,scopeKey:this.options.scopeKey,creatorOrganizationReference:creator.organizationReference,creatorActorIdentifier:creator.actorIdentifier,requestKey,requestHash,command,receipt,status:'provisional',createdAt:now,expiresAt}
   const invitation:PendingSubjectControllerInvitation={id:invitationId,scopeKey:this.options.scopeKey,registrationId,recipientKind:command.controller.contact.kind,recipientHash:hash(command.controller.contact.value),status:'pending',expiresAt}
   await transaction.put(names.registrations,record)
   await transaction.put(names.invitations,invitation)
   return receipt
  })
 }
 async read(input:Readonly<{participant:unknown;registrationId:string}>):Promise<ProvisionalSubjectRegistrationReceipt>{
  const creator=await this.creator(input.participant)
  const record=await this.options.store.get<ProvisionalSubjectRegistrationRecord>(provisionalSubjectRegistrationCollections(this.options.scopeKey).registrations,input.registrationId)
  if(!record||record.expiresAt<=this.now())throw failure('subject_registration_not_found',404)
  if(record.scopeKey!==this.options.scopeKey||record.creatorOrganizationReference!==creator.organizationReference)throw failure('subject_registration_forbidden',403)
  return record.receipt
 }
}
