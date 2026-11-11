import {createHash} from 'node:crypto'
import {TaskService,type TaskRecord,type TaskRepository,type ListTasksQuery} from 'tasks-core-node-ts'
import type {IVaultRepository} from 'gdc-common-utils-ts/storage'
import {CommunicationClaim} from 'gdc-common-utils-ts/models/interoperable-claims/communication-claims'
import {CommunicationCategoryCodes} from 'gdc-common-utils-ts/constants/communication'
import {createCommMsgExtendedDraft} from 'gdc-sdk-node-ts'
import {buildSubjectCommunicationGroupReference} from 'sos-data-utils-ts/subject-communication-group'
import {AppointmentClaim,EncounterClaim,EncounterHistoryClaim,EncounterStatusR5} from 'fhir-data-utils-ts/claims'
import {planPortalEncounterChange,type PortalEncounterSourceOutcome} from 'sos-data-utils-ts/portal-encounter-journey'
import {buildFlatClaimResourceEntry,type FlatClaimResourceEntry} from 'fhir-data-utils-ts/flat-claim-resource-graph'
import {TaskClaim} from 'sos-data-utils-ts/task-artifact-schema'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type PortalCareResourceType='Appointment'|'Encounter'|'EncounterHistory'|'Task'
/** Trusted adapter input. Public portals send intent; their BFF resolves flat entries and authority. */
export type PortalEncounterMutation=Readonly<{
  operationId:string;encounterReference:string;expectedRevision?:number;create?:FlatClaimResourceEntry
  relatedTask?:Readonly<{entry:FlatClaimResourceEntry;expectedRevision?:number}>
  status?:EncounterStatusR5;destination?:FlatClaimResourceEntry;sourceOutcome?:PortalEncounterSourceOutcome;destinationExpectedRevision?:number
}>
export type PortalCareStoredResource=Readonly<{
  id:string;scopeKey:string;subjectIdentifier:string;generationId:string;expiresAt:number
  entry:FlatClaimResourceEntry;revision:number;remindAt:string|null
}>
export type PortalCareNotification=Readonly<{
  id:string;scopeKey:string;subjectIdentifier:string;generationId:string;expiresAt:number
  kind:'care';resourceReference:string;occurredAt:string;readAt?:string
  communication:ReturnType<typeof createCommMsgExtendedDraft>['message']
}>
export type PortalCareSaveOptions=Readonly<{expectedRevision?:number;remindAt?:string|null}>
export type PortalCareOperation=
  | Readonly<{kind:'search';resourceType:PortalCareResourceType}>
  | Readonly<{kind:'save';entry:FlatClaimResourceEntry;mode:'create'|'update';options?:PortalCareSaveOptions}>
  | Readonly<{kind:'encounter';mutation:PortalEncounterMutation}>
  | Readonly<{kind:'notifications'}>
  | Readonly<{kind:'acknowledge';id:string}>
  | Readonly<{kind:'tick'}>
export type PortalCareOperationResult=
  | Readonly<{kind:'resources';resources:readonly PortalCareStoredResource[]}>
  | Readonly<{kind:'notifications';notifications:readonly PortalCareNotification[]}>
  | Readonly<{kind:'acknowledged'}>
  | Readonly<{kind:'tick';dispatched:number}>
export type PortalCareVaultOptions=Readonly<{
  store:TransactionalVaultRepository;scopeKey:string;subjectIdentifier:string;generationId:string
  actorIdentifier:string;recipientActorIdentifier:string;expiresAt:number;communicationsCollection:string
  /** The BFF derives authority from its verified session, selected subject and professional capabilities. */
  assertAccess:(transaction:IVaultRepository,action:'read'|'write',resourceType?:PortalCareResourceType)=>Promise<void>
  /** Optional provider/section boundary within an already authorized subject. */
  assertResourceAccess?:(transaction:IVaultRepository,action:'read'|'write',entry:FlatClaimResourceEntry)=>Promise<void>
  now?:()=>number
  /** Called before care writes, inside their transaction; the owning delivery port may enqueue one wake-up. */
  enqueueNotice?:(transaction:IVaultRepository,notice:PortalCareNotification)=>Promise<void>
}>

/**
 * Synthetic provider over the existing Confidential Storage port. It owns no database,
 * process-local authority, telephone channel or replacement task engine. TaskService is
 * the same task lifecycle implementation used by Chat/GW; its repository is adapted here.
 */
export class PortalCareVaultProvider {
  readonly collectionNames:Readonly<{resources:string;tasks:string;communications:string}>
  private readonly options:PortalCareVaultOptions
  private readonly now:()=>number
  constructor(options:PortalCareVaultOptions){
    for(const value of [options.scopeKey,options.subjectIdentifier,options.generationId,options.actorIdentifier,options.recipientActorIdentifier,options.communicationsCollection])
      if(typeof value!=='string'||!value.trim())throw new TypeError('care_context_invalid')
    if(!Number.isFinite(options.expiresAt)||typeof options.assertAccess!=='function')throw new TypeError('care_context_invalid')
    this.options=options;this.now=options.now??Date.now
    const prefix=`portal_care_${hash(options.scopeKey)}`
    this.collectionNames=Object.freeze({resources:`${prefix}_resources`,tasks:`${prefix}_tasks`,communications:options.communicationsCollection})
  }

  async search(resourceType:PortalCareResourceType):Promise<readonly PortalCareStoredResource[]>{
    assertResourceType(resourceType)
    return this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'read',resourceType)
      return (await this.resources(transaction)).filter(row=>row.entry.resourceType===resourceType)
    })
  }

  /** Trusted BFF fixtures are atomic and never overwrite later user edits or emit delivery claims. */
  async seed(entries:readonly FlatClaimResourceEntry[]):Promise<void>{
    const normalized=entries.map(entry=>this.normalize(entry))
    await this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'read')
      const existing=await this.resources(transaction),jobs=await this.taskRepository(transaction)
      const engine=this.taskService(jobs),created:PortalCareStoredResource[]=[]
      for(const entry of normalized){
        if(existing.some(row=>row.entry.reference===entry.reference))continue
        const record=this.record(entry,1,this.reminderDate(entry,{}))
        await this.replaceReminder(engine,jobs,record)
        created.push(record)
      }
      for(const record of created)await transaction.put(this.collectionNames.resources,record)
      await jobs.flush()
    })
  }

  async save(raw:FlatClaimResourceEntry,mode:'create'|'update',options:PortalCareSaveOptions={}):Promise<PortalCareStoredResource>{
    const entry=this.normalize(raw)
    if(entry.resourceType==='EncounterHistory')throw new TypeError('care_history_write_requires_encounter_transaction')
    if(mode!=='create'&&mode!=='update')throw new TypeError('care_mutation_invalid')
    const remindAt=this.reminderDate(entry,options)
    return this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'write',entry.resourceType as PortalCareResourceType)
      await this.options.assertResourceAccess?.(transaction,'write',entry)
      const id=this.resourceId(entry),previous=await transaction.get<PortalCareStoredResource>(this.collectionNames.resources,id)
      if(previous&&this.owns(previous))await this.options.assertResourceAccess?.(transaction,'write',previous.entry)
      if(previous&&this.owns(previous)&&equal(previous.entry,entry)&&previous.remindAt===remindAt)return previous
      if(mode==='create'&&previous)throw new Error('care_resource_conflict')
      if(mode==='update'&&(!previous||!this.owns(previous)))throw new Error('care_resource_not_found')
      if(options.expectedRevision!==undefined&&previous?.revision!==options.expectedRevision)throw new Error('care_revision_conflict')
      const jobs=await this.taskRepository(transaction)
      const record=this.record(entry,(previous?.revision??0)+1,remindAt)
      await this.replaceReminder(this.taskService(jobs),jobs,record)
      const notice=this.notice(record,`${record.id}-${record.revision}`,`${entry.resourceType} ${mode==='create'?'created':'updated'}`)
      await this.options.enqueueNotice?.(transaction,notice)
      await transaction.put(this.collectionNames.resources,record)
      await transaction.put(this.collectionNames.communications,notice)
      await jobs.flush()
      return record
    })
  }

  /** One transaction owns the stages, immutable milestones, notification and retry receipt. */
  async mutateEncounter(mutation:PortalEncounterMutation):Promise<readonly PortalCareStoredResource[]>{
    const keys=['operationId','encounterReference','expectedRevision','create','status','destination','sourceOutcome','destinationExpectedRevision','relatedTask']
    if(!mutation||Object.keys(mutation).some(key=>!keys.includes(key))
      ||typeof mutation.operationId!=='string'||typeof mutation.encounterReference!=='string'
      ||!/^[A-Za-z0-9._-]{1,96}$/u.test(mutation.operationId||'')
      ||!/^Encounter\/[A-Za-z0-9._-]{1,128}$/u.test(mutation.encounterReference||''))throw new TypeError('encounter_mutation_invalid')
    const fingerprint=hash(JSON.stringify({actor:this.options.actorIdentifier,mutation}))
    const receipts=`${this.collectionNames.resources}_operations`
    const id=hash([this.options.scopeKey,this.options.generationId,this.options.subjectIdentifier,mutation.operationId].join('\0'))
    await this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'write','Encounter')
      const receipt=await transaction.get<{id:string;fingerprint:string}>(receipts,id)
      if(receipt){if(receipt.fingerprint!==fingerprint)throw new Error('encounter_idempotency_conflict');return}
      const rows=await this.resources(transaction)
      const previous=rows.find(row=>row.entry.reference===mutation.encounterReference)
      let entries:readonly FlatClaimResourceEntry[]
      const at=new Date(this.now()).toISOString()
      if(mutation.create){
        const created=this.normalize(mutation.create)
        if(created.resourceType!=='Encounter'||created.reference!==mutation.encounterReference
          ||created.claims[EncounterClaim.Status]!==EncounterStatusR5.Planned
          ||mutation.expectedRevision!==undefined||mutation.destination||mutation.status||mutation.sourceOutcome)throw new TypeError('encounter_mutation_invalid')
        if(previous||await transaction.get(this.collectionNames.resources,this.resourceId(created)))throw new Error('care_resource_conflict')
        entries=[created]
      }else{
        if(!previous)throw new Error('care_resource_not_found')
        if(!Number.isInteger(mutation.expectedRevision)||mutation.expectedRevision!==previous.revision)throw new Error('care_revision_conflict')
        let destination:FlatClaimResourceEntry|undefined
        if(mutation.destination){
          destination=this.normalize(mutation.destination)
          const existing=rows.find(row=>row.entry.reference===destination!.reference)
          if(existing){
            if(existing.revision!==mutation.destinationExpectedRevision)throw new Error('care_revision_conflict')
            destination=existing.entry
          }else{
            if(await transaction.get(this.collectionNames.resources,this.resourceId(destination)))throw new Error('care_resource_conflict')
            if(destination.claims[EncounterClaim.Status]!==EncounterStatusR5.Planned)throw new TypeError('encounter_destination_invalid')
          }
        }
        entries=planPortalEncounterChange({subjectIdentifier:this.options.subjectIdentifier,source:previous.entry,occurredAt:at,
          historyId:`${mutation.operationId}-source`,status:mutation.status,destination,sourceOutcome:mutation.sourceOutcome,
          destinationHistoryId:`${mutation.operationId}-destination`,
        })
      }
      if(mutation.relatedTask){
        const companion=mutation.relatedTask
        if(typeof companion!=='object'||Object.keys(companion).some(key=>!['entry','expectedRevision'].includes(key)))throw new TypeError('encounter_task_invalid')
        await this.authorize(transaction,'write','Task')
        const task=this.normalize(companion.entry)
        const source=entries.find(entry=>entry.reference===mutation.encounterReference)!
        if(task.resourceType!=='Task'||task.claims[TaskClaim.BasedOn]!==mutation.encounterReference||task.claims[TaskClaim.Focus]!==source.claims[EncounterClaim.ServiceType])throw new TypeError('encounter_task_invalid')
        const previousTask=rows.find(row=>row.entry.reference===task.reference)
        if(companion.expectedRevision===undefined){if(previousTask||await transaction.get(this.collectionNames.resources,this.resourceId(task)))throw new Error('care_resource_conflict')}
        else if(!Number.isInteger(companion.expectedRevision)||companion.expectedRevision<1||previousTask?.revision!==companion.expectedRevision)throw new Error('care_revision_conflict')
        entries=[...entries,task]
      }
      for(const entry of entries)await this.options.assertResourceAccess?.(transaction,'write',entry)
      const jobs=await this.taskRepository(transaction),engine=this.taskService(jobs)
      const records:PortalCareStoredResource[]=[]
      for(const raw of entries){
        const entry=this.normalize(raw),old=rows.find(row=>row.entry.reference===entry.reference)
        if(entry.resourceType==='EncounterHistory'&&(old||await transaction.get(this.collectionNames.resources,this.resourceId(entry))))throw new Error('encounter_history_immutable')
        const record=this.record(entry,(old?.revision??0)+1,this.reminderDate(entry,{remindAt:old?.remindAt??null}))
        if(entry.resourceType==='Encounter'||entry.resourceType==='Task')await this.replaceReminder(engine,jobs,record)
        records.push(record)
      }
      const changed=records.find(record=>record.entry.reference===mutation.encounterReference)!
      const notice=this.notice(changed,hash(`encounter-notice\0${id}`),'Encounter journey updated')
      const taskRecord=records.find(record=>record.entry.resourceType==='Task')
      const taskNotice=taskRecord?this.notice(taskRecord,hash(`encounter-task-notice\0${id}`),'Assistance task updated'):undefined
      await this.options.enqueueNotice?.(transaction,notice)
      for(const record of records)await transaction.put(this.collectionNames.resources,record)
      await transaction.put(this.collectionNames.communications,notice)
      if(taskNotice)await transaction.put(this.collectionNames.communications,taskNotice)
      await jobs.flush()
      await transaction.put(receipts,{id,fingerprint,scopeKey:this.options.scopeKey,generationId:this.options.generationId,
        subjectIdentifier:this.options.subjectIdentifier,expiresAt:this.options.expiresAt})
    })
    return [...await this.search('Encounter'),...await this.search('EncounterHistory')]
  }

  async notifications():Promise<readonly PortalCareNotification[]>{
    return this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'read')
      const rows=await transaction.query<PortalCareNotification>(this.collectionNames.communications,{where:[{attribute:'subjectIdentifier',equals:this.options.subjectIdentifier},{attribute:'kind',equals:'care'}]})
      const references=new Set((await this.resources(transaction)).map(row=>row.entry.reference))
      const visible:PortalCareNotification[]=[]
      for(const row of rows){
        if(this.owns(row)&&references.has(row.resourceReference)&&await this.canRead(transaction,resourceTypeOf(row.resourceReference)))visible.push(row)
      }
      return visible.sort((a,b)=>a.occurredAt.localeCompare(b.occurredAt))
    })
  }

  async acknowledge(id:string):Promise<void>{
    if(typeof id!=='string'||!/^[a-zA-Z0-9_-]{1,160}$/u.test(id))throw new TypeError('care_notification_id_invalid')
    await this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'read')
      const notice=await transaction.get<PortalCareNotification>(this.collectionNames.communications,id)
      if(!notice||!this.owns(notice))throw new Error('care_notification_not_found')
      await this.authorize(transaction,'read',resourceTypeOf(notice.resourceReference))
      if(!notice.readAt)await transaction.put(this.collectionNames.communications,{...notice,readAt:new Date(this.now()).toISOString()})
    })
  }

  /** Request polling and an external worker may both tick; each claim is committed once. No in-process timers. */
  async dispatchDue():Promise<number>{
    const candidates=await this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'read')
      return (await this.taskRepository(transaction)).list({status:'scheduled'})
    })
    let delivered=0
    for(const candidate of candidates){
      if(Date.parse(candidate.scheduledFor??'')>this.now())continue
      delivered+=await this.options.store.runTransaction(async transaction=>{
        await this.authorize(transaction,'read')
        const rows=await this.resources(transaction),jobs=await this.taskRepository(transaction),engine=this.taskService(jobs)
        const task=await engine.getTask(candidate.id)
        if(!task||task.status!=='scheduled'||Date.parse(task.scheduledFor??'')>this.now())return 0
        const record=rows.find(row=>row.entry.reference===task.metadata.focus)
        if(record&&!await this.canRead(transaction,record.entry.resourceType as PortalCareResourceType))return 0
        if(!record||String(record.revision)!==task.metadata['resource-revision']||terminal(record.entry)
          ||!Number.isFinite(Date.parse(task.scheduledFor??''))||(task.dueAt!==undefined&&Date.parse(task.dueAt)<this.now())){
          await engine.closeTask({taskId:task.id,status:'cancelled',reason:'care-reminder-obsolete'})
          await jobs.flush();return 0
        }
        const notice=this.notice(record,`${task.id}-due`,`${record.entry.resourceType} reminder`)
        await engine.closeTask({taskId:task.id,status:'completed',reason:'care-reminder-recorded'})
        await this.options.enqueueNotice?.(transaction,notice)
        await transaction.put(this.collectionNames.communications,notice)
        await jobs.flush()
        return 1
      })
    }
    return delivered
  }

  private async authorize(transaction:IVaultRepository,action:'read'|'write',resourceType?:PortalCareResourceType){
    if(this.now()>=this.options.expiresAt)throw new Error('care_context_expired')
    await this.options.assertAccess(transaction,action,resourceType)
  }
  private async canRead(transaction:IVaultRepository,resourceType:PortalCareResourceType){
    try{await this.authorize(transaction,'read',resourceType);return true}
    catch(error){if(error&&typeof error==='object'&&'status' in error&&error.status===403)return false;throw error}
  }
  private owns(record:Pick<PortalCareStoredResource,'scopeKey'|'subjectIdentifier'|'generationId'>){
    return record.scopeKey===this.options.scopeKey&&record.subjectIdentifier===this.options.subjectIdentifier&&record.generationId===this.options.generationId
  }
  private async resources(transaction:IVaultRepository){
    const rows=await transaction.query<PortalCareStoredResource>(this.collectionNames.resources,{where:[{attribute:'subjectIdentifier',equals:this.options.subjectIdentifier}]})
    const visible:PortalCareStoredResource[]=[]
    for(const row of rows){
      if(!this.owns(row))continue
      try{await this.options.assertResourceAccess?.(transaction,'read',row.entry);visible.push(row)}
      catch(error){if(!(error&&typeof error==='object'&&'status' in error&&error.status===403))throw error}
    }
    return visible
  }
  private resourceId(entry:FlatClaimResourceEntry){return hash([this.options.scopeKey,this.options.generationId,this.options.subjectIdentifier,entry.reference].join('\0'))}
  private record(entry:FlatClaimResourceEntry,revision:number,remindAt:string|null):PortalCareStoredResource{
    const {scopeKey,subjectIdentifier,generationId,expiresAt}=this.options
    return {id:this.resourceId(entry),scopeKey,subjectIdentifier,generationId,expiresAt,entry,revision,remindAt}
  }
  private normalize(entry:FlatClaimResourceEntry):FlatClaimResourceEntry{
    if(!entry||Object.keys(entry).some(key=>!['entryId','reference','resourceType','claims'].includes(key)))throw new TypeError('care_resource_invalid')
    assertResourceType(entry.resourceType)
    if(!/^[a-zA-Z0-9._-]{1,128}$/u.test(entry.entryId)||entry.reference!==`${entry.resourceType}/${entry.entryId}`
      ||!entry.claims||typeof entry.claims!=='object'||JSON.stringify(entry.claims).length>64_000)throw new TypeError('care_resource_invalid')
    let normalized:FlatClaimResourceEntry
    try{normalized=buildFlatClaimResourceEntry(entry)}catch{throw new TypeError('care_resource_invalid')}
    const claims=normalized.claims
    const subject=entry.resourceType==='Task'?(claims[TaskClaim.For]||claims[TaskClaim.Subject])
      :entry.resourceType==='Encounter'?(claims[EncounterClaim.Subject]||claims[EncounterClaim.Patient])
        :entry.resourceType==='EncounterHistory'?claims[EncounterHistoryClaim.Subject]
        :claims[AppointmentClaim.Patient]||claims['Appointment.subject']
    const subjectMatch=subject?referenceIdentity(subject)===referenceIdentity(this.options.subjectIdentifier)
      :entry.resourceType==='Appointment'&&String(claims[AppointmentClaim.ParticipantActor]||'').split(',').some(value=>referenceIdentity(value)===referenceIdentity(this.options.subjectIdentifier))
    if(!subjectMatch)throw new TypeError('care_resource_subject_mismatch')
    for(const key of [AppointmentClaim.Start,AppointmentClaim.End,AppointmentClaim.Date,EncounterClaim.PeriodStart,EncounterClaim.PeriodEnd,EncounterClaim.ActualPeriodStart,EncounterClaim.ActualPeriodEnd,EncounterHistoryClaim.ActualPeriodStart,EncounterHistoryClaim.ActualPeriodEnd,TaskClaim.ScheduledAt,TaskClaim.AutoCloseAt,TaskClaim.WindowStart,TaskClaim.WindowEnd]){
      if(key in claims&&!Number.isFinite(Date.parse(claims[key])))throw new TypeError('care_resource_date_invalid')
    }
    return normalized
  }
  private reminderDate(entry:FlatClaimResourceEntry,options:PortalCareSaveOptions){
    if(terminal(entry))return null
    const value=options.remindAt===undefined?(entry.resourceType==='Task'?entry.claims[TaskClaim.ScheduledAt]:undefined):options.remindAt
    if(value===undefined||value===null)return null
    if(typeof value!=='string'||!Number.isFinite(Date.parse(value)))throw new TypeError('care_reminder_date_invalid')
    return new Date(value).toISOString()
  }
  private taskService(repository:TaskRepository){return new TaskService({repository,now:()=>new Date(this.now())})}
  private async taskRepository(transaction:IVaultRepository){
    const rows=await transaction.query<TaskRecord>(this.collectionNames.tasks,{where:[{attribute:'subjectId',equals:this.options.subjectIdentifier}]})
    const own=rows.filter(row=>row.metadata['scope-key']===this.options.scopeKey&&row.metadata['generation-id']===this.options.generationId)
    return new BufferedVaultTaskRepository(own,transaction,this.collectionNames.tasks)
  }
  private async replaceReminder(engine:TaskService,repository:TaskRepository,record:PortalCareStoredResource){
    for(const job of await repository.list({subjectId:this.options.subjectIdentifier})){
      if(job.metadata.focus===record.entry.reference&&!['completed','cancelled'].includes(job.status))
        await engine.closeTask({taskId:job.id,status:'cancelled',reason:'care-resource-changed'})
    }
    if(!record.remindAt)return
    const id=hash(`${record.id}\0${record.revision}\0${record.remindAt}`)
    const dueAt=record.entry.resourceType==='Task'?(record.entry.claims[TaskClaim.AutoCloseAt]||record.entry.claims[TaskClaim.WindowEnd]):record.entry.claims[AppointmentClaim.End]
    await engine.createTask({id,subjectId:this.options.subjectIdentifier,title:`${record.entry.resourceType} reminder`,channels:['push'],status:'active',...(dueAt?{dueAt}:{}),metadata:{
      focus:record.entry.reference,'scope-key':this.options.scopeKey,'generation-id':this.options.generationId,'resource-revision':String(record.revision),owner:this.options.recipientActorIdentifier,
    }})
    await engine.scheduleTask({taskId:id,scheduledFor:record.remindAt})
  }
  private notice(record:PortalCareStoredResource,id:string,text:string):PortalCareNotification{
    const {scopeKey,subjectIdentifier,generationId,expiresAt}=this.options,occurredAt=new Date(this.now()).toISOString()
    const parent=buildSubjectCommunicationGroupReference(subjectIdentifier)
    const draft=createCommMsgExtendedDraft({messageId:id,thid:`${id}-request`,subject:subjectIdentifier,sender:this.options.actorIdentifier,sent:occurredAt,status:'completed',category:CommunicationCategoryCodes.Notification.claim,claims:{
      [CommunicationClaim.Identifier]:id,[CommunicationClaim.Subject]:subjectIdentifier,[CommunicationClaim.Recipient]:this.options.recipientActorIdentifier,
      [CommunicationClaim.ContentReference]:record.entry.reference,[CommunicationClaim.Text]:text,[CommunicationClaim.PartOf]:parent,
    }})
    return {id,scopeKey,subjectIdentifier,generationId,expiresAt,kind:'care',resourceReference:record.entry.reference,occurredAt,communication:{...draft.message,pthid:parent}}
  }
}

/** Shared operation boundary; callers supply the already authorized provider, never browser authority flags. */
export async function executePortalCareOperation(provider:PortalCareVaultProvider,input:PortalCareOperation):Promise<PortalCareOperationResult>{
  if(!input||typeof input!=='object'||Array.isArray(input))throw new TypeError('care_operation_invalid')
  const allowed:Record<string,readonly string[]>={search:['kind','resourceType'],save:['kind','entry','mode','options'],encounter:['kind','mutation'],notifications:['kind'],acknowledge:['kind','id'],tick:['kind']}
  if(!allowed[input.kind]||Object.keys(input).some(key=>!allowed[input.kind].includes(key)))throw new TypeError('care_operation_invalid')
  if(input.kind==='search')return {kind:'resources',resources:await provider.search(input.resourceType)}
  if(input.kind==='encounter')return {kind:'resources',resources:await provider.mutateEncounter(input.mutation)}
  if(input.kind==='save'){
    if(input.options&&(Object.keys(input.options).some(key=>!['expectedRevision','remindAt'].includes(key))
      ||(input.options.expectedRevision!==undefined&&(!Number.isInteger(input.options.expectedRevision)||input.options.expectedRevision<1))))throw new TypeError('care_mutation_invalid')
    const record=await provider.save(input.entry,input.mode,input.options)
    return {kind:'resources',resources:await provider.search(record.entry.resourceType as PortalCareResourceType)}
  }
  if(input.kind==='notifications'){await provider.dispatchDue();return {kind:'notifications',notifications:await provider.notifications()}}
  if(input.kind==='acknowledge'){await provider.acknowledge(input.id);return {kind:'acknowledged'}}
  if(input.kind==='tick')return {kind:'tick',dispatched:await provider.dispatchDue()}
  throw new TypeError('care_operation_invalid')
}

/** Transaction-local unit of work, not a second backing store. All vault reads precede flush. */
class BufferedVaultTaskRepository implements TaskRepository {
  private readonly rows:Map<string,TaskRecord>
  private readonly pending=new Set<string>()
  constructor(rows:readonly TaskRecord[],private readonly vault:IVaultRepository,private readonly collection:string){this.rows=new Map(rows.map(row=>[row.id,structuredClone(row)]))}
  async save(task:TaskRecord){this.rows.set(task.id,structuredClone(task));this.pending.add(task.id);return structuredClone(task)}
  async getById(id:string){const row=this.rows.get(id);return row?structuredClone(row):undefined}
  async list(query:ListTasksQuery={}){return [...this.rows.values()].filter(row=>(!query.subjectId||row.subjectId===query.subjectId)&&(!query.status||row.status===query.status)).map(row=>structuredClone(row))}
  async delete(id:string){this.rows.delete(id);this.pending.add(id)}
  async flush(){for(const id of this.pending){const row=this.rows.get(id);if(row)await this.vault.put(this.collection,row);else await this.vault.delete(this.collection,id)}}
}
function hash(value:string){return createHash('sha256').update(value).digest('hex')}
function referenceIdentity(value:string){return value.trim().replace(/^(?:Patient|Organization)\//u,'')}
function resourceTypeOf(reference:string){const type=reference.split('/')[0];assertResourceType(type);return type}
function assertResourceType(value:unknown):asserts value is PortalCareResourceType{if(!['Appointment','Encounter','EncounterHistory','Task'].includes(String(value)))throw new TypeError('care_resource_type_invalid')}
function terminal(entry:FlatClaimResourceEntry){return ['cancelled','completed','fulfilled','finished','entered-in-error'].includes(entry.claims[`${entry.resourceType}.status`]||'')}
function equal(a:FlatClaimResourceEntry,b:FlatClaimResourceEntry){return a.reference===b.reference&&JSON.stringify(Object.entries(a.claims).sort())===JSON.stringify(Object.entries(b.claims).sort())}
