// Flow contract: one authorized IVault transaction persists an emergency ServiceRequest, its triage Task and optional literal Communication; restart/retry, denied authority, foreign subjects and injected partial writes cannot create duplicates or partial graphs, and existing Encounter transactions retain their own guard.
import test from 'node:test'
import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import {PortalCareVaultProvider,executePortalCareOperation} from '../dist/portal-care-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {CommunicationClaim as C,ServiceRequestClaim as S,EncounterClaim as E} from 'fhir-data-utils-ts/claims'
import {TaskClaim as T} from 'sos-data-utils-ts/task-artifact-schema'
const require=createRequire(import.meta.url)

const text='  Synthetic message, caf\u00e9\n\u6c34\n  '
function fixture(extra={}){
 const now=Date.UTC(2030,0,1)
 const store=new TransactionalMemoryVaultRepository()
 const context={store,scopeKey:safe.tenantId,subjectIdentifier:`urn:uuid:${safe.resourceUuid}`,generationId:safe.resourceUuid,actorIdentifier:safe.didWeb,recipientActorIdentifier:safe.didWeb,expiresAt:now+60_000,communicationsCollection:'emergency-contract-communications',assertAccess:async()=>{},now:()=>now,...extra}
 const input={
  intake:{idempotencyKey:'emergency-request-one',serviceRequestEntryId:'request-one',triageTaskEntryId:'triage-one',subjectReference:`Patient/${safe.resourceUuid}`,requesterReference:'RelatedPerson/requester-one',targetServiceReference:'HealthcareService/service-one',triageOwnerReference:'Group/triage-one',jurisdiction:safe.countryIso2,receivedAt:new Date(now).toISOString(),communicationThreadId:'thread-one'},
  serviceRequestIdentifier:`urn:uuid:${safe.resourceUuid}`,triageTaskIdentifier:'urn:uuid:00000000-0000-4000-8000-000000000012',
  assistanceCode:{system:'https://example.invalid/fhir/CodeSystem/assistance',code:'urgent-care'},
  patientMessage:{entryId:'patient-message-one',identifier:'urn:uuid:00000000-0000-4000-8000-000000000013',text},
 }
 return {store,context,input,provider:new PortalCareVaultProvider(context)}
}

test('persists and reopens the actual ServiceRequest/Task/Communication graph with exact body and subject equivalence',async()=>{
 const f=fixture()
 const result=await executePortalCareOperation(f.provider,{kind:'emergency',request:f.input})
 assert.equal(result.kind,'resources')
 const reopened=new PortalCareVaultProvider(f.context)
 const requests=await reopened.search('ServiceRequest'),tasks=await reopened.search('Task'),messages=await reopened.search('Communication')
 assert.equal(requests.length,1);assert.equal(tasks.length,1);assert.equal(messages.length,1)
 assert.equal(requests[0].entry.claims[S.Subject],f.input.intake.subjectReference)
 assert.equal(tasks[0].entry.claims[T.Focus],requests[0].entry.reference)
 assert.equal(tasks[0].entry.claims[T.Owner],f.input.intake.triageOwnerReference)
 assert.equal(messages[0].entry.claims[C.ContentString],text)
 assert.equal(messages[0].entry.claims[C.BasedOn],requests[0].entry.reference)
 assert.equal(messages[0].entry.claims[C.Sender],f.input.intake.requesterReference)
 assert.equal(messages[0].entry.claims[C.Recipient],f.input.intake.targetServiceReference)
 assert.deepEqual(await reopened.search('Encounter'),[])
})

test('concurrent retries are stable and changing the message under the same operation fails without overwrite',async()=>{
 const f=fixture()
 await Promise.all([f.provider.requestEmergency(f.input),f.provider.requestEmergency(f.input)])
 await assert.rejects(f.provider.requestEmergency({...f.input,patientMessage:{...f.input.patientMessage,text:'Changed request'}}),/idempotency_conflict/)
 assert.equal((await f.provider.search('ServiceRequest')).length,1)
 assert.equal((await f.provider.search('Task')).length,1)
 assert.equal((await f.provider.search('Communication'))[0].entry.claims[C.ContentString],text)
})

test('a real write failure rolls back the entire graph and operation receipt, allowing the unchanged retry',async()=>{
 const f=fixture(),original=f.store.runTransaction.bind(f.store)
 let injected=false
 f.store.runTransaction=operation=>original(transaction=>operation({...transaction,put:async(collection,record)=>{
  const result=await transaction.put(collection,record)
  if(!injected&&record.entry?.resourceType==='Communication'){injected=true;throw new Error('injected_message_write')}
  return result
 }}))
 await assert.rejects(f.provider.requestEmergency(f.input),/injected_message_write/)
 assert.deepEqual(await f.store.query(f.provider.collectionNames.resources,{}),[])
 assert.deepEqual(await f.store.query(`${f.provider.collectionNames.resources}_operations`,{}),[])
 await f.provider.requestEmergency(f.input)
 assert.equal((await f.provider.search('Communication')).length,1)
})

test('existing access/resource callbacks and exact subject binding reject before any graph is committed',async()=>{
 const denied=fixture({assertAccess:async(_transaction,action,type)=>{if(action==='write'&&type==='Communication')throw new Error('care_write_forbidden')}})
 await assert.rejects(denied.provider.requestEmergency(denied.input),/forbidden/)
 assert.deepEqual(await denied.store.query(denied.provider.collectionNames.resources,{}),[])
 const foreign=fixture()
 await assert.rejects(foreign.provider.requestEmergency({...foreign.input,intake:{...foreign.input.intake,subjectReference:'Patient/foreign-one'}}),/subject_mismatch/)
 assert.deepEqual(await foreign.store.query(foreign.provider.collectionNames.resources,{}),[])
 const route=fixture({assertResourceAccess:async(_transaction,_action,entry)=>{if(entry.resourceType==='ServiceRequest'&&entry.claims[S.Performer]!=='HealthcareService/service-one')throw new Error('care_service_forbidden')}})
 await assert.rejects(route.provider.requestEmergency({...route.input,intake:{...route.input.intake,targetServiceReference:'HealthcareService/foreign-one'}}),/forbidden/)
 assert.deepEqual(await route.store.query(route.provider.collectionNames.resources,{}),[])
})

test('the old Encounter companion guard still rejects a Task focused on a ServiceRequest',async()=>{
 const f=fixture()
 const encounter={entryId:'encounter-one',reference:'Encounter/encounter-one',resourceType:'Encounter',claims:{[E.Subject]:f.context.subjectIdentifier,[E.Status]:'planned',[E.ServiceType]:'HealthcareService/service-one'}}
 const task={entryId:'triage-one',reference:'Task/triage-one',resourceType:'Task',claims:{[T.For]:f.context.subjectIdentifier,[T.BasedOn]:encounter.reference,[T.Focus]:'ServiceRequest/request-one',[T.Status]:'requested'}}
 await assert.rejects(f.provider.mutateEncounter({operationId:'old-guard-one',encounterReference:encounter.reference,create:encounter,relatedTask:{entry:task}}),/encounter_task_invalid/)
 assert.deepEqual(await f.provider.search('Encounter'),[])
})

test('an existing authorized Encounter is retained unchanged and a missing link cannot be fabricated',async()=>{
 const f=fixture()
 const encounter={entryId:'existing-one',reference:'Encounter/existing-one',resourceType:'Encounter',claims:{[E.Subject]:f.context.subjectIdentifier,[E.Status]:'planned',[E.ServiceType]:'HealthcareService/service-one'}}
 await f.provider.seed([encounter])
 const original=await f.provider.search('Encounter')
 await f.provider.requestEmergency({...f.input,encounterReference:encounter.reference})
 assert.equal((await f.provider.search('ServiceRequest'))[0].entry.claims[S.Encounter],encounter.reference)
 assert.deepEqual(await f.provider.search('Encounter'),original)
 await assert.rejects(f.provider.requestEmergency({...f.input,intake:{...f.input.intake,idempotencyKey:'missing-link-one'},encounterReference:'Encounter/missing-one'}),/encounter_not_found/)
 assert.deepEqual(await f.provider.search('Encounter'),original)
})

function plannedEncounter(f,extra={}){
 return {entryId:'planned-emergency-one',reference:'Encounter/planned-emergency-one',resourceType:'Encounter',claims:{[E.Subject]:f.context.subjectIdentifier,[E.Status]:'planned',[E.ServiceType]:f.input.intake.targetServiceReference,[E.ServiceProvider]:`Organization/${safe.resourceUuid}`,[E.Class]:'http://terminology.hl7.org/CodeSystem/v3-ActCode|AMB',...extra}}
}

test('creates a planned Encounter with the whole emergency graph in one read-before-write transaction',async()=>{
 const f=fixture(),run=f.store.runTransaction.bind(f.store)
 f.store.runTransaction=operation=>run(transaction=>{let wrote=false;return operation({...transaction,
  get:async(...args)=>{assert.equal(wrote,false,'durable transaction read after write');return transaction.get(...args)},
  query:async(...args)=>{assert.equal(wrote,false,'durable transaction query after write');return transaction.query(...args)},
  put:async(...args)=>{wrote=true;return transaction.put(...args)},
 })})
 const planned=plannedEncounter(f),result=await f.provider.requestEmergency({...f.input,plannedEncounter:planned})
 assert.equal(result.length,4)
 assert.deepEqual(result.find(row=>row.entry.resourceType==='Encounter').entry,planned)
 assert.equal(result.find(row=>row.entry.resourceType==='ServiceRequest').entry.claims[S.Encounter],planned.reference)
 assert.equal(result.find(row=>row.entry.resourceType==='Task').entry.claims[T.Focus],'ServiceRequest/request-one')
 assert.equal((await f.provider.notifications()).length,1)
 const another={...f.input,intake:{...f.input.intake,idempotencyKey:'another-operation',serviceRequestEntryId:'another-request',triageTaskEntryId:'another-triage'},patientMessage:{...f.input.patientMessage,entryId:'another-message'}}
 assert.equal((await f.provider.requestEmergency(another)).length,3)
 assert.deepEqual(await f.provider.requestEmergency({...f.input,plannedEncounter:planned}),result)
})

test('same semantic operation keeps the first timestamps across concurrent and restarted server-clock retries',async()=>{
 const f=fixture(),input={...f.input,plannedEncounter:plannedEncounter(f)}
 const retry={...input,intake:{...input.intake,receivedAt:new Date(Date.parse(input.intake.receivedAt)+5000).toISOString()}}
 const [first,second]=await Promise.all([f.provider.requestEmergency(input),f.provider.requestEmergency(retry)])
 assert.deepEqual(second,first)
 const restarted=new PortalCareVaultProvider({...f.context,now:()=>Date.parse(retry.intake.receivedAt)})
 assert.deepEqual(await restarted.requestEmergency(retry),first)
 assert.equal(first.find(row=>row.entry.resourceType==='ServiceRequest').entry.claims[S.AuthoredOn],input.intake.receivedAt)
 assert.equal(first.find(row=>row.entry.resourceType==='Communication').entry.claims[C.Sent],input.intake.receivedAt)
 assert.equal((await f.provider.notifications()).length,1)
})

test('a failed planned Encounter write rolls back every resource, notice and operation receipt',async()=>{
 const f=fixture(),run=f.store.runTransaction.bind(f.store);let failed=false
 f.store.runTransaction=operation=>run(transaction=>operation({...transaction,put:async(collection,record)=>{
  const result=await transaction.put(collection,record)
  if(!failed&&record.entry?.resourceType==='Encounter'){failed=true;throw new Error('planned_encounter_write_failed')}
  return result
 }}))
 const input={...f.input,plannedEncounter:plannedEncounter(f)}
 await assert.rejects(f.provider.requestEmergency(input),/planned_encounter_write_failed/)
 for(const collection of [f.provider.collectionNames.resources,f.provider.collectionNames.communications,`${f.provider.collectionNames.resources}_operations`])assert.deepEqual(await f.store.query(collection,{}),[])
 assert.equal((await f.provider.requestEmergency(input)).length,4)
})

test('planned Encounter identity, subject, lifecycle and service cannot diverge from the request',async()=>{
 for(const mutate of [
  (f,input)=>({...input,plannedEncounter:plannedEncounter(f,{[E.Status]:'in-progress'})}),
  (f,input)=>({...input,plannedEncounter:plannedEncounter(f,{[E.Subject]:'urn:uuid:00000000-0000-4000-8000-000000000099'})}),
  (f,input)=>({...input,plannedEncounter:plannedEncounter(f,{[E.ServiceType]:'HealthcareService/foreign-one'})}),
  (f,input)=>({...input,plannedEncounter:plannedEncounter(f),encounterReference:'Encounter/different-one'}),
 ]){
  const f=fixture();await assert.rejects(f.provider.requestEmergency(mutate(f,f.input)),/encounter|subject_mismatch/)
  assert.deepEqual(await f.store.query(f.provider.collectionNames.resources,{}),[])
 }
})

test('planned Encounter permission is checked before commit and retry still binds current actor and message',async()=>{
 const denied=fixture({assertResourceAccess:async(_transaction,action,entry)=>{if(action==='write'&&entry.resourceType==='Encounter')throw new Error('planned_encounter_forbidden')}})
 await assert.rejects(denied.provider.requestEmergency({...denied.input,plannedEncounter:plannedEncounter(denied)}),/planned_encounter_forbidden/)
 assert.deepEqual(await denied.store.query(denied.provider.collectionNames.resources,{}),[])
 const providerBound=fixture({assertResourceAccess:async(_transaction,_action,entry)=>{if(entry.resourceType==='Encounter'&&entry.claims[E.ServiceProvider]!==`Organization/${safe.resourceUuid}`)throw new Error('planned_provider_forbidden')}})
 await assert.rejects(providerBound.provider.requestEmergency({...providerBound.input,plannedEncounter:plannedEncounter(providerBound,{[E.ServiceProvider]:'Organization/foreign-one'})}),/planned_provider_forbidden/)
 assert.deepEqual(await providerBound.store.query(providerBound.provider.collectionNames.resources,{}),[])
 const f=fixture(),input={...f.input,plannedEncounter:plannedEncounter(f)};await f.provider.requestEmergency(input)
 const foreign=new PortalCareVaultProvider({...f.context,actorIdentifier:'did:web:example.invalid:other-actor'})
 await assert.rejects(foreign.requestEmergency(input),/idempotency_conflict/)
 await assert.rejects(f.provider.requestEmergency({...input,patientMessage:{...input.patientMessage,text:'Changed'}}),/idempotency_conflict/)
 await assert.rejects(f.provider.requestEmergency({...input,plannedEncounter:plannedEncounter(f,{[E.PeriodStart]:'2030-01-01T11:00:00.000Z'})}),/idempotency_conflict/)
 await assert.rejects(f.provider.requestEmergency({...input,assistanceCode:{...input.assistanceCode,code:'different-care'}}),/idempotency_conflict/)
 assert.equal((await f.provider.search('Communication'))[0].entry.claims[C.ContentString],text)
})

test('public emergency consumer types retain the Core contract and precise optional planned Encounter',()=>{
 execFileSync(process.execPath,[require.resolve('typescript/bin/tsc'),'--noEmit','--strict','--skipLibCheck','--target','ES2023','--module','NodeNext','--moduleResolution','NodeNext',fileURLToPath(new URL('./fixtures/portal-emergency-public-consumer.ts',import.meta.url))],{stdio:'pipe'})
})
