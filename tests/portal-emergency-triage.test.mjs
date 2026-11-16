// Flow contract: responders transition the persisted ServiceRequest-focused triage Task through the shared Core lifecycle; current ownership/revisions, linked Encounter history and retry receipts remain atomic, and generic saves cannot bypass that lifecycle.
import test from 'node:test'
import assert from 'node:assert/strict'
import {PortalCareVaultProvider} from '../dist/portal-care-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {createPortalDemoEncounterServices} from 'sos-data-utils-ts/portal-demo-encounter-services'
import {TaskClaim as T} from 'sos-data-utils-ts/task-artifact-schema'
import {EncounterClaim as E,ServiceRequestClaim as S,CommunicationClaim as C} from 'fhir-data-utils-ts/claims'

const responder='PractitionerRole/responder-one'
async function fixture(linked=false){
 const now=Date.UTC(2030,0,1),subject=`urn:uuid:${safe.resourceUuid}`
 const store=new TransactionalMemoryVaultRepository()
 const provider=new PortalCareVaultProvider({store,scopeKey:safe.tenantId,subjectIdentifier:subject,generationId:safe.resourceUuid,actorIdentifier:safe.didWeb,recipientActorIdentifier:safe.didWeb,expiresAt:now+60_000,communicationsCollection:'emergency-triage-notices',assertAccess:async()=>{},now:()=>now})
 if(linked)await provider.seed([{entryId:'existing-one',reference:'Encounter/existing-one',resourceType:'Encounter',claims:{[E.Subject]:subject,[E.Status]:'planned',[E.ServiceType]:'HealthcareService/service-one',[E.ServiceProvider]:`Organization/${safe.resourceUuid}`,[E.Class]:createPortalDemoEncounterServices(`Organization/${safe.resourceUuid}`)[0].classToken}}])
 await provider.requestEmergency({intake:{idempotencyKey:'request-one',serviceRequestEntryId:'request-one',triageTaskEntryId:'triage-one',subjectReference:`Patient/${safe.resourceUuid}`,requesterReference:'RelatedPerson/requester-one',targetServiceReference:'HealthcareService/service-one',triageOwnerReference:'Group/triage-one',jurisdiction:safe.countryIso2,receivedAt:new Date(now).toISOString(),communicationThreadId:'thread-one'},serviceRequestIdentifier:'request-one',triageTaskIdentifier:'triage-one',assistanceCode:{system:'https://example.invalid/codes',code:'urgent-care'},patientMessage:{entryId:'message-one',identifier:'message-one',text:'  Synthetic request\n  '},...(linked?{encounterReference:'Encounter/existing-one'}:{})})
 const command=(action,expectedRevision,extra={})=>({operationId:`triage-${action}`,taskReference:'Task/triage-one',expectedRevision,action,responderReference:responder,...extra})
 return {provider,store,command}
}

test('uses the Core triage lifecycle without changing the ServiceRequest focus or message',async()=>{
 const f=await fixture(),request=(await f.provider.search('ServiceRequest'))[0],message=(await f.provider.search('Communication'))[0]
 await f.provider.transitionEmergencyTriage(f.command('acknowledge',1))
 let task=(await f.provider.search('Task'))[0]
 assert.equal(task.entry.claims[T.Status],'accepted');assert.equal(task.entry.claims[T.Owner],responder)
 await f.provider.transitionEmergencyTriage(f.command('start',2))
 await f.provider.transitionEmergencyTriage(f.command('complete',3))
 task=(await f.provider.search('Task'))[0]
 assert.equal(task.entry.claims[T.Status],'completed');assert.equal(task.entry.claims[T.Focus],request.entry.reference)
 assert.deepEqual((await f.provider.search('ServiceRequest'))[0],request)
 assert.deepEqual((await f.provider.search('Communication'))[0],message)
 assert.deepEqual(await f.provider.search('Encounter'),[])
})

test('generic saves cannot bypass or downgrade a persisted emergency triage profile',async()=>{
 const f=await fixture(),original=(await f.provider.search('Task'))[0]
 for(const claims of [{...original.entry.claims,[T.Status]:'completed'},{...original.entry.claims,[T.Status]:'completed',[T.Code]:'ordinary-task'}]){
  await assert.rejects(f.provider.save({...original.entry,claims},'update',{expectedRevision:1}),/care_emergency_write_requires_transaction/)
 }
 assert.deepEqual((await f.provider.search('Task'))[0],original)
})

test('a foreign responder and stale revision cannot mutate the accepted Task or its retry receipt',async()=>{
 const f=await fixture();await f.provider.transitionEmergencyTriage(f.command('acknowledge',1))
 const original=(await f.provider.search('Task'))[0]
 await assert.rejects(f.provider.transitionEmergencyTriage(f.command('start',2,{responderReference:'PractitionerRole/foreign-one'})),/responder_owner_required/)
 await assert.rejects(f.provider.transitionEmergencyTriage(f.command('start',1)),/revision_conflict/)
 assert.deepEqual((await f.provider.search('Task'))[0],original)
})

test('linked Encounter, history and Task roll back together and an exact retry writes each milestone once',async()=>{
 const f=await fixture(true);await f.provider.transitionEmergencyTriage(f.command('acknowledge',1))
 const originalTask=(await f.provider.search('Task'))[0],originalEncounter=(await f.provider.search('Encounter'))[0]
 const run=f.store.runTransaction.bind(f.store);let injected=false
 f.store.runTransaction=operation=>run(transaction=>operation({...transaction,put:async(collection,record)=>{
  const result=await transaction.put(collection,record)
  if(!injected&&record.entry?.resourceType==='EncounterHistory'){injected=true;throw new Error('injected_triage_history_write')}
  return result
 }}))
 const command=f.command('start',2,{encounterExpectedRevision:1})
 await assert.rejects(f.provider.transitionEmergencyTriage(command),/injected_triage_history_write/)
 assert.deepEqual((await f.provider.search('Task'))[0],originalTask)
 assert.deepEqual((await f.provider.search('Encounter'))[0],originalEncounter)
 assert.deepEqual(await f.provider.search('EncounterHistory'),[])
 await f.provider.transitionEmergencyTriage(command);await f.provider.transitionEmergencyTriage(command)
 assert.equal((await f.provider.search('Task'))[0].entry.claims[T.Status],'in-progress')
 assert.equal((await f.provider.search('Task'))[0].entry.claims[T.Focus],'ServiceRequest/request-one')
 assert.equal((await f.provider.search('Encounter'))[0].entry.claims[E.Status],'in-progress')
 assert.equal((await f.provider.search('EncounterHistory')).length,1)
 await f.provider.transitionEmergencyTriage(f.command('complete',3,{encounterExpectedRevision:2}))
 assert.equal((await f.provider.search('Encounter'))[0].entry.claims[E.Status],'completed')
 assert.equal((await f.provider.search('EncounterHistory')).length,2)
 assert.equal((await f.provider.search('ServiceRequest'))[0].entry.claims[S.Encounter],'Encounter/existing-one')
 assert.equal((await f.provider.search('Communication'))[0].entry.claims[C.ContentString],'  Synthetic request\n  ')
})
