// Flow contract: the existing task engine and transactional vault persist subject-scoped care resources, reminder jobs and Communications atomically; retries, reset, role denial and concurrent ticks cannot duplicate or leak work.
import assert from 'node:assert/strict'
import test from 'node:test'
import {PortalCareVaultProvider} from '../dist/portal-care-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createPortalDemoCareEntries} from 'sos-data-utils-ts/portal-demo-care-fixtures'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {AppointmentClaim,AppointmentStatus,EncounterClaim,EncounterStatusR5} from 'fhir-data-utils-ts/claims'
import {TaskClaim,TaskStatus} from 'sos-data-utils-ts/task-artifact-schema'

function fixture(overrides={}){
  // A fixed clock allows assertions on due, rescheduled and expired work.
  let now=Date.UTC(2030,0,1)
  const store=overrides.store??new TransactionalMemoryVaultRepository()
  const context={scopeKey:examples.tenantId,subjectIdentifier:examples.didWeb,generationId:examples.resourceUuid,
    actorIdentifier:examples.didWeb,recipientActorIdentifier:examples.didWeb,expiresAt:now+7*86_400_000,
    communicationsCollection:'care-contract-communications',assertAccess:async()=>{},now:()=>now,...overrides,store}
  const provider=new PortalCareVaultProvider(context)
  return {store,context,provider,entries:createPortalDemoCareEntries({subjectReference:context.subjectIdentifier,idPrefix:examples.resourceUuid,now}),
    advance:ms=>{now+=ms},current:()=>now}
}

test('seed, restart and search return persisted independent resources and a task-engine reminder',async()=>{
  const f=fixture()
  await f.provider.seed(f.entries)
  await f.provider.seed(f.entries)
  const reopened=new PortalCareVaultProvider(f.context)
  for(const entry of f.entries)assert.deepEqual((await reopened.search(entry.resourceType)).map(row=>row.entry),[entry])
  const jobs=await f.store.query(f.provider.collectionNames.tasks,{})
  assert.equal(jobs.length,1)
  assert.equal(jobs[0].status,'scheduled')
  assert.equal(jobs[0].metadata.focus,f.entries[2].reference)
  assert.deepEqual(jobs[0].channels,['push'])
})

test('due reminders become durable Communications once across concurrent processors and acknowledgement',async()=>{
  const f=fixture();await f.provider.seed(f.entries)
  assert.equal(await f.provider.dispatchDue(),0)
  f.advance(60_001)
  const counts=await Promise.all([f.provider.dispatchDue(),f.provider.dispatchDue()])
  assert.equal(counts.reduce((a,b)=>a+b,0),1)
  const notices=await f.provider.notifications()
  assert.equal(notices.length,1)
  assert.equal(notices[0].resourceReference,f.entries[2].reference)
  assert.ok(notices[0].communication.body.data.length)
  await f.provider.acknowledge(notices[0].id)
  assert.ok((await new PortalCareVaultProvider(f.context).notifications())[0].readAt)
  assert.equal((await f.store.query(f.provider.collectionNames.tasks,{}))[0].status,'completed')
})

test('create retries and identical edits do not duplicate resources or notifications',async()=>{
  const f=fixture(),entry=f.entries[0]
  await f.provider.save(entry,'create');await f.provider.save(entry,'create')
  assert.equal((await f.provider.search('Appointment')).length,1)
  assert.equal((await f.provider.notifications()).length,1)
  const edited={...entry,claims:{...entry.claims,[AppointmentClaim.Description]:'Changed appointment'}}
  await assert.rejects(f.provider.save(edited,'create'),/conflict/)
  await f.provider.save(edited,'update',{expectedRevision:1})
  await f.provider.save(edited,'update',{expectedRevision:1})
  assert.equal((await f.provider.notifications()).length,2)
  await assert.rejects(f.provider.save(entry,'update',{expectedRevision:1}),/revision/)
})

test('rescheduling and cancellation close old engine jobs before they can notify',async()=>{
  const f=fixture();await f.provider.seed(f.entries)
  const task=f.entries[2]
  const updated={...task,claims:{...task.claims,[TaskClaim.ScheduledAt]:new Date(f.current()+120_000).toISOString()}}
  await f.provider.save(updated,'update')
  f.advance(60_001);assert.equal(await f.provider.dispatchDue(),0)
  await f.provider.save({...updated,claims:{...updated.claims,[TaskClaim.Status]:TaskStatus.Cancelled}},'update')
  f.advance(120_000);assert.equal(await f.provider.dispatchDue(),0)
  const jobs=await f.store.query(f.provider.collectionNames.tasks,{})
  assert.ok(jobs.every(job=>job.status==='cancelled'))
})

test('an Encounter update keeps Appointment and Encounter identities and references distinct',async()=>{
  const f=fixture();await f.provider.seed(f.entries)
  const appointment={...f.entries[0],claims:{...f.entries[0].claims,[AppointmentClaim.Status]:AppointmentStatus.Fulfilled}}
  await f.provider.save(appointment,'update')
  const encounter={...f.entries[1],claims:{...f.entries[1].claims,[EncounterClaim.Status]:EncounterStatusR5.InProgress}}
  await f.provider.save(encounter,'update')
  assert.equal((await f.provider.search('Encounter'))[0].entry.claims[EncounterClaim.Appointment],appointment.reference)
  assert.equal((await f.provider.search('Appointment'))[0].entry.claims[AppointmentClaim.Status],AppointmentStatus.Fulfilled)
})

test('another subject, generation or deployment cannot see resources, jobs or notices',async()=>{
  const f=fixture();await f.provider.seed(f.entries);f.advance(60_001);await f.provider.dispatchDue()
  for(const change of [{subjectIdentifier:examples.didWeb+':other'},{generationId:examples.resourceUuid+'-reset'},{scopeKey:examples.tenantId+'-other'}]){
    const other=new PortalCareVaultProvider({...f.context,...change})
    assert.deepEqual(await other.search('Task'),[])
    assert.deepEqual(await other.notifications(),[])
    assert.equal(await other.dispatchDue(),0)
    await assert.rejects(other.acknowledge((await f.provider.notifications())[0].id),/not_found/)
  }
})

test('expired contexts and rejected BFF permissions fail before reads or mutations',async()=>{
  const f=fixture();await f.provider.seed(f.entries)
  const denied=new PortalCareVaultProvider({...f.context,assertAccess:async(_vault,action)=>{if(action==='write')throw new Error('care_write_forbidden')}})
  assert.equal((await denied.search('Task')).length,1)
  await assert.rejects(denied.save(f.entries[0],'update'),/forbidden/)
  f.advance(8*86_400_000)
  await assert.rejects(f.provider.search('Task'),/expired/)
  await assert.rejects(f.provider.dispatchDue(),/expired/)
})

test('foreign subject claims, nested native FHIR, invalid dates and unsupported resources are rejected',async()=>{
  const f=fixture(),entry=f.entries[0]
  const invalid=[{...entry,claims:{...entry.claims,[AppointmentClaim.Patient]:examples.didWeb+':other'}},
    {...entry,resource:{resourceType:'Appointment'}},
    {...entry,claims:{...entry.claims,[AppointmentClaim.Start]:'invalid-date'}},
    {...entry,resourceType:'Patient'}]
  for(const item of invalid)await assert.rejects(f.provider.save(item,'create'),/care_/)
  assert.deepEqual(await f.provider.search('Appointment'),[])
})

test('failure after the first write rolls back resources, tasks and Communications; retry succeeds',async()=>{
  const f=fixture(),original=f.store.runTransaction.bind(f.store)
  let fail=true
  f.store.runTransaction=operation=>original(transaction=>operation({...transaction,put:async(...args)=>{
    const result=await transaction.put(...args);if(fail){fail=false;throw new Error('injected_after_write')}return result
  }}))
  await assert.rejects(f.provider.save(f.entries[2],'create'),/injected_after_write/)
  assert.deepEqual(await f.provider.search('Task'),[])
  assert.deepEqual(await f.provider.notifications(),[])
  assert.deepEqual(await f.store.query(f.provider.collectionNames.tasks,{}),[])
  await f.provider.save(f.entries[2],'create')
  assert.equal((await f.provider.search('Task')).length,1)
  assert.equal((await f.provider.notifications()).length,1)
})

test('very late reminders are cancelled rather than delivered or reported completed',async()=>{
  const f=fixture();await f.provider.seed(f.entries);f.advance(2*86_400_000)
  assert.equal(await f.provider.dispatchDue(),0)
  assert.deepEqual(await f.provider.notifications(),[])
  assert.equal((await f.store.query(f.provider.collectionNames.tasks,{}))[0].status,'cancelled')
})

test('section-scoped viewers share authorized Encounter data but cannot mutate or read hidden notices',async()=>{
  const f=fixture();await f.provider.seed(f.entries)
  await f.provider.save({...f.entries[1],claims:{...f.entries[1].claims,[EncounterClaim.Status]:EncounterStatusR5.InProgress}},'update')
  await f.provider.save({...f.entries[2],claims:{...f.entries[2].claims,[TaskClaim.Description]:'Updated task'}},'update')
  const readOnly=new PortalCareVaultProvider({...f.context,assertAccess:async(_tx,action)=>{
    if(action==='write')throw Object.assign(new Error('care_write_forbidden'),{status:403})
  }})
  assert.deepEqual(await readOnly.search('Encounter'),await f.provider.search('Encounter'))
  await assert.rejects(readOnly.save(f.entries[1],'update'),/forbidden/)
  const tasksOnly=new PortalCareVaultProvider({...f.context,assertAccess:async(_tx,action,type)=>{
    if(action==='write'||type==='Encounter')throw Object.assign(new Error('care_section_forbidden'),{status:403})
  }})
  assert.equal((await tasksOnly.notifications()).length,1)
  assert.equal((await tasksOnly.notifications())[0].resourceReference,f.entries[2].reference)
  await assert.rejects(tasksOnly.acknowledge((await f.provider.notifications()).find(n=>n.resourceReference===f.entries[1].reference).id),/forbidden/)
})
