// Flow contract: authorized Encounter changes atomically commit both stages, linked assistance Tasks, immutable history, notices and an idempotency receipt; failure, stale revisions, revocation and foreign subjects never leave partial writes.
import test from 'node:test'
import assert from 'node:assert/strict'
import {PortalCareVaultProvider} from '../dist/portal-care-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {FHIR_ENCOUNTER_TRANSFER_TEST_DATA as f} from 'fhir-data-utils-ts/data'
import {EncounterClaim as E,EncounterStatusR5 as S} from 'fhir-data-utils-ts/claims'
import {buildFlatClaimResourceEntry} from 'fhir-data-utils-ts/flat-claim-resource-graph'
import {portalCareEntryFromView} from 'sos-data-utils-ts/portal-care-view'
import {TaskClaim,TaskStatus} from 'sos-data-utils-ts/task-artifact-schema'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'

const entry=which=>buildFlatClaimResourceEntry({resourceType:'Encounter',entryId:which.id,claims:{
  [E.Identifier]:which.identifier,[E.Subject]:f.subjectReference,[E.Status]:S.Planned,
  [E.Class]:`${f.class.system}|${f.class.code}`,[E.ServiceProvider]:f.senderReference,[E.ServiceType]:which.serviceReference,[E.Location]:which.locationReference,
}})
function setup(overrides={}){
  const store=new TransactionalMemoryVaultRepository();let deny=false
  const provider=new PortalCareVaultProvider({store,scopeKey:examples.tenantId,subjectIdentifier:f.subjectReference,generationId:examples.resourceUuid,
    actorIdentifier:f.senderReference,recipientActorIdentifier:f.subjectReference,expiresAt:Date.parse(f.occurredAt)+86_400_000,
    communicationsCollection:'encounter-contract-notices',now:()=>Date.parse(f.occurredAt),assertAccess:async()=>{if(deny)throw Object.assign(new Error('forbidden'),{status:403})},...overrides,
  })
  return {store,provider,revoke:()=>{deny=true}}
}
const create={operationId:f.source.id,encounterReference:f.source.reference,create:entry(f.source)}
const start={operationId:f.sourceHistory.id,encounterReference:f.source.reference,expectedRevision:1,status:S.InProgress}
const transfer={operationId:f.destinationHistory.id,encounterReference:f.source.reference,expectedRevision:2,destination:entry(f.destination),sourceOutcome:S.OnHold}

test('non-string operation identities fail before creation',async()=>{
  const {provider}=setup()
  // Numeric input is the malformed wire value under test.
  await assert.rejects(provider.mutateEncounter({...create,operationId:42}),/invalid/)
  assert.equal((await provider.search('Encounter')).length,0)
})
test('resource policy filters another provider from reads and rejects its writes',async()=>{
  const {provider}=setup({assertResourceAccess:async(_transaction,_action,resource)=>{
    if(resource.claims[E.ServiceProvider]!==f.senderReference)throw Object.assign(new Error('provider_forbidden'),{status:403})
  }})
  const own=entry(f.source),foreign={...entry(f.destination),claims:{...entry(f.destination).claims,[E.ServiceProvider]:f.indexRecipientReference}}
  await provider.seed([own,foreign])
  assert.equal((await provider.search('Encounter')).length,1)
  await assert.rejects(provider.save(foreign,'update'),/provider_forbidden/)
})

test('restart-safe creation, start and transfer retain one identity, both stages and immutable histories',async()=>{
  const {provider}=setup()
  await provider.mutateEncounter(create);await provider.mutateEncounter(create)
  await provider.mutateEncounter(start);await provider.mutateEncounter(start)
  const before=await provider.search('EncounterHistory')
  await provider.mutateEncounter(transfer);await provider.mutateEncounter(transfer)
  const encounters=await provider.search('Encounter')
  assert.equal(encounters.length,2)
  assert.equal(encounters.find(x=>x.entry.reference===f.source.reference).entry.claims[E.Status],S.OnHold)
  assert.equal(encounters.find(x=>x.entry.reference===f.destination.reference).entry.claims[E.Status],S.InProgress)
  const history=await provider.search('EncounterHistory')
  assert.equal(history.length,3);assert.ok(history.some(x=>JSON.stringify(x)===JSON.stringify(before[0])))
  assert.equal((await provider.notifications()).length,3)
})
test('failure after the first write rolls back stages, history, notifications and receipt; identical retry succeeds',async()=>{
  const {provider,store}=setup();await provider.mutateEncounter(create);await provider.mutateEncounter(start)
  const before=[await provider.search('Encounter'),await provider.search('EncounterHistory'),await provider.notifications()]
  const run=store.runTransaction.bind(store);let fail=true
  store.runTransaction=callback=>run(async transaction=>{let writes=0;return callback(new Proxy(transaction,{get(target,key){
    if(key==='put')return async(...args)=>{if(fail&&++writes===2){fail=false;throw new Error('injected_after_first_write')}return target.put(...args)}
    const value=target[key];return typeof value==='function'?value.bind(target):value
  }}))})
  await assert.rejects(provider.mutateEncounter(transfer),/injected_after_first_write/)
  assert.deepEqual([await provider.search('Encounter'),await provider.search('EncounterHistory'),await provider.notifications()],before)
  await provider.mutateEncounter(transfer);assert.equal((await provider.search('Encounter')).length,2)
})
test('changed replay payload, stale revision, malformed input and revoked sessions are rejected',async()=>{
  const f=setup();await f.provider.mutateEncounter(create);await f.provider.mutateEncounter(start)
  await assert.rejects(f.provider.mutateEncounter({...start,status:S.Completed}),/idempotency/)
  await assert.rejects(f.provider.mutateEncounter({...transfer,expectedRevision:1}),/revision/)
  await assert.rejects(f.provider.mutateEncounter({...transfer,actorIdentifier:examples.didWeb}),/invalid/)
  f.revoke();await assert.rejects(f.provider.mutateEncounter(start),/forbidden/)
})


test('assistance Task and Encounter transition commit together with retry-safe history and notices',async()=>{
  const {provider,store}=setup()
  const task=portalCareEntryFromView({kind:'task',id:examples.resourceUuid,title:'Assistance',status:TaskStatus.Requested,focusReference:f.source.serviceReference,basedOnReference:f.source.reference},f.subjectReference)
  const initial={...create,relatedTask:{entry:task}}
  await provider.mutateEncounter(initial);await provider.mutateEncounter(initial)
  assert.equal((await provider.search('Task'))[0].revision,1)
  assert.equal((await provider.notifications()).length,2)
  const next={...start,relatedTask:{entry:{...task,claims:{...task.claims,[TaskClaim.Status]:TaskStatus.InProgress}},expectedRevision:1}}
  const before=[await provider.search('Encounter'),await provider.search('Task'),await provider.search('EncounterHistory'),await provider.notifications()]
  const run=store.runTransaction.bind(store);let fail=true
  store.runTransaction=callback=>run(async transaction=>{let writes=0;return callback(new Proxy(transaction,{get(target,key){
    if(key==='put')return async(...args)=>{if(fail&&++writes===3){fail=false;throw new Error('injected_assistance_write')}return target.put(...args)}
    const value=target[key];return typeof value==='function'?value.bind(target):value
  }}))})
  await assert.rejects(provider.mutateEncounter(next),/injected_assistance_write/)
  assert.deepEqual([await provider.search('Encounter'),await provider.search('Task'),await provider.search('EncounterHistory'),await provider.notifications()],before)
  await provider.mutateEncounter(next);await provider.mutateEncounter(next)
  assert.equal((await provider.search('Task'))[0].entry.claims[TaskClaim.Status],TaskStatus.InProgress)
  assert.equal((await provider.search('EncounterHistory')).length,1)
  assert.equal((await provider.notifications()).length,4)
})

test('companion Tasks require the exact Encounter and their own write permission before any save',async()=>{
  const {provider}=setup({assertAccess:async(_tx,action,type)=>{if(action==='write'&&type==='Task')throw new Error('task_forbidden')}})
  const task=portalCareEntryFromView({kind:'task',id:examples.resourceUuid,title:'Assistance',status:TaskStatus.Requested,focusReference:f.source.serviceReference,basedOnReference:f.source.reference},f.subjectReference)
  await assert.rejects(provider.mutateEncounter({...create,relatedTask:{entry:task}}),/task_forbidden/)
  assert.equal((await provider.search('Encounter')).length,0)
  const open=setup().provider
  await assert.rejects(open.mutateEncounter({...create,relatedTask:{entry:{...task,claims:{...task.claims,[TaskClaim.BasedOn]:f.destination.reference}}}}),/invalid/)
  assert.equal((await open.search('Encounter')).length,0)
})

test('a hidden foreign-provider Encounter cannot be overwritten by recreating its reference',async()=>{
  const {provider,store}=setup({assertResourceAccess:async(_tx,_action,resource)=>{
    if(resource.claims[E.ServiceProvider]!==f.senderReference)throw Object.assign(new Error('provider_forbidden'),{status:403})
  }})
  const foreign={...entry(f.source),claims:{...entry(f.source).claims,[E.ServiceProvider]:f.indexRecipientReference}}
  await provider.seed([foreign])
  await assert.rejects(provider.mutateEncounter(create),/conflict/)
  const rows=await store.query(provider.collectionNames.resources,{})
  assert.deepEqual(rows[0].entry,foreign)
})

test('generic updates cannot replace a hidden foreign-provider resource with an own-provider payload',async()=>{
  const {provider,store}=setup({assertResourceAccess:async(_tx,_action,resource)=>{
    if(resource.claims[E.ServiceProvider]!==f.senderReference)throw Object.assign(new Error('provider_forbidden'),{status:403})
  }})
  const foreign={...entry(f.source),claims:{...entry(f.source).claims,[E.ServiceProvider]:f.indexRecipientReference}}
  await provider.seed([foreign])
  await assert.rejects(provider.save(entry(f.source),'update'),/provider_forbidden/)
  assert.deepEqual((await store.query(provider.collectionNames.resources,{}))[0].entry,foreign)
})

test('one atomic assistance operation enqueues one wake-up for both persisted notices',async()=>{
 let wakeups=0
 const {provider}=setup({enqueueNotice:async()=>{wakeups++}})
 const task=portalCareEntryFromView({kind:'task',id:examples.resourceUuid,title:'Assistance',status:TaskStatus.Requested,focusReference:f.source.serviceReference,basedOnReference:f.source.reference},f.subjectReference)
 await provider.mutateEncounter({...create,relatedTask:{entry:task}})
 assert.equal((await provider.notifications()).length,2)
 assert.equal(wakeups,1)
})
