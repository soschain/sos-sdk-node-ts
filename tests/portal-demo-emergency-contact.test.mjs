// Flow contract: a call targets an explicitly active card emergency contact independently of controller authority; removal blocks new calls, and terminal events retain the original participant and Encounter identity.
import assert from 'node:assert/strict'
import test from 'node:test'
import {PortalDemoExchange} from '../dist/portal-demo-exchange.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD,SOSCHAIN_PERSONAL_DEMO_STORIES,SoschainPersonalDemoSubjectIds} from 'sos-data-utils-ts/portal-demo-fixtures'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const contact={...SOSCHAIN_PERSONAL_DEMO_STORIES[SoschainPersonalDemoSubjectIds.Animal].contacts[0],subjectId:safe.didWeb,actorIdentifier:safe.firstContactIdentifier}
const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:'soschain',tenantId:'demo-soschain'})
const card={cardNumber:SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD.find(subject=>subject.id===SoschainPersonalDemoSubjectIds.Animal).cardNumber21,generationId:safe.resourceUuid,subjectIdentifier:safe.subjectCardProviders.animalIndexDid,displayName:contact.label,controllerActorIdentifier:safe.didWeb,subjectKind:'animal',sourceSector:'animal-research',expiresAt:Date.now()+60_000,emergencyContacts:[contact]}
const event={version:1,callId:safe.resourceUuid,threadId:safe.didWeb,subjectIdentifier:card.subjectIdentifier,professionalGroupReference:`Group/${safe.resourceUuid}`,callerActorIdentifier:safe.subjectCardProviders.humanIndexDid,recipientActorIdentifier:contact.actorIdentifier,media:['audio'],state:'ringing',occurredAt:new Date().toISOString()}
const professional={actorIdentifier:event.callerActorIdentifier,professionalGroupReference:event.professionalGroupReference}

test('resolves explicit contacts and calls the selected recipient rather than assuming the controller',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await exchange.registerCard(scope,card)
  assert.deepEqual((await exchange.resolveCard(scope,card.cardNumber)).emergencyContacts,[contact])
  await exchange.submitEvent(scope,event,professional)
  assert.equal((await exchange.listEvents(scope,card.subjectIdentifier,{actorIdentifier:contact.actorIdentifier})).length,1)
  assert.deepEqual(await exchange.listEvents(scope,card.subjectIdentifier,{actorIdentifier:card.controllerActorIdentifier}),[])
})

test('does not infer emergency-contact status from controller authority after contacts are removed',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await exchange.registerCard(scope,{...card,emergencyContacts:[]})
  await assert.rejects(exchange.submitEvent(scope,{...event,recipientActorIdentifier:card.controllerActorIdentifier},professional),/identity_mismatch/)
  await assert.rejects(exchange.submitEvent(scope,event,professional),/identity_mismatch/)
})

test('rejects malformed or duplicate active recipients before persisting the directory',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await assert.rejects(exchange.registerCard(scope,{...card,emergencyContacts:[{...contact,actorIdentifier:''}]}),/contact_invalid/)
  await assert.rejects(exchange.registerCard(scope,{...card,emergencyContacts:[contact,contact]}),/contact_invalid/)
  await assert.rejects(exchange.resolveCard(scope,card.cardNumber),/card_not_found/)
})

test('receives calls by recipient identity without selecting or controlling the attended card',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await exchange.registerCard(scope,card)
  await exchange.submitEvent(scope,event,professional)
  const recipient={actorIdentifier:contact.actorIdentifier}
  const incoming=await exchange.listRecipientEvents(scope,recipient)
  assert.equal(incoming.length,1)
  assert.equal(incoming[0].callId,event.callId)
  assert.equal(incoming[0].subjectIdentifier,card.subjectIdentifier)
  assert.equal(incoming[0].recipientActorIdentifier,contact.actorIdentifier)
  assert.deepEqual(await exchange.listRecipientEvents(scope,{actorIdentifier:card.controllerActorIdentifier}),[])
  await exchange.revokeGeneration(scope,card.generationId)
  assert.deepEqual(await exchange.listRecipientEvents(scope,recipient),[])
})

test('atomically lets only one registered recipient session answer and rejects sibling grants or completion',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await exchange.registerCard(scope,card);await exchange.submitEvent(scope,event,professional)
  const first={actorIdentifier:contact.actorIdentifier,deviceKeyId:safe.resourceUuid}
  const second={actorIdentifier:contact.actorIdentifier,deviceKeyId:safe.demoOrganizationUuids.healthCare}
  const received={...event,state:'received'}
  const answers=await Promise.allSettled([exchange.submitEvent(scope,received,first),exchange.submitEvent(scope,received,second)])
  assert.equal(answers.filter(result=>result.status==='fulfilled').length,1)
  assert.match(answers.find(result=>result.status==='rejected').reason.message,/answered_on_another_device/)
  await exchange.submitEvent(scope,received,first)
  await assert.rejects(exchange.submitEvent(scope,received,{actorIdentifier:contact.actorIdentifier}),/answered_on_another_device/)
  await assert.rejects(exchange.submitEvent(scope,{...event,state:'completed'},second),/answered_on_another_device/)
  await exchange.submitEvent(scope,{...event,state:'completed'},professional)
})

test('commits a call and notification jobs atomically before dispatch, with rollback on enqueue failure',async()=>{
  const store=new TransactionalMemoryVaultRepository()
  let fail=true,dispatched=0
  const exchange=new PortalDemoExchange({store,delivery:{
    async enqueue(_scope,event,transaction){await transaction.put('test_notification_jobs',{id:event.callId});if(fail)throw new Error('enqueue_failed')},
    async dispatch(){dispatched++},
  }})
  await exchange.registerCard(scope,card)
  await assert.rejects(exchange.submitEvent(scope,event,professional),/enqueue_failed/)
  assert.deepEqual(await exchange.listRecipientEvents(scope,{actorIdentifier:contact.actorIdentifier}),[])
  assert.deepEqual(await store.query('test_notification_jobs',{}),[])
  assert.equal(dispatched,0)
  fail=false;await exchange.submitEvent(scope,event,professional)
  assert.equal(dispatched,1)
  assert.equal((await store.query('test_notification_jobs',{})).length,1)
})
