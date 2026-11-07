// Flow contract: two authorized portal BFFs share synthetic card and Communication state through one injected Confidential Storage vault, without GW calls; tenant, participant, generation, TTL and terminal-state checks remain enforced.
import assert from 'node:assert/strict'
import test from 'node:test'
import {PortalDemoExchange, createPortalDemoExchangeHandler, PortalDemoExchangeClient} from '../dist/portal-demo-exchange.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {demoWorkspaceStorageNamespace} from 'sos-data-utils-ts/demo-workspace-scope'

const scope = buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:'soschain',tenantId:'demo-soschain'})
const other = buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:'vetchain',tenantId:'demo-vetchain'})
const card = {cardNumber:'123456789012345678901',generationId:'generation-1',subjectIdentifier:'urn:uuid:subject',displayName:'Synthetic subject',controllerActorIdentifier:'urn:uuid:controller',subjectKind:'animal',sourceSector:'animal-research',expiresAt:Date.now()+60_000}
const event = {version:1,callId:'call-1',threadId:'thread-1',subjectIdentifier:card.subjectIdentifier,professionalGroupReference:'Group/team-1',callerActorIdentifier:'urn:uuid:employee',recipientActorIdentifier:card.controllerActorIdentifier,media:['video'],state:'ringing',occurredAt:new Date().toISOString()}
const professional={actorIdentifier:event.callerActorIdentifier,professionalGroupReference:event.professionalGroupReference}
const controller={actorIdentifier:card.controllerActorIdentifier}

test('shares a card and one Communication history across BFF clients without a GW',async()=>{
  const store=new TransactionalMemoryVaultRepository()
  const exchange=new PortalDemoExchange({store})
  await exchange.registerCard(scope,card)
  const handle=createPortalDemoExchangeHandler({exchange,scope,bearer:'fixture-service-token-at-least-32-characters'})
  const client=new PortalDemoExchangeClient({baseUrl:'http://localhost:4317',bearer:'fixture-service-token-at-least-32-characters',fetchImpl:async(url,init)=>handle(new Request(url,init))})
  assert.equal((await client.resolveCard(scope,card.cardNumber)).subjectIdentifier,card.subjectIdentifier)
  await client.submitEvent(scope,event,professional)
  await exchange.submitEvent(scope,{...event,state:'received',occurredAt:new Date(Date.now()+1).toISOString()},controller)
  await client.submitEvent(scope,{...event,state:'completed',occurredAt:new Date(Date.now()+2).toISOString()},professional)
  assert.deepEqual((await exchange.listEvents(scope,card.subjectIdentifier,controller)).map(item=>item.state),['ringing','received','completed'])
  assert.equal((await client.listEvents(scope,card.subjectIdentifier,professional)).at(-1).state,'completed')
  const communications=await store.query(`${demoWorkspaceStorageNamespace(scope)}__demo-communications`,{})
  assert.equal(communications.length,3)
  assert.ok(communications.every(row=>row.communication.body.data[0].type==='Communication'))
  assert.ok(!JSON.stringify(communications).includes('participantToken'))
})

test('rejects cross-scope discovery, stale generations and expired cards',async()=>{
  let now=Date.now();const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository(),now:()=>now})
  await exchange.registerCard(scope,card)
  await assert.rejects(exchange.resolveCard(other,card.cardNumber),/card_not_found/)
  await exchange.revokeGeneration(scope,card.generationId)
  await assert.rejects(exchange.resolveCard(scope,card.cardNumber),/card_not_found/)
  await exchange.registerCard(scope,{...card,generationId:'generation-2'})
  now=card.expiresAt+1
  await assert.rejects(exchange.resolveCard(scope,card.cardNumber),/card_not_found/)
})

test('enforces participants, immutable call identity and terminal states',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()});await exchange.registerCard(scope,card)
  await assert.rejects(exchange.submitEvent(scope,event,{actorIdentifier:'urn:uuid:stranger'}),/participant_forbidden/)
  await exchange.submitEvent(scope,event,professional)
  assert.deepEqual(await exchange.listEvents(scope,card.subjectIdentifier,{actorIdentifier:'urn:uuid:stranger'}),[])
  await assert.rejects(exchange.submitEvent(scope,{...event,state:'received'},professional),/recipient_required/)
  await assert.rejects(exchange.submitEvent(scope,{...event,state:'cancelled'},controller),/caller_required/)
  await assert.rejects(exchange.submitEvent(scope,{...event,recipientActorIdentifier:'urn:uuid:another',state:'declined'},{actorIdentifier:'urn:uuid:another'}),/identity_mismatch/)
  await exchange.submitEvent(scope,{...event,state:'declined'},controller)
  await assert.rejects(exchange.submitEvent(scope,{...event,state:'completed'},professional),/transition_invalid/)
  assert.equal((await exchange.listEvents(scope,card.subjectIdentifier,controller)).length,2)
})

test('rejects missing service credentials before touching vault state',async()=>{
  assert.throws(()=>createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer:'replace-with-shared-private-bff-service-credential'}),/credential_required/)
  const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer:'fixture-service-token-at-least-32-characters'})
  assert.equal((await handler(new Request('http://localhost/api/internal/demo/exchange',{method:'POST',body:'{}'}))).status,401)
  const response=await handler(new Request('http://localhost/api/internal/demo/exchange',{method:'POST',headers:{authorization:'Bearer fixture-service-token-at-least-32-characters'},body:JSON.stringify({operation:'resolveCard',scope:other,cardNumber:card.cardNumber})}))
  assert.equal(response.status,403)
  const malformed=await handler(new Request('http://localhost/api/internal/demo/exchange',{method:'POST',headers:{authorization:'Bearer fixture-service-token-at-least-32-characters'},body:'private-input-not-json'}))
  assert.deepEqual(await malformed.json(),{error:'demo_exchange_request_invalid'})
})

test('serializes same-clock transitions and makes the same terminal retry idempotent',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository(),now:()=>Date.parse(event.occurredAt)})
  await exchange.registerCard(scope,card)
  await exchange.submitEvent(scope,event,professional)
  await exchange.submitEvent(scope,{...event,state:'received'},controller)
  await exchange.submitEvent(scope,{...event,state:'completed'},professional)
  await exchange.submitEvent(scope,{...event,state:'completed'},professional)
  assert.deepEqual((await exchange.listEvents(scope,card.subjectIdentifier,controller)).map(row=>row.state),['ringing','received','completed'])
})

test('does not let a second subject overwrite a call identifier already bound in the same scope',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await exchange.registerCard(scope,card)
  const second={...card,cardNumber:'123456789012345678902',subjectIdentifier:'urn:uuid:other-subject'}
  await exchange.registerCard(scope,second)
  await exchange.submitEvent(scope,event,professional)
  await assert.rejects(exchange.submitEvent(scope,{...event,subjectIdentifier:second.subjectIdentifier},professional),/identity_mismatch/)
  assert.equal((await exchange.listEvents(scope,card.subjectIdentifier,controller)).length,1)
})
