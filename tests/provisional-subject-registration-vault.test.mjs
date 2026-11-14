// Flow contract: authorized provisional registration atomically persists a pending controller invitation in the existing transactional vault, without registering an owned/discoverable card. Only the exact creator organization may replay its request; changed requests conflict and invalid authority never writes.
import test from 'node:test'
import assert from 'node:assert/strict'
import {randomUUID,createHash} from 'node:crypto'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {PortalDemoExchange,PortalDemoExchangeClient,createPortalDemoExchangeHandler} from '../dist/portal-demo-exchange.js'

const creator={organizationReference:`Organization/${safe.demoOrganizationUuids.animalCare}`,actorIdentifier:`urn:uuid:${safe.resourceUuid}`,expiresAt:Date.now()+60_000}
const command=()=>({operationId:randomUUID(),subject:{kind:'animal',alternateName:'Provisional subject',ncbiTaxonomyId:'9615'},controller:{legalName:'Proposed responsible party',contact:{kind:'email',value:safe.firstContactEmail},relationship:'RESPRSN'}})
async function setup(options={}){
 const {ProvisionalSubjectRegistrationVault,provisionalSubjectRegistrationCollections}=await import('../dist/provisional-subject-registration-vault.js')
 const store=options.store??new TransactionalMemoryVaultRepository()
 const provider=new ProvisionalSubjectRegistrationVault({store,scopeKey:safe.tenantId,assertCreator:async()=>creator,...options})
 return {provider,store,names:provisionalSubjectRegistrationCollections(safe.tenantId)}
}
test('persists separate subject and pending invitation records without any owned card',async()=>{
 const {provider,store,names}=await setup(),input=command()
 const receipt=await provider.register({participant:{},command:input})
 assert.equal(receipt.status,'provisional')
 assert.equal(receipt.controllerInvitation.status,'pending')
 assert.equal(receipt.evidence.status,'pending')
 const registrations=await store.query(names.registrations,{}),invitations=await store.query(names.invitations,{})
 assert.equal(registrations.length,1);assert.equal(invitations.length,1)
 assert.notEqual(receipt.subjectIdentifier,creator.actorIdentifier)
 assert.equal(invitations[0].status,'pending')
 assert.equal(Object.hasOwn(invitations[0],'workspaceOwnerUid'),false)
 assert.equal(Object.hasOwn(registrations[0],'cardNumber'),false)
})
test('replays only the same creator organization and exact normalized payload',async()=>{
 const {provider}=await setup(),input=command()
 assert.deepEqual(await provider.register({participant:{},command:input}),await provider.register({participant:{},command:input}))
 await assert.rejects(provider.register({participant:{},command:{...input,subject:{...input.subject,alternateName:'Changed'}}}),/conflict/)
})
test('retains registration idempotency after a later explicit controller claim',async()=>{
 const {provider,store,names}=await setup(),input=command()
 const receipt=await provider.register({participant:{},command:input})
 const record=await store.get(names.registrations,receipt.registrationId)
 await store.put(names.registrations,{...record,status:'claimed',claimedByOwnerHash:createHash('sha256').update(`${safe.tenantId}\0${safe.resourceUuid}`).digest('hex')})
 assert.deepEqual(await provider.register({participant:{},command:input}),receipt)
 assert.equal((await store.query(names.registrations,{})).length,1)
})
test('reads the immutable creation receipt after an explicit controller claim without treating it as live ownership state',async()=>{
 const {provider,store,names}=await setup(),input=command()
 const receipt=await provider.register({participant:{},command:input})
 const record=await store.get(names.registrations,receipt.registrationId)
 await store.put(names.registrations,{...record,status:'claimed',claimedByOwnerHash:createHash('sha256').update(`${safe.tenantId}\0${safe.resourceUuid}`).digest('hex')})
 assert.deepEqual(await provider.read({participant:{},registrationId:receipt.registrationId}),receipt)
})
test('fails closed before writes when trusted creator admission rejects or expires',async()=>{
 for(const assertCreator of [async()=>{throw Object.assign(new Error('subject_registration_forbidden'),{status:403})},async()=>({...creator,expiresAt:0})]){
  const {provider,store,names}=await setup({assertCreator})
  await assert.rejects(provider.register({participant:{},command:command()}))
  assert.equal((await store.query(names.registrations,{})).length,0)
  assert.equal((await store.query(names.invitations,{})).length,0)
 }
})
test('keeps a matching professional email a proposed controller invitation',async()=>{
 const {provider,store,names}=await setup(),input=command()
 input.controller.contact.value=safe.individualEmail
 const receipt=await provider.register({participant:{verifiedEmail:safe.individualEmail},command:input})
 assert.equal(receipt.controllerInvitation.status,'pending')
 assert.equal(Object.hasOwn((await store.query(names.invitations,{}))[0],'acceptedByUid'),false)
})
test('denies another creator organization reading the provisional receipt',async()=>{
 const {provider}=await setup({assertCreator:async participant=>participant.other?{...creator,organizationReference:`Organization/${safe.demoOrganizationUuids.healthCare}`}:creator})
 const receipt=await provider.register({participant:{},command:command()})
 await assert.rejects(provider.read({participant:{other:true},registrationId:receipt.registrationId}),/forbidden/)
 assert.deepEqual(await provider.read({participant:{},registrationId:receipt.registrationId}),receipt)
 await assert.rejects(provider.read({participant:{},registrationId:randomUUID()}),/not_found/)
})
test('rolls back provisional registration when the invitation write fails',async()=>{
 class FailingVault extends TransactionalMemoryVaultRepository{
  runTransaction(operation){return super.runTransaction(transaction=>operation({...transaction,put:async(collection,records)=>{
   if(collection.endsWith('__subject-registration-invitations'))throw new Error('injected_invitation_failure')
   return transaction.put(collection,records)
  }}))}
 }
 const {provider,store,names}=await setup({store:new FailingVault()})
 await assert.rejects(provider.register({participant:{},command:command()}),/injected_invitation_failure/)
 assert.equal((await store.query(names.registrations,{})).length,0)
 assert.equal((await store.query(names.invitations,{})).length,0)
})
test('uses the existing authenticated peer client and handler with an injected registration provider',async()=>{
 const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:safe.tenantId,tenantId:`demo-${safe.tenantId}`})
 const {provider,store}=await setup({scopeKey:scope.key})
 let admitted=0
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store}),scope,bearer:'synthetic-subject-registration-peer-credential',registrationProvider:async input=>{
  admitted++;assert.equal(input.scope.key,scope.key)
  return provider.register(input)
 }})
 const client=new PortalDemoExchangeClient({baseUrl:'http://localhost',bearer:'synthetic-subject-registration-peer-credential',fetchImpl:async(url,init)=>handler(new Request(url,init))})
 const intent=command()
 const receipt=await client.registerSubject(scope,{actorIdentifier:creator.actorIdentifier},intent)
 assert.equal(receipt.status,'provisional');assert.equal(admitted,1)
 const other=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:`${safe.tenantId}-other`,tenantId:`demo-${safe.tenantId}-other`})
 await assert.rejects(client.registerSubject(other,{actorIdentifier:creator.actorIdentifier},command()),/scope_forbidden/)
 assert.equal(admitted,1)
 const denied=new PortalDemoExchangeClient({baseUrl:'http://localhost',bearer:'wrong-synthetic-subject-registration-credential',fetchImpl:async(url,init)=>handler(new Request(url,init))})
 await assert.rejects(denied.registerSubject(scope,{},command()),/unauthorized/)
 assert.equal(admitted,1)
 await assert.rejects(client.registerSubject(scope,{actorIdentifier:creator.actorIdentifier},{...intent,subject:{...intent.subject,alternateName:'Changed'}}),error=>error.status===409&&/request_conflict/.test(error.message))
})
test('reads persisted registration receipts through the same authenticated peer transport and creator admission',async()=>{
 const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:safe.tenantId,tenantId:`demo-${safe.tenantId}`})
 const {provider,store}=await setup({scopeKey:scope.key,assertCreator:async participant=>participant.other?{...creator,organizationReference:`Organization/${safe.demoOrganizationUuids.healthCare}`}:creator})
 const receipt=await provider.register({participant:{},command:command()})
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store}),scope,bearer:'synthetic-subject-registration-peer-credential',registrationReadProvider:input=>provider.read(input)})
 const client=new PortalDemoExchangeClient({baseUrl:'http://localhost',bearer:'synthetic-subject-registration-peer-credential',fetchImpl:async(url,init)=>handler(new Request(url,init))})
 assert.deepEqual(await client.readSubjectRegistration(scope,{actorIdentifier:creator.actorIdentifier},receipt.registrationId),receipt)
 await assert.rejects(client.readSubjectRegistration(scope,{other:true},receipt.registrationId),error=>error.status===403&&/forbidden/.test(error.message))
 await assert.rejects(client.readSubjectRegistration(scope,{},randomUUID()),error=>error.status===404&&/not_found/.test(error.message))
})
