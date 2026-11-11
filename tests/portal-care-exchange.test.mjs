// Flow contract: real loopback HTTP transports the same care operations between authorized BFF clients and the owning vault; an absent provider, bad service credential or another subject cannot grant access.
import test from 'node:test'
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {randomBytes} from 'node:crypto'
import {PortalDemoExchange,PortalDemoExchangeClient,createPortalDemoExchangeHandler} from '../dist/portal-demo-exchange.js'
import {PortalConsentVaultProvider} from '../dist/portal-consent-vault.js'
import {buildConsentClaimsSimple} from 'gdc-common-utils-ts/utils/consent'
import {HealthcareActorRoles,HealthcareConsentPurposes} from 'gdc-common-utils-ts/constants/healthcare'
import {IndividualLogicalSections} from 'gdc-common-utils-ts/constants/individual-sections'
import {ClaimConsent as C} from 'gdc-common-utils-ts/models/consent-rule'
import {PortalCareVaultProvider} from '../dist/portal-care-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope,demoWorkspaceStorageNamespace} from 'sos-data-utils-ts/demo-workspace-scope'
import {createPortalDemoCareEntries} from 'sos-data-utils-ts/portal-demo-care-fixtures'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {EncounterClaim as E,EncounterStatusR5 as S} from 'fhir-data-utils-ts/claims'
import {buildFlatClaimResourceEntry} from 'fhir-data-utils-ts/flat-claim-resource-graph'
import {FHIR_ENCOUNTER_TRANSFER_TEST_DATA as encounterFixture} from 'fhir-data-utils-ts/data'
import {TaskClaim} from 'sos-data-utils-ts/task-artifact-schema'
import {SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD} from 'sos-data-utils-ts/portal-demo-fixtures'
import {buildSubjectCommunicationGroupReference} from 'sos-data-utils-ts/subject-communication-group'
import {CommunicationClaim} from 'gdc-common-utils-ts/models/interoperable-claims/communication-claims'

async function fixture(t,withCare=true){
  const store=new TransactionalMemoryVaultRepository(),bearer=randomBytes(32).toString('base64url')
  const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:examples.tenantId,tenantId:`demo-${examples.tenantId}`})
  const provider=new PortalCareVaultProvider({store,scopeKey:scope.key,subjectIdentifier:examples.didWeb,generationId:examples.resourceUuid,
    actorIdentifier:examples.didWeb,recipientActorIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,
    communicationsCollection:`${demoWorkspaceStorageNamespace(scope)}__demo-communications`,assertAccess:async()=>{}})
  await provider.seed(createPortalDemoCareEntries({subjectReference:examples.didWeb,idPrefix:examples.resourceUuid,now:Date.now()}))
  const consents=new PortalConsentVaultProvider({store,scopeKey:scope.key,subjectIdentifier:examples.didWeb,generationId:examples.resourceUuid,expiresAt:Date.now()+60_000,assertAccess:async()=>{}})
  let factoryCalls=0
  const exchange=new PortalDemoExchange({store})
  await exchange.registerCard(scope,{cardNumber:SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD[0].cardNumber21,generationId:examples.resourceUuid,
    subjectIdentifier:examples.didWeb,displayName:examples.individualGivenName,controllerActorIdentifier:examples.didWeb,
    subjectKind:'person',sourceSector:'onehealth-research',expiresAt:Date.now()+60_000})
  const handler=createPortalDemoExchangeHandler({scope,bearer,exchange,consentProviderFactory:async input=>{
    if(input.subjectIdentifier!==examples.didWeb||input.participant.actorIdentifier!==examples.didWeb)throw new Error('consent_subject_forbidden')
    return {provider:consents,actor:{actorKind:'professional',email:examples.firstContactEmail},actorRole:HealthcareActorRoles.MedicalDoctors}
  },...(withCare?{careProviderFactory:async input=>{
    factoryCalls++
    if(input.subjectIdentifier!==examples.didWeb||input.participant.actorIdentifier!==examples.didWeb)throw new Error('care_subject_forbidden')
    return provider
  }}:{})})
  const server=createServer(async(req,res)=>{
    try{
      const chunks=[];for await(const chunk of req)chunks.push(chunk)
      const response=await handler(new Request('http://localhost'+req.url,{method:req.method,headers:req.headers,body:Buffer.concat(chunks)}))
      res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()))
    }catch{res.writeHead(500);res.end()}
  })
  // This loopback address is an OS-assigned test listener, never an operational endpoint.
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))})
  const baseUrl=`http://127.0.0.1:${server.address().port}`
  return {scope,store,provider,consents,bearer,baseUrl,exchange,client:new PortalDemoExchangeClient({baseUrl,bearer}),factoryCalls:()=>factoryCalls,
    participant:{actorIdentifier:examples.didWeb}}
}

test('an authenticated peer reads and updates the same persisted care resource over HTTP',async t=>{
  const f=await fixture(t)
  const first=await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'search',resourceType:'Task'})
  assert.equal(first.kind,'resources');assert.equal(first.resources.length,1)
  const entry=first.resources[0].entry
  const result=await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'save',entry:{...entry,claims:{...entry.claims,[TaskClaim.Description]:'Updated through the peer BFF'}},mode:'update',options:{expectedRevision:1}})
  assert.equal(result.resources[0].revision,2)
  assert.deepEqual(result.resources,await f.provider.search('Task'))
  const notices=await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'notifications'})
  assert.equal(notices.notifications.length,1)
})

test('a permission request atomically records one Communication carrying its draft Consent Bundle and retries without duplication',async t=>{
 const f=await fixture(t)
 const claims={...buildConsentClaimsSimple({subjectDid:examples.didWeb,actor:examples.firstContactEmail,actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,actions:[IndividualLogicalSections.Encounters.attributeValue],consentIdentifier:examples.resourceUuid}).consentClaims,[C.status]:'draft'}
 await f.client.consent(f.scope,examples.didWeb,f.participant,{kind:'request',claims})
 await f.client.consent(f.scope,examples.didWeb,f.participant,{kind:'request',claims})
 const notices=await f.store.query(`${demoWorkspaceStorageNamespace(f.scope)}__demo-communications`,{})
 assert.equal(notices.length,1)
 const communication=notices[0].communication.body.data[0].resource.meta.claims
 assert.equal(communication[CommunicationClaim.Sender],f.participant.actorIdentifier)
 assert.equal(communication[CommunicationClaim.Recipient],examples.didWeb)
 const bundle=JSON.parse(Buffer.from(communication[CommunicationClaim.ContentAttachmentData],'base64').toString('utf8'))
 assert.equal(bundle.resourceType,'Bundle');assert.equal(bundle.data.length,1)
 assert.equal(bundle.data[0].resource.resourceType,'Consent')
 assert.deepEqual(bundle.data[0].resource.meta.claims,claims)
 assert.equal((await f.consents.read()).revision,1)
 await assert.rejects(f.store.runTransaction(transaction=>f.exchange.recordPermissionRequest(f.scope,examples.didWeb,{actorIdentifier:examples.didWeb+':other'},claims,transaction,true)),/consent_request_conflict/)
 assert.deepEqual(await f.exchange.listRecipientEvents(f.scope,f.participant),[])
})

test('a failed permission-request Communication write rolls back its draft Consent',async t=>{
 const f=await fixture(t)
 const run=f.store.runTransaction.bind(f.store)
 f.store.runTransaction=callback=>run(transaction=>callback(new Proxy(transaction,{get(target,key){
  if(key==='put')return async(collection,record)=>{if(record.communication)throw new Error('injected_permission_audit_failure');return target.put(collection,record)}
  const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value
 }})))
 const claims={...buildConsentClaimsSimple({subjectDid:examples.didWeb,actor:examples.firstContactEmail,actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,actions:[IndividualLogicalSections.Encounters.attributeValue],consentIdentifier:examples.resourceUuid}).consentClaims,[C.status]:'draft'}
 await assert.rejects(f.client.consent(f.scope,examples.didWeb,f.participant,{kind:'request',claims}))
 assert.deepEqual(await f.consents.read(),{revision:0,claims:[]})
 assert.deepEqual(await f.store.query(`${demoWorkspaceStorageNamespace(f.scope)}__demo-communications`,{}),[])
})

test('care notices and call Communications coexist without breaking the call timeline',async t=>{
  const f=await fixture(t),caller=examples.didWeb+':professional',group=buildSubjectCommunicationGroupReference(caller)
  await f.exchange.registerCard(f.scope,{cardNumber:SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD[0].cardNumber21,generationId:examples.resourceUuid,
    subjectIdentifier:examples.didWeb,displayName:examples.individualGivenName,controllerActorIdentifier:examples.didWeb,
    subjectKind:'person',sourceSector:'onehealth-research',expiresAt:Date.now()+60_000})
  const task=(await f.provider.search('Task'))[0]
  await f.provider.save({...task.entry,claims:{...task.entry.claims,[TaskClaim.Description]:'Updated task'}},'update')
  const event={version:1,callId:examples.resourceUuid,threadId:buildSubjectCommunicationGroupReference(examples.didWeb),subjectIdentifier:examples.didWeb,
    professionalGroupReference:group,callerActorIdentifier:caller,recipientActorIdentifier:examples.didWeb,media:['audio'],state:'ringing',occurredAt:new Date().toISOString()}
  await f.exchange.submitEvent(f.scope,event,{actorIdentifier:caller,professionalGroupReference:group})
  const calls=await f.exchange.listEvents(f.scope,examples.didWeb,{actorIdentifier:examples.didWeb})
  assert.equal(calls.length,1)
  assert.equal(calls[0].callId,event.callId)
  assert.equal((await f.provider.notifications()).length,1)
})

test('invalid service credentials, missing provider and forged subject fail closed',async t=>{
  const f=await fixture(t)
  const bad=new PortalDemoExchangeClient({baseUrl:f.baseUrl,bearer:randomBytes(32).toString('base64url')})
  await assert.rejects(bad.care(f.scope,examples.didWeb,f.participant,{kind:'search',resourceType:'Encounter'}))
  assert.equal(f.factoryCalls(),0)
  await assert.rejects(f.client.care(f.scope,examples.didWeb+':other',f.participant,{kind:'search',resourceType:'Encounter'}),/forbidden/)
  const disabled=await fixture(t,false)
  await assert.rejects(disabled.client.care(disabled.scope,examples.didWeb,disabled.participant,{kind:'search',resourceType:'Task'}),/unavailable/)
})

test('atomic encounter commands cross the real peer HTTP boundary and read back immutable history',async t=>{
  const f=await fixture(t),item=encounterFixture.source
  const create=buildFlatClaimResourceEntry({resourceType:'Encounter',entryId:item.id,claims:{[E.Subject]:examples.didWeb,[E.Status]:S.Planned,[E.Class]:`${encounterFixture.class.system}|${encounterFixture.class.code}`,[E.ServiceProvider]:encounterFixture.senderReference,[E.ServiceType]:item.serviceReference}})
  const mutation={operationId:item.id,encounterReference:create.reference,create}
  await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'encounter',mutation})
  const start={operationId:encounterFixture.sourceHistory.id,encounterReference:create.reference,expectedRevision:1,status:S.InProgress}
  await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'encounter',mutation:start})
  await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'encounter',mutation:start})
  const history=await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'search',resourceType:'EncounterHistory'})
  assert.equal(history.resources.length,1)
  assert.deepEqual(history.resources,await f.provider.search('EncounterHistory'))
  const records=await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'search',resourceType:'Encounter'})
  assert.equal(records.resources.find(row=>row.entry.reference===create.reference).revision,2)
})

test('encounter conflicts retain their public error category and HTTP status',async t=>{
 const f=await fixture(t),item=encounterFixture.source
 const create=buildFlatClaimResourceEntry({resourceType:'Encounter',entryId:item.id,claims:{[E.Subject]:examples.didWeb,[E.Status]:S.Planned,[E.Class]:`${encounterFixture.class.system}|${encounterFixture.class.code}`}})
 const mutation={operationId:item.id,encounterReference:create.reference,create}
 await f.client.care(f.scope,examples.didWeb,f.participant,{kind:'encounter',mutation})
 const response=await fetch(f.baseUrl+'/api/internal/demo/exchange',{method:'POST',headers:{authorization:`Bearer ${f.bearer}`,'content-type':'application/json'},body:JSON.stringify({operation:'care',scope:f.scope,subjectIdentifier:examples.didWeb,participant:f.participant,care:{kind:'encounter',mutation:{...mutation,create:{...create,claims:{...create.claims,[E.ServiceType]:encounterFixture.destination.serviceReference}}}}})})
 assert.equal(response.status,409)
 assert.deepEqual(await response.json(),{error:'encounter_idempotency_conflict'})
})

test('the authenticated peer can request a draft and inspect its exact effective permissions, but cannot approve itself',async t=>{
 const f=await fixture(t),section=IndividualLogicalSections.Encounters.attributeValue
 const claims=buildConsentClaimsSimple({subjectDid:examples.didWeb,actor:examples.firstContactEmail,actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,actions:[section],consentIdentifier:examples.resourceUuid}).consentClaims
 const inspect={kind:'inspect',purpose:HealthcareConsentPurposes.Treatment,sections:[section]}
 assert.equal((await f.client.consent(f.scope,examples.didWeb,f.participant,inspect)).evaluation.allowed,false)
 await assert.rejects(f.client.consent(f.scope,examples.didWeb,f.participant,{kind:'request',claims}),/draft/)
 const draft={...claims,[C.status]:'draft'}
 await assert.rejects(f.client.consent(f.scope,examples.didWeb,f.participant,{kind:'request',claims:{...draft,[C.actorIdentifier]:examples.individualEmail}}),error=>error.message.includes('forbidden')&&error.status===403)
 const requested=await f.client.consent(f.scope,examples.didWeb,f.participant,{kind:'request',claims:draft})
 assert.equal(requested.kind,'request');assert.equal(requested.claims[C.status],'draft')
 assert.equal((await f.client.consent(f.scope,examples.didWeb,f.participant,inspect)).evaluation.allowed,false)
 await f.consents.replace([{...claims,[C.actorIdentifier]:examples.firstContactEmail+','+examples.individualEmail}],1)
 const effective=await f.client.consent(f.scope,examples.didWeb,f.participant,inspect)
 assert.equal(effective.evaluation.allowed,true)
 assert.equal(JSON.stringify(effective).includes(examples.individualEmail),false)
 await assert.rejects(f.client.consent(f.scope,examples.didWeb+':other',f.participant,inspect))
})
