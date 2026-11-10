// Flow contract: real loopback HTTP transports the same care operations between authorized BFF clients and the owning vault; an absent provider, bad service credential or another subject cannot grant access.
import test from 'node:test'
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {randomBytes} from 'node:crypto'
import {PortalDemoExchange,PortalDemoExchangeClient,createPortalDemoExchangeHandler} from '../dist/portal-demo-exchange.js'
import {PortalCareVaultProvider} from '../dist/portal-care-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope,demoWorkspaceStorageNamespace} from 'sos-data-utils-ts/demo-workspace-scope'
import {createPortalDemoCareEntries} from 'sos-data-utils-ts/portal-demo-care-fixtures'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {TaskClaim} from 'sos-data-utils-ts/task-artifact-schema'
import {SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD} from 'sos-data-utils-ts/portal-demo-fixtures'
import {buildSubjectCommunicationGroupReference} from 'sos-data-utils-ts/subject-communication-group'

async function fixture(t,withCare=true){
  const store=new TransactionalMemoryVaultRepository(),bearer=randomBytes(32).toString('base64url')
  const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:examples.tenantId,tenantId:`demo-${examples.tenantId}`})
  const provider=new PortalCareVaultProvider({store,scopeKey:scope.key,subjectIdentifier:examples.didWeb,generationId:examples.resourceUuid,
    actorIdentifier:examples.didWeb,recipientActorIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,
    communicationsCollection:`${demoWorkspaceStorageNamespace(scope)}__demo-communications`,assertAccess:async()=>{}})
  await provider.seed(createPortalDemoCareEntries({subjectReference:examples.didWeb,idPrefix:examples.resourceUuid,now:Date.now()}))
  let factoryCalls=0
  const exchange=new PortalDemoExchange({store})
  const handler=createPortalDemoExchangeHandler({scope,bearer,exchange,...(withCare?{careProviderFactory:async input=>{
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
  return {scope,provider,bearer,baseUrl,exchange,client:new PortalDemoExchangeClient({baseUrl,bearer}),factoryCalls:()=>factoryCalls,
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
