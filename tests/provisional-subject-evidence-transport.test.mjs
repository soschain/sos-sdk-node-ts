// Flow contract: the existing authenticated peer transport carries bounded binary evidence separately from small ordinary commands, preserves exact bytes and pending receipts, and rejects unauthenticated, oversized or mismarked requests before provider use.
import test from 'node:test'
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {PortalDemoExchange,PortalDemoExchangeClient,createPortalDemoExchangeHandler} from '../dist/portal-demo-exchange.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {buildSha3_384EvidenceContentIdFromDigest} from 'antifraud-data-utils-ts/identity-assurance'
const bearer='synthetic-pending-evidence-peer-credential'
const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:safe.tenantId,tenantId:`demo-${safe.tenantId}`})
const command={operationId:safe.resourceUuid,registrationId:safe.resourceUuid,verificationMethod:'sripp',subject:{},controller:{}}
const participant={actorIdentifier:`urn:uuid:${safe.resourceUuid}`}
test('transfers more than an ordinary envelope as actual bytes and reads its pending metadata',async()=>{
 const bytes=new Uint8Array(2*1024*1024).fill(65)
 const receipt={evidenceId:safe.resourceUuid,registrationId:safe.resourceUuid,status:'pending',documents:[{slot:'subject',contentId:buildSha3_384EvidenceContentIdFromDigest(createHash('sha3-384').update(bytes).digest()),mediaType:'application/pdf',fileName:'subject.pdf',size:bytes.length}]}
 let calls=0
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer,subjectEvidenceProvider:{
  async submit(input){calls++;assert.equal(input.scope.key,scope.key);assert.deepEqual(input.documents[0].bytes,bytes);assert.deepEqual(input.command,command);return receipt},
  async read(input){assert.equal(input.registrationId,safe.resourceUuid);return receipt},
 }})
 const client=new PortalDemoExchangeClient({baseUrl:'http://localhost',bearer,fetchImpl:async(url,init)=>handler(new Request(url,init))})
 assert.deepEqual(await client.submitSubjectEvidence(scope,participant,command,[{slot:'subject',fileName:'subject.pdf',mediaType:'application/pdf',bytes}]),receipt)
 assert.deepEqual(await client.readSubjectEvidence(scope,participant,safe.resourceUuid),receipt)
 assert.equal(calls,1)
})
test('keeps ordinary envelopes limited and rejects oversized marked evidence before reading its body',async()=>{
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer})
 const ordinary=await handler(new Request('http://localhost',{method:'POST',headers:{authorization:`Bearer ${bearer}`},body:JSON.stringify({operation:'readSubjectRegistration',scope,padding:'x'.repeat(33*1024)})}))
 assert.equal(ordinary.status,413)
 const oversized=await handler(new Request('http://localhost',{method:'POST',headers:{authorization:`Bearer ${bearer}`,'x-portal-evidence-transfer':'1','content-length':String(50*1024*1024)},body:'{}'}))
 assert.equal(oversized.status,413)
})
test('requires the existing peer credential before accessing evidence body content',async()=>{
 let reads=0
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer})
 const response=await handler({headers:new Headers({'x-portal-evidence-transfer':'1'}),method:'POST',async text(){reads++;throw new Error('body_must_not_be_read')}})
 assert.equal(response.status,401);assert.equal(reads,0)
})
test('accepts three actual maximum-size files including independent base64 rounding and JSON overhead',async()=>{
 const size=10*1024*1024,bytes=Buffer.alloc(size),encoded=bytes.toString('base64url')
 const contentId=buildSha3_384EvidenceContentIdFromDigest(createHash('sha3-384').update(bytes).digest())
 const slots=['subject','controller','relationship']
 const receipt={evidenceId:safe.resourceUuid,registrationId:safe.resourceUuid,status:'pending',documents:slots.map(slot=>({slot,contentId,mediaType:'application/pdf',fileName:`${slot}.pdf`,size}))}
 let calls=0
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer,subjectEvidenceProvider:{
  async submit(input){calls++;assert.equal(input.documents.length,3);for(const document of input.documents){assert.equal(document.bytes.length,size);assert.equal(buildSha3_384EvidenceContentIdFromDigest(createHash('sha3-384').update(document.bytes).digest()),contentId)}return receipt},
  async read(){return receipt},
 }})
 const wire=JSON.stringify({operation:'submitSubjectEvidence',scope,participant,command,documents:slots.map(slot=>({slot,fileName:`${slot}.pdf`,attachment:{id:slot,media_type:'application/pdf',byte_count:size,data:{base64:encoded}}}))})
 assert.ok(Buffer.byteLength(wire)>40*1024*1024)
 const response=await handler(new Request('http://localhost',{method:'POST',headers:{authorization:`Bearer ${bearer}`,'content-type':'application/json','x-portal-evidence-transfer':'1','content-length':String(Buffer.byteLength(wire))},body:wire}))
 assert.equal(response.status,200);assert.deepEqual((await response.json()).result,receipt);assert.equal(calls,1)
})
test('rejects a syntactically valid receipt CID that does not match the bytes actually submitted',async()=>{
 const bytes=Uint8Array.from(Buffer.from('actual-subject-document'))
 const wrong=buildSha3_384EvidenceContentIdFromDigest(createHash('sha3-384').update('different-document').digest())
 const receipt={evidenceId:safe.resourceUuid,registrationId:safe.resourceUuid,status:'pending',documents:[{slot:'subject',contentId:wrong,mediaType:'application/pdf',fileName:'subject.pdf',size:bytes.length}]}
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()}),scope,bearer,subjectEvidenceProvider:{async submit(){return receipt},async read(){return receipt}}})
 const client=new PortalDemoExchangeClient({baseUrl:'http://localhost',bearer,fetchImpl:async(url,init)=>handler(new Request(url,init))})
 await assert.rejects(client.submitSubjectEvidence(scope,participant,command,[{slot:'subject',fileName:'subject.pdf',mediaType:'application/pdf',bytes}]),/receipt_invalid/)
})
