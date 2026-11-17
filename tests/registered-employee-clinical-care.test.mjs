// Flow contract: a registered member's current PIN/DCR identity and independent active Encounter Consent admit only fixed Task triage reads/transitions. Real AES/full-PQC custody and signed/encrypted GW peers bind issuer/audience/thread; GW licence denials remain denials. No generic transport, controller opener, browser role, native-FHIR payload or arbitrary route grants authority.
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {readFileSync} from 'node:fs'
import * as api from '../dist/index.js'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {buildAuthorityDidWeb,buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {OrganizationWorkflowCapabilities as Cap,OrganizationWorkflowGroupKinds as Kind} from 'sos-data-utils-ts/organization-workflow-access'
import {TaskClaim as T} from 'fhir-data-utils-ts/claims'

const collections={profiles:'synthetic-clinical-profiles',walletSessions:'synthetic-clinical-sessions',enrollmentGrants:'synthetic-clinical-enrollments',workflowAuthorizations:'synthetic-clinical-workflow-consents'}
const seed=Buffer.alloc(32,23).toString('base64url'),token=Buffer.alloc(32,37).toString('base64url'),sessionId=createHash('sha256').update(token).digest('hex')
const clock=new Date('2026-01-01T00:00:00Z'),route={tenantId:safe.tenantId,jurisdiction:'CA',sector:safe.sector},role='ISCO-08|2250'
// Existing governed synthetic provider wire; no frozen SDK is imported or executed.
const providerDid=JSON.parse(readFileSync(new URL('./fixtures/employee-draft-provider-oracle.json',import.meta.url),'utf8')).providerDid
const baseUrl=safe.httpsBaseUrl,hostAuthorityDid=buildAuthorityDidWeb({authority:baseUrl}),prefix=`/${route.tenantId}/cds-${route.jurisdiction}/v1/${route.sector}/organization/org.hl7.fhir.r5/Task`
const clinicalId=safe.demoOrganizationUuids.healthCare,taskId=safe.resourceUuid,groupReference=`Group/${safe.demoOrganizationUuids.publicHealth}`
const need=()=>{assert.equal(typeof api.RegisteredEmployeeClinicalCareClient,'function','missing purpose-fixed registered employee clinical-care port');return api.RegisteredEmployeeClinicalCareClient}
const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),digestString:async(v,a)=>createHash(a.replaceAll('-','').toLowerCase()).update(v).digest('hex'),randomUUID})

async function fixture(contactKind='phone'){
 const vault=new api.TransactionalMemoryVaultRepository(),sealer=api.createAesGcmProfileSealer(Buffer.alloc(32,7)),contact={contactKind,contact:contactKind==='phone'?safe.phoneE164:safe.individualEmail}
 const actorDid=buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role}),profileId=safe.resourceUuid,ownerId='synthetic-clinical-owner',clientInstanceId='synthetic-clinical-installation',tenantIssuer=`urn:uuid:${safe.demoOrganizationUuids.animalCare}`
 const keys=await api.openServerProfileCustodyKeys({walletKeyDerivationId:'synthetic-clinical-keys',unlockedWalletSeed:seed,binding:{kind:'enrollment'}})
 const profile={id:profileId,profileId,ownerId,actorDid,profileDid:actorDid,providerDid,routeContext:route,actorKind:ActorKinds.OrganizationEmployee,actorMode:'member',status:'active',clientId:'synthetic-clinical-client',clientInstanceId,deviceDid:'synthetic-clinical-device',tenantIssuer,allowedSubjectDids:[actorDid],walletKeyDerivationId:'synthetic-clinical-keys',publicJwks:keys.publicJwks.map(key=>({...key})),storagePublicJwk:{...keys.storagePublicJwk},confidentialStorageProfile:'confidential-pqc-v1',clinicalCreatorBinding:{authorIdentifier:`urn:uuid:${clinicalId}`,role},protectedWalletSeed:await api.protectServerProfileSecret(seed,'fixture-742619',`${profileId}:wallet-seed`,sealer),failedUnlocks:0,credentialRevision:0,createdAt:'2020-01-01T00:00:00Z',updatedAt:'2020-01-01T00:00:00Z'}
 const session={id:sessionId,ownerId,profileId,credentialRevision:0,sealedWalletSeed:await sealer.seal(seed,`${ownerId}:${profileId}:${sessionId}:wallet-session-seed`),expiresAt:'2027-01-01T00:00:00Z'}
 const enrollment={...api.createEmployeeActivationGrant({...contact,employeeDid:actorDid,employeeRoleCode:role,providerDid,routeContext:route,createdAt:new Date('2020-01-01T00:00:00Z'),expiresAt:new Date('2020-01-02T00:00:00Z')}),id:'synthetic-clinical-consumed-grant',tenantIssuer,accessPath:'test-network',consumedEnrollments:[{ownerId,profileId,clientInstanceId}]}
 const authorization={id:createHash('sha256').update(profileId).update('\0').update(Kind.EncounterOperations).digest('base64url'),profileId,providerDid,status:'active',groupKind:Kind.EncounterOperations,groupReference,organizationReference:`Organization/${route.tenantId}`,memberPractitionerRoleReference:`PractitionerRole/${clinicalId}`,capabilities:[Cap.EncounterCruds,Cap.EncounterHistoryCruds],consentId:'synthetic-active-encounter-consent',assignedByProfileId:'synthetic-controller',assignedAt:'2020-01-01T00:00:00Z',assignmentMode:'controller-assigned'}
 await vault.put(collections.profiles,profile);await vault.put(collections.walletSessions,session);await vault.put(collections.enrollmentGrants,enrollment);await vault.put(collections.workflowAuthorizations,authorization)
 const clientSigning=keys.publicJwks.find(key=>key.kty==='AKP'&&key.alg==='ML-DSA-44'),clientEncryption=keys.publicJwks.find(key=>key.kty==='OKP'&&key.crv==='ML-KEM-768')
 assert.ok(clientSigning);assert.ok(clientEncryption)
 const peer=new OrganizationRegistrationWallet({resolveRecipientJwk:async did=>{assert.equal(did,actorDid);return clientEncryption}}),peerContext={runtime:{runtimeId:'synthetic-clinical-gateway',runtimeType:'backend-service'}}
 await peer.provisionCommunicationKeys(peerContext,Buffer.alloc(32,17).toString('base64url'));const peerKeys=peer.getPublicJwks(peerContext)
 const client=await api.openRegisteredCommunicationWallet({walletKeyDerivationId:profile.walletKeyDerivationId,unlockedWalletSeed:seed,registeredPublicJwks:profile.publicJwks,resolveRecipientJwk:async did=>{assert.equal(did,providerDid);return peerKeys.encryption}})
 const task={resourceType:'Task',id:taskId,meta:{claims:{[T.Status]:'requested',[T.Intent]:'order',[T.Code]:'triage',[T.Focus]:`ServiceRequest/${taskId}`,[T.For]:`Patient/${safe.demoOrganizationUuids.animalCare}`,[T.Requester]:`RelatedPerson/${safe.demoOrganizationUuids.publicSafety}`,[T.Owner]:groupReference,[T.AuthoredOn]:'2025-12-31T12:00:00Z','Task.meta.versionId':'7'}}}
 const state={fault:'',requests:[],mutations:[],afterReceive:undefined,afterDecrypt:undefined},jobs=new Map()
 async function fetchImpl(url,init){
  assert.equal(init.method,'POST');assert.equal(init.redirect,'error');assert.equal(init.headers.Authorization,'Bearer synthetic-host-verified-token');assert.equal(init.headers['Content-Type'],'application/x-www-form-urlencoded')
  const path=new URL(url).pathname;assert.ok([prefix+'/_search',prefix+'/_search-response',prefix+'/_batch',prefix+'/_batch-response'].includes(path),'only fixed Task triage routes')
  const packed=new URLSearchParams(init.body).get('request');assert.ok(packed)
  const opened=await peer.unpackWithContext(packed,{context:peerContext}),message=opened.content
  assert.equal(await crypto.verifyJws(opened.meta.jws.compact,clientSigning),true);assert.equal(message.iss,actorDid);assert.equal(message.aud,providerDid);assert.equal(message.client_id,profile.clientId)
  state.requests.push({path,message});await state.afterReceive?.({path,message})
  if(state.fault==='licence')return new Response(JSON.stringify({error:'employee_licence_inactive'}),{status:403})
  if(state.fault==='conflict'&&path.endsWith('/_batch'))return new Response(JSON.stringify({error:'version_conflict'}),{status:409})
  if(!path.endsWith('-response')){jobs.set(message.thid,{path,message});if(path.endsWith('/_batch'))state.mutations.push(message);return new Response('{}',{status:202})}
  const job=jobs.get(message.thid);assert.ok(job)
  let body
  if(job.path.endsWith('/_search')){
   const row=structuredClone(task)
   if(state.fault==='native')row.status='requested'
   if(state.fault==='nested')row.meta.claims[T.For]={reference:'Patient/forged'}
   if(state.fault==='version')delete row.meta.claims['Task.meta.versionId']
   if(state.fault==='owner')row.meta.claims[T.Owner]='Group/foreign'
   body={data:[{resource:row,response:{status:'200'}}]}
  }else body={data:[{response:{status:'200'}}]}
  const response={iss:state.fault==='issuer'?`${providerDid}:foreign`:providerDid,aud:state.fault==='audience'?`${actorDid}:foreign`:actorDid,thid:state.fault==='thread'?'unrelated-thread':job.message.thid,body}
  const responsePacked=await peer.packForRecipientWithContext(response,actorDid,{context:peerContext});await state.afterDecrypt?.()
  return new Response(new URLSearchParams({response:responsePacked}).toString(),{status:200})
 }
 const options={vault,sealer,collections,gateway:{baseUrl,hostAuthorityDid,providerDid,responseIssuer:providerDid,resolveRecipientJwk:async did=>{assert.equal(did,providerDid);return peerKeys.encryption},resolveGatewaySigningJwk:async did=>{assert.equal(did,providerDid);return state.fault==='key'?{...peerKeys.signing,kid:'wrong-gateway-key'}:peerKeys.signing}},encounterAuthorization:{groupReference},triageRouting:{professionalGroupReference:groupReference,escalationGroupReference:`Group/${safe.demoOrganizationUuids.animalCare}`},fetchImpl,pollOptions:{intervalMs:0,timeoutMs:1000},now:()=>new Date(clock)}
 const input={ownerId,profileId,profileSessionToken:token,verifiedContact:contact,idToken:'synthetic-host-verified-token'}
 return {vault,sealer,profile,session,enrollment,authorization,task,state,options,input,client,peer,peerContext,clientSigning}
}

test('retains real AES PIN protection and actual signed/encrypted registered communication custody',async()=>{
 const s=await fixture();assert.equal(await api.openServerProfileSecret(s.profile.protectedWalletSeed,'fixture-742619',`${s.profile.profileId}:wallet-seed`,s.sealer),seed)
 const packed=await s.client.wallet.packForRecipientWithContext({iss:s.profile.actorDid,aud:providerDid,thid:'synthetic-control',body:{}},providerDid,{context:s.client.context}),opened=await s.peer.unpackWithContext(packed,{context:s.peerContext})
 assert.equal(await crypto.verifyJws(opened.meta.jws.compact,s.clientSigning),true)
})
test('lists fixed claims-first Task triage through real phone and email member custody without exposing secrets',async()=>{
 const Client=need()
 for(const kind of ['phone','email']){const s=await fixture(kind),client=new Client(s.options),rows=await client.listEmergencyTriageTasks(s.input)
  assert.equal(rows.length,1);assert.equal(rows[0].entry.reference,`Task/${taskId}`);assert.equal(rows[0].versionId,'7');assert.equal(rows[0].entry.claims[T.Owner],groupReference)
  assert.equal(s.state.requests[0].message.body.data[0].resource.meta.claims[T.Code],'triage')
  for(const secret of [seed,token,s.session.sealedWalletSeed])assert.equal(JSON.stringify(rows).includes(secret),false)
  assert.equal('submitAndPoll'in client,false);assert.equal('transport'in client,false)
 }
})
test('re-reads authoritative Task and applies one conditional claims-only transition with server-derived responder',async()=>{
 const Client=need(),s=await fixture(),result=await new Client(s.options).transitionEmergencyTriageTask(s.input,{taskReference:`Task/${taskId}`,action:'acknowledge'})
 assert.equal(result.entry.claims[T.Status],'accepted');assert.equal(result.entry.claims[T.Owner],`PractitionerRole/${clinicalId}`);assert.equal(result.previousVersionId,'7')
 assert.equal(s.state.mutations.length,1);const entry=s.state.mutations[0].body.data[0]
 assert.equal(entry.request.method,'PUT');assert.equal(entry.request.ifMatch,'W/"7"');assert.equal(entry.request.url,`Task/${taskId}`)
 assert.deepEqual(Object.keys(entry.resource).sort(),['id','meta','resourceType'])
})
test('rejects wrong owner, phone, PIN handle, expired session and stale credential revision before fetch',async()=>{
 const Client=need()
 for(const fault of ['owner','contact','token','expired','revision']){const s=await fixture(),input={...s.input}
  if(fault==='owner')input.ownerId='foreign-owner';if(fault==='contact')input.verifiedContact={contactKind:'phone',contact:safe.firstContactPhoneE164};if(fault==='token')input.profileSessionToken='not-a-current-session'
  if(fault==='expired')await s.vault.put(collections.walletSessions,{...s.session,expiresAt:'2020-01-01T00:00:00Z'})
  if(fault==='revision')await s.vault.put(collections.profiles,{...s.profile,credentialRevision:1})
  await assert.rejects(()=>new Client(s.options).listEmergencyTriageTasks(input));assert.equal(s.state.requests.length,0)
 }
})
test('requires current independent Encounter Consent, exact group/member/provider and both capabilities before fetch',async()=>{
 const Client=need()
 for(const patch of [{status:'inactive'},{providerDid:`${providerDid}:foreign`},{groupKind:Kind.SchedulingOperations},{groupReference:'Group/foreign'},{organizationReference:'Organization/foreign'},{memberPractitionerRoleReference:'PractitionerRole/foreign'},{capabilities:[Cap.EncounterCruds]}]){
  const s=await fixture();await s.vault.put(collections.workflowAuthorizations,{...s.authorization,...patch});await assert.rejects(()=>new Client(s.options).listEmergencyTriageTasks(s.input));assert.equal(s.state.requests.length,0)
 }
})
test('rejects controller mode, inactive employee, wrong clinical role and public-key tampering before fetch',async()=>{
 const Client=need()
 for(const fault of ['controller','inactive','role','key']){const s=await fixture(),p=structuredClone(s.profile)
  if(fault==='controller'){p.actorKind=ActorKinds.OrganizationController;p.actorMode='controller'}if(fault==='inactive')p.status='inactive';if(fault==='role')p.clinicalCreatorBinding.role='ISCO-08|2261';if(fault==='key'){const key=p.publicJwks.find(k=>k.alg==='ML-DSA-44');key.pub=Buffer.alloc(Buffer.from(key.pub,'base64url').length,9).toString('base64url')}
  await s.vault.put(collections.profiles,p);await assert.rejects(()=>new Client(s.options).listEmergencyTriageTasks(s.input));assert.equal(s.state.requests.length,0)
 }
})
test('fails closed on wrong signed GW key, issuer, audience or correlation thread',async()=>{
 const Client=need()
 for(const fault of ['key','issuer','audience','thread']){const s=await fixture();s.state.fault=fault;await assert.rejects(()=>new Client(s.options).listEmergencyTriageTasks(s.input));assert.equal(s.state.mutations.length,0)}
})
test('rejects native FHIR siblings, non-scalar Task claims and missing Task version before update',async()=>{
 const Client=need()
 for(const fault of ['native','nested','version','owner']){const s=await fixture();s.state.fault=fault;await assert.rejects(()=>new Client(s.options).transitionEmergencyTriageTask(s.input,{taskReference:`Task/${taskId}`,action:'acknowledge'}));assert.equal(s.state.mutations.length,0)}
})
test('never claims a mutation after GW-owned licence denial or a conditional version conflict',async()=>{
 const Client=need()
 for(const fault of ['licence','conflict']){const s=await fixture();s.state.fault=fault;await assert.rejects(()=>new Client(s.options).transitionEmergencyTriageTask(s.input,{taskReference:`Task/${taskId}`,action:'acknowledge'}));assert.equal(s.state.mutations.length,0)}
})
test('rechecks current profile/PIN and Consent after asynchronous request/response work before releasing results',async()=>{
 const Client=need()
 for(const fault of ['profile','consent']){const s=await fixture();s.state.afterReceive=async()=>{if(fault==='profile')await s.vault.put(collections.profiles,{...s.profile,credentialRevision:1});else await s.vault.put(collections.workflowAuthorizations,{...s.authorization,status:'inactive'})};await assert.rejects(()=>new Client(s.options).listEmergencyTriageTasks(s.input));assert.equal(s.state.mutations.length,0)}
})
test('does not admit arbitrary route/resource/action fields or _delete under the fixed triage command',async()=>{
 const Client=need()
 for(const command of [{taskReference:`Task/${taskId}`,action:'_delete'},{taskReference:`Task/${taskId}`,action:'acknowledge',path:'/arbitrary',resourceType:'Group'},{taskReference:'Task/../Group/foreign',action:'acknowledge'}]){const s=await fixture();await assert.rejects(()=>new Client(s.options).transitionEmergencyTriageTask(s.input,command));assert.equal(s.state.requests.length,0)}
})

test('admits the operational Encounter Consent independently of the distinct department triage queue',async()=>{
 const Client=need(),s=await fixture(),workflowGroupReference=`Group/${Kind.EncounterOperations}-synthetic-operational-group`
 assert.notEqual(workflowGroupReference,groupReference)
 await s.vault.put(collections.workflowAuthorizations,{...s.authorization,groupReference:workflowGroupReference})
 const options={...s.options,encounterAuthorization:{groupReference:workflowGroupReference}},client=new Client(options)
 const rows=await client.listEmergencyTriageTasks(s.input)
 assert.equal(rows[0].entry.claims[T.Owner],groupReference)
 const result=await client.transitionEmergencyTriageTask(s.input,{taskReference:`Task/${taskId}`,action:'acknowledge'})
 assert.equal(result.entry.claims[T.Owner],`PractitionerRole/${clinicalId}`)
 assert.equal(s.state.mutations.length,1)
})

test('does not substitute the department queue for the separately configured operational Consent group',async()=>{
 const Client=need(),s=await fixture(),workflowGroupReference=`Group/${Kind.EncounterOperations}-synthetic-operational-group`
 const client=new Client({...s.options,encounterAuthorization:{groupReference:workflowGroupReference}})
 // The stored record still names the queue group, not the admitted operational group.
 await assert.rejects(()=>client.listEmergencyTriageTasks(s.input))
 assert.equal(s.state.requests.length,0)
 assert.equal(s.state.mutations.length,0)
})

test('does not treat the operational Consent group as a department Task owner after valid independent admission',async()=>{
 const Client=need(),s=await fixture(),workflowGroupReference=`Group/${Kind.EncounterOperations}-synthetic-operational-group`
 await s.vault.put(collections.workflowAuthorizations,{...s.authorization,groupReference:workflowGroupReference})
 s.task.meta.claims[T.Owner]=workflowGroupReference
 const client=new Client({...s.options,encounterAuthorization:{groupReference:workflowGroupReference}})
 await assert.rejects(()=>client.transitionEmergencyTriageTask(s.input,{taskReference:`Task/${taskId}`,action:'acknowledge'}))
 assert.ok(s.state.requests.some(row=>row.path===prefix+'/_search'),'valid operational admission must reach the authoritative Task read')
 assert.equal(s.state.mutations.length,0)
})
