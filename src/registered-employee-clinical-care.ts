import {createHash,randomUUID} from 'node:crypto'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import type {ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import type {PublicJwk} from 'antifraud-data-utils-ts/cryptography'
import type {FlatClaimResourceEntry} from 'fhir-data-utils-ts/flat-claim-resource-graph'
import {TaskClaim} from 'fhir-data-utils-ts/claims'
import {OrganizationWorkflowCapabilities as Cap,OrganizationWorkflowGroupKinds as Kind} from 'sos-data-utils-ts/organization-workflow-access'
import type {PollOptions} from 'sos-data-utils-ts/gateway-transport-contract'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
import {buildTenantResourceActionPath} from 'sos-sdk-core-ts/gateway-routing'
import {extractBundleSearchResources} from 'sos-sdk-core-ts/gateway-response-reader'
import {readEmergencyTriageTask,transitionEmergencyTriageTask,type EmergencyTriageAction} from 'sos-sdk-core-ts/care-emergency-alert-orchestration'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import {resolveRegisteredEmployeeDraftRequester,RegisteredEmployeeDraftRequesterDeniedError} from './registered-employee-draft-requester.js'
import {openRegisteredCommunicationWallet} from './registered-communication-wallet.js'
import {RegisteredGatewayTransport,createVerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import {own,text,pick,json,fingerprint,profileFields,sessionFields,StoredProfileStateInvalidError} from './stored-profile-state.js'

type Row=Record<string,unknown>
export type RegisteredEmployeeClinicalCareInput=Readonly<{
 ownerId:string;profileId:string;profileSessionToken:string;verifiedContact:ActorContactInput;idToken:string
}>
export type RegisteredEmployeeClinicalCareOptions=Readonly<{
 vault:TransactionalVaultRepository;sealer:ServerProfileSealer
 collections:Readonly<{profiles:string;walletSessions:string;enrollmentGrants:string;workflowAuthorizations:string}>
 gateway:Readonly<{
  baseUrl:string;hostAuthorityDid:string;providerDid:string;responseIssuer:string
  resolveRecipientJwk:(did:string)=>Promise<Readonly<Record<string,unknown>>>
  resolveGatewaySigningJwk:(did:string)=>Promise<PublicJwk>
 }>
 /** Expected operational workflow group from trusted host policy, separate from Task routing. */
 encounterAuthorization:Readonly<{groupReference:string}>
 /** Trusted host routing; no browser-provided group or escalation target. */
 triageRouting:Readonly<{professionalGroupReference:string;escalationGroupReference?:string}>
 fetchImpl?:typeof fetch;pollOptions?:PollOptions;now?:()=>Date
}>
export type RegisteredEmployeeClinicalTask=Readonly<{entry:FlatClaimResourceEntry;versionId:string}>
export type RegisteredEmployeeTriageCommand=Readonly<{taskReference:string;action:EmergencyTriageAction}>
export class RegisteredEmployeeClinicalCareDeniedError extends Error{
 constructor(readonly reason:string='binding_denied',readonly status=403){super(`registered_employee_clinical_care_${reason}`)}
}
const denied=(reason='binding_denied',status=403)=>new RegisteredEmployeeClinicalCareDeniedError(reason,status)
const same=(a:unknown,b:unknown)=>fingerprint(a)===fingerprint(b)
function fields(value:unknown,allowed:readonly string[]):Row{const data=own(value);if(Object.keys(data).some(key=>!allowed.includes(key)))throw denied();return data}
function reference(value:unknown,kind:string):string{const v=text(value);if(!new RegExp(`^${kind}/[A-Za-z0-9][A-Za-z0-9.-]{0,63}$`,'u').test(v))throw denied('reference_invalid');return v}
function segment(value:unknown):string{const v=text(value,512);if(!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(v))throw denied('route_invalid');return v}
const profileSnapshotFields=[...profileFields,'status']
type Snapshot={profile:Row;session:Row;enrollments:Row[];authorization:Row;responder:string;route:{tenantId:string;jurisdiction:string;sector:string}}
type OpenedClinicalCare={before:Snapshot;exchange:(action:'_search'|'_batch',body:Row)=>Promise<unknown>;guard:()=>Promise<void>}

/**
 * Fixed Task triage for a registered employee. Recorded DCR identity is only
 * a custody prerequisite; current local Encounter Consent is separate, and
 * GW remains authoritative for clinical permissions and active licences.
 * No path/resource/action transport escape hatch, controller admission,
 * patient discovery, handover, scheduling, campaigns or RTC issuance exists.
 * The HTTP peer may be injected for protocol tests; this is not online GW proof.
 */
export class RegisteredEmployeeClinicalCareClient{
 readonly #options:RegisteredEmployeeClinicalCareOptions
 constructor(options:RegisteredEmployeeClinicalCareOptions){
  const names=Object.values(options.collections).map(v=>text(v));if(new Set(names).size!==4)throw denied('collections_invalid')
  const gateway={...options.gateway},url=new URL(text(gateway.baseUrl))
  if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))))throw denied('gateway_invalid')
  if(!text(gateway.providerDid).startsWith('did:web:')||gateway.responseIssuer!==gateway.providerDid)throw denied('gateway_binding_invalid')
  if(typeof gateway.resolveRecipientJwk!=='function'||typeof gateway.resolveGatewaySigningJwk!=='function')throw denied('gateway_binding_invalid')
  reference(options.triageRouting.professionalGroupReference,'Group')
  const encounterGroupReference=reference(options.encounterAuthorization?.groupReference,'Group')
  if(options.triageRouting.escalationGroupReference!==undefined)reference(options.triageRouting.escalationGroupReference,'Group')
  this.#options=Object.freeze({...options,collections:Object.freeze({...options.collections}),gateway:Object.freeze({...gateway,baseUrl:url.href.replace(/\/+$/u,'')}),encounterAuthorization:Object.freeze({groupReference:encounterGroupReference}),triageRouting:Object.freeze({...options.triageRouting}),pollOptions:Object.freeze({...options.pollOptions})})
 }
 #now(){const date=this.#options.now?.()??new Date();if(!(date instanceof Date)||!Number.isFinite(date.getTime()))throw denied('clock_invalid');return date}
 #input(value:RegisteredEmployeeClinicalCareInput){
  try{
  const raw=fields(value,['ownerId','profileId','profileSessionToken','verifiedContact','idToken'])
  if(typeof raw.profileSessionToken!=='string'||!raw.profileSessionToken.trim())throw denied('wallet_session_required',401)
  const ownerId=text(raw.ownerId),profileId=text(raw.profileId),profileSessionToken=text(raw.profileSessionToken),idToken=text(raw.idToken,65536)
  if(/[\/\\]/u.test(profileId)||!/^[A-Za-z0-9_-]{43}$/u.test(profileSessionToken)||Buffer.from(profileSessionToken,'base64url').toString('base64url')!==profileSessionToken)throw denied()
  const contact=fields(raw.verifiedContact,['contactKind','contact']);if(contact.contactKind!=='phone'&&contact.contactKind!=='email')throw denied()
  return {ownerId,profileId,profileSessionToken,idToken,verifiedContact:{contactKind:contact.contactKind,contact:text(contact.contact)} as ActorContactInput}
  }catch(error){
   if(error instanceof StoredProfileStateInvalidError)throw denied('input_invalid',400)
   throw error
  }
 }
 async #open(value:RegisteredEmployeeClinicalCareInput):Promise<OpenedClinicalCare>{
  try{
  const input=this.#input(value),options=this.#options,names=options.collections,sessionId=createHash('sha256').update(input.profileSessionToken).digest('hex')
  const capture=async(port:IVaultRepository):Promise<Snapshot>=>{
   const rawProfile=await port.get<Row&{id:string}>(names.profiles,input.profileId)
   const profile=pick(own(rawProfile),profileSnapshotFields)
   const rawSession=await port.get<Row&{id:string}>(names.walletSessions,sessionId),session=pick(own(rawSession),sessionFields)
   if(profile.id!==input.profileId||profile.profileId!==input.profileId||profile.ownerId!==input.ownerId||profile.actorKind!==ActorKinds.OrganizationEmployee||profile.actorMode!=='member'||profile.status!==undefined&&profile.status!=='active')throw denied()
   if(profile.providerDid!==options.gateway.providerDid||session.id!==sessionId||session.ownerId!==input.ownerId||session.profileId!==input.profileId)throw denied()
   const expiry=Date.parse(text(session.expiresAt));if(!Number.isFinite(expiry)||expiry<=this.#now().getTime())throw denied('session_expired')
   const routeRaw=fields(profile.routeContext,['tenantId','jurisdiction','sector']),route={tenantId:segment(routeRaw.tenantId),jurisdiction:segment(routeRaw.jurisdiction),sector:segment(routeRaw.sector)}
   const creator=fields(profile.clinicalCreatorBinding,['authorIdentifier','role']),author=text(creator.authorIdentifier)
   if(!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(author))throw denied('clinical_creator_invalid')
   const responder=reference(`PractitionerRole/${author.slice('urn:uuid:'.length)}`,'PractitionerRole');text(creator.role)
   const grantId=(identity:string)=>createHash('sha256').update(identity).update('\0').update(Kind.EncounterOperations).digest('base64url')
   const rawAuthorization=await port.get<Row&{id:string}>(names.workflowAuthorizations,grantId(input.profileId))??await port.get<Row&{id:string}>(names.workflowAuthorizations,grantId(responder))
   const authorization=own(json(rawAuthorization))
   if(authorization.providerDid!==profile.providerDid||authorization.profileId!==undefined&&authorization.profileId!==input.profileId||authorization.status!=='active'||authorization.groupKind!==Kind.EncounterOperations||authorization.organizationReference!==`Organization/${route.tenantId}`||authorization.memberPractitionerRoleReference!==responder||authorization.groupReference!==options.encounterAuthorization.groupReference||!Array.isArray(authorization.capabilities)||!authorization.capabilities.includes(Cap.EncounterCruds)||!authorization.capabilities.includes(Cap.EncounterHistoryCruds))throw denied('current_encounter_consent_required')
   text(authorization.consentId);reference(authorization.groupReference,'Group')
   const enrollments=(await port.query<Row&{id:string}>(names.enrollmentGrants,{where:[{attribute:'employeeDid',equals:text(profile.actorDid)}]})).map(value=>own(json(value))).sort((a,b)=>text(a.id).localeCompare(text(b.id)))
   return {profile,session,enrollments,authorization,responder,route}
  }
  const before=await options.vault.runTransaction(capture)
  const identity=await resolveRegisteredEmployeeDraftRequester({vault:options.vault,sealer:options.sealer,collections:{profiles:names.profiles,walletSessions:names.walletSessions,enrollmentGrants:names.enrollmentGrants},gatewayBaseUrl:options.gateway.baseUrl,hostAuthorityDid:options.gateway.hostAuthorityDid,now:()=>this.#now()},{ownerId:input.ownerId,profileId:input.profileId,profileSessionToken:input.profileSessionToken,verifiedContact:input.verifiedContact})
  const creator=own(before.profile.clinicalCreatorBinding)
  if(identity.recordedRole!==creator.role||identity.actorDid!==before.profile.actorDid||identity.clientId!==before.profile.clientId||!same(identity.routeContext,before.route))throw denied('clinical_creator_invalid')
  const guard=async()=>{await options.vault.runTransaction(async port=>{const current=await capture(port);if(!same(current,before))throw denied('changed_or_revoked')})}
  await guard()
  const seed=await options.sealer.unseal(text(before.session.sealedWalletSeed),`${input.ownerId}:${input.profileId}:${sessionId}:wallet-session-seed`)
  const communication=await openRegisteredCommunicationWallet({walletKeyDerivationId:text(before.profile.walletKeyDerivationId??input.profileId),unlockedWalletSeed:seed,registeredPublicJwks:before.profile.publicJwks as readonly Readonly<Record<string,unknown>>[],resolveRecipientJwk:options.gateway.resolveRecipientJwk})
  await guard()
  const adapter=createVerifiedGatewaySecureAdapter({gatewayDid:options.gateway.providerDid,pack:message=>communication.wallet.packForRecipientWithContext(message,options.gateway.providerDid,{context:communication.context}),decrypt:packed=>communication.wallet.unpackWithContext(packed,{context:communication.context}),resolveGatewaySigningJwk:options.gateway.resolveGatewaySigningJwk,errorPrefix:'registered_employee_clinical_care'})
  const secure=Object.freeze({gatewayDid:adapter.gatewayDid,pack:async(message:Row)=>{await guard();const result=await adapter.pack(message);await guard();return result},unpackVerified:async(packed:string)=>{await guard();const result=await adapter.unpackVerified(packed);await guard();return result}})
  const transport=new RegisteredGatewayTransport({baseUrl:options.gateway.baseUrl,bearerToken:input.idToken,fetchImpl:options.fetchImpl,secureTransportAdapter:secure,errorPrefix:'registered_employee_clinical_care',submitError:status=>denied('gateway_denied',status)})
  const path=(action:'_search'|'_batch')=>buildTenantResourceActionPath({...before.route,version:'v1',section:'organization',format:'org.hl7.fhir.r5',resourceType:'Task',action})
  const exchange=async(action:'_search'|'_batch',body:Row)=>{
   await guard();const thid=`clinical-triage-${randomUUID()}`,payload={thid,jti:thid,iss:identity.actorDid,aud:options.gateway.providerDid,client_id:identity.clientId,body}
   const result=await transport.exchange(path(action),payload,options.gateway.responseIssuer,options.pollOptions);await guard();return result.poll.body
  }
  return {before,exchange,guard}
  }catch(error){
   if(error instanceof StoredProfileStateInvalidError||error instanceof RegisteredEmployeeDraftRequesterDeniedError)throw denied()
   throw error
  }
 }
 #tasks(body:unknown):readonly RegisteredEmployeeClinicalTask[]{
  const rows=extractBundleSearchResources(body),result:RegisteredEmployeeClinicalTask[]=[],seen=new Set<string>()
  for(const candidate of rows){
   const resource=own(candidate);if(resource.resourceType!=='Task')throw denied('task_resource_required',502)
   fields(resource,['resourceType','id','meta']);const id=text(resource.id),ref=reference(`Task/${id}`,'Task');if(seen.has(ref))throw denied('task_ambiguous',502);seen.add(ref)
   const meta=fields(resource.meta,['claims']),raw=own(meta.claims),claims:Record<string,string>={}
   for(const [name,value]of Object.entries(raw)){
    if(!name.startsWith('Task.'))throw denied('task_claims_required',502)
    const scalar=Array.isArray(value)&&value.length===1?value[0]:value
    if(typeof scalar!=='string'||!scalar)throw denied('task_scalar_claim_required',502)
    claims[name]=scalar
   }
   if(claims[TaskClaim.Code]!=='triage')throw denied('triage_task_required',502)
   const entry:FlatClaimResourceEntry=Object.freeze({entryId:id,reference:ref,resourceType:'Task',claims:Object.freeze(claims)})
   readEmergencyTriageTask(entry)
   const versionId=text(claims['Task.meta.versionId']);if(!/^[A-Za-z0-9.-]{1,128}$/u.test(versionId))throw denied('task_version_required',502)
   result.push(Object.freeze({entry,versionId}))
  }
  return Object.freeze(result)
 }
 async #read(opened:OpenedClinicalCare):Promise<readonly RegisteredEmployeeClinicalTask[]>{
  const body=await opened.exchange('_search',{resourceType:'Bundle',type:'batch',data:[{resource:{resourceType:'Task',id:'search',meta:{claims:{[TaskClaim.Code]:'triage'}}}}]})
  return this.#tasks(body).filter(({entry})=>[this.#options.triageRouting.professionalGroupReference,opened.before.responder].includes(readEmergencyTriageTask(entry).ownerReference))
 }
 async listEmergencyTriageTasks(input:RegisteredEmployeeClinicalCareInput):Promise<readonly RegisteredEmployeeClinicalTask[]>{
  const opened=await this.#open(input),rows=await this.#read(opened);await opened.guard();return rows
 }
 async transitionEmergencyTriageTask(input:RegisteredEmployeeClinicalCareInput,command:RegisteredEmployeeTriageCommand):Promise<Readonly<{entry:FlatClaimResourceEntry;previousVersionId:string}>>{
  const raw=fields(command,['taskReference','action']),taskReference=reference(raw.taskReference,'Task'),action=text(raw.action)
  if(!['acknowledge','start','escalate','reject','complete'].includes(action))throw denied('triage_action_invalid',400)
  const opened=await this.#open(input),row=(await this.#read(opened)).find(task=>task.entry.reference===taskReference)
  if(!row)throw denied('triage_task_not_found',404)
  const current=readEmergencyTriageTask(row.entry),routing=this.#options.triageRouting
  if(current.ownerReference!==(action==='acknowledge'?routing.professionalGroupReference:opened.before.responder))throw denied('triage_owner_required')
  const entry=transitionEmergencyTriageTask({taskEntry:row.entry,action:action as EmergencyTriageAction,responderReference:opened.before.responder,...(action==='escalate'?{escalationOwnerReference:reference(routing.escalationGroupReference,'Group')}:{}),occurredAt:this.#now().toISOString()})
  await opened.exchange('_batch',{resourceType:'Bundle',type:'batch',data:[{type:'Task-v5.0.0',id:entry.entryId,resource:{resourceType:'Task',id:entry.entryId,meta:{claims:entry.claims}},request:{method:'PUT',url:entry.reference,ifMatch:`W/"${row.versionId}"`}}]})
  await opened.guard();return Object.freeze({entry,previousVersionId:row.versionId})
 }
}
