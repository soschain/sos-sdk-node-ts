import {createHash} from 'node:crypto'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import {buildAuthorityDidWeb,buildOrganizationEmployeeDidWeb,normalizeActorContact,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import type {RegisteredEmployeeDraftRequester} from 'sos-data-utils-ts/registered-employee-draft-requester-contract'
import {EmployeeActivationGrantVersions} from 'sos-data-utils-ts/employee-routing'
import {PROFILE_SECRET_ENVELOPE_VERSION} from 'sos-data-utils-ts/server-profile-secret-contract'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import type {PortableProfessionalProvider} from './portable-professional-evidence.js'
import {employeeActivationGrantMatchesContact} from './employee-activation-grant.js'
import {openServerProfileCustodyKeys} from './server-profile-custody-keys.js'
import {own,text,json,pick,fingerprint,revision,profileFields,sessionFields,StoredProfileStateInvalidError} from './stored-profile-state.js'

type Row=Record<string,unknown>
/** A fixed admission denial; backend/KMS operational errors remain distinct. */
export class RegisteredEmployeeDraftRequesterDeniedError extends Error{
 constructor(){super('registered_employee_draft_requester_denied')}
}
const denied=()=>new RegisteredEmployeeDraftRequesterDeniedError()
export type RegisteredEmployeeDraftRequesterOptions=Readonly<{
 vault:TransactionalVaultRepository
 sealer:ServerProfileSealer
 collections:Readonly<{profiles:string;walletSessions:string;enrollmentGrants:string}>
 /** Host configuration only. Never populate this catalog from a request body. */
 providers:readonly PortableProfessionalProvider[]
 hostAuthorityDid:string
 now?:()=>Date
}>
export type RegisteredEmployeeDraftRequesterInput=Readonly<{
 ownerId:string
 profileId:string
 profileSessionToken:string
 /** Firebase/contact possession has already been verified by the trusted host. */
 verifiedContact:ActorContactInput
}>
const grantFields=['id','version','employeeDid','employeeRoleCode','employeeActorIdentifier','providerDid','routeContext','createdAt','expiresAt','consumedEnrollments','tenantIssuer','accessPath'] as const
function route(value:unknown){const data=own(value);return {tenantId:text(data.tenantId),jurisdiction:text(data.jurisdiction),sector:text(data.sector)}}
function sameRoute(left:ReturnType<typeof route>,right:ReturnType<typeof route>){return left.tenantId===right.tenantId&&left.jurisdiction===right.jurisdiction&&left.sector===right.sector}
/** Namespace boundary only: full SOS organization-DID profile validation is separate. */
function namespace(providerDid:string,authority:string):void{
 const prefix=`${authority}:`
 if(!providerDid.startsWith(prefix)||/[/?#\\\s]/u.test(providerDid))throw denied()
 for(const part of providerDid.slice(prefix.length).split(':')){
  let decoded:string
  try{decoded=decodeURIComponent(part)}catch{throw denied()}
  if(!decoded||decoded==='.'||decoded==='..'||/[/?#\\\s]/u.test(decoded))throw denied()
 }
}

/**
 * Projects recorded enrollment identity for a pending permission proposal.
 * It does not return current employment, licence, SMART or Consent authority.
 */
export async function resolveRegisteredEmployeeDraftRequester(options:RegisteredEmployeeDraftRequesterOptions,input:RegisteredEmployeeDraftRequesterInput):Promise<RegisteredEmployeeDraftRequester>{
 try{return await resolve(options,input)}catch(error){if(error instanceof StoredProfileStateInvalidError)throw denied();throw error}
}
async function resolve(options:RegisteredEmployeeDraftRequesterOptions,input:RegisteredEmployeeDraftRequesterInput):Promise<RegisteredEmployeeDraftRequester>{
 const vault=options.vault,sealer=options.sealer,now=options.now,authority=text(options.hostAuthorityDid)
 const values=own(input)
 if(Object.keys(values).some(name=>!['ownerId','profileId','profileSessionToken','verifiedContact'].includes(name)))throw denied()
 const ownerId=text(values.ownerId),profileId=text(values.profileId),token=text(values.profileSessionToken)
 if(/[\/\\]/u.test(profileId))throw denied()
 if(!/^[A-Za-z0-9_-]{43}$/u.test(token)||Buffer.from(token,'base64url').toString('base64url')!==token)throw denied()
 const sessionId=createHash('sha256').update(token,'utf8').digest('hex')
 const contactValue=own(values.verifiedContact)
 if(contactValue.contactKind!=='email'&&contactValue.contactKind!=='phone')throw denied()
 const contact:ActorContactInput=Object.freeze({contactKind:contactValue.contactKind,contact:normalizeActorContact({contactKind:contactValue.contactKind,contact:text(contactValue.contact)})})
 const names=own(options.collections),collections={profiles:text(names.profiles),walletSessions:text(names.walletSessions),enrollmentGrants:text(names.enrollmentGrants)}
 if(new Set(Object.values(collections)).size!==3)throw denied()
 const catalogValue=json(options.providers)
 if(!Array.isArray(catalogValue)||!catalogValue.length)throw denied()
 const catalog=catalogValue.map(value=>{
  const entry=own(value),url=new URL(text(entry.baseUrl))
  if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))))throw denied()
  return {authority:buildAuthorityDidWeb({authority:url.origin}),route:route(entry)}
 })
 const clock=()=>{const date=now?.()??new Date();if(!(date instanceof Date)||!Number.isFinite(date.getTime()))throw denied();return date.getTime()}
 async function capture(port:IVaultRepository){
  const [rawProfile,rawSession]=await Promise.all([port.get<Row&{id:string}>(collections.profiles,profileId),port.get<Row&{id:string}>(collections.walletSessions,sessionId)])
  const profile=pick(own(rawProfile),profileFields),session=pick(own(rawSession),sessionFields)
  if(profile.id!==profileId||profile.profileId!==profileId||profile.ownerId!==ownerId||profile.actorKind!==ActorKinds.OrganizationEmployee||profile.actorMode!=='member')throw denied()
  const actorDid=text(profile.actorDid),providerDid=text(profile.providerDid),context=route(profile.routeContext)
  if(profile.profileDid!==actorDid||profile.confidentialStorageProfile!=='confidential-pqc-v1')throw denied()
  namespace(providerDid,authority)
  if(catalog.filter(entry=>entry.authority===authority&&sameRoute(entry.route,context)).length!==1)throw denied()
  text(profile.clientId);const installation=text(profile.clientInstanceId);text(profile.deviceDid)
  if(session.id!==sessionId||session.ownerId!==ownerId||session.profileId!==profileId||revision(session.credentialRevision)!==revision(profile.credentialRevision))throw denied()
  const deadline=Date.parse(text(session.expiresAt))
  if(!Number.isFinite(deadline)||deadline<=clock())throw denied()
  if(!Number.isSafeInteger(profile.failedUnlocks)||Number(profile.failedUnlocks)<0)throw denied()
  if(profile.lockedUntil!==undefined){const locked=Date.parse(text(profile.lockedUntil));if(!Number.isFinite(locked)||locked>clock())throw denied()}
  if(own(profile.protectedWalletSeed).version!==PROFILE_SECRET_ENVELOPE_VERSION||!Array.isArray(profile.publicJwks))throw denied()
  const records=await port.query<Row&{id:string}>(collections.enrollmentGrants,{where:[{attribute:'employeeDid',equals:actorDid}]})
  const matches:Row[]=[]
  for(const raw of records){
   const grant=pick(own(raw),grantFields)
   if(grant.consumedEnrollments===undefined)continue
   if(!Array.isArray(grant.consumedEnrollments))throw denied()
   const consumed=grant.consumedEnrollments.map(own).filter(value=>value.ownerId===ownerId&&value.profileId===profileId&&value.clientInstanceId===installation)
   if(consumed.length>1)throw denied()
   if(consumed.length===1)matches.push(grant)
  }
  if(matches.length!==1)throw denied()
  const grant=matches[0]!
  text(grant.id)
  if(grant.version!==EmployeeActivationGrantVersions.V1||grant.employeeDid!==actorDid||grant.providerDid!==providerDid||!sameRoute(route(grant.routeContext),context)||grant.tenantIssuer!==profile.tenantIssuer)throw denied()
  if(grant.accessPath!==undefined&&grant.accessPath!=='test-network')throw denied()
  // These dates validate the retained invitation record, not current access.
  // Its completed DCR tuple remains usable after invitation expiry.
  const created=Date.parse(text(grant.createdAt)),expired=Date.parse(text(grant.expiresAt))
  if(!Number.isFinite(created)||!Number.isFinite(expired)||expired<=created)throw denied()
  const recordedRole=text(grant.employeeRoleCode)
  if(!employeeActivationGrantMatchesContact({employeeActorIdentifier:text(grant.employeeActorIdentifier)},contact)||buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role:recordedRole})!==actorDid)throw denied()
  return {profile,session,grant,context,actorDid,providerDid,recordedRole}
 }
 const before=await vault.runTransaction(capture)
 const seed=await sealer.unseal(text(before.session.sealedWalletSeed),`${ownerId}:${profileId}:${sessionId}:wallet-session-seed`)
 if(typeof seed!=='string'||!/^[A-Za-z0-9_-]{43}$/u.test(seed)||Buffer.from(seed,'base64url').toString('base64url')!==seed)throw denied()
 const publicJwks=before.profile.publicJwks
 if(!Array.isArray(publicJwks))throw denied()
 try{
  await openServerProfileCustodyKeys({walletKeyDerivationId:text(before.profile.walletKeyDerivationId??profileId,512),unlockedWalletSeed:seed,binding:{kind:'registered',publicJwks:publicJwks.map(own),storagePublicJwk:own(before.profile.storagePublicJwk)}})
 }catch(error){if(error instanceof TypeError&&error.message==='server_profile_custody_binding_invalid')throw denied();throw error}
 await vault.runTransaction(async port=>{const current=await capture(port);if(fingerprint(before)!==fingerprint(current))throw denied()})
 return Object.freeze({ownerId,profileId,actorDid:before.actorDid,providerDid:before.providerDid,routeContext:Object.freeze({...before.context}),clientId:text(before.profile.clientId),clientInstanceId:text(before.profile.clientInstanceId),recordedRole:before.recordedRole})
}
