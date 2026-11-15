import {createHash,createPublicKey,randomBytes,randomUUID,verify} from 'node:crypto'
import {CryptographyService,type PublicJwk} from 'antifraud-data-utils-ts/cryptography'
import {normalizeUuid} from 'antifraud-data-utils-ts/organization-identity'
import {CompositionAttesterModes} from 'fhir-data-utils-ts'
import type {RegisteredProfileBinding,RegisteredProfileRecord,RegisteredProfileSessionRecord,RegisteredProfileAuthorizedSubject} from 'sos-data-utils-ts/registered-profile-contract'
import type {PollOptions} from 'sos-data-utils-ts/gateway-transport-contract'
import {buildScopeSmartCompositionAccess} from 'sos-data-utils-ts/consent-smart-scopes'
import {RegisteredProfileSessions,type RegisteredProfileSessionsOptions} from './registered-profile-sessions.js'
import {RegisteredGatewayTransport,createVerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import {openRegisteredCommunicationWallet} from './registered-communication-wallet.js'
import {SosGatewaySubjectDirectoryClient,type AuthorizedIndividualSubject,type AuthorizedSubjectVerifiedContact} from './subject-card-directory-client.js'
import type {RegisteredSmartTokenAlgorithm} from './registered-did-keys.js'

export type RegisteredProfileAccessOptions=RegisteredProfileSessionsOptions&Readonly<{
 gateway:Readonly<{
  baseUrl:string
  providerDid:string
  responseIssuer:string
  resolveRecipientJwk:(did:string)=>Promise<Readonly<Record<string,unknown>>>
  resolveGatewaySigningJwk:(did:string)=>Promise<PublicJwk>
  /** Host-selected SMART method/algorithm; never inferred from token headers. */
  smartTokenVerification:Readonly<{algorithm:RegisteredSmartTokenAlgorithm;resolveSigningJwk:(providerDid:string)=>Promise<PublicJwk>}>
 }>
 fetchImpl?:typeof fetch
 pollOptions?:PollOptions
}>
type SessionInput=RegisteredProfileBinding&Readonly<{sessionId:string}>
type AuthInput=SessionInput&Readonly<{idToken:string}>
type Session=RegisteredProfileSessionRecord&{id:string}
type Profile=RegisteredProfileRecord&{id:string}
export type RegisteredProfileView=Omit<RegisteredProfileRecord,'protectedWalletSeed'|'protectedVpToken'|'failedUnlocks'|'lockedUntil'|'allowedSubjectDids'>&Readonly<{allowedSubjectDids:readonly string[]}>
type Opened=Awaited<ReturnType<RegisteredProfileSessions['resolve']>>
const denied=()=>new Error('registered_profile_access_binding_denied')
const changed=()=>new Error('registered_profile_access_changed_or_revoked')
function record(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value))throw denied()
 const result:Record<string,unknown>=Object.create(null)
 for(const [name,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){if(!('value' in descriptor))throw denied();result[name]=descriptor.value}
 return result
}
function text(value:unknown):string{
 if(typeof value!=='string'||!value||value.trim()!==value||value.length>65536)throw denied()
 return value
}
const equal=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b)
function scope(value:string,subject:string){
 const question=value.indexOf('?'),head=value.slice(0,question),query=new URLSearchParams(value.slice(question+1))
 const keys=[...query.keys()]
 if(question<0||!/^organization\/Composition\.(r|rs|cruds)$/u.test(head)||query.get('subject')!==subject||keys.some(key=>key!=='subject'&&key!=='section')||new Set(keys).size!==keys.length)throw denied()
 const sections=(query.get('section')??'').split(',').filter(Boolean)
 if(!sections.length||new Set(sections).size!==sections.length)throw denied()
 return {head,sections}
}

/**
 * Host-only registered individual-controller use case. Directory discovery is
 * not Consent: only a separately verified SMART grant can populate a selected
 * clinical session. Authentication/contact verification remain host duties.
 */
export class RegisteredProfileAccess{
 private readonly sessions:RegisteredProfileSessions
 private readonly options:RegisteredProfileAccessOptions
 private readonly baseUrl:string
 private readonly crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value,'utf8').digest('hex'),randomUUID})
 constructor(options:RegisteredProfileAccessOptions){
  const gateway={...options.gateway,smartTokenVerification:Object.freeze({...options.gateway.smartTokenVerification})},url=new URL(gateway.baseUrl)
  if((url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname)))||url.username||url.password||url.search||url.hash)throw denied()
  if(!text(gateway.providerDid).startsWith('did:web:')||gateway.responseIssuer!==gateway.providerDid)throw denied()
  if(!['ES384','ES256','ML-DSA-44','ML-DSA-65','ML-DSA-87'].includes(gateway.smartTokenVerification.algorithm)||typeof gateway.smartTokenVerification.resolveSigningJwk!=='function')throw denied()
  this.baseUrl=url.href.replace(/\/+$/u,'')
  this.options={...options,collections:Object.freeze({...options.collections}),gateway:Object.freeze(gateway),pollOptions:Object.freeze({...options.pollOptions})}
  this.sessions=new RegisteredProfileSessions(this.options)
 }
 private now(){const value=this.options.now?.()??new Date();if(!Number.isFinite(value.getTime()))throw denied();return value}
 private route(binding:Pick<RegisteredProfileBinding,'providerDid'|'routeContext'>):string{
  if(binding.providerDid!==this.options.gateway.providerDid)throw denied()
  const {tenantId,jurisdiction,sector}=binding.routeContext
  if(!/^[-a-zA-Z0-9]+$/u.test(tenantId)||!/^\p{L}{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(jurisdiction)||!/^[-a-z0-9]+$/u.test(sector))throw denied()
  return `/${tenantId}/cds-${jurisdiction}/v1/${sector}`
 }
 private admit(profile:RegisteredProfileRecord){
  if(profile.actorKind!=='individual_controller'||!['self','controller'].includes(profile.actorMode))throw denied()
  text(profile.clientId)
 }
 private profileView(profile:Profile,session?:Session):RegisteredProfileView{
  // Never let a base profile's relationship override this card's assignment.
  // Select public fields explicitly so host-only extension fields in a vault
  // row cannot escape along with the two known protected envelopes.
  const publicProfile:RegisteredProfileView={ownerId:profile.ownerId,profileId:profile.profileId,actorDid:profile.actorDid,providerDid:profile.providerDid,routeContext:profile.routeContext,
   actorKind:profile.actorKind,actorMode:session?.actorMode??profile.actorMode,profileDid:profile.profileDid,allowedSubjectDids:profile.allowedSubjectDids,
   clientId:profile.clientId,deviceDid:profile.deviceDid,publicJwks:profile.publicJwks,createdAt:profile.createdAt,updatedAt:profile.updatedAt,
   walletKeyDerivationId:profile.walletKeyDerivationId,clientInstanceId:profile.clientInstanceId,storagePublicJwk:profile.storagePublicJwk,
   confidentialStorageProfile:profile.confidentialStorageProfile,clinicalCreatorBinding:profile.clinicalCreatorBinding,tenantIssuer:profile.tenantIssuer,credentialRevision:profile.credentialRevision,
   ...(session?.attester?{attester:session.attester}:{})}
  const view=structuredClone(publicProfile)
  return Object.freeze({...view,allowedSubjectDids:Object.freeze([...view.allowedSubjectDids])})
 }
 async listProfiles(input:Pick<RegisteredProfileBinding,'ownerId'|'providerDid'|'routeContext'>){
  this.route(input);text(input.ownerId)
  const rows=await this.options.vault.query<Profile>(this.options.collections.profiles,{where:[{attribute:'ownerId',equals:input.ownerId},{attribute:'providerDid',equals:input.providerDid}]})
  return rows.flatMap(profile=>{
   if(profile.ownerId!==input.ownerId||profile.providerDid!==input.providerDid)throw denied()
   if(!equal(profile.routeContext,input.routeContext)||profile.actorKind!=='individual_controller'||!['self','controller'].includes(profile.actorMode))return []
   this.admit(profile)
   const {publicJwks:_keys,storagePublicJwk:_storage,...metadata}=this.profileView(profile)
   return [metadata]
  })
 }
 async unlockActorProfile(input:RegisteredProfileBinding&Readonly<{pin:string}>){
  this.route(input)
  // Admission precedes PIN/session mutations, while custody repeats exact
  // owner/provider/route binding under its own transaction.
  const profile=await this.options.vault.get<Profile>(this.options.collections.profiles,input.profileId)
  if(!profile)throw denied()
  this.admit(profile)
  const opened=await this.sessions.unlock(input)
  return this.resolveActorSession({...input,sessionId:opened.session.sessionId})
 }
 private async opened(input:SessionInput){
  this.route(input)
  const opened=await this.sessions.resolve(input,text(input.sessionId))
  this.admit(opened.profile)
  return opened
 }
 async resolveActorSession(input:SessionInput){
  const opened=await this.opened(input)
  return {sessionId:opened.session.sessionId,profile:this.profileView(opened.profile,opened.session),profileId:opened.profile.profileId,actorDid:opened.profile.actorDid,authorizedSubjectDids:[...(opened.session.authorizedSubjectDids??[])],expiresAt:opened.session.expiresAt,...await this.capabilities(input,opened)}
 }
 async lock(binding:RegisteredProfileBinding,sessionId:string){this.route(binding);await this.sessions.lock(binding,sessionId)}
 private async communication(input:SessionInput,opened:Opened){
  const seed=await this.options.sealer.unseal(opened.session.sealedUnlockedWalletSeed,`${input.sessionId}:unlocked-wallet-seed`)
  const communication=await openRegisteredCommunicationWallet({walletKeyDerivationId:opened.profile.walletKeyDerivationId||opened.profile.profileId,unlockedWalletSeed:seed,registeredPublicJwks:opened.profile.publicJwks,resolveRecipientJwk:this.options.gateway.resolveRecipientJwk})
  return createVerifiedGatewaySecureAdapter({gatewayDid:this.options.gateway.providerDid,
   pack:message=>communication.wallet.packForRecipientWithContext({...message,iss:opened.profile.actorDid,client_id:opened.profile.clientId},this.options.gateway.providerDid,{context:communication.context}),
   decrypt:packed=>communication.wallet.unpackWithContext(packed,{context:communication.context}),
   resolveGatewaySigningJwk:this.options.gateway.resolveGatewaySigningJwk,errorPrefix:'registered_profile_access'})
 }
 private async transport(input:AuthInput,opened:Opened){
  return new RegisteredGatewayTransport({baseUrl:this.baseUrl,bearerToken:text(input.idToken),fetchImpl:this.options.fetchImpl,secureTransportAdapter:await this.communication(input,opened),errorPrefix:'registered_profile_access',submitError:(status)=>new Error(`registered_profile_access_gateway_denied:${status}`)})
 }
 private async capabilities(input:SessionInput,opened:Opened,tokenExpiry?:number){
  const adapter=await this.communication(input,opened),threads=new Set<string>()
  const guard=async()=>{
   if(tokenExpiry!==undefined&&Math.floor(this.now().getTime()/1000)>=tokenExpiry)throw new Error('registered_profile_access_token_expired')
   await this.commit(opened)
  }
  return {
   secureTransportAdapter:Object.freeze({
    pack:async(message:Record<string,unknown>):Promise<string>=>{
     await guard();const snapshot=structuredClone(record(message)),thread=text(snapshot.thid)
     const packed=await adapter.pack(snapshot);await guard();threads.add(thread);return packed
    },
    unpack:async(packed:string):Promise<unknown>=>{
     await guard();const response=record(await adapter.unpackVerified(text(packed)))
     if(response.iss!==this.options.gateway.responseIssuer||response.aud!==opened.profile.actorDid||typeof response.thid!=='string'||!threads.has(response.thid))throw denied()
     await guard();threads.delete(response.thid);return response
    },
   }),
   confidentialStorageAdapter:Object.freeze({
    protect:async<T extends Readonly<{content:unknown}>>(document:T)=>{await guard();const result=await opened.custody.confidentialStorageAdapter.protect(document);await guard();return result},
    unprotect:async<T extends Readonly<{jwe:unknown}>>(document:T)=>{await guard();const result=await opened.custody.confidentialStorageAdapter.unprotect(document);await guard();return result},
   }),
  }
 }
 private message(opened:Opened,body:Readonly<Record<string,unknown>>,audience:string){
  const thid=randomUUID()
  return {thid,jti:thid,iss:opened.profile.actorDid,aud:audience,client_id:opened.profile.clientId,body}
 }
 private async commit(opened:Opened,updated?:Session,updatedProfile?:Profile):Promise<void>{
  // All reads precede any write. Exact snapshots cover PIN rewrap, lock,
  // concurrent directory/selection changes, route reassignment and expiry.
  await this.options.vault.runTransaction(async port=>{
   const profile=await port.get<Profile>(this.options.collections.profiles,opened.profile.id)
   const session=await port.get<Session>(this.options.collections.sessions,opened.session.id)
   if(!profile||!session||!equal(profile,opened.profile)||!equal(session,opened.session)||Date.parse(session.expiresAt)<=this.now().getTime())throw changed()
   if(updatedProfile)await port.put(this.options.collections.profiles,updatedProfile)
   if(updated)await port.put(this.options.collections.sessions,updated)
  })
 }
 private async queryAuthorizedSubjects(input:AuthInput&Readonly<{verifiedContact:AuthorizedSubjectVerifiedContact}>,opened:Opened){
  const verifiedContact=structuredClone(input.verifiedContact),transport=await this.transport(input,opened)
  await this.commit(opened)
  const directory=new SosGatewaySubjectDirectoryClient({baseUrl:this.baseUrl,registeredExchange:async(path,payload,poll)=>{
   const result=await transport.exchange(path,this.message(opened,record(payload.body),opened.profile.providerDid),this.options.gateway.responseIssuer,poll??this.options.pollOptions)
   return result.poll
  }})
  return directory.listAuthorizedIndividualSubjects(opened.profile.routeContext,{verifiedContact,expectedProviderDid:opened.profile.providerDid,pollOptions:this.options.pollOptions})
 }
 /** Read the current signed directory without clearing a selected SMART context or persisting discoveries. */
 async readAuthorizedSubjects(input:AuthInput&Readonly<{verifiedContact:AuthorizedSubjectVerifiedContact}>):Promise<readonly AuthorizedIndividualSubject[]>{
  const opened=await this.opened(input),subjects=await this.queryAuthorizedSubjects(input,opened)
  await this.commit(opened)
  return subjects
 }
 async refreshAuthorizedSubjects(input:AuthInput&Readonly<{verifiedContact:AuthorizedSubjectVerifiedContact}>){
  const opened=await this.opened(input),subjects=await this.queryAuthorizedSubjects(input,opened)
  const assignments:RegisteredProfileAuthorizedSubject[]=subjects.map(subject=>{
   const role=(subject.role??'').trim().toUpperCase().split(/[|/#:]/u).at(-1)
   let reference=subject.relatedPersonId
   if(reference){
    const hex=normalizeUuid(reference)
    if(hex)reference=`urn:uuid:${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`
    if(!/^(?:urn:|https?:\/\/)/iu.test(reference))throw denied()
   }
   return {subjectDid:subject.subjectDid,transportSubjectDid:text(subject.subjectClaims['org.schema.Organization.did']),actorMode:role==='ONESELF'?'self':role==='RESPRSN'?'controller':'member',...(reference?{attester:{mode:CompositionAttesterModes.Personal,party:{reference}}}:{})}
  })
  const {subjectDid:_subject,selectedSubjectDid:_selected,sealedAccessToken:_token,attester:_attester,actorMode:_mode,...rest}=opened.session
  const authorizedSubjectDids=assignments.map(subject=>subject.subjectDid)
  await this.commit(opened,{...rest,authorizedSubjects:assignments,authorizedSubjectDids,scopes:[]},{...opened.profile,allowedSubjectDids:authorizedSubjectDids,updatedAt:this.now().toISOString()})
  return {session:await this.resolveActorSession(input),subjects}
 }
 private async token(compact:string,opened:Opened,jti:string,patient:string,requested:readonly string[],body:Record<string,unknown>){
  const parts=text(compact).split('.')
  if(parts.length!==3||parts.some(part=>!part||!/^[A-Za-z0-9_-]+$/u.test(part)))throw denied()
  const policy=this.options.gateway.smartTokenVerification
  const header=record(JSON.parse(Buffer.from(parts[0]!,'base64url').toString('utf8'))),key=await policy.resolveSigningJwk(this.options.gateway.providerDid),publicKey=record(key)
  if(['d','k','dBytes','privBytes','priv','privateKey','secretKeyBytes'].some(field=>field in publicKey)||publicKey.use!==undefined&&publicKey.use!=='sig'||header.alg!==policy.algorithm||publicKey.alg!==policy.algorithm||header.kid!==publicKey.kid||typeof publicKey.kid!=='string'||!publicKey.kid)throw denied()
  if(policy.algorithm==='ES384'||policy.algorithm==='ES256'){
   const curve=policy.algorithm==='ES384'?'P-384':'P-256',size=policy.algorithm==='ES384'?48:32
   if(publicKey.kty!=='EC'||publicKey.crv!==curve)throw denied()
   for(const field of ['x','y']){const value=text(publicKey[field]);if(Buffer.from(value,'base64url').length!==size||Buffer.from(value,'base64url').toString('base64url')!==value)throw denied()}
   const ec=createPublicKey({key:{kty:'EC',crv:curve,x:text(publicKey.x),y:text(publicKey.y)},format:'jwk'})
   if(!verify(policy.algorithm==='ES384'?'sha384':'sha256',Buffer.from(`${parts[0]}.${parts[1]}`,'ascii'),{key:ec,dsaEncoding:'ieee-p1363'},Buffer.from(parts[2]!,'base64url')))throw denied()
  }else if(key.kty!=='AKP'||key.alg!==policy.algorithm||!await this.crypto.verifyJws(compact,key))throw denied()
  const claims=record(JSON.parse(Buffer.from(parts[1]!,'base64url').toString('utf8'))),now=Math.floor(this.now().getTime()/1000)
  if(claims.iss!==opened.profile.providerDid||claims.aud!==opened.profile.providerDid||claims.sub!==opened.profile.actorDid||claims.jti!==jti||!Number.isSafeInteger(claims.exp)||Number(claims.exp)<=now)throw new Error('registered_profile_access_token_expired_or_binding_invalid')
  if(!Number.isSafeInteger(claims.iat)||Number(claims.iat)>now||(claims.nbf!==undefined&&(!Number.isSafeInteger(claims.nbf)||Number(claims.nbf)>now)))throw denied()
  if(body.subject!==patient||body.token_type!=='Bearer'||typeof body.scope!=='string'||claims.scope!==body.scope)throw denied()
  const grants=body.scope.split(/\s+/u).filter(Boolean)
  if(!grants.length||new Set(grants).size!==grants.length||grants.join(' ')!==body.scope)throw denied()
  for(const grant of grants){const actual=scope(grant,patient);if(!requested.some(value=>{const allowed=scope(value,patient),actions=allowed.head.split('.')[1]!,grantedActions=actual.head.split('.')[1]!;return [...grantedActions].every(action=>actions.includes(action))&&actual.sections.every(section=>allowed.sections.includes('*')||allowed.sections.includes(section))}))throw denied()}
  return {claims,scopes:grants}
 }
 async selectAuthorizedSubject(input:AuthInput&Readonly<{subjectDid:string;scopes:readonly string[]}>){
  const opened=await this.opened(input),assignment=opened.session.authorizedSubjects?.find(subject=>subject.subjectDid===input.subjectDid)
  if(!assignment?.transportSubjectDid||!opened.session.authorizedSubjectDids?.includes(input.subjectDid))throw denied()
  const patient=assignment.transportSubjectDid
  if(!Array.isArray(input.scopes)||!input.scopes.length)throw denied()
  const requested=input.scopes.map(value=>{const parsed=scope(text(value),input.subjectDid);return buildScopeSmartCompositionAccess({subjectDid:patient,sections:parsed.sections,accessVerb:parsed.head.endsWith('.cruds')?'cruds':parsed.head.endsWith('.rs')?'rs':'r'})})
  const path=`${this.route(input)}/identity/openid/smart/token`,audience=`${this.baseUrl}${path}`,operation=randomUUID()
  const assertion=await opened.custody.signClientAssertion({clientId:opened.profile.clientId,audience,issuedAt:Math.floor(this.now().getTime()/1000),jti:randomUUID()})
  const message={thid:operation,jti:operation,iss:opened.profile.actorDid,aud:audience,client_id:opened.profile.clientId,body:{client_id:opened.profile.clientId,sub:opened.profile.actorDid,id_token:text(input.idToken),client_assertion:assertion,client_assertion_type:'private_key_jwt',acr_values:'urn:antifraud:acr:openid4vp:individual',purpose:'TREAT',scope:requested.join(' ')}}
  const result=await(await this.transport(input,opened)).exchange(path,message,this.options.gateway.responseIssuer,this.options.pollOptions)
  const body=record(record(result.poll.body).body),accessToken=text(body.access_token)
  const validated=await this.token(accessToken,opened,operation,patient,requested,body)
  const sealedAccessToken=await this.options.sealer.seal(accessToken,`${input.sessionId}:access-token`)
  const {attester:_oldAttester,...rest}=opened.session
  const updated={...rest,subjectDid:patient,selectedSubjectDid:input.subjectDid,scopes:validated.scopes,sealedAccessToken,actorMode:assignment.actorMode,...(assignment.attester?{attester:assignment.attester}:{})}
  await this.commit(opened,updated)
  return this.resolveSession(input)
 }
 async resolveSession(input:SessionInput){
  const opened=await this.opened(input),session=opened.session
  if(!session.subjectDid||!session.selectedSubjectDid||!session.sealedAccessToken||!session.scopes.length||!session.authorizedSubjects?.some(subject=>subject.subjectDid===session.selectedSubjectDid&&subject.transportSubjectDid===session.subjectDid))throw denied()
  const assignment=session.authorizedSubjects.find(subject=>subject.subjectDid===session.selectedSubjectDid)
  if(!assignment||session.actorMode!==assignment.actorMode||!equal(session.attester,assignment.attester))throw denied()
  const accessToken=await this.options.sealer.unseal(session.sealedAccessToken,`${input.sessionId}:access-token`)
  // The operation jti was verified before sealing; resolve re-verifies all
  // currently available authority and time claims, not a fresh HTTP operation.
  const parts=accessToken.split('.');if(parts.length!==3)throw denied()
  const claims=record(JSON.parse(Buffer.from(parts[1]!,'base64url').toString('utf8')))
  await this.token(accessToken,opened,text(claims.jti),session.subjectDid,session.scopes,{subject:session.subjectDid,scope:session.scopes.join(' '),token_type:'Bearer'})
  await this.commit(opened)
  return {sessionId:input.sessionId,profile:this.profileView(opened.profile,session),subjectDid:session.subjectDid,selectedSubjectDid:session.selectedSubjectDid,actorMode:session.actorMode??opened.profile.actorMode,scopes:[...session.scopes],accessToken,...(session.attester?{attester:session.attester}:{}),...await this.capabilities(input,opened,Number(claims.exp))}
 }
}
