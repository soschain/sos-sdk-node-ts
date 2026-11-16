import {createHash,sign} from 'node:crypto'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import {StoredProfileSignatureProfiles,type RegisteredProfileBinding,type StoredProfileSignatureCommand,type StoredProfileSignatureResult} from 'sos-data-utils-ts/registered-profile-contract'
import {PROFILE_SECRET_ENVELOPE_VERSION} from 'sos-data-utils-ts/server-profile-secret-contract'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import {deriveProfileEcSigningMaterial} from './profile-ec-signing-material.js'
import {text,own,json,pick,fingerprint,revision,profileFields,sessionFields} from './stored-profile-state.js'

type Row=Record<string,unknown>
export type StoredProfileSigningOptions=Readonly<{
 vault:TransactionalVaultRepository
 sealer:ServerProfileSealer
 profilesCollection:string
 session:Readonly<{format:'registered-profile-session-v1';collection:string;sessionId:string}>
  |Readonly<{format:'sealed-wallet-session-v1';collection:string;sessionToken:string}>
 binding:RegisteredProfileBinding
 now?:()=>Date
}>
const denied=()=>new Error('stored_profile_signing_binding_denied')
const stale=()=>new Error('stored_profile_signing_state_changed')
/**
 * Signs one admitted stored-profile operation. It neither verifies domain
 * credentials nor grants a role, subject relationship, licence or SMART scope.
 * No network, enrollment, key provisioning or reusable signing handle exists.
 */
export async function signStoredProfilePayload(options:StoredProfileSigningOptions,command:StoredProfileSignatureCommand):Promise<StoredProfileSignatureResult>{
 const vault=options.vault,sealer=options.sealer,now=options.now
 const input=own(command),kind=input.profile
 const presentation=kind===StoredProfileSignatureProfiles.IndividualIdentityPresentation
 if(!presentation&&kind!==StoredProfileSignatureProfiles.OrganizationActorDetachedCredential)throw denied()
 const permitted=presentation?['profile','subjectDid','claims']:['profile','payload']
 if(Object.keys(input).some(name=>!permitted.includes(name)))throw denied()
 const claims=presentation?own(json(input.claims)):undefined
 const subject=presentation?text(input.subjectDid):undefined
 let detached:Buffer|undefined
 if(!presentation){
  if(typeof input.payload==='string')detached=Buffer.from(input.payload,'utf8')
  else if(input.payload instanceof Uint8Array&&(Object.getPrototypeOf(input.payload)===Uint8Array.prototype||Buffer.isBuffer(input.payload)))detached=Buffer.from(input.payload)
  else throw denied()
 }
 const captured=own(options.binding),route=own(captured.routeContext)
 const binding={ownerId:text(captured.ownerId),profileId:text(captured.profileId),actorDid:text(captured.actorDid),providerDid:text(captured.providerDid),routeContext:{tenantId:text(route.tenantId),jurisdiction:text(route.jurisdiction),sector:text(route.sector)}}
 const ref=own(options.session),format=ref.format,profilesCollection=text(options.profilesCollection),sessionCollection=text(ref.collection)
 if(profilesCollection===sessionCollection)throw denied()
 if(presentation?format!=='registered-profile-session-v1':format!=='sealed-wallet-session-v1')throw denied()
 const rawIdentifier=text(presentation?ref.sessionId:ref.sessionToken)
 if(!presentation&&(!/^[A-Za-z0-9_-]{43}$/u.test(rawIdentifier)||Buffer.from(rawIdentifier,'base64url').toString('base64url')!==rawIdentifier))throw denied()
 const sessionId=presentation?rawIdentifier:createHash('sha256').update(rawIdentifier,'utf8').digest('hex')
 const clock=()=>{const date=now?.()??new Date();if(!(date instanceof Date)||!Number.isFinite(date.getTime()))throw denied();return date.getTime()}
 function validate(profile:Row,session:Row):void{
  if(profile.id!==binding.profileId||profile.profileId!==binding.profileId||profile.ownerId!==binding.ownerId||profile.actorDid!==binding.actorDid||profile.providerDid!==binding.providerDid)throw denied()
  const actualRoute=own(profile.routeContext)
  for(const field of ['tenantId','jurisdiction','sector'] as const)if(actualRoute[field]!==binding.routeContext[field])throw denied()
  if(session.id!==sessionId||session.ownerId!==binding.ownerId||session.profileId!==binding.profileId||(presentation&&session.sessionId!==sessionId))throw denied()
  if(revision(profile.credentialRevision)!==revision(session.credentialRevision))throw stale()
  const expires=Date.parse(text(session.expiresAt))
  if(!Number.isFinite(expires)||expires<=clock())throw new Error('stored_profile_signing_session_expired')
  if(!Number.isSafeInteger(profile.failedUnlocks)||Number(profile.failedUnlocks)<0)throw denied()
  if(profile.lockedUntil!==undefined){const deadline=Date.parse(text(profile.lockedUntil));if(!Number.isFinite(deadline))throw denied();if(deadline>clock())throw new Error('stored_profile_signing_profile_locked')}
  const envelope=own(profile.protectedWalletSeed)
  if(envelope.version!==PROFILE_SECRET_ENVELOPE_VERSION)throw denied()
  if(!Array.isArray(profile.publicJwks)||!profile.publicJwks.length)throw denied()
  const keys=profile.publicJwks.map(own)
  if(new Set(keys.map(key=>text(key.kid))).size!==keys.length)throw denied()
  for(const key of keys)if(['d','k','dBytes','privBytes','priv','privateKey','secretKeyBytes'].some(name=>Object.hasOwn(key,name)))throw denied()
  if(presentation){
   if(profile.actorKind!==ActorKinds.IndividualController||!['self','controller'].includes(String(profile.actorMode)))throw denied()
   const transportSubject=text(session.subjectDid),selected=text(session.selectedSubjectDid??session.subjectDid)
   if(!['self','controller','member'].some(mode=>mode===session.actorMode))throw denied()
   if(subject!==selected||!Array.isArray(session.scopes)||!session.scopes.length||!session.sealedAccessToken)throw denied()
   if(!Array.isArray(session.authorizedSubjectDids)||!session.authorizedSubjectDids.includes(selected)||!Array.isArray(session.authorizedSubjects))throw denied()
   const assignments=session.authorizedSubjects.map(own).filter(entry=>entry.subjectDid===selected&&entry.transportSubjectDid===transportSubject)
   if(assignments.length!==1||assignments[0]!.actorMode!==session.actorMode||fingerprint(assignments[0]!.attester??null)!==fingerprint(session.attester??null))throw denied()
   for(const scope of session.scopes){const value=text(scope),separator=value.indexOf('?');if(separator<1||new URLSearchParams(value.slice(separator+1)).get('subject')!==transportSubject)throw denied()}
   const vp=own(claims?.vp)
   if(claims?.iss!==binding.actorDid||claims.sub!==binding.actorDid||vp.holder!==binding.actorDid)throw denied()
   for(const name of ['aud','nonce','state','jti'])text(claims[name])
   if(!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||Number(claims.iat)>Math.floor(clock()/1000)||Number(claims.exp)<=Math.floor(clock()/1000)||Number(claims.exp)<=Number(claims.iat)||Number(claims.exp)>Number(claims.iat)+300)throw denied()
  }else if(profile.actorKind!==ActorKinds.OrganizationController||profile.actorMode!=='controller')throw denied()
 }
 async function capture(port:IVaultRepository){
  const [rawProfile,rawSession]=await Promise.all([port.get<Row&{id:string}>(profilesCollection,binding.profileId),port.get<Row&{id:string}>(sessionCollection,sessionId)])
  const profile=pick(own(rawProfile),profileFields),session=pick(own(rawSession),sessionFields)
  validate(profile,session)
  return {profile,session}
 }
 const before=await vault.runTransaction(capture)
 const seed=await sealer.unseal(text(presentation?before.session.sealedUnlockedWalletSeed:before.session.sealedWalletSeed),presentation?`${sessionId}:unlocked-wallet-seed`:`${binding.ownerId}:${binding.profileId}:${sessionId}:wallet-session-seed`)
 if(typeof seed!=='string'||!/^[A-Za-z0-9_-]{43}$/u.test(seed)||Buffer.from(seed,'base64url').toString('base64url')!==seed)throw denied()
 const id=text(before.profile.walletKeyDerivationId??before.profile.profileId,512)
 const purpose=presentation?'vp-token-signing':'actor-signing',owner=presentation?`runtime:${id}:server-runtime:default`:`profile:${id}:default`
 const material=deriveProfileEcSigningMaterial(seed,owner,purpose)
 const expected=material.publicJwk
 const matches=(before.profile.publicJwks as unknown[]).map(own).filter(key=>key.kid===expected.kid)
 if(matches.length!==1)throw denied()
 const registered=matches[0]!
 for(const field of ['kty','crv','x','y','kid'])if(registered[field]!==expected[field])throw denied()
 for(const[field,value]of [['alg','ES384'],['use','sig'],['purpose',purpose],['ownerScope',presentation?'runtime':'profile']])if(registered[field]!==undefined&&registered[field]!==value)throw denied()
 const publicJwk=Object.freeze({kty:'EC' as const,crv:'P-384' as const,alg:'ES384' as const,use:'sig' as const,kid:text(expected.kid),x:text(expected.x),y:text(expected.y)})
 const header=presentation?{typ:'application/vp+jwt',alg:'ES384',kid:publicJwk.kid}:{typ:'application/vc+ld+json',alg:'ES384',kid:publicJwk.kid,b64:false,crit:['b64']}
 const encodedHeader=Buffer.from(JSON.stringify(header),'utf8').toString('base64url')
 const encodedPayload=presentation?Buffer.from(JSON.stringify(claims),'utf8').toString('base64url'):''
 const bytes=presentation?Buffer.from(`${encodedHeader}.${encodedPayload}`,'ascii'):Buffer.concat([Buffer.from(`${encodedHeader}.`,'ascii'),detached!])
 const signature=sign('sha384',bytes,{key:material.key,dsaEncoding:'ieee-p1363'}).toString('base64url')
 await vault.runTransaction(async port=>{
  const current=await capture(port)
  if(fingerprint(current)!==fingerprint(before))throw stale()
 })
 return Object.freeze({jws:`${encodedHeader}.${encodedPayload}.${signature}`,verificationMethod:`${binding.actorDid}#${publicJwk.kid}`,publicJwk})
}
