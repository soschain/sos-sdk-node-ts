import {randomUUID} from 'node:crypto'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
import type {RegisteredProfileBinding,RegisteredProfileRecord,RegisteredProfileSessionRecord} from 'sos-data-utils-ts/registered-profile-contract'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import {openServerProfileSecret,protectServerProfileSecret,ProfilePinRejectedError,type ProfileProtectionOptions} from './server-profile-protection.js'
import {openServerProfileCustodyKeys} from './server-profile-custody-keys.js'

type StoredProfile=RegisteredProfileRecord&{id:string}
type StoredSession=RegisteredProfileSessionRecord&{id:string}
export type RegisteredProfileSessionsOptions=Readonly<{
 vault:TransactionalVaultRepository
 collections:Readonly<{profiles:string;sessions:string}>
 /** Host-configured session families sharing exact ownerId/profileId fields. */
 additionalSessionCollections?:readonly string[]
 sealer:ServerProfileSealer
 now?:()=>Date
 sessionTtlSeconds?:number
 maxFailedUnlocks?:number
 lockSeconds?:number
 protection?:ProfileProtectionOptions
}>
const denied=()=>new Error('registered_profile_binding_denied')
const stale=()=>new Error('registered_profile_changed_or_revoked')
function required(value:unknown):string{if(typeof value!=='string'||!value.trim()||value.length>4096)throw denied();return value}
function revision(profile:RegisteredProfileRecord):number{
 const value=profile.credentialRevision??0
 if(!Number.isSafeInteger(value)||value<0)throw denied()
 return value
}
function equal(a:unknown,b:unknown):boolean{return JSON.stringify(a)===JSON.stringify(b)}
function unchanged(before:StoredProfile,current:StoredProfile):void{
 // Include both ciphertext and public authority: a same-timestamp rewrap or
 // reassignment must not let an off-transaction opening commit stale custody.
 if(!equal(before,current))throw stale()
}
function bounded(value:number|undefined,fallback:number,max:number):number{
 const result=value??fallback
 if(!Number.isSafeInteger(result)||result<1||result>max)throw new TypeError('registered_profile_session_policy_invalid')
 return result
}

/**
 * Host-only custody/session persistence for already registered profiles.
 * The host supplies authenticated account and routed provider bindings. This
 * layer does not enroll actors, approve roles, discover subjects or grant SMART
 * access. It never rotates the registered seed or substitutes communication keys.
 */
export class RegisteredProfileSessions{
 private readonly sessionCollections:readonly string[]
 private readonly ttl:number
 private readonly maxFailures:number
 private readonly lockSeconds:number
 constructor(private readonly options:RegisteredProfileSessionsOptions){
  required(options.collections.profiles);required(options.collections.sessions)
  if(options.collections.profiles===options.collections.sessions)throw new TypeError('registered_profile_collections_must_differ')
  const additional=options.additionalSessionCollections??[]
  if(!Array.isArray(additional))throw new TypeError('registered_profile_session_collections_invalid')
  const sessions=[options.collections.sessions,...additional.map(value=>required(value))]
  if(new Set(sessions).size!==sessions.length||sessions.includes(options.collections.profiles))throw new TypeError('registered_profile_session_collections_invalid')
  this.sessionCollections=Object.freeze(sessions)
  this.options={...options,collections:Object.freeze({...options.collections})}
  this.ttl=bounded(options.sessionTtlSeconds,300,86400)
  this.maxFailures=bounded(options.maxFailedUnlocks,5,100)
  this.lockSeconds=bounded(options.lockSeconds,300,86400)
 }
 private now():Date{
  const date=this.options.now?.()??new Date()
  if(!Number.isFinite(date.getTime()))throw new TypeError('registered_profile_clock_invalid')
  return date
 }
 private async profile(binding:RegisteredProfileBinding,port:IVaultRepository=this.options.vault):Promise<StoredProfile>{
  for(const value of [binding.ownerId,binding.profileId,binding.actorDid,binding.providerDid,binding.routeContext.tenantId,binding.routeContext.jurisdiction,binding.routeContext.sector])required(value)
  const profile=await port.get<StoredProfile>(this.options.collections.profiles,binding.profileId)
  if(!profile||profile.id!==binding.profileId||profile.profileId!==binding.profileId||profile.ownerId!==binding.ownerId||profile.actorDid!==binding.actorDid||profile.providerDid!==binding.providerDid)throw denied()
  for(const field of ['tenantId','jurisdiction','sector'] as const)if(profile.routeContext[field]!==binding.routeContext[field])throw denied()
  revision(profile)
  if(!Number.isSafeInteger(profile.failedUnlocks)||profile.failedUnlocks<0)throw denied()
  return profile
 }
 private assertUnlocked(profile:StoredProfile):void{
  if(profile.lockedUntil){
   const deadline=Date.parse(profile.lockedUntil)
   if(!Number.isFinite(deadline))throw denied()
   if(deadline>this.now().getTime())throw new Error('registered_profile_locked')
  }
 }
 private async custody(profile:StoredProfile,seed:string){
  // Existing records without a document key require an explicit governed
  // migration; absence must not silently provision or register replacement keys.
  if(!profile.storagePublicJwk)throw new Error('registered_profile_storage_key_migration_required')
  return openServerProfileCustodyKeys({walletKeyDerivationId:profile.walletKeyDerivationId||profile.profileId,unlockedWalletSeed:seed,binding:{kind:'registered',publicJwks:profile.publicJwks,storagePublicJwk:profile.storagePublicJwk}})
 }
 /** PIN-only check: preserve historical stored subsets without publishing keys or returning registered capabilities. */
 private async validatePinCustody(profile:StoredProfile,seed:string):Promise<void>{
  const derived=await openServerProfileCustodyKeys({walletKeyDerivationId:profile.walletKeyDerivationId||profile.profileId,unlockedWalletSeed:seed,binding:{kind:'enrollment'}})
  if(!Array.isArray(profile.publicJwks)||!profile.publicJwks.length)throw denied()
  const ownPublic=(value:unknown):Record<string,unknown>=>{
   if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw denied()
   const result:Record<string,unknown>=Object.create(null)
   for(const [name,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){if(!('value' in descriptor))throw denied();result[name]=descriptor.value}
   if(['d','k','dBytes','privBytes','priv','privateKey','secretKeyBytes'].some(name=>name in result))throw denied()
   return result
  }
  const match=(value:unknown,documentOnly=false):string=>{
   const actual=ownPublic(value)
   if(typeof actual.kid!=='string'||!actual.kid)throw denied()
   const expected=derived.descriptors.find(descriptor=>descriptor.kid===actual.kid&&(!documentOnly||descriptor.purpose==='document-at-rest'))
   if(!expected)throw denied()
   const fields=expected.publicJwk.kty==='EC'?['kty','crv','x','y','kid']:expected.publicJwk.kty==='AKP'?['kty','alg','pub','kid']:['kty','crv','x','kid']
   if(fields.some(name=>typeof actual[name]!=='string'||actual[name]!==expected.publicJwk[name]))throw denied()
   for(const [name,requiredValue] of [['alg',expected.alg],['use',expected.use],['purpose',expected.purpose],['ownerScope',expected.ownerScope]])if(actual[name]!==undefined&&actual[name]!==requiredValue)throw denied()
   return actual.kid
  }
  const kids=new Set<string>()
  for(const key of profile.publicJwks){const kid=match(key);if(kids.has(kid))throw denied();kids.add(kid)}
  if(profile.storagePublicJwk!==undefined)match(profile.storagePublicJwk,true)
 }
 async unlock(input:RegisteredProfileBinding&Readonly<{pin:string}>){
  const before=await this.profile(input);this.assertUnlocked(before)
  let seed:string,vp:string|undefined
  try{
   seed=await openServerProfileSecret(before.protectedWalletSeed,input.pin,`${before.profileId}:wallet-seed`,this.options.sealer)
   if(before.protectedVpToken)vp=await openServerProfileSecret(before.protectedVpToken,input.pin,`${before.profileId}:vp-token`,this.options.sealer)
  }catch(error){
   if(error instanceof ProfilePinRejectedError){
    // Throw only after the failure count commits. Throwing inside a durable
    // transaction would roll back the rate limit as well as the failed action.
    await this.options.vault.runTransaction(async port=>{
     const current=await this.profile(input,port)
     if(revision(current)!==revision(before)||!equal(current.protectedWalletSeed,before.protectedWalletSeed)||!equal(current.protectedVpToken,before.protectedVpToken))throw stale()
     const failedUnlocks=current.failedUnlocks+1
     await port.put(this.options.collections.profiles,{...current,failedUnlocks,...(failedUnlocks>=this.maxFailures?{lockedUntil:new Date(this.now().getTime()+this.lockSeconds*1000).toISOString()}:{}),updatedAt:this.now().toISOString()})
    })
   }
   throw error
  }
  const custody=await this.custody(before,seed)
  const sessionId=randomUUID(),session:StoredSession={id:sessionId,sessionId,ownerId:before.ownerId,profileId:before.profileId,credentialRevision:revision(before),scopes:[],authorizedSubjectDids:[],sealedUnlockedWalletSeed:await this.options.sealer.seal(seed,`${sessionId}:unlocked-wallet-seed`),...(vp!==undefined?{sealedUnlockedVpToken:await this.options.sealer.seal(vp,`${sessionId}:unlocked-vp-token`)}:{}),expiresAt:new Date(this.now().getTime()+this.ttl*1000).toISOString()}
  const profile=await this.options.vault.runTransaction(async port=>{
   const current=await this.profile(input,port);unchanged(before,current);this.assertUnlocked(current)
   const {lockedUntil:_locked,...rest}=current
   const updated={...rest,failedUnlocks:0,updatedAt:this.now().toISOString()}
   await port.put(this.options.collections.profiles,updated)
   await port.put(this.options.collections.sessions,session)
   return updated
  })
  return {profile,session,custody}
 }
 async resolve(binding:RegisteredProfileBinding,sessionId:string){
  required(sessionId)
  const before=await this.options.vault.get<StoredSession>(this.options.collections.sessions,sessionId)
  if(!before||before.id!==sessionId||before.sessionId!==sessionId||before.ownerId!==binding.ownerId||before.profileId!==binding.profileId)throw denied()
  const profile=await this.profile(binding)
  if((before.credentialRevision??0)!==revision(profile))throw stale()
  const expires=Date.parse(before.expiresAt)
  if(!Number.isFinite(expires)||expires<=this.now().getTime()){
   await this.options.vault.runTransaction(async port=>{const current=await port.get<StoredSession>(this.options.collections.sessions,sessionId);if(current&&equal(current,before))await port.delete(this.options.collections.sessions,sessionId)})
   throw new Error('registered_profile_session_expired')
  }
  const seed=await this.options.sealer.unseal(before.sealedUnlockedWalletSeed,`${sessionId}:unlocked-wallet-seed`)
  const custody=await this.custody(profile,seed)
  await this.options.vault.runTransaction(async port=>{
   const currentProfile=await this.profile(binding,port),session=await port.get<StoredSession>(this.options.collections.sessions,sessionId)
   unchanged(profile,currentProfile)
   if(!session||!equal(before,session)||Date.parse(session.expiresAt)<=this.now().getTime())throw stale()
  })
  return {profile,session:before,custody}
 }
 async lock(binding:RegisteredProfileBinding,sessionId:string):Promise<void>{
  required(sessionId)
  await this.options.vault.runTransaction(async port=>{
   await this.profile(binding,port)
   const session=await port.get<StoredSession>(this.options.collections.sessions,sessionId)
   if(!session)return
   if(session.ownerId!==binding.ownerId||session.profileId!==binding.profileId)throw denied()
   await port.delete(this.options.collections.sessions,sessionId)
  })
 }
 /** Caller must first authorize recovery/passkey custody; possession alone is not authorization. */
 async replacePin(input:RegisteredProfileBinding&Readonly<{authorizedWalletSeed:string;authorizedVpToken?:string;newPin:string}>){
  const before=await this.profile(input)
  await this.validatePinCustody(before,input.authorizedWalletSeed)
  if(before.protectedVpToken&&!input.authorizedVpToken)throw new Error('registered_profile_authorized_vp_required')
  const protectedWalletSeed=await protectServerProfileSecret(input.authorizedWalletSeed,input.newPin,`${before.profileId}:wallet-seed`,this.options.sealer,this.options.protection)
  const protectedVpToken=before.protectedVpToken?await protectServerProfileSecret(input.authorizedVpToken!,input.newPin,`${before.profileId}:vp-token`,this.options.sealer,this.options.protection):undefined
  return this.options.vault.runTransaction(async port=>{
   const current=await this.profile(input,port);unchanged(before,current)
   const groups=await Promise.all(this.sessionCollections.map(async collection=>({collection,rows:await port.query<{id:string;ownerId:string;profileId:string}>(collection,{where:[{attribute:'ownerId',equals:input.ownerId},{attribute:'profileId',equals:input.profileId}]})})))
   for(const group of groups)for(const row of group.rows)if(row.ownerId!==input.ownerId||row.profileId!==input.profileId||typeof row.id!=='string'||!row.id)throw denied()
   const {lockedUntil:_locked,...rest}=current
   const updated={...rest,protectedWalletSeed,...(protectedVpToken?{protectedVpToken}:{}),failedUnlocks:0,credentialRevision:revision(current)+1,updatedAt:this.now().toISOString()}
   await port.put(this.options.collections.profiles,updated)
   for(const group of groups)for(const row of group.rows)await port.delete(group.collection,row.id)
   return updated
  })
 }
}
