import {createHash,randomBytes,timingSafeEqual} from 'node:crypto'
import {encodeBase58btc,decodeBase58btc} from 'antifraud-data-utils-ts/encoding'
import {normalizeActorContact} from 'antifraud-data-utils-ts/organization-identity'
import type {ProfileRecoveryIdentity,ProfileRecoveryRecord,ProfileRecoveryNotification} from 'sos-data-utils-ts/profile-recovery-contract'

export type ProfileRecoveryKms=Readonly<{
 keyName:string
 encrypt(cleartext:Uint8Array,aad:Uint8Array):Promise<string>
 decrypt(ciphertext:string,aad:Uint8Array):Promise<Uint8Array>
}>
export type ProfileRecoveryRepository<PreparedProfile>=Readonly<{
 get(profileId:string):Promise<ProfileRecoveryRecord|null|undefined>
 put(record:ProfileRecoveryRecord,expectedGeneration:null):Promise<void>
 rotate(record:ProfileRecoveryRecord,expectedGeneration:number,notification:ProfileRecoveryNotification,preparedProfile:PreparedProfile|undefined):Promise<void>
}>
export type ProfileRecoveryServiceOptions<PreparedProfile>=Readonly<{
 repository:ProfileRecoveryRepository<PreparedProfile>
 kms:ProfileRecoveryKms
 environment:string
 now?:()=>Date
 randomBytes?:(size:number)=>Uint8Array
 /** Trusted host resealing only; the coordinator never returns a plaintext seed. */
 prepareRestoredProfile?:(input:Readonly<{walletSeed:Uint8Array;identity:ProfileRecoveryIdentity}>)=>Promise<PreparedProfile>
}>

const invalid=()=>new Error('profile_recovery_binding_denied')
const materialInvalid=()=>new Error('profile_recovery_material_invalid')
function text(value:unknown):string{
 if(typeof value!=='string'||!value.trim()||value.length>4096||/[\r\n]/u.test(value))throw invalid()
 return value
}
function own(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw invalid()
 const result:Record<string,unknown>=Object.create(null)
 for(const [name,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){
  if(!('value'in descriptor))throw invalid()
  result[name]=descriptor.value
 }
 return result
}
function identity(value:ProfileRecoveryIdentity):ProfileRecoveryIdentity{
 const input=own(value),profileId=text(input.profileId),ownerId=text(input.ownerId)
 const controllerKind=input.controllerKind
 if(controllerKind!=='individual-controller'&&controllerKind!=='organization-controller')throw invalid()
 if(typeof input.contact!=='string')throw invalid()
 const raw=text(input.contact.trim())
 if(input.contactKind==='email'){
  // This versioned email AAD uses the historical trim/lowercase profile, not
  // the more permissive mailto/whitespace actor alias normalization.
  const contact=raw.trim().toLowerCase()
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(contact))throw invalid()
  return Object.freeze({profileId,ownerId,controllerKind,contactKind:'email',contact})
 }
 if(input.contactKind==='phone')return Object.freeze({profileId,ownerId,controllerKind,contactKind:'phone',contact:normalizeActorContact({contactKind:'phone',contact:raw})})
 throw invalid()
}
function generation(value:unknown):number{
 if(!Number.isSafeInteger(value)||typeof value!=='number'||value<1||value>=Number.MAX_SAFE_INTEGER)throw invalid()
 return value
}
function aad(environment:string,binding:ProfileRecoveryIdentity,value:number):Uint8Array{
 const fields=binding.contactKind==='email'
  ?['uhc-profile-recovery-v1',environment,binding.profileId,binding.ownerId,binding.contact,binding.controllerKind,String(value)]
  :['sos-profile-recovery-v1',environment,binding.profileId,binding.ownerId,'phone',binding.contact,binding.controllerKind,String(value)]
 return Buffer.from(fields.join('\n'),'utf8')
}
function bytes(value:Uint8Array):Buffer{
 if(!(value instanceof Uint8Array)||value.byteLength!==32)throw materialInvalid()
 return Buffer.from(value)
}
function fingerprint(seed:Uint8Array):string{return createHash('sha256').update(seed).digest('base64url')}
function matchesFingerprint(seed:Uint8Array,value:string):boolean{
 if(!/^[A-Za-z0-9_-]{43}$/u.test(value))return false
 const expected=Buffer.from(value,'base64url'),actual=createHash('sha256').update(seed).digest()
 return expected.length===actual.length&&timingSafeEqual(expected,actual)
}
function xor(left:Uint8Array,right:Uint8Array):Buffer{
 const result=Buffer.alloc(32)
 for(let index=0;index<32;index++)result[index]=left[index]!^right[index]!
 return result
}
function code(share:Uint8Array):string{
 const payload=Buffer.concat([Buffer.from([1]),share])
 const checksum=createHash('sha256').update(payload).digest().subarray(0,4)
 return 'uhcr1-'+encodeBase58btc(Buffer.concat([payload,checksum]))
}
function decode(value:string):Buffer{
 if(typeof value!=='string'||value.length>256)throw materialInvalid()
 const normalized=value.trim().replace(/\s+/gu,'')
 if(!normalized.startsWith('uhcr1-z'))throw materialInvalid()
 let decoded:Uint8Array
 try{decoded=decodeBase58btc(normalized.slice('uhcr1-'.length))}catch{throw materialInvalid()}
 const packed=Buffer.from(decoded)
 if(packed.length!==37||packed[0]!==1)throw materialInvalid()
 const checksum=createHash('sha256').update(packed.subarray(0,33)).digest().subarray(0,4)
 if(!timingSafeEqual(checksum,packed.subarray(33)))throw materialInvalid()
 return Buffer.from(packed.subarray(1,33))
}

/** Trusted server recovery coordination; admission and atomic vault persistence remain host-owned ports. */
export class ProfileRecoveryService<PreparedProfile=unknown>{
 private readonly repository:ProfileRecoveryRepository<PreparedProfile>
 private readonly kms:ProfileRecoveryKms
 private readonly environment:string
 private readonly clock:()=>Date
 private readonly random:(size:number)=>Uint8Array
 private readonly prepare:ProfileRecoveryServiceOptions<PreparedProfile>['prepareRestoredProfile']
 constructor(options:ProfileRecoveryServiceOptions<PreparedProfile>){
  this.environment=text(options.environment)
  const repository=options.repository,kms=options.kms
  this.repository=Object.freeze({get:repository.get.bind(repository),put:repository.put.bind(repository),rotate:repository.rotate.bind(repository)})
  this.kms=Object.freeze({keyName:text(kms.keyName),encrypt:kms.encrypt.bind(kms),decrypt:kms.decrypt.bind(kms)})
  this.clock=options.now??(()=>new Date())
  this.random=options.randomBytes??(size=>randomBytes(size))
  this.prepare=options.prepareRestoredProfile
 }
 private now():string{
  const result=this.clock()
  if(!(result instanceof Date)||!Number.isFinite(result.getTime()))throw new Error('profile_recovery_clock_invalid')
  return result.toISOString()
 }
 private async material(seed:Uint8Array,binding:ProfileRecoveryIdentity,value:number){
  const server=bytes(this.random(32)),user=xor(seed,server)
  try{
   const encryptedServerShare=await this.kms.encrypt(server,aad(this.environment,binding,value))
   if(typeof encryptedServerShare!=='string'||!encryptedServerShare)throw new Error('profile_recovery_kms_encrypt_invalid')
   return {encryptedServerShare,recoveryCode:code(user)}
  }finally{server.fill(0);user.fill(0)}
 }
 async enroll(input:ProfileRecoveryIdentity,walletSeed:Uint8Array):Promise<{recoveryCode:string}>{
  const binding=identity(input),seed=bytes(walletSeed)
  try{
   if(await this.repository.get(binding.profileId))throw new Error('profile_recovery_already_enrolled')
   const createdAt=this.now(),material=await this.material(seed,binding,1)
   const common={profileId:binding.profileId,ownerId:binding.ownerId,controllerKind:binding.controllerKind,kmsKeyName:this.kms.keyName,encryptedServerShare:material.encryptedServerShare,seedFingerprint:fingerprint(seed),generation:1,createdAt}
   const record:ProfileRecoveryRecord=binding.contactKind==='email'
    ?{...common,version:'uhc-profile-recovery-v1',verifiedEmail:binding.contact}
    :{...common,version:'sos-profile-recovery-v1',contactKind:'phone',verifiedTelephone:binding.contact}
   // Initial prepared profile/application data and callbacks stay in the host
   // repository closure. No callable handle crosses a clone/serialization boundary.
   await this.repository.put(record,null)
   return {recoveryCode:material.recoveryCode}
  }finally{seed.fill(0)}
 }
 async recover(input:ProfileRecoveryIdentity,recoveryCode:string):Promise<{replacementRecoveryCode:string}>{
  const binding=identity(input),loaded=await this.repository.get(binding.profileId)
  if(!loaded)throw new Error('profile_recovery_not_found')
  own(loaded)
  const current=structuredClone(loaded)
  if(current.profileId!==binding.profileId||current.ownerId!==binding.ownerId||current.controllerKind!==binding.controllerKind)throw invalid()
  if(binding.contactKind==='email'){
   if(current.version!=='uhc-profile-recovery-v1'||current.verifiedEmail!==binding.contact||current.contactKind!==undefined||current.verifiedTelephone!==undefined)throw invalid()
  }else if(current.version!=='sos-profile-recovery-v1'||current.contactKind!=='phone'||current.verifiedTelephone!==binding.contact||current.verifiedEmail!==undefined)throw invalid()
  if(current.kmsKeyName!==this.kms.keyName)throw new Error('profile_recovery_kms_key_mismatch')
  const previous=generation(current.generation),user=decode(recoveryCode)
  let server:Buffer|undefined,seed:Buffer|undefined
  try{
   server=bytes(await this.kms.decrypt(text(current.encryptedServerShare),aad(this.environment,binding,previous)))
   seed=xor(server,user)
   if(!matchesFingerprint(seed,current.seedFingerprint))throw materialInvalid()
   const next=previous+1,rotatedAt=this.now(),replacement=await this.material(seed,binding,next)
   const record:ProfileRecoveryRecord={...current,encryptedServerShare:replacement.encryptedServerShare,generation:next,rotatedAt}
   const common={profileId:binding.profileId,ownerId:binding.ownerId,controllerKind:binding.controllerKind,eventId:`${binding.profileId}:recovery:${next}`,generation:next,recoveredAt:rotatedAt}
   const notification:ProfileRecoveryNotification=binding.contactKind==='email'
    ?{...common,version:'uhc-profile-recovery-notification-v1',verifiedEmail:binding.contact}
    :{...common,version:'sos-profile-recovery-notification-v1',contactKind:'phone',verifiedTelephone:binding.contact}
   const restored=await this.prepare?.({walletSeed:seed,identity:binding})
   await this.repository.rotate(record,previous,notification,restored)
   return {replacementRecoveryCode:replacement.recoveryCode}
  }finally{user.fill(0);server?.fill(0);seed?.fill(0)}
 }
}
