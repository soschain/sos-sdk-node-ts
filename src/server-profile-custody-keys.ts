import {createECDH,createHash,createPrivateKey,randomBytes,randomUUID,sign,type KeyObject} from 'node:crypto'
import {CryptographyService,type MlkemPrivateJwk} from 'antifraud-data-utils-ts/cryptography'
import {OrganizationRegistrationWallet} from './organization-registration-wallet.js'

type PublicKey=Readonly<Record<string,unknown>>
export type ServerProfileKeyPurpose='actor-signing'|'document-at-rest'|'openid-id-token-signing'|'vp-token-signing'|'comm-signing'|'comm-encryption'
/** Public selection metadata. It does not establish role, owner, licence or signing authorization. */
export type ServerProfileKeyDescriptor=Readonly<{
 ownerScope:'profile'|'runtime'
 purpose:ServerProfileKeyPurpose
 kid:string
 alg:'ES384'|'ML-DSA-44'|'ML-KEM-768'
 use:'sig'|'enc'
 publicJwk:PublicKey
 defaultForPurpose?:true
}>
export type ServerProfileCustodyKeysOptions=Readonly<{
 walletKeyDerivationId:string
 unlockedWalletSeed:string
 binding:Readonly<{kind:'enrollment'}>|Readonly<{kind:'registered';publicJwks:readonly PublicKey[];storagePublicJwk:PublicKey}>
}>
type SignInput=Readonly<{clientId:string;payload:Readonly<Record<string,unknown>>}>
const failure=()=>new TypeError('server_profile_custody_binding_invalid')
function own(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw failure()
 const result:Record<string,unknown>=Object.create(null)
 for(const [name,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){
  if(!('value' in descriptor))throw failure()
  result[name]=descriptor.value
 }
 return result
}
function ecKey(seed:string,owner:string,purpose:ServerProfileKeyPurpose):{publicJwk:PublicKey;key:KeyObject}{
 const namespace=`${owner}:${purpose}`,material=`${seed}:${namespace}`
 for(let attempt=0;attempt<256;attempt++){
  const scalar=createHash('sha512').update(`${material}:${namespace}:${attempt}:0`,'utf8').digest().subarray(0,48)
  const curve=createECDH('secp384r1')
  try{curve.setPrivateKey(scalar)}catch{scalar.fill(0);continue}
  const encoded=curve.getPublicKey(undefined,'uncompressed'),privateBytes=curve.getPrivateKey()
  try{
   const x=encoded.subarray(1,49).toString('base64url'),y=encoded.subarray(49,97).toString('base64url')
   const canonical=JSON.stringify({crv:'P-384',kty:'EC',x,y})
   const kid=`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${createHash('sha256').update(canonical,'utf8').digest('base64url')}`
   const publicJwk=Object.freeze({kty:'EC',crv:'P-384',alg:'ES384',use:'sig',kid,x,y})
   return {publicJwk,key:createPrivateKey({key:{...publicJwk,d:privateBytes.toString('base64url')},format:'jwk'})}
  }finally{scalar.fill(0);privateBytes.fill(0)}
 }
 throw new Error('server_profile_ec_derivation_failed')
}
function descriptor(ownerScope:ServerProfileKeyDescriptor['ownerScope'],purpose:ServerProfileKeyPurpose,alg:ServerProfileKeyDescriptor['alg'],use:ServerProfileKeyDescriptor['use'],publicJwk:PublicKey):ServerProfileKeyDescriptor{
 if(typeof publicJwk.kid!=='string')throw failure()
 return Object.freeze({kid:publicJwk.kid,ownerScope,purpose,use,alg,publicJwk:Object.freeze({...publicJwk}),defaultForPurpose:true})
}
function match(expected:ServerProfileKeyDescriptor,value:unknown):void{
 const actual=own(value)
 if(['d','dBytes','privBytes','priv','privateKey','secretKeyBytes','k'].some(field=>field in actual))throw failure()
 for(const [field,entry] of Object.entries(expected.publicJwk))if(actual[field]!==entry)throw failure()
 if((actual.alg!==undefined&&actual.alg!==expected.alg)||(actual.use!==undefined&&actual.use!==expected.use)
  ||(actual.purpose!==undefined&&actual.purpose!==expected.purpose)||(actual.ownerScope!==undefined&&actual.ownerScope!==expected.ownerScope))throw failure()
}
function snapshot(value:unknown,seen=new Set<object>()):unknown{
 if(value===null||typeof value==='string'||typeof value==='boolean')return value
 if(typeof value==='number'&&Number.isFinite(value))return value
 if(typeof value!=='object'||!value||seen.has(value))throw new TypeError('server_profile_signing_payload_invalid')
 seen.add(value)
 try{
  if(Array.isArray(value))return value.map(entry=>snapshot(entry,seen))
  const input=own(value),result:Record<string,unknown>=Object.create(null)
  for(const [name,entry] of Object.entries(input))result[name]=snapshot(entry,seen)
  return result
 }finally{seen.delete(value)}
}

/** JSON-compatible document projection without executing accessors or toJSON. */
function documentSnapshot(value:unknown,seen=new Set<object>()):unknown{
 if(value===null||typeof value==='string'||typeof value==='boolean')return value
 if(typeof value==='number')return Number.isFinite(value)?value:null
 if(typeof value!=='object'||!value||seen.has(value))throw new TypeError('server_profile_document_content_invalid')
 seen.add(value)
 try{
  if(Array.isArray(value)){
   if(Object.getPrototypeOf(value)!==Array.prototype)throw failure()
   const descriptors=Object.getOwnPropertyDescriptors(value),result:unknown[]=[]
   for(let index=0;index<value.length;index++){
    const entry=descriptors[String(index)]
    if(entry&&!('value' in entry))throw failure()
    result.push(!entry||entry.value===undefined?null:documentSnapshot(entry.value,seen))
   }
   return result
  }
  const input=own(value),result:Record<string,unknown>=Object.create(null)
  for(const [name,entry] of Object.entries(input))if(entry!==undefined)result[name]=documentSnapshot(entry,seen)
  return result
 }finally{seen.delete(value)}
}

/** Recovers existing purpose-separated custody. Enrollment creates no authority; registered mode requires exact stored material. */
export async function openServerProfileCustodyKeys(options:ServerProfileCustodyKeysOptions){
 const id=options.walletKeyDerivationId,seed=options.unlockedWalletSeed
 if(typeof id!=='string'||!id||id.trim()!==id||id.length>512||typeof seed!=='string'||!/^[A-Za-z0-9_-]{43}$/u.test(seed)
  ||Buffer.from(seed,'base64url').toString('base64url')!==seed)throw failure()
 const binding=own(options.binding)
 if(binding.kind!=='enrollment'&&binding.kind!=='registered')throw failure()
 const profileOwner=`profile:${id}:default`,runtimeOwner=`runtime:${id}:server-runtime:default`
 const actor=ecKey(seed,profileOwner,'actor-signing'),idToken=ecKey(seed,runtimeOwner,'openid-id-token-signing'),vp=ecKey(seed,runtimeOwner,'vp-token-signing')
 const crypto=new CryptographyService({getRandomBytes:async size=>randomBytes(size),digestString:async(data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data,'utf8').digest('hex'),randomUUID})
 const storageSeed=createHash('sha512').update(`${seed}:${profileOwner}:document-at-rest:0`,'utf8').digest()
 const storage=await crypto.generateKeyPairMlKem(storageSeed,'ML-KEM-768')
 storageSeed.fill(0);storage.secretKeyBytes.fill(0)
 const communication=new OrganizationRegistrationWallet(),context={profile:{profileId:id},runtime:{runtimeId:`${id}:server-runtime`,runtimeType:'backend-service'}}
 await communication.provisionCommunicationKeys(context,seed)
 const pair=communication.getPublicJwks(context)
 const descriptors=Object.freeze([
  descriptor('profile','actor-signing','ES384','sig',actor.publicJwk),
  descriptor('profile','document-at-rest','ML-KEM-768','enc',{...storage.publicJWKey}),
  descriptor('runtime','openid-id-token-signing','ES384','sig',idToken.publicJwk),
  descriptor('runtime','vp-token-signing','ES384','sig',vp.publicJwk),
  descriptor('runtime','comm-signing','ML-DSA-44','sig',{...pair.signing,use:'sig'}),
  descriptor('runtime','comm-encryption','ML-KEM-768','enc',{...pair.encryption}),
 ])
 const dcr=descriptors.filter(entry=>entry.purpose!=='document-at-rest')
 if(binding.kind==='registered'){
  if(!Array.isArray(binding.publicJwks)||binding.publicJwks.length!==5)throw failure()
  const registered=binding.publicJwks.map(own)
  if(new Set(registered.map(entry=>entry.kid)).size!==5)throw failure()
  for(const expected of dcr){const matches=registered.filter(entry=>entry.kid===expected.kid);if(matches.length!==1)throw failure();match(expected,matches[0])}
  match(descriptors[1]!,binding.storagePublicJwk)
 }
 const managed=(entry:typeof actor,embedPublicKey:boolean)=>async(input:SignInput):Promise<string>=>{
  if(typeof input.clientId!=='string'||!input.clientId||input.clientId.trim()!==input.clientId)throw new TypeError('server_profile_signing_client_binding_required')
  const payload=snapshot(input.payload) as Record<string,unknown>
  if(payload.client_id!==input.clientId)throw new TypeError('server_profile_signing_client_binding_invalid')
  const protectedHeader={alg:'ES384',typ:'JWT',kid:entry.publicJwk.kid,...(embedPublicKey?{jwk:entry.publicJwk}:{})}
  const encodedHeader=Buffer.from(JSON.stringify(protectedHeader),'utf8').toString('base64url'),encodedPayload=Buffer.from(JSON.stringify(payload),'utf8').toString('base64url')
  const inputBytes=`${encodedHeader}.${encodedPayload}`
  const signature=sign('sha384',Buffer.from(inputBytes,'utf8'),{key:entry.key,dsaEncoding:'ieee-p1363'}).toString('base64url')
  return `${inputBytes}.${signature}`
 }
 /** Exact detached credential bytes; this operation never substitutes the VP key. */
 const signActorDetachedJws=async(input:Readonly<{payload:string|Uint8Array}>):Promise<string>=>{
  if(typeof input.payload!=='string'&&!(input.payload instanceof Uint8Array))throw new TypeError('server_profile_detached_payload_invalid')
  const header={typ:'application/vc+ld+json',alg:'ES384',kid:actor.publicJwk.kid,b64:false,crit:['b64']}
  const encodedHeader=Buffer.from(JSON.stringify(header),'utf8').toString('base64url')
  const payload=typeof input.payload==='string'?Buffer.from(input.payload,'utf8'):Buffer.from(input.payload)
  const signingBytes=Buffer.concat([Buffer.from(`${encodedHeader}.`,'ascii'),payload])
  const signature=sign('sha384',signingBytes,{key:actor.key,dsaEncoding:'ieee-p1363'}).toString('base64url')
  return `${encodedHeader}..${signature}`
 }
 /** Separate existing presentation profile; does not relax either client-bound API above. */
 const signIdentityPresentationJws=async(input:Readonly<{claims:Readonly<Record<string,unknown>>}>):Promise<string>=>{
  const claims=snapshot(own(input.claims))
  const header={typ:'application/vp+jwt',alg:'ES384',kid:vp.publicJwk.kid}
  const encodedHeader=Buffer.from(JSON.stringify(header),'utf8').toString('base64url'),encodedPayload=Buffer.from(JSON.stringify(claims),'utf8').toString('base64url')
  const signingInput=`${encodedHeader}.${encodedPayload}`
  const signature=sign('sha384',Buffer.from(signingInput,'ascii'),{key:vp.key,dsaEncoding:'ieee-p1363'}).toString('base64url')
  return `${signingInput}.${signature}`
 }
 /** Registered SMART private_key_jwt assertion, using the runtime ID-token key. */
 const signClientAssertion=async(input:Readonly<{clientId:string;audience:string;issuedAt:number;jti:string}>):Promise<string>=>{
  if(binding.kind!=='registered')throw new Error('server_profile_assertion_registered_binding_required')
  const {clientId,audience,issuedAt,jti}=input
  if(typeof clientId!=='string'||!clientId||clientId.trim()!==clientId||typeof audience!=='string'||!audience||typeof jti!=='string'||!jti||!Number.isSafeInteger(issuedAt)||issuedAt<0)throw failure()
  const header={typ:'JWT',alg:'ES384',kid:idToken.publicJwk.kid}
  const claims={iss:clientId,sub:clientId,aud:audience,iat:issuedAt,exp:issuedAt+300,jti}
  const encodedHeader=Buffer.from(JSON.stringify(header),'utf8').toString('base64url'),encodedPayload=Buffer.from(JSON.stringify(claims),'utf8').toString('base64url')
  const signingInput=`${encodedHeader}.${encodedPayload}`
  return `${signingInput}.${sign('sha384',Buffer.from(signingInput,'ascii'),{key:idToken.key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`
 }
 // id, seed and binding are already snapshots of the opening inputs. Never
 // reread caller options here: logical row IDs do not select custody owners.
 const ownerBinding=createHash('sha256').update(`storage:profile:${id}`,'utf8').digest('base64url')
 const documentHeader=Object.freeze({typ:'gdc-confidential-document+jwe',cty:'application/json',enc:'A256GCM',gdc_pq_profile:'confidential-pqc-v1',gdc_key_purpose:'document-at-rest',gdc_owner_binding:ownerBinding})
 const withStorageKey=async<T>(operation:(key:MlkemPrivateJwk)=>Promise<T>):Promise<T>=>{
  if(binding.kind!=='registered')throw new Error('server_profile_document_registered_binding_required')
  const material=createHash('sha512').update(`${seed}:${profileOwner}:document-at-rest:0`,'utf8').digest()
  let pair:Awaited<ReturnType<CryptographyService['generateKeyPairMlKem']>>|undefined
  try{
   pair=await crypto.generateKeyPairMlKem(material,'ML-KEM-768')
   match(descriptors[1]!,pair.publicJWKey)
   return await operation({...pair.publicJWKey,dBytes:pair.secretKeyBytes})
  }finally{material.fill(0);pair?.secretKeyBytes.fill(0)}
 }
 const confidentialStorageAdapter=Object.freeze({
  async protect<T extends Readonly<{content:unknown}>>(document:T):Promise<Omit<T,'content'|'jwe'>&{jwe:string}>{
   const input=own(document)
   if(!Object.hasOwn(input,'content')||input.content===undefined)throw new TypeError('server_profile_document_content_required')
   const content=documentSnapshot(input.content),{content:_content,...metadata}=input
   const jwe=await withStorageKey(key=>crypto.encryptJweToCompact(JSON.stringify(content),documentHeader,key,key))
   return {...metadata,jwe} as Omit<T,'content'|'jwe'>&{jwe:string}
  },
  async unprotect<T extends Readonly<{jwe:unknown}>>(document:T):Promise<Omit<T,'jwe'|'content'>&{content:unknown}>{
   const input=own(document)
   if(typeof input.jwe!=='string'||!input.jwe)throw new TypeError('server_profile_document_compact_jwe_required')
   const decoded=await withStorageKey(key=>crypto.decryptJwe(input.jwe as string,key)),header=own(decoded.protectedHeader)
   for(const [name,value] of Object.entries(documentHeader))if(header[name]!==value)throw new Error('server_profile_document_owner_or_policy_binding_invalid')
   if(header.alg!=='ML-KEM-768+HKDF-SHA256+A256GCMKW'||header.kid!==descriptors[1]!.kid)throw new Error('server_profile_document_key_binding_invalid')
   const content:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(decoded.decryptedBytes))
   const {jwe:_jwe,...metadata}=input
   return {...metadata,content} as Omit<T,'jwe'|'content'>&{content:unknown}
  },
 })
 return Object.freeze({descriptors,publicJwks:Object.freeze(dcr.map(entry=>entry.publicJwk)),storagePublicJwk:descriptors[1]!.publicJwk,signActorJws:managed(actor,false),signVpJws:managed(vp,true),signActorDetachedJws,signIdentityPresentationJws,signClientAssertion,confidentialStorageAdapter})
}
