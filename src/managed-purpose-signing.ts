import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService,type MldsaPublicJwk} from 'antifraud-data-utils-ts/cryptography'

type PurposeProfile=Readonly<{
 scope:'profile'|'runtime'
 identity:string
 walletId:'controller-signing-pqc-v1'|'default'
 purpose:'actor-signing'|'openid-id-token-signing'
 algorithm:'ML-DSA-65'|'ML-DSA-44'
 seed:string
}>
type ManagedPublicJwk=Readonly<MldsaPublicJwk&{kid:string;use:'sig'}>
const invalid=()=>new TypeError('managed_purpose_signing_input_invalid')
export function ownSigningInput(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw invalid()
 const result:Record<string,unknown>=Object.create(null)
 for(const [key,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){
  if(!('value' in descriptor))throw invalid()
  result[key]=descriptor.value
 }
 return result
}
export function signingText(value:unknown):string{
 if(typeof value!=='string'||!value.length||value.length>65536)throw invalid()
 return value
}
function jsonSnapshot(value:unknown,seen=new Set<object>()):unknown{
 if(value===null||typeof value==='string'||typeof value==='boolean')return value
 if(typeof value==='number'&&Number.isFinite(value))return value
 if(!value||typeof value!=='object'||seen.has(value))throw invalid()
 seen.add(value)
 try{
  if(Array.isArray(value)){
   if(Object.getPrototypeOf(value)!==Array.prototype)throw invalid()
   const result:unknown[]=[]
   for(let index=0;index<value.length;index++){
    const descriptor=Object.getOwnPropertyDescriptor(value,String(index))
    if(!descriptor||!('value' in descriptor))throw invalid()
    result.push(jsonSnapshot(descriptor.value,seen))
   }
   return result
  }
  const source=ownSigningInput(value),result:Record<string,unknown>=Object.create(null)
  for(const [key,entry] of Object.entries(source))result[key]=jsonSnapshot(entry,seen)
  return result
 }finally{seen.delete(value)}
}
export function snapshotSigningClaims(value:unknown):Record<string,unknown>{
 return jsonSnapshot(ownSigningInput(value)) as Record<string,unknown>
}

/** Internal engine for the two fixed public capabilities; not a wallet or public policy API. */
export async function openPurposeSigningMaterial(profile:PurposeProfile){
 const {scope,identity,walletId,purpose,algorithm,seed}=profile
 const owner=`${scope}:${identity}:${walletId}`
 const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),digestString:async(value,hash)=>createHash(hash.replaceAll('-','').toLowerCase()).update(value,'utf8').digest('hex'),randomUUID})
 const derive=async()=>{
  const material=createHash('sha512').update(`${seed}:${owner}:${purpose}:0`,'utf8').digest()
  try{return await crypto.generateKeyPairMlDsa(material.subarray(0,32),algorithm)}
  finally{material.fill(0)}
 }
 const initial=await derive()
 const publicJwk:ManagedPublicJwk=Object.freeze({...initial.publicJWKey,use:'sig',kid:`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${initial.publicJWKey.kid}`})
 initial.secretKeyBytes.fill(0)
 const withKey=async<T>(operation:(secret:Uint8Array)=>Promise<T>):Promise<T>=>{
  const pair=await derive()
  try{
   if(pair.publicJWKey.pub!==publicJwk.pub||pair.publicJWKey.alg!==algorithm)throw invalid()
   return await operation(pair.secretKeyBytes)
  }finally{pair.secretKeyBytes.fill(0)}
 }
 return {publicJwk,crypto,withKey}
}
