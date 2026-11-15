import {openPurposeSigningMaterial,ownSigningInput,signingText,snapshotSigningClaims} from './managed-purpose-signing.js'

export type RuntimeAccessTokenSignerOptions=Readonly<{
 runtimeId:string
 seedMaterial:string
}>
/** Fixed runtime signing capability; issuer, audience, account facts and time policy stay with the host. */
export async function openRuntimeAccessTokenSigner(options:RuntimeAccessTokenSignerOptions){
 const input=ownSigningInput(options),id=signingText(input.runtimeId),seed=signingText(input.seedMaterial)
 const {publicJwk,crypto,withKey}=await openPurposeSigningMaterial({scope:'runtime',identity:id,walletId:'default',purpose:'openid-id-token-signing',algorithm:'ML-DSA-44',seed})
 const signAccessToken=async(request:Readonly<{claims:Readonly<Record<string,unknown>>}>):Promise<string>=>{
  const input=ownSigningInput(request),claims=snapshotSigningClaims(input.claims)
  const header={typ:'at+jwt',alg:'ML-DSA-44',kid:publicJwk.kid}
  const signed=await withKey(key=>crypto.signDataJws(claims,header,key))
  return `${signed.protected}.${signed.payload}.${signed.signature}`
 }
 return Object.freeze({publicJwk,signAccessToken})
}
