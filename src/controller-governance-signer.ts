import {openPurposeSigningMaterial,ownSigningInput,signingText} from './managed-purpose-signing.js'

export type ControllerGovernanceSignerOptions=Readonly<{
 keyDerivationId:string
 unlockedWalletSeed:string
}>
/** Fixed extra governance key; the host independently admits the controller and checks published authority. */
export async function openControllerGovernanceSigner(options:ControllerGovernanceSignerOptions){
 const input=ownSigningInput(options),id=signingText(input.keyDerivationId),seed=signingText(input.unlockedWalletSeed)
 const {publicJwk,crypto,withKey}=await openPurposeSigningMaterial({scope:'profile',identity:id,walletId:'controller-signing-pqc-v1',purpose:'actor-signing',algorithm:'ML-DSA-65',seed})
 const signDetachedCredential=async(request:Readonly<{payload:string|Uint8Array}>):Promise<string>=>{
  const {payload}=ownSigningInput(request)
  if(typeof payload!=='string'&&!(payload instanceof Uint8Array))throw new TypeError('controller_governance_payload_invalid')
  const header={typ:'application/vc+ld+json',alg:'ML-DSA-65',kid:publicJwk.kid,b64:false,crit:['b64']}
  const encoded=Buffer.from(JSON.stringify(header),'utf8').toString('base64url')
  const bytes=Buffer.concat([Buffer.from(`${encoded}.`,'ascii'),typeof payload==='string'?Buffer.from(payload,'utf8'):Buffer.from(payload)])
  const signature=await withKey(key=>crypto.signBytes(bytes,key,'ML-DSA-65'))
  return `${encoded}..${Buffer.from(signature).toString('base64url')}`
 }
 return Object.freeze({publicJwk,signDetachedCredential})
}
