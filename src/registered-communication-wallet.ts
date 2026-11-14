import {OrganizationRegistrationWallet,type RegistrationWalletContext} from './organization-registration-wallet.js'

const failure=()=>new Error('registered_communication_wallet_binding_invalid')
function ownData(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value))throw failure()
 const result:Record<string,unknown>=Object.create(null)
 for(const [name,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){
  if(!Object.hasOwn(descriptor,'value'))throw failure()
  Object.defineProperty(result,name,{value:descriptor.value,enumerable:true})
 }
 return result
}

/**
 * Recovers communication custody for an already unlocked, registered profile.
 * The host supplies the exact stored derivation identity, approved unlocked
 * seed and registered public JWKS. Matching a kid alone is insufficient.
 * No registration, rotation, profile opening or DCR operation occurs here.
 */
export async function openRegisteredCommunicationWallet(options:Readonly<{
 walletKeyDerivationId:string
 unlockedWalletSeed:string
 registeredPublicJwks:readonly Readonly<Record<string,unknown>>[]
 resolveRecipientJwk:(did:string)=>Promise<Readonly<Record<string,unknown>>>
}>):Promise<Readonly<{wallet:OrganizationRegistrationWallet;context:RegistrationWalletContext}>>{
 const id=options.walletKeyDerivationId,seed=options.unlockedWalletSeed
 if(typeof id!=='string'||!id||id.trim()!==id||id.length>512
  ||typeof seed!=='string'||!/^[A-Za-z0-9_-]{43}$/u.test(seed)||Buffer.from(seed,'base64url').byteLength!==32
  ||!Array.isArray(options.registeredPublicJwks))throw failure()
 const registered=options.registeredPublicJwks.map(ownData)
 const context=Object.freeze({
  profile:Object.freeze({profileId:id}),
  runtime:Object.freeze({runtimeId:`${id}:server-runtime`,runtimeType:'backend-service'}),
 })
 const wallet=new OrganizationRegistrationWallet({resolveRecipientJwk:options.resolveRecipientJwk})
 await wallet.provisionCommunicationKeys(context,seed)
 const publicKeys=wallet.getPublicJwks(context)
 for(const [kind,key] of Object.entries(publicKeys)){
  const matches=registered.filter(candidate=>candidate.kid===key.kid)
  if(matches.length!==1)throw failure()
  const match=matches[0]!
  if('d'in match||'dBytes'in match||'privBytes'in match)throw failure()
  const fields=key.kty==='AKP'?['kty','alg','pub','kid']:['kty','crv','x','kid']
  const actual=key as unknown as Record<string,unknown>
  if(fields.some(field=>typeof match[field]!=='string'||match[field]!==actual[field])
   ||(match.use!==undefined&&match.use!==(kind==='signing'?'sig':'enc')))throw failure()
 }
 return Object.freeze({wallet,context})
}
