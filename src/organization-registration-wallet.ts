import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService,Content,type MlkemPublicJwk,type MldsaPublicJwk} from 'antifraud-data-utils-ts/cryptography'

export type RegistrationWalletContext=Readonly<{
  profile?:Readonly<{profileId:string}>
  runtime:Readonly<{runtimeId:string;runtimeType:string}>
  walletId?:string
}>
type WalletKeys={signing:MldsaPublicJwk&{kid:string};signingSecret:Uint8Array;encryption:MlkemPublicJwk&{kid:string};encryptionSecret:Uint8Array}
type WalletOptions=Readonly<{resolveRecipientJwk?:(did:string)=>Promise<Readonly<Record<string,unknown>>>}>

/** Server-owned communication custody; this wallet neither issues identity nor verifies contact possession. */
export class OrganizationRegistrationWallet {
  private readonly keys=new Map<string,WalletKeys>()
  private readonly cryptography=new CryptographyService({
    getRandomBytes:async count=>randomBytes(count),
    digestString:async (data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data,'utf8').digest('hex'),
    randomUUID,
  })
  constructor(private readonly options:WalletOptions={}){}
  private owner(context:RegistrationWalletContext):string{
    if(!context.runtime.runtimeId.trim())throw new TypeError('registration_wallet_runtime_required')
    return `runtime:${context.runtime.runtimeId}:${context.walletId??'default'}`
  }
  private requireKeys(context:RegistrationWalletContext):WalletKeys{
    const keys=this.keys.get(this.owner(context))
    if(!keys)throw new Error('registration_wallet_not_provisioned')
    return keys
  }
  async provisionCommunicationKeys(context:RegistrationWalletContext,seedMaterial:string):Promise<void>{
    if(!seedMaterial.trim())throw new TypeError('registration_wallet_seed_required')
    const owner=this.owner(context)
    const derive=(purpose:string,length:number)=>createHash('sha512').update(`${seedMaterial}:${owner}:${purpose}:0`,'utf8').digest().subarray(0,length)
    const signing=await this.cryptography.generateKeyPairMlDsa(derive('comm-signing',32),'ML-DSA-44')
    const encryption=await this.cryptography.generateKeyPairMlKem(derive('comm-encryption',64),'ML-KEM-768')
    const signingKey={...signing.publicJWKey,kid:`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${signing.publicJWKey.kid}`}
    this.keys.set(owner,{signing:signingKey,signingSecret:signing.secretKeyBytes,encryption:encryption.publicJWKey,encryptionSecret:encryption.secretKeyBytes})
  }
  getPublicJwks(context:RegistrationWalletContext):Readonly<{signing:MldsaPublicJwk;encryption:MlkemPublicJwk}>{
    const keys=this.requireKeys(context)
    return structuredClone({signing:keys.signing,encryption:keys.encryption})
  }
  async packForRecipientWithContext(content:object,recipientDid:string,options:Readonly<{context:RegistrationWalletContext}>):Promise<string>{
    const keys=this.requireKeys(options.context)
    const recipient=await this.options.resolveRecipientJwk?.(recipientDid)
    if(!recipient||recipient.kty!=='OKP'||!['ML-KEM-512','ML-KEM-768','ML-KEM-1024'].includes(String(recipient.crv))||typeof recipient.x!=='string'||'d' in recipient||'dBytes' in recipient)throw new Error('registration_recipient_encryption_key_invalid')
    const jws=await this.cryptography.signDataJws(content,{alg:'ML-DSA-44',kid:keys.signing.kid,typ:'JWS'},keys.signingSecret)
    const compact=`${jws.protected}.${jws.payload}.${jws.signature}`
    return this.cryptography.encryptJweToCompact(compact,{enc:'A256GCM',skid:keys.encryption.kid,cty:'JWS'},{...keys.encryption,dBytes:keys.encryptionSecret},recipient as unknown as MlkemPublicJwk)
  }
  async unpackWithContext(packed:string,options:Readonly<{context:RegistrationWalletContext}>):Promise<Readonly<{content:unknown;meta:Record<string,unknown>}>>{
    const keys=this.requireKeys(options.context)
    const envelope=this.cryptography.parseCompactJwe(packed)
    const decrypted=await this.cryptography.decryptJwe(envelope,{...keys.encryption,dBytes:keys.encryptionSecret})
    const payload=Content.bytesToStringUTF8(decrypted.decryptedBytes)
    const header=decrypted.protectedHeader as Record<string,unknown>
    if(header.cty==='JWS'){
      const parts=payload.split('.')
      if(parts.length!==3)throw new Error('registration_response_jws_invalid')
      const content=Content.base64UrlSafeToJSON(parts[1]) as Record<string,unknown>
      return {content:Object.keys(content).length===1&&content.payload&&typeof content.payload==='object'?content.payload:content,meta:{jwe:{protected:header},jws:{compact:payload}}}
    }
    return {content:JSON.parse(payload),meta:{jwe:{protected:header}}}
  }
}
