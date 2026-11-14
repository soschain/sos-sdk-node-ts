import {createCipheriv,createDecipheriv,randomBytes,scryptSync} from 'node:crypto'
import {PROFILE_SECRET_ENVELOPE_VERSION,type PinProtectedProfileSecret,type ProfileScryptParameters,type AesGcmCiphertext} from 'sos-data-utils-ts/server-profile-secret-contract'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
export type {PinProtectedProfileSecret,ProfileScryptParameters,AesGcmCiphertext} from 'sos-data-utils-ts/server-profile-secret-contract'
export type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
export type ProfileProtectionOptions=Readonly<{cost?:number;blockSize?:number;parallelization?:number}>

/** Authenticated PIN-layer rejection; host custody failures retain their original error. */
export class ProfilePinRejectedError extends Error{
 constructor(){super('Profile PIN rejected.');this.name='ProfilePinRejectedError'}
}
function pinInput(pin:string):void{
 if(typeof pin!=='string'||pin.length<6)throw new TypeError('profile_secret_pin_invalid')
}
function own(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw new TypeError('profile_secret_envelope_invalid')
 const result:Record<string,unknown>=Object.create(null)
 for(const [key,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){
  if(!('value' in descriptor))throw new TypeError('profile_secret_envelope_invalid')
  result[key]=descriptor.value
 }
 return result
}
function bytes(value:unknown,length?:number):Buffer{
 if(typeof value!=='string'||!/^[A-Za-z0-9_-]*$/u.test(value))throw new TypeError('profile_secret_encoding_invalid')
 const decoded=Buffer.from(value,'base64url')
 if(decoded.toString('base64url')!==value||(length!==undefined&&decoded.length!==length))throw new TypeError('profile_secret_encoding_invalid')
 return decoded
}
function parameters(value:unknown):ProfileScryptParameters{
 const p=own(value),cost=p.cost,blockSize=p.blockSize,parallelization=p.parallelization
 if(p.name!=='scrypt'||p.keyLength!==32||!Number.isSafeInteger(cost)||!Number.isSafeInteger(blockSize)||!Number.isSafeInteger(parallelization))throw new TypeError('profile_secret_kdf_invalid')
 const n=cost as number,r=blockSize as number,parallel=parallelization as number
 if(n<2||n>262144||(n&(n-1))!==0||r<1||r>32||parallel<1||parallel>16||n*r*parallel>1048576)throw new TypeError('profile_secret_kdf_bounds_invalid')
 bytes(p.saltBase64Url,16)
 return {name:'scrypt',saltBase64Url:p.saltBase64Url as string,cost:n,blockSize:r,parallelization:parallel,keyLength:32}
}
function ciphertext(value:unknown):AesGcmCiphertext{
 const p=own(value);bytes(p.ivBase64Url,12);bytes(p.tagBase64Url,16);bytes(p.ciphertextBase64Url)
 return {ivBase64Url:p.ivBase64Url as string,tagBase64Url:p.tagBase64Url as string,ciphertextBase64Url:p.ciphertextBase64Url as string}
}
function derive(pin:string,p:ProfileScryptParameters):Buffer{
 pinInput(pin)
 return scryptSync(pin,bytes(p.saltBase64Url,16),32,{N:p.cost,r:p.blockSize,p:p.parallelization,maxmem:Math.max(64*1024*1024,256*p.cost*p.blockSize)})
}
function encrypt(cleartext:Buffer,key:Buffer,aad:string):AesGcmCiphertext{
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv)
 cipher.setAAD(Buffer.from(aad,'utf8'))
 const encrypted=Buffer.concat([cipher.update(cleartext),cipher.final()])
 return {ivBase64Url:iv.toString('base64url'),ciphertextBase64Url:encrypted.toString('base64url'),tagBase64Url:cipher.getAuthTag().toString('base64url')}
}
function decrypt(value:AesGcmCiphertext,key:Buffer,aad:string):Buffer{
 const decipher=createDecipheriv('aes-256-gcm',key,bytes(value.ivBase64Url,12))
 decipher.setAAD(Buffer.from(aad,'utf8'));decipher.setAuthTag(bytes(value.tagBase64Url,16))
 return Buffer.concat([decipher.update(bytes(value.ciphertextBase64Url)),decipher.final()])
}

/** Requires both a PIN-derived key and independently hosted custody; never generates an account seed. */
export async function protectServerProfileSecret(cleartext:string,pin:string,aad:string,hostSealer:ServerProfileSealer,options:ProfileProtectionOptions={}):Promise<PinProtectedProfileSecret>{
 pinInput(pin)
 if(typeof cleartext!=='string'||typeof aad!=='string')throw new TypeError('profile_secret_string_input_required')
 const kdf=parameters({name:'scrypt',saltBase64Url:randomBytes(16).toString('base64url'),cost:options.cost??16384,blockSize:options.blockSize??8,parallelization:options.parallelization??1,keyLength:32})
 const pinKey=derive(pin,kdf),dek=randomBytes(32)
 try{
  const wrapped=await hostSealer.seal(dek.toString('base64url'),`${aad}:dek`)
  if(typeof wrapped!=='string')throw new TypeError('profile_secret_host_ciphertext_invalid')
  return {version:PROFILE_SECRET_ENVELOPE_VERSION,kdf,payload:encrypt(Buffer.from(cleartext,'utf8'),dek,`${aad}:payload`),pinWrappedHostDek:encrypt(Buffer.from(wrapped,'utf8'),pinKey,`${aad}:host-wrapped-dek`)}
 }finally{pinKey.fill(0);dek.fill(0)}
}

/** Wrong PIN never reaches the host; host outages and authenticated payload corruption remain distinct. */
export async function openServerProfileSecret(envelope:PinProtectedProfileSecret,pin:string,aad:string,hostSealer:ServerProfileSealer):Promise<string>{
 pinInput(pin)
 if(typeof aad!=='string')throw new TypeError('profile_secret_string_input_required')
 const source=own(envelope)
 if(source.version!==PROFILE_SECRET_ENVELOPE_VERSION)throw new TypeError('profile_secret_envelope_invalid')
 const kdf=parameters(source.kdf),payload=ciphertext(source.payload),pinWrapped=ciphertext(source.pinWrappedHostDek),pinKey=derive(pin,kdf)
 let wrapped:string
 try{wrapped=decrypt(pinWrapped,pinKey,`${aad}:host-wrapped-dek`).toString('utf8')}
 catch{throw new ProfilePinRejectedError()}
 finally{pinKey.fill(0)}
 const encoded=await hostSealer.unseal(wrapped,`${aad}:dek`)
 let dek:Buffer
 try{dek=bytes(encoded,32)}catch{throw new Error('Profile host returned an invalid DEK.')}
 try{return decrypt(payload,dek,`${aad}:payload`).toString('utf8')}
 finally{dek.fill(0)}
}
