import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
export type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'

const AES_PREFIX='local-test-v1.'
function strings(cleartext:unknown,aad:unknown):asserts cleartext is string{
 if(typeof cleartext!=='string'||typeof aad!=='string')throw new TypeError('profile_sealer_string_input_required')
}

/** Existing AES envelope adapter. The host selects custody and supplies the actual 256-bit key. */
export function createAesGcmProfileSealer(keyBytes:Uint8Array):ServerProfileSealer{
 if(!(keyBytes instanceof Uint8Array)||keyBytes.byteLength!==32)throw new TypeError('profile_sealer_aes_key_invalid')
 const key=Buffer.from(keyBytes)
 return Object.freeze({
  async seal(cleartext:string,aad:string){
   strings(cleartext,aad)
   const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv)
   cipher.setAAD(Buffer.from(aad,'utf8'))
   const ciphertext=Buffer.concat([cipher.update(cleartext,'utf8'),cipher.final()])
   return `${AES_PREFIX}${Buffer.concat([iv,cipher.getAuthTag(),ciphertext]).toString('base64url')}`
  },
  async unseal(ciphertext:string,aad:string){
   strings(ciphertext,aad)
   if(!ciphertext.startsWith(AES_PREFIX))throw new Error('profile_sealer_aes_envelope_invalid')
   const encoded=ciphertext.slice(AES_PREFIX.length),packed=Buffer.from(encoded,'base64url')
   if(!/^[A-Za-z0-9_-]+$/u.test(encoded)||packed.length<28||packed.toString('base64url')!==encoded)throw new Error('profile_sealer_aes_envelope_invalid')
   const decipher=createDecipheriv('aes-256-gcm',key,packed.subarray(0,12))
   decipher.setAAD(Buffer.from(aad,'utf8'));decipher.setAuthTag(packed.subarray(12,28))
   return Buffer.concat([decipher.update(packed.subarray(28)),decipher.final()]).toString('utf8')
  },
 })
}

/** Raw symmetric KMS ciphertext/AAD adapter; runtime selection and IAM remain host responsibilities. */
export function createGoogleKmsProfileSealer(options:Readonly<{
 keyName:string;accessToken?:()=>Promise<string>;fetchImpl?:typeof fetch;requestTimeoutMs?:number
}>):ServerProfileSealer{
 const {keyName}=options
 if(typeof keyName!=='string'||!/^projects\/[A-Za-z0-9][A-Za-z0-9._:-]*\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+$/u.test(keyName))throw new TypeError('profile_sealer_kms_key_name_invalid')
 const fetchImpl=options.fetchImpl??fetch,timeout=options.requestTimeoutMs??15000
 if(!Number.isSafeInteger(timeout)||timeout<1)throw new TypeError('profile_sealer_request_timeout_invalid')
 const accessToken=options.accessToken??(async()=>{
  const response=await fetchImpl('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',{
   headers:{'Metadata-Flavor':'Google'},redirect:'error',signal:AbortSignal.timeout(timeout),
  })
  if(!response.ok)throw new Error(`profile_sealer_metadata_http_${response.status}`)
  const value:unknown=await response.json()
  const token=value&&typeof value==='object'?(value as Record<string,unknown>).access_token:undefined
  if(typeof token!=='string'||!token.trim())throw new Error('profile_sealer_metadata_token_missing')
  return token
 })
 async function call(operation:'encrypt'|'decrypt',body:Record<string,string>):Promise<Record<string,unknown>>{
  const token=await accessToken()
  if(typeof token!=='string'||!token.trim())throw new Error('profile_sealer_access_token_missing')
  const response=await fetchImpl(`https://cloudkms.googleapis.com/v1/${keyName}:${operation}`,{
   method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(timeout),
  })
  if(!response.ok)throw new Error(`profile_sealer_kms_${operation}_http_${response.status}`)
  const value:unknown=await response.json()
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error(`profile_sealer_kms_${operation}_invalid`)
  return value as Record<string,unknown>
 }
 return Object.freeze({
  async seal(cleartext:string,aad:string){
   strings(cleartext,aad)
   const result=await call('encrypt',{plaintext:Buffer.from(cleartext,'utf8').toString('base64'),additionalAuthenticatedData:Buffer.from(aad,'utf8').toString('base64')})
   if(typeof result.ciphertext!=='string'||!result.ciphertext)throw new Error('profile_sealer_kms_encrypt_invalid')
   return result.ciphertext
  },
  async unseal(ciphertext:string,aad:string){
   strings(ciphertext,aad)
   const result=await call('decrypt',{ciphertext,additionalAuthenticatedData:Buffer.from(aad,'utf8').toString('base64')})
   if(typeof result.plaintext!=='string'||!result.plaintext)throw new Error('profile_sealer_kms_decrypt_invalid')
   const plaintext=Buffer.from(result.plaintext,'base64')
   if(plaintext.toString('base64')!==result.plaintext)throw new Error('profile_sealer_kms_decrypt_invalid')
   return new TextDecoder('utf-8',{fatal:true}).decode(plaintext)
  },
 })
}
