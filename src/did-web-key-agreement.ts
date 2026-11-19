import {createPublicKey} from 'node:crypto'
import {isIP} from 'node:net'
import {isDeepStrictEqual} from 'node:util'
import type {PublicJwk} from 'antifraud-data-utils-ts/cryptography'

export type ResolveDidWebKeyAgreementJwkOptions=Readonly<{
 fetchImpl?:typeof fetch
 /** Fixed publication convention; never an arbitrary path or fallback. */
 publicationProfile?:'did-web'|'hosted-well-known'
 /** Explicit loopback-only test transport; the document must retain the requested DID. */
 didDocumentUrl?:string
 /** Trusted host test capability; never forward a browser-supplied value. */
 allowTestLoopbackDocument?:true
 requestTimeoutMs?:number
}>
type ObjectValue=Record<string,unknown>
const invalid=()=>new Error('did_web_agreement_binding_invalid')
const maximumBytes=1024*1024
function object(value:unknown):ObjectValue{
 if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw invalid()
 const result:ObjectValue=Object.create(null)
 for(const [name,descriptor]of Object.entries(Object.getOwnPropertyDescriptors(value))){if(!('value'in descriptor))throw invalid();result[name]=descriptor.value}
 return result
}
function string(value:unknown):string{if(typeof value!=='string'||!value||value.trim()!==value)throw invalid();return value}
function localId(value:unknown,did:string):string{
 const raw=string(value),id=raw.startsWith('#')?did+raw:raw
 if(!id.startsWith(did+'#')||!id.slice(did.length+1)||/[\s#]/u.test(id.slice(did.length+1)))throw invalid()
 return id
}
function endpoint(did:string,override:string|undefined,allowTest:boolean,profile:'did-web'|'hosted-well-known'):URL{
 if(!did.startsWith('did:web:')||/[\s/?#\\]/u.test(did))throw invalid()
 const [encodedHost,...segments]=did.slice(8).split(':');if(!encodedHost)throw invalid()
 const host=decodeURIComponent(encodedHost),origin=new URL('https://'+host)
 const ip=isIP(origin.hostname.replace(/^\[|\]$/gu,''))
 if(origin.username||origin.password||origin.host.toLowerCase()!==host.toLowerCase()||origin.pathname!=='/'||origin.search||origin.hash)throw invalid()
 if(ip&&(!allowTest||override===undefined||!['127.0.0.1','[::1]'].includes(origin.hostname)))throw invalid()
 const path=segments.map(segment=>{const value=decodeURIComponent(segment);if(!value||value==='.'||value==='..'||/[/?#\\\u0000-\u001f\u007f]/u.test(value))throw invalid();return encodeURIComponent(value)})
 const suffix=profile==='hosted-well-known'?'.well-known/did.json':'did.json'
 const canonical=new URL(path.length?'/'+path.join('/')+'/'+suffix:'/.well-known/did.json',origin)
 if(override===undefined)return canonical
 if(!allowTest)throw new Error('did_web_agreement_test_transport_required')
 const target=new URL(override)
 if(!['http:','https:'].includes(target.protocol)||!['localhost','127.0.0.1','[::1]'].includes(target.hostname)||target.username||target.password||target.search||target.hash)throw invalid()
 if(ip&&(target.hostname!==origin.hostname||target.port!==origin.port))throw invalid()
 // Reject traversal even when URL normalizes it before exposing pathname.
 const transportPath=override.slice(override.indexOf('://')+3).replace(/^[^/]+/u,'')
 for(const part of transportPath.split('/')){const decoded=decodeURIComponent(part);if(decoded==='.'||decoded==='..'||/[/\\\u0000-\u001f\u007f]/u.test(decoded))throw invalid()}
 return target
}
async function bounded<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{
 if(signal.aborted)throw signal.reason
 let abort:(()=>void)|undefined
 try{return await Promise.race([promise,new Promise<never>((_resolve,reject)=>{abort=()=>reject(signal.reason);signal.addEventListener('abort',abort,{once:true})})])}
 finally{if(abort)signal.removeEventListener('abort',abort)}
}
async function document(response:Response,signal:AbortSignal):Promise<ObjectValue>{
 if(!response.ok||response.redirected)throw new Error('did_web_agreement_document_http_'+response.status)
 const declared=response.headers.get('content-length');if(declared!==null&&(!/^\d+$/u.test(declared)||Number(declared)>maximumBytes))throw new Error('did_web_agreement_document_too_large')
 const reader=response.body?.getReader();if(!reader)throw invalid()
 const chunks:Uint8Array[]=[];let size=0
 try{for(;;){const next=await bounded(reader.read(),signal);if(next.done)break;size+=next.value.byteLength;if(size>maximumBytes){await reader.cancel();throw new Error('did_web_agreement_document_too_large')}chunks.push(next.value)}}
 finally{reader.releaseLock()}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}
 return object(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)))
}
function publicObject(value:unknown):ObjectValue{
 const key=object(value)
 if(['d','k','p','q','dp','dq','qi','oth','dBytes','privBytes','priv','privateKey','privateKeyBytes','secretKey','secretKeyBytes'].some(field=>field in key)||key.kty==='oct')throw invalid()
 return key
}
function agreementObject(value:unknown,id:string):ObjectValue{
 const key=publicObject(value)
 key.kid=key.kid===undefined||key.kid===''?id.slice(id.indexOf('#')+1):string(key.kid)
 return key
}
function encoded(value:unknown,length:number):string{const text=string(value),bytes=Buffer.from(text,'base64url');if(bytes.length!==length||bytes.toString('base64url')!==text)throw invalid();return text}
function supportedKey(key:ObjectValue):PublicJwk|undefined{
 if(key.use!==undefined&&key.use!=='enc')return undefined
 if(key.key_ops!==undefined){if(!Array.isArray(key.key_ops)||!key.key_ops.length||new Set(key.key_ops).size!==key.key_ops.length||key.key_ops.some(value=>!['encrypt','wrapKey','deriveKey','deriveBits'].includes(String(value))))throw invalid()}
 const operations=key.key_ops===undefined?undefined:Array.isArray(key.key_ops)?key.key_ops.map(string):undefined
 const metadata={...(key.kid===undefined?{}:{kid:string(key.kid)}),...(key.use===undefined?{}:{use:'enc'}),...(operations===undefined?{}:{key_ops:operations})}
 if(key.kty==='EC'){
  const crv=string(key.crv),length=crv==='P-384'?48:['P-256','secp256k1'].includes(crv)?32:0;if(!length)return undefined
  const x=encoded(key.x,length),y=encoded(key.y,length)
  createPublicKey({format:'jwk',key:{kty:'EC',crv,x,y}})
  // AF's existing EC public contract names these algorithms. Other algorithm
  // labels require an owning public-type extension; they are never cast here.
  let alg:'ES256'|'ES384'|'ES256K'|undefined
  if(key.alg!==undefined){if(key.alg!=='ES256'&&key.alg!=='ES384'&&key.alg!=='ES256K')throw invalid();alg=key.alg}
  return {...key,...metadata,kty:'EC',crv,x,y,...(alg?{alg}:{})}
 }
 const crv=key.crv
 if(key.kty==='OKP'&&(crv==='ML-KEM-512'||crv==='ML-KEM-768'||crv==='ML-KEM-1024')){
  const length=crv==='ML-KEM-512'?800:crv==='ML-KEM-768'?1184:1568,x=encoded(key.x,length)
  return {...key,...metadata,...(key.alg===undefined?{}:{alg:string(key.alg)}),kty:'OKP',crv,x}
 }
 return undefined
}

/**
 * Resolve the first supported public JWK in the DID's declared keyAgreement
 * order. EC and ML-KEM are supported by the existing AF PublicJwk contract;
 * this API does not promise X25519/RSA, signing-profile admission or JSON-LD
 * processing. Only the selected fixed publication document or explicit
 * loopback test route is fetched. Remote methods are never dereferenced. The injected
 * fetch and loopback opt-in are trusted host/test capabilities, not browser
 * options. A matching test document does not prove public HTTPS ownership.
 * Standards: https://w3c-ccg.github.io/did-method-web/ and
 * https://www.w3.org/TR/did-core/#key-agreement
 */
export async function resolveDidWebKeyAgreementJwk(did:string,options:ResolveDidWebKeyAgreementJwkOptions={}):Promise<PublicJwk>{
 string(did);const profile=options.publicationProfile??'did-web'
 if(profile!=='did-web'&&profile!=='hosted-well-known')throw new TypeError('did_web_agreement_publication_profile_invalid')
 const target=endpoint(did,options.didDocumentUrl,options.allowTestLoopbackDocument===true,profile),timeout=options.requestTimeoutMs??15000
 if(!Number.isSafeInteger(timeout)||timeout<1||timeout>120000)throw new TypeError('did_web_agreement_timeout_invalid')
 const signal=AbortSignal.timeout(timeout),response=await bounded((options.fetchImpl??fetch)(target.href,{headers:{Accept:'application/did+json, application/json'},credentials:'omit',redirect:'error',signal}),signal)
 const doc=await document(response,signal);if(doc.id!==did)throw new Error('did_web_agreement_document_identity_mismatch')
 const methods=new Map<string,ObjectValue>()
 const definitions=doc.verificationMethod
 if(definitions!==undefined&&!Array.isArray(definitions))throw invalid()
 for(const value of definitions??[]){const method=object(value),id=localId(method.id,did);if(methods.has(id))throw invalid();methods.set(id,method)}
 if(!Array.isArray(doc.keyAgreement)||!doc.keyAgreement.length)throw invalid()
 const seen=new Set<string>(),candidates:PublicJwk[]=[]
 for(const reference of doc.keyAgreement){
  const embedded=typeof reference==='string'?undefined:object(reference),id=localId(embedded?.id??reference,did)
  if(seen.has(id))throw invalid();seen.add(id)
  const top=methods.get(id),method=embedded??top;if(!method||method.controller!==did||!string(method.type))throw invalid()
  const key=agreementObject(method.publicKeyJwk,id)
  if(embedded&&top){const other=agreementObject(top.publicKeyJwk,id);if(top.controller!==did||top.type!==embedded.type||!isDeepStrictEqual(other,key))throw invalid()}
  const selected=supportedKey(key);if(selected)candidates.push(selected)
 }
 if(!candidates.length)throw new Error('did_web_agreement_supported_key_not_found')
 return candidates[0]!
}
