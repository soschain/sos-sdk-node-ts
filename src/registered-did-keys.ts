import type {DidDocument,VerificationMethod} from 'antifraud-data-utils-ts/did-document'
import type {MldsaPublicJwk,MlkemPublicJwk} from 'antifraud-data-utils-ts/cryptography'

type Options=Readonly<{fetchImpl?:typeof fetch;didDocumentUrl?:string;allowLoopbackHttp?:boolean;requestTimeoutMs?:number}>
type Row=Record<string,unknown>
const fail=()=>new Error('registered_did_document_key_binding_invalid')
function row(value:unknown):Row{if(!value||typeof value!=='object'||Array.isArray(value))throw fail();return value as Row}
function text(value:unknown):string{if(typeof value!=='string'||!value||value.trim()!==value)throw fail();return value}
function localMethodId(value:unknown,did:string):string{
 const id=text(value),full=id.startsWith('#')?`${did}${id}`:id
 if(!full.startsWith(`${did}#`)||!full.slice(did.length+1)||full.slice(did.length+1).includes('#')||/\s/u.test(full))throw fail()
 return full
}
function documentUrl(did:string,options:Options):URL{
 if(!did.startsWith('did:web:')||/[/?#\s\\]/u.test(did))throw fail()
 const [encodedAuthority,...rawPath]=did.slice('did:web:'.length).split(':')
 if(!encodedAuthority)throw fail()
 const authority=decodeURIComponent(encodedAuthority),origin=new URL(`https://${authority}`)
 if(origin.username||origin.password||origin.host.toLowerCase()!==authority.toLowerCase()||origin.pathname!=='/'||origin.search||origin.hash)throw fail()
 const loopback=['localhost','127.0.0.1','[::1]'].includes(origin.hostname)
 if(loopback&&options.allowLoopbackHttp)origin.protocol='http:'
 const path=rawPath.map(part=>{
  const decoded=decodeURIComponent(part)
  if(!decoded||decoded==='.'||decoded==='..'||/[/?#\s\\]/u.test(decoded))throw fail()
  return encodeURIComponent(decoded)
 })
 const target=new URL(path.length?`${path.join('/')}/did.json`:'.well-known/did.json',origin)
 if(options.didDocumentUrl!==undefined){
  if(path.length)throw new TypeError('registered_did_host_document_override_required')
  const override=new URL(options.didDocumentUrl)
  if(override.username||override.password||override.search||override.hash||override.origin!==origin.origin)throw fail()
  return override
 }
 return target
}
async function readDocument(response:Response):Promise<DidDocument>{
 const maximumBytes=1024*1024,declared=response.headers.get('content-length')
 if(declared!==null&&Number(declared)>maximumBytes)throw new Error('registered_did_document_too_large')
 const reader=response.body?.getReader()
 if(!reader)throw fail()
 const chunks:Uint8Array[]=[];let length=0
 try{
  for(;;){const chunk=await reader.read();if(chunk.done)break;length+=chunk.value.byteLength;if(length>maximumBytes){await reader.cancel();throw new Error('registered_did_document_too_large')}chunks.push(chunk.value)}
 }finally{reader.releaseLock()}
 const bytes=new Uint8Array(length);let offset=0
 for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength}
 return row(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes))) as unknown as DidDocument
}

/**
 * Resolves the configured operational did:web communication profile, not every
 * DID method or algorithm. Only local authentication and keyAgreement methods
 * establish candidates; untrusted key identifiers never become fetch targets.
 */
export async function resolveRegisteredDidWebKeys(did:string,options:Options={}):Promise<Readonly<{
 signingJwk:MldsaPublicJwk;keyAgreementJwk:MlkemPublicJwk;signingMethodId:string;keyAgreementMethodId:string
}>>{
 text(did)
 const target=documentUrl(did,options),timeout=options.requestTimeoutMs??15000
 if(!Number.isSafeInteger(timeout)||timeout<1)throw new TypeError('registered_did_document_timeout_invalid')
 const response=await(options.fetchImpl??fetch)(target.href,{headers:{Accept:'application/did+json, application/json'},redirect:'error',signal:AbortSignal.timeout(timeout)})
 if(!response.ok)throw new Error(`registered_did_document_http_${response.status}`)
 const document=await readDocument(response)
 if(document.id!==did)throw new Error('registered_did_document_identity_mismatch')
 const methods=new Map<string,VerificationMethod>()
 if(document.verificationMethod!==undefined&&!Array.isArray(document.verificationMethod))throw fail()
 for(const value of document.verificationMethod??[]){
  const method=row(value) as unknown as VerificationMethod
  const rawId=text(method.id),id=rawId.startsWith('#')?localMethodId(rawId,did):rawId
  if(methods.has(id))throw fail()
  methods.set(id,method)
 }
 function candidates(relationship:'authentication'|'keyAgreement'){
  const refs=document[relationship]
  if(!Array.isArray(refs))throw fail()
  const selected=new Map<string,{methodId:string;key:Row}>()
  for(const reference of refs){
   const id=localMethodId(typeof reference==='string'?reference:row(reference).id,did)
   const embedded=typeof reference==='string'?undefined:row(reference)
   const top=methods.get(id)
   const method=embedded??top
   if(!method||method.controller!==did||!text(method.type))throw fail()
   const key=row(method.publicKeyJwk)
   if('d'in key||'dBytes'in key||'privBytes'in key||'privateKey'in key||'secretKeyBytes'in key)throw fail()
   const supported=relationship==='authentication'
    ?key.kty==='AKP'&&['ML-DSA-44','ML-DSA-65','ML-DSA-87'].includes(String(key.alg))&&typeof key.pub==='string'&&!!key.pub
    :key.kty==='OKP'&&['ML-KEM-512','ML-KEM-768','ML-KEM-1024'].includes(String(key.crv))&&typeof key.x==='string'&&!!key.x
   if(!supported)continue
   if(key.use!==undefined&&key.use!==(relationship==='authentication'?'sig':'enc'))throw fail()
   const fragment=id.slice(did.length+1),kid=key.kid===undefined?fragment:text(key.kid)
   if(kid!==fragment&&kid!==id)throw fail()
   if(embedded&&top){
    const other=row(top.publicKeyJwk),fields=relationship==='authentication'?['kty','alg','pub','kid']:['kty','crv','x','kid']
    if(top.controller!==did||fields.some(field=>other[field]!==key[field]))throw fail()
   }
   const prior=selected.get(id)
   if(prior){for(const field of ['kty','alg','pub','crv','x','kid'])if(prior.key[field]!==key[field])throw fail();continue}
   selected.set(id,{methodId:id,key:{...key,kid}})
  }
  if(selected.size!==1)throw fail()
  return [...selected.values()][0]!
 }
 const signing=candidates('authentication'),agreement=candidates('keyAgreement')
 return {signingJwk:signing.key as unknown as MldsaPublicJwk,keyAgreementJwk:agreement.key as unknown as MlkemPublicJwk,signingMethodId:signing.methodId,keyAgreementMethodId:agreement.methodId}
}
