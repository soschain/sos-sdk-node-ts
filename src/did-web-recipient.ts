type PublicJwk=Readonly<Record<string,unknown>>
type ResolverOptions=Readonly<{fetchImpl?:typeof fetch;didDocumentUrl?:string}>
export {buildAuthorityDidWeb} from 'antifraud-data-utils-ts/organization-identity'

/** Resolve the existing operational did:web publication route, with an explicit host-route override. */
export async function resolveDidWebKeyAgreementJwk(recipientDid:string,options:ResolverOptions={}):Promise<PublicJwk>{
  const did=String(recipientDid??'').trim()
  if(!did.startsWith('did:web:'))throw new TypeError('did_web_recipient_required')
  const [authority,...path]=did.slice('did:web:'.length).split(':')
  const host=decodeURIComponent(authority)
  const origin=new URL(`https://${host}`)
  if(origin.username||origin.password||origin.host!==host||path.some(part=>!part||part==='.'||part==='..'||/[/?#]/u.test(decodeURIComponent(part))))throw new TypeError('did_web_recipient_invalid')
  const loopback=['localhost','127.0.0.1','[::1]'].includes(origin.hostname)
  const url=options.didDocumentUrl??`${loopback?'http':'https'}://${host}/${path.length?`${path.join('/')}/`:''}.well-known/did.json`
  const resolved=new URL(url)
  if(resolved.protocol!=='https:'&&!(resolved.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(resolved.hostname)))throw new TypeError('did_document_https_required')
  const response=await (options.fetchImpl??fetch)(resolved.href,{headers:{Accept:'application/did+json, application/json'},redirect:'error'})
  if(!response.ok)throw new Error(`did_document_http_error:${response.status}`)
  const document=await response.json() as Record<string,unknown>
  if(document.id!==did)throw new Error('did_document_identity_mismatch')
  const methods=new Map((Array.isArray(document.verificationMethod)?document.verificationMethod:[]).map(value=>[value.id,value]))
  for(const agreement of Array.isArray(document.keyAgreement)?document.keyAgreement:[]){
    const method=typeof agreement==='string'?methods.get(agreement):agreement
    const key=method?.publicKeyJwk as Record<string,unknown>|undefined
    if(!key||typeof key!=='object'||(key.use&&key.use!=='enc')||'d' in key||'dBytes' in key)continue
    if(!key.kid&&typeof method.id==='string'&&method.id.includes('#'))return {...key,kid:method.id.slice(method.id.lastIndexOf('#')+1)}
    return {...key}
  }
  throw new Error('did_public_encryption_key_missing')
}
