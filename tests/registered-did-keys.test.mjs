// Flow contract: fetch only the configured did:web document, preserve its path and identity, select local authentication/keyAgreement methods for the current ML-DSA/ML-KEM profile, and reject redirects, external references, private keys or ambiguous methods. This public-key resolution contract does not grant tenant, employee or subject authority.
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {readFile} from 'node:fs/promises'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const fixture=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url),'utf8'))
const signing=fixture.publicJwks.find(key=>key.kty==='AKP'),agreement=fixture.publicJwks.find(key=>key.kty==='OKP')
const load=()=>import('../dist/registered-did-keys.js')
const did=`${safe.didWeb}:ClinicCase:cds-ES-MD:v1:health-care`
const hostDid=safe.didWeb.split(':').slice(0,3).join(':')
function document(identity=did){
 const methods=[{id:`${identity}#${signing.kid}`,type:'JsonWebKey2020',controller:identity,publicKeyJwk:structuredClone(signing)},{id:`${identity}#${agreement.kid}`,type:'JsonWebKey2020',controller:identity,publicKeyJwk:structuredClone(agreement)}]
 return {'@context':'https://www.w3.org/ns/did/v1',id:identity,verificationMethod:methods,authentication:[methods[0].id],keyAgreement:[methods[1].id]}
}

test('fetches the exact case-preserving canonical path and separates communication authentication from key agreement',async()=>{
 const {resolveRegisteredDidWebKeys}=await load(),seen=[]
 const result=await resolveRegisteredDidWebKeys(did,{fetchImpl:async(url,init)=>{
  seen.push(String(url));assert.equal(init.redirect,'error');assert.ok(init.signal)
  return Response.json(document())
 }})
 assert.deepEqual(seen,[`https://${new URL(safe.httpsBaseUrl).host}/${safe.tenantId}/ClinicCase/cds-ES-MD/v1/health-care/did.json`])
 assert.deepEqual(result.signingJwk,signing);assert.deepEqual(result.keyAgreementJwk,agreement)
 assert.equal(result.signingMethodId,`${did}#${signing.kid}`)
 assert.equal(result.keyAgreementMethodId,`${did}#${agreement.kid}`)
})

test('supports explicit local HTTP through real transport and never follows a redirect',async()=>{
 const {resolveRegisteredDidWebKeys}=await load()
 let localDid,redirect=false,requests=0,serverFailure
 const server=createServer((request,response)=>{
  try{
  requests++
  if(redirect){response.writeHead(302,{Location:'/untrusted-followup'});response.end();return}
  assert.equal(request.url,'/ClinicCase/cds-ES-MD/v1/health-care/did.json')
  response.writeHead(200,{'Content-Type':'application/did+json'});response.end(JSON.stringify(document(localDid)))
  }catch(error){serverFailure=error;response.writeHead(500);response.end()}
 })
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{
  localDid=`did:web:127.0.0.1%3A${server.address().port}:ClinicCase:cds-ES-MD:v1:health-care`
  const result=await resolveRegisteredDidWebKeys(localDid,{allowLoopbackHttp:true})
  assert.equal(result.signingMethodId,`${localDid}#${signing.kid}`)
  redirect=true
  await assert.rejects(resolveRegisteredDidWebKeys(localDid,{allowLoopbackHttp:true}))
  assert.equal(requests,2)
  assert.equal(serverFailure,undefined)
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
})

test('accepts local fragment references and embedded methods, with a trusted same-origin host document override',async()=>{
 const {resolveRegisteredDidWebKeys}=await load()
 for(const embedded of [false,true]){
  const value=document(hostDid)
  value.authentication=embedded?[value.verificationMethod[0]]:[`#${signing.kid}`]
  value.keyAgreement=embedded?[value.verificationMethod[1]]:[`#${agreement.kid}`]
  if(embedded)value.verificationMethod=[]
  const didDocumentUrl=`${new URL(safe.httpsBaseUrl).origin}/host/cds-ES-MD/v1/test-network/.well-known/did.json`
  const result=await resolveRegisteredDidWebKeys(hostDid,{didDocumentUrl,fetchImpl:async url=>{assert.equal(String(url),didDocumentUrl);return Response.json(value)}})
  assert.equal(result.signingJwk.kid,signing.kid)
 }
})

test('rejects a different document/controller, external or missing references, duplicate methods and private material',async()=>{
 const {resolveRegisteredDidWebKeys}=await load()
 const foreignDocument=document();foreignDocument.id=`${did}:foreign`
 const foreignController=document();foreignController.verificationMethod[0].controller=`${did}:foreign`
 const external=document();external.authentication=[`${did}:foreign#external-method`]
 const missing=document();missing.keyAgreement=['#missing-key']
 const duplicate=document();duplicate.verificationMethod.push(structuredClone(duplicate.verificationMethod[0]))
 const privateKey=document();privateKey.verificationMethod[0].publicKeyJwk.privBytes='not-public-material'
 const kidMismatch=document();kidMismatch.verificationMethod[0].publicKeyJwk.kid='unrelated-method'
 const assertionOnly=document();assertionOnly.assertionMethod=assertionOnly.authentication;delete assertionOnly.authentication
 const ambiguous=document();const additional={...ambiguous.verificationMethod[0],id:`${did}#additional-key`,publicKeyJwk:{...signing,kid:'additional-key'}};ambiguous.verificationMethod.push(additional);ambiguous.authentication.push(additional.id)
 for(const value of [foreignDocument,foreignController,external,missing,duplicate,privateKey,kidMismatch,assertionOnly,ambiguous]){
  let requests=0
  await assert.rejects(resolveRegisteredDidWebKeys(did,{fetchImpl:async()=>{requests++;return Response.json(value)}}))
  assert.equal(requests,1,'external verification-method references must never trigger another fetch')
 }
})

test('rejects unsafe overrides and path traversal before requesting any document',async()=>{
 const {resolveRegisteredDidWebKeys}=await load()
 let requests=0
 const fetchImpl=async()=>{requests++;throw new Error('must_not_fetch')}
 const foreignOrigin=new URL(safe.httpsBaseUrl);foreignOrigin.hostname=`foreign.${foreignOrigin.hostname}`
 const insecureOrigin=new URL(safe.httpsBaseUrl);insecureOrigin.protocol='http:'
 for(const [identity,options] of [
  [did,{didDocumentUrl:foreignOrigin.href,fetchImpl}],
  [did,{didDocumentUrl:insecureOrigin.href,fetchImpl}],
  [`${hostDid}:..:did`,{fetchImpl}],
  [`${hostDid}:%2e%2e:did`,{fetchImpl}],
  [`${hostDid}:encoded%2Fslash`,{fetchImpl}],
 ])await assert.rejects(resolveRegisteredDidWebKeys(identity,options))
 assert.equal(requests,0)
})

test('bounds actual streamed document bytes even when no Content-Length is declared',async()=>{
 const {resolveRegisteredDidWebKeys}=await load()
 const value={...document(),untrustedPadding:'x'.repeat(1024*1024)}
 await assert.rejects(resolveRegisteredDidWebKeys(did,{fetchImpl:async()=>Response.json(value)}),/too_large/)
})
