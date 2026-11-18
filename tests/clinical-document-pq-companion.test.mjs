// Flow contract: an authorized clinical document keeps its standard ES256 SHC and receives a separate RFC7797 ML-DSA-65 proof over those exact compact bytes. Each organization owns an independent sealed proof seed, unrelated to profile/communication keys; verifiers bind both signatures to the same configured issuer and current author authority is rechecked across custody awaits.
import assert from 'node:assert/strict'
import test from 'node:test'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import * as sdk from '../dist/index.js'
import {CryptographyService,encodePostQuantumDetachedProofQr,decodePostQuantumDetachedProofQr} from 'antifraud-data-utils-ts/cryptography'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {FhirIpsCreatorKinds} from 'sos-data-utils-ts/clinical-creator-contract'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {decodeSoschainSmartHealthCardQr} from 'sos-data-utils-ts/clinical-document-shc'

const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value,'utf8').digest('hex'),randomUUID})
const organization=`Organization/${safe.demoOrganizationUuids.healthCare}`,subject=`Patient/${safe.resourceUuid}`,documentReference=`Composition/${safe.resourceUuid}`,issuer=`${safe.httpsBaseUrl}/clinical-issuers/${safe.demoOrganizationUuids.healthCare}`
const purpose='clinical-document-pq-proof',collection='synthetic-clinical-proof-keys',clock=()=>1_800_000_000
function snapshot(){return{documentReference,revision:'7',authorizationRevision:'authorization-3',organizationReference:organization,subjectReference:subject,licensedClinicalAuthor:true,permittedResourceTypes:['Procedure'],fhirVersion:'4.0.1',clinicalCreatorBinding:{kind:FhirIpsCreatorKinds.Professional,actorIdentifier:`urn:uuid:${safe.resourceUuid}`,authorIdentifier:`urn:uuid:${safe.demoOrganizationUuids.healthCare}`,ownerIdentifier:organization,role:HealthcareActorRoles.Dentist},bundle:{resourceType:'Bundle',type:'document',entry:[
 {fullUrl:documentReference,resource:{resourceType:'Composition',status:'final',subject:{reference:subject},author:[{reference:organization}],title:'Synthetic clinical document',date:'2027-01-15T08:00:00.000Z',type:{text:'Clinical document'}}},
 {fullUrl:subject,resource:{resourceType:'Patient'}},
 {fullUrl:`Procedure/${safe.resourceUuid}`,resource:{resourceType:'Procedure',status:'completed',subject:{reference:subject},performedDateTime:'2027-01-15T08:00:00.000Z'}},
]}}}
function need(){for(const name of ['createOrganizationClinicalDocumentProofKeyVault','createClinicalDocumentCompanionIssuer','verifyClinicalDocumentCompanion'])assert.equal(typeof sdk[name],'function',`missing owned ${name} boundary`)}
function fixture(){
 need();const vault=new sdk.TransactionalMemoryVaultRepository(),aes=sdk.createAesGcmProfileSealer(Buffer.alloc(32,47)),state={source:snapshot(),afterProofUnseal:undefined,contexts:[],seeds:[]}
 const sealer={seal:async(clear,aad)=>{if(aad.includes(purpose)){state.contexts.push(aad);state.seeds.push(clear)}return aes.seal(clear,aad)},unseal:async(sealed,aad)=>{const clear=await aes.unseal(sealed,aad);if(aad.includes(purpose)&&state.afterProofUnseal)await state.afterProofUnseal();return clear}}
 const documents={readAuthorizedDocument:async()=>structuredClone(state.source)},keys=sdk.createOrganizationClinicalDocumentKeyVault({vault,sealer,collection:'synthetic-clinical-es-keys'}),proofKeys=sdk.createOrganizationClinicalDocumentProofKeyVault({vault,sealer,collection}),issuers=[{organizationReference:organization,issuer}]
 const service=sdk.createClinicalDocumentCompanionIssuer({documents,keys,proofKeys,issuers,nowSeconds:clock})
 return{vault,sealer,state,documents,keys,proofKeys,issuers,service,command:{operationId:'synthetic-companion-issue',documentReference,expectedRevision:'7'}}
}
const code=expected=>error=>error?.code===expected
async function combinedJwks(f){return{keys:[...(await f.service.publicJwks(issuer)).keys,...(await f.service.publicProofJwks(issuer)).keys]}}

test('explicit Demo realm retains both independent signing keys after organization reset and provider reconstruction',async()=>{
 assert.equal(typeof sdk.createDemoClinicalDocumentCompanionIssuer,'function')
 const f=fixture(),realm={organizationReference:'Organization/synthetic-demo-signing-realm',issuer:safe.httpsBaseUrl+'/demo-clinical-issuer'}
 const options={documents:f.documents,keys:f.keys,proofKeys:f.proofKeys,signingRealm:realm,nowSeconds:clock}
 const service=sdk.createDemoClinicalDocumentCompanionIssuer(options),card=await service.issue(f.command)
 const jwks={keys:[...(await service.publicJwks(realm.issuer)).keys,...(await service.publicProofJwks(realm.issuer)).keys]}
 f.state.source=undefined
 const restarted=sdk.createDemoClinicalDocumentCompanionIssuer({...options,keys:sdk.createOrganizationClinicalDocumentKeyVault({vault:f.vault,sealer:f.sealer,collection:'synthetic-clinical-es-keys'}),proofKeys:sdk.createOrganizationClinicalDocumentProofKeyVault({vault:f.vault,sealer:f.sealer,collection})})
 assert.deepEqual(await restarted.publicJwks(realm.issuer),{keys:jwks.keys.filter(key=>key.kty==='EC')})
 assert.deepEqual(await restarted.publicProofJwks(realm.issuer),{keys:jwks.keys.filter(key=>key.kty==='AKP')})
 const verified=await sdk.verifyClinicalDocumentCompanion({credential:card.qrValues,companion:card.companion.pqcValues,trustedIssuers:[realm],nowSeconds:clock(),fetchImpl:async()=>Response.json(jwks)})
 assert.equal(verified.status,'verified');assert.equal(verified.organizationReference,realm.organizationReference)
 await assert.rejects(restarted.issue(f.command),error=>error.code==='clinical_document_shc_authorization_denied')
 f.state.source=snapshot()
 const other='Organization/'+safe.demoOrganizationUuids.animalCare
 f.state.source.organizationReference=other;f.state.source.clinicalCreatorBinding.ownerIdentifier=other;f.state.source.bundle.entry[0].resource.author=[{reference:other}]
 const next=await restarted.issue(f.command)
 assert.equal(next.issuer,card.issuer);assert.equal(next.companion.kid,card.companion.kid)
 assert.equal(JSON.parse(Buffer.from(next.compactJws.split('.')[0],'base64url')).kid,JSON.parse(Buffer.from(card.compactJws.split('.')[0],'base64url')).kid)
})
async function verify(f,card,extra={}){const jwks=await combinedJwks(f);return sdk.verifyClinicalDocumentCompanion({credential:card.compactJws,companion:card.companion.detachedJws,trustedIssuers:f.issuers,nowSeconds:clock(),fetchImpl:async url=>{assert.equal(String(url),issuer+'/.well-known/jwks.json');return Response.json(jwks)},...extra})}

test('retained AF native ML-DSA-65 detached crypto and existing pqc numeric transport agree on exact external bytes',async()=>{
 const pair=await crypto.generateKeyPairMlDsa(randomBytes(32),'ML-DSA-65')
 try{
  const bytes=Buffer.from('synthetic-exact-external-clinical-credential','utf8'),header=Buffer.from(JSON.stringify({alg:'ML-DSA-65',kid:pair.publicJWKey.kid,b64:false,crit:['b64']})).toString('base64url')
  const signature=await crypto.signBytes(Buffer.concat([Buffer.from(header+'.'),bytes]),pair.secretKeyBytes,'ML-DSA-65'),proof=`${header}..${Buffer.from(signature).toString('base64url')}`
  assert.equal(await crypto.verifyDetachedJws(bytes,proof,pair.publicJWKey),true)
  assert.equal(await crypto.verifyDetachedJws(Buffer.from('different-clinical-credential'),proof,pair.publicJWKey),false)
  assert.equal(decodePostQuantumDetachedProofQr(encodePostQuantumDetachedProofQr(proof)),proof)
 }finally{pair.secretKeyBytes.fill(0)}
})

test('issued companion verifies native ML-DSA over exact ES256 card bytes while retaining ordinary SHC verification',async()=>{
 const f=fixture(),card=await f.service.issue(f.command),jwks=await combinedJwks(f),publicKey=(await f.service.publicProofJwks(issuer)).keys[0]
 assert.equal(card.companion.alg,'ML-DSA-65');assert.equal(publicKey.kty,'AKP');assert.equal(publicKey.alg,'ML-DSA-65')
 const protectedProof=JSON.parse(Buffer.from(card.companion.detachedJws.split('.')[0],'base64url'))
 assert.equal(protectedProof.purpose,purpose);assert.equal(protectedProof.iss,issuer);assert.equal(protectedProof.organizationReference,organization)
 assert.equal(await crypto.verifyDetachedJws(Buffer.from(card.compactJws,'utf8'),card.companion.detachedJws,publicKey),true)
 assert.equal(decodePostQuantumDetachedProofQr(card.companion.pqcValues),card.companion.detachedJws)
 const ordinary=await sdk.verifyClinicalDocumentHealthCard({credential:card.compactJws,trustedIssuers:f.issuers,nowSeconds:clock(),fetchImpl:async()=>Response.json(jwks)})
 assert.equal(ordinary.status,'verified');assert.equal(JSON.parse(Buffer.from(card.compactJws.split('.')[0],'base64url')).alg,'ES256')
 const result=await verify(f,card);assert.equal(result.status,'verified');assert.equal(result.issuer,issuer);assert.equal(result.companion.alg,'ML-DSA-65')
})

test('proof seeds are persisted per organization, survive restart and never reuse the ES256 or another organization key',async()=>{
 const f=fixture(),first=await f.service.issue(f.command),a=(await f.service.publicProofJwks(issuer)).keys[0]
 const reloadedProof=sdk.createOrganizationClinicalDocumentProofKeyVault({vault:f.vault,sealer:f.sealer,collection}),reloaded=sdk.createClinicalDocumentCompanionIssuer({documents:f.documents,keys:f.keys,proofKeys:reloadedProof,issuers:f.issuers,nowSeconds:clock})
 assert.deepEqual(await reloaded.publicProofJwks(issuer),await f.service.publicProofJwks(issuer))
 const otherOrg=`Organization/${safe.resourceUuid}`,otherIssuer=`${safe.httpsBaseUrl}/clinical-issuers/${safe.resourceUuid}`
 f.state.source.organizationReference=otherOrg;f.state.source.clinicalCreatorBinding.ownerIdentifier=otherOrg;f.state.source.bundle.entry[0].resource.author=[{reference:otherOrg}]
 const other=sdk.createClinicalDocumentCompanionIssuer({documents:f.documents,keys:f.keys,proofKeys:reloadedProof,issuers:[{organizationReference:otherOrg,issuer:otherIssuer}],nowSeconds:clock})
 await other.issue({...f.command,operationId:'synthetic-other-organization'});const b=(await other.publicProofJwks(otherIssuer)).keys[0]
 assert.notEqual(a.kid,b.kid);assert.notEqual(a.pub,b.pub);assert.notEqual(a.kid,(await f.service.publicJwks(issuer)).keys[0].kid)
 assert.equal(await crypto.verifyDetachedJws(Buffer.from(first.compactJws),first.companion.detachedJws,b),false)
 assert.equal((await f.vault.query(collection,{})).length,2)
})

test('proof custody seals only independent 32-byte seeds with organization, purpose, algorithm and kid AAD and returns no private material',async()=>{
 const f=fixture(),card=await f.service.issue(f.command),jwks=await f.service.publicProofJwks(issuer)
 assert.equal(f.state.seeds.length,1);assert.equal(Buffer.from(f.state.seeds[0],'base64url').length,32)
 for(const token of [organization,purpose,'ML-DSA-65',jwks.keys[0].kid])assert.ok(f.state.contexts[0].includes(token))
 const result=JSON.stringify({card,jwks});assert.equal(result.includes(f.state.seeds[0]),false)
 for(const key of jwks.keys)for(const field of ['priv','privBytes','d','seed','secretKeyBytes'])assert.equal(field in key,false)
 const [stored]=await f.vault.query(collection,{});assert.equal(JSON.stringify(stored).includes(f.state.seeds[0]),false)
})

test('a proof for a different valid signed card or a tampered signature never verifies',async()=>{
 const f=fixture(),first=await f.service.issue(f.command)
 f.state.source.bundle.entry[2].resource.performedDateTime='2027-01-16T08:00:00.000Z'
 const second=await f.service.issue({...f.command,operationId:'synthetic-second-card'})
 await assert.rejects(verify(f,second,{companion:first.companion.detachedJws}),code('clinical_document_pq_signature_invalid'))
 const[h,,s]=first.companion.detachedJws.split('.'),changed=s[0]==='A'?'B':'A'
 await assert.rejects(verify(f,first,{companion:`${h}..${changed}${s.slice(1)}`}),code('clinical_document_pq_signature_invalid'))
})

test('wrong kid, same-kid foreign public bytes and private proof keys are rejected without a new discovery endpoint',async()=>{
 const f=fixture(),card=await f.service.issue(f.command),jwks=await combinedJwks(f),pair=await crypto.generateKeyPairMlDsa(randomBytes(32),'ML-DSA-65')
 try{for(const change of [key=>({...key,kid:'foreign-kid'}),key=>({...key,pub:pair.publicJWKey.pub}),key=>({...key,priv:'must-not-be-published'})]){
  const changed={keys:jwks.keys.map(k=>k.kty==='AKP'?change(k):k)}
  await assert.rejects(verify(f,card,{fetchImpl:async url=>{assert.equal(String(url),issuer+'/.well-known/jwks.json');return Response.json(changed)}}),code('clinical_document_pq_key_invalid'))
 }}finally{pair.secretKeyBytes.fill(0)}
})

test('unknown issuer or a foreign organization mapping cannot authenticate a companion through a caller-selected URL',async()=>{
 const f=fixture(),card=await f.service.issue(f.command);let fetches=0
 await assert.rejects(verify(f,card,{trustedIssuers:[],fetchImpl:async()=>{fetches++;throw Error('must-not-fetch')}}),code('clinical_document_shc_issuer_untrusted'))
 assert.equal(fetches,0)
 await assert.rejects(verify(f,card,{trustedIssuers:[{issuer,organizationReference:'Organization/foreign'}]}),code('clinical_document_pq_key_invalid'))
})

test('revoked clinical authority during proof key opening releases neither signed companion nor a replacement author grant',async()=>{
 const f=fixture();await f.service.issue(f.command)
 f.state.afterProofUnseal=async()=>{f.state.source.licensedClinicalAuthor=false}
 await assert.rejects(f.service.issue({...f.command,operationId:'synthetic-after-revocation'}),code('clinical_document_shc_authorization_denied'))
})

test('public proof JWKS projection is read-only before authorized issuance and never creates an organization seed',async()=>{
 const f=fixture()
 assert.deepEqual(await f.service.publicProofJwks(issuer),{keys:[]})
 assert.equal(f.state.seeds.length,0);assert.deepEqual(await f.vault.query(collection,{}),[])
})

test('companion transport parity: a single numeric SHC QR verifies the proof over its exact compact bytes',async()=>{
 const f=fixture(),card=await f.service.issue(f.command)
 assert.equal(card.qrValues.length,1,'small real issued card must exercise single-QR transport')
 assert.match(card.qrValues[0],/^shc:\/\d+$/u)
 assert.equal(decodeSoschainSmartHealthCardQr(card.qrValues),card.compactJws)
 const canonical=await verify(f,card),transport=await verify(f,card,{credential:card.qrValues[0],companion:card.companion.pqcValues})
 assert.deepEqual(transport,canonical)
})

test('companion transport parity: reversed numeric SHC chunks verify the same exact compact card',async()=>{
 const f=fixture()
 // Deliberately incompressible synthetic clinical text exercises actual owned
 // multi-QR encoding; no hand-built QR framing or duplicate parser lives here.
 f.state.source.bundle.entry[2].resource.code={text:'synthetic-chunked-clinical-text-'+randomBytes(2400).toString('base64url')}
 const card=await f.service.issue(f.command)
 assert.ok(card.qrValues.length>1,'issued card must genuinely require multiple QR chunks')
 const reversed=[...card.qrValues].reverse();assert.equal(decodeSoschainSmartHealthCardQr(reversed),card.compactJws)
 const canonical=await verify(f,card),transport=await verify(f,card,{credential:reversed,companion:card.companion.pqcValues})
 assert.deepEqual(transport,canonical)
})

test('companion transport parity: signed-file wrapper verifies the proof over the contained compact card',async()=>{
 const f=fixture(),card=await f.service.issue(f.command),wrapper=JSON.stringify({verifiableCredential:[card.compactJws]})
 const canonical=await verify(f,card),transport=await verify(f,card,{credential:wrapper})
 assert.deepEqual(transport,canonical)
})

test('companion transport parity: another valid card and a tampered proof remain rejected through QR and file transports',async()=>{
 const f=fixture(),first=await f.service.issue(f.command)
 f.state.source.bundle.entry[2].resource.performedDateTime='2027-01-16T08:00:00.000Z'
 const second=await f.service.issue({...f.command,operationId:'synthetic-second-transport-card'})
 await assert.rejects(verify(f,second,{credential:[...second.qrValues],companion:first.companion.pqcValues}),code('clinical_document_pq_signature_invalid'))
 const [header,,encoded]=first.companion.detachedJws.split('.'),signature=Buffer.from(encoded,'base64url');signature[0]^=1
 const changed=encodePostQuantumDetachedProofQr(`${header}..${signature.toString('base64url')}`)
 await assert.rejects(verify(f,first,{credential:JSON.stringify({verifiableCredential:[first.compactJws]}),companion:changed}),code('clinical_document_pq_signature_invalid'))
})
