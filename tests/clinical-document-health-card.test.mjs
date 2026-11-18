// Flow contract: an already-authorized stored clinical document is issued with its organization's independent sealed P-256 key; verification checks the complete signed SHC against a configured issuer/JWKS before exposing clinical data. Real AES, native ES256/P1363 and canonical numeric codecs are used; trusted document authorization is an injected server port, not browser role input or online-licence proof.
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {createPublicKey,generateKeyPairSync,sign,verify} from 'node:crypto'
import {deflateRawSync,inflateRawSync} from 'node:zlib'
import {readFileSync} from 'node:fs'
import * as api from '../dist/index.js'
import {prepareSmartHealthCard,assembleSmartHealthCardJws} from 'sos-data-utils-ts'
import {encodeSoschainSmartHealthCardQr,decodeSoschainSmartHealthCardQr} from 'sos-data-utils-ts/clinical-document-shc'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {FhirIpsCreatorKinds} from 'sos-data-utils-ts/clinical-creator-contract'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const collection='synthetic-clinical-issuer-keys',organization=`Organization/${safe.demoOrganizationUuids.healthCare}`,subject=`Patient/${safe.resourceUuid}`
const issuer=`${safe.httpsBaseUrl}/clinical-issuers/${safe.demoOrganizationUuids.healthCare}`,documentReference=`Composition/${safe.resourceUuid}`,nowSeconds=()=>1_800_000_000
const document={resourceType:'Bundle',type:'document',entry:[
 {fullUrl:documentReference,resource:{resourceType:'Composition',id:safe.resourceUuid,status:'final',type:{text:'Clinical document'},subject:{reference:subject},author:[{reference:organization}],attester:[{mode:'professional',party:{reference:`urn:uuid:${safe.demoOrganizationUuids.healthCare}`}}],date:'2027-01-15T08:00:00.000Z',title:'Synthetic clinical record',section:[{entry:[{reference:`Procedure/${safe.resourceUuid}`}]}]}},
 {fullUrl:subject,resource:{resourceType:'Patient',id:safe.resourceUuid}},
 {fullUrl:`Procedure/${safe.resourceUuid}`,resource:{resourceType:'Procedure',id:safe.resourceUuid,status:'completed',subject:{reference:subject},performedDateTime:'2027-01-15T08:00:00.000Z',bodySite:[{text:'Recorded clinical site'}],meta:{versionId:'7'}}},
]}
function snapshot(){return{documentReference,revision:'7',authorizationRevision:'authorization-3',organizationReference:organization,subjectReference:subject,licensedClinicalAuthor:true,permittedResourceTypes:['Procedure'],fhirVersion:'4.0.1',clinicalCreatorBinding:{kind:FhirIpsCreatorKinds.Professional,actorIdentifier:`urn:uuid:${safe.resourceUuid}`,authorIdentifier:`urn:uuid:${safe.demoOrganizationUuids.healthCare}`,ownerIdentifier:organization,role:HealthcareActorRoles.Dentist,actorDids:[safe.didWeb]},bundle:structuredClone(document)}}
function need(){
 for(const name of ['createOrganizationClinicalDocumentKeyVault','createClinicalDocumentHealthCardIssuer','verifyClinicalDocumentHealthCard'])assert.equal(typeof api[name],'function',`missing owned ${name} boundary`)
 return api
}
async function fixture(){
 const sdk=need(),vault=new api.TransactionalMemoryVaultRepository(),sealer=api.createAesGcmProfileSealer(Buffer.alloc(32,31)),state={current:snapshot(),reads:0,afterRead:undefined}
 const documents={readAuthorizedDocument:async input=>{assert.equal(input.documentReference,documentReference);state.reads++;const result=structuredClone(state.current);if(state.afterRead)await state.afterRead(state.reads);return result}}
 const keys=sdk.createOrganizationClinicalDocumentKeyVault({vault,sealer,collection})
 const issuers=[{organizationReference:organization,issuer}]
 const service=sdk.createClinicalDocumentHealthCardIssuer({documents,keys,issuers,nowSeconds})
 return{sdk,vault,sealer,state,documents,keys,issuers,service,command:{operationId:'synthetic-issue-operation',documentReference,expectedRevision:'7'}}
}
const code=expected=>error=>error?.code===expected
async function issue(f){return f.service.issue(f.command)}
const readPayload=compact=>JSON.parse(inflateRawSync(Buffer.from(compact.split('.')[1],'base64url')).toString('utf8'))

test('explicit Demo signing realm shares its key across authorized organizations without rewriting clinical ownership',async()=>{
 assert.equal(typeof api.createDemoClinicalDocumentHealthCardIssuer,'function')
 const f=await fixture(),realm={organizationReference:'Organization/synthetic-demo-signing-realm',issuer:safe.httpsBaseUrl+'/demo-clinical-issuer'}
 const service=api.createDemoClinicalDocumentHealthCardIssuer({documents:f.documents,keys:f.keys,signingRealm:realm,nowSeconds})
 const first=await service.issue(f.command),before=JSON.stringify(f.state.current)
 assert.equal(first.issuer,realm.issuer)
 assert.equal(JSON.stringify(f.state.current),before)
 const other='Organization/'+safe.demoOrganizationUuids.animalCare
 f.state.current.organizationReference=other
 f.state.current.clinicalCreatorBinding.ownerIdentifier=other
 f.state.current.bundle.entry[0].resource.author=[{reference:other}]
 const secondBefore=JSON.stringify(f.state.current),second=await service.issue(f.command)
 assert.equal(second.issuer,first.issuer)
 assert.equal(JSON.parse(Buffer.from(first.compactJws.split('.')[0],'base64url')).kid,JSON.parse(Buffer.from(second.compactJws.split('.')[0],'base64url')).kid)
 assert.equal(JSON.stringify(f.state.current),secondBefore)
 assert.ok(JSON.stringify(readPayload(second.compactJws)).includes(other))
})

test('Demo public keys verify a printed credential after document reset and signing-provider reconstruction',async()=>{
 assert.equal(typeof api.createDemoClinicalDocumentHealthCardIssuer,'function')
 const f=await fixture(),realm={organizationReference:'Organization/synthetic-demo-signing-realm',issuer:safe.httpsBaseUrl+'/demo-clinical-issuer'}
 const options={documents:f.documents,keys:f.keys,signingRealm:realm,nowSeconds}
 const service=api.createDemoClinicalDocumentHealthCardIssuer(options),card=await service.issue(f.command),jwks=await service.publicJwks(realm.issuer)
 f.state.current=undefined
 const keys=api.createOrganizationClinicalDocumentKeyVault({vault:f.vault,sealer:f.sealer,collection})
 const restarted=api.createDemoClinicalDocumentHealthCardIssuer({...options,keys}),reads=f.state.reads
 assert.deepEqual(await restarted.publicJwks(realm.issuer),jwks)
 const verified=await api.verifyClinicalDocumentHealthCard({credential:card.qrValues,trustedIssuers:[realm],nowSeconds:nowSeconds(),fetchImpl:async()=>Response.json(jwks)})
 assert.equal(verified.status,'verified')
 assert.equal(verified.organizationReference,realm.organizationReference)
 assert.equal(f.state.reads,reads)
 await assert.rejects(restarted.issue(f.command),error=>error.code==='clinical_document_shc_authorization_denied')
})

test('a shared Demo issuer never grants authorship or initializes a public key on an unauthorized read',async()=>{
 assert.equal(typeof api.createDemoClinicalDocumentHealthCardIssuer,'function')
 const f=await fixture(),realm={organizationReference:'Organization/synthetic-demo-signing-realm',issuer:safe.httpsBaseUrl+'/demo-clinical-issuer'}
 const service=api.createDemoClinicalDocumentHealthCardIssuer({documents:f.documents,keys:f.keys,signingRealm:realm,nowSeconds})
 assert.deepEqual(await service.publicJwks(realm.issuer),{keys:[]})
 f.state.current.licensedClinicalAuthor=false
 await assert.rejects(service.issue(f.command),error=>error.code==='clinical_document_shc_authorization_denied')
 assert.deepEqual(await service.publicJwks(realm.issuer),{keys:[]})
})
function signatureValid(compact,jwk){const[h,p,s]=compact.split('.');return verify('sha256',Buffer.from(`${h}.${p}`),{key:createPublicKey({key:jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(s,'base64url'))}

test('retained control: actual AES vault envelope and native ES256/P1363 use canonical SHC numeric transport',async()=>{
 const vault=new api.TransactionalMemoryVaultRepository(),sealer=api.createAesGcmProfileSealer(Buffer.alloc(32,31)),pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'})
 const sealed=await sealer.seal('synthetic-private-material','synthetic-clinical-purpose');await vault.put(collection,{id:'synthetic-control',sealed});assert.equal(await sealer.unseal((await vault.get(collection,'synthetic-control')).sealed,'synthetic-clinical-purpose'),'synthetic-private-material')
 const prepared=prepareSmartHealthCard({issuer,kid:'synthetic-control-kid',notBefore:nowSeconds(),fhirVersion:'4.0.1',fhirBundle:document})
 const compact=assembleSmartHealthCardJws(prepared,sign('sha256',prepared.signingBytes,{key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'))
 assert.equal(signatureValid(compact,pair.publicKey.export({format:'jwk'})),true);assert.equal(decodeSoschainSmartHealthCardQr(encodeSoschainSmartHealthCardQr(compact)),compact)
})

test('issues a real organization ES256 signature without reconstructing or mutating its authorized clinical source',async()=>{
 const f=await fixture(),before=JSON.stringify(f.state.current.bundle),card=await issue(f),jwks=await f.service.publicJwks(issuer)
 assert.equal(card.issuer,issuer);assert.equal(card.documentReference,documentReference);assert.equal(card.documentRevision,'7');assert.equal(card.compactJws.split('.')[2].length,86)
 assert.equal(jwks.keys.length,1);const key=jwks.keys[0];assert.equal(key.crv,'P-256');assert.equal(key.alg,'ES256');assert.equal(key.use,'sig');assert.equal('d'in key,false);assert.equal(signatureValid(card.compactJws,key),true)
 assert.equal(decodeSoschainSmartHealthCardQr(card.qrValues),card.compactJws);assert.equal(JSON.stringify(f.state.current.bundle),before)
 const procedure=readPayload(card.compactJws).vc.credentialSubject.fhirBundle.entry.map(e=>e.resource).find(r=>r.resourceType==='Procedure');assert.equal(procedure.performedDateTime,document.entry[2].resource.performedDateTime);assert.deepEqual(procedure.bodySite,document.entry[2].resource.bodySite)
})

test('organization keys persist through a fresh key-vault instance and are independent between organizations',async()=>{
 const f=await fixture(),first=await issue(f),secondOrg=`Organization/${safe.resourceUuid}`,secondIssuer=`${safe.httpsBaseUrl}/clinical-issuers/${safe.resourceUuid}`
 const reloadedKeys=f.sdk.createOrganizationClinicalDocumentKeyVault({vault:f.vault,sealer:f.sealer,collection}),reloaded=f.sdk.createClinicalDocumentHealthCardIssuer({documents:f.documents,keys:reloadedKeys,issuers:f.issuers,nowSeconds})
 assert.deepEqual(await reloaded.publicJwks(issuer),await f.service.publicJwks(issuer))
 f.state.current.organizationReference=secondOrg;f.state.current.clinicalCreatorBinding.ownerIdentifier=secondOrg;f.state.current.bundle.entry[0].resource.author=[{reference:secondOrg}]
 const other=f.sdk.createClinicalDocumentHealthCardIssuer({documents:f.documents,keys:reloadedKeys,issuers:[{organizationReference:secondOrg,issuer:secondIssuer}],nowSeconds}),card=await other.issue({...f.command,operationId:'second-organization'})
 const a=(await reloaded.publicJwks(issuer)).keys[0],b=(await other.publicJwks(secondIssuer)).keys[0];assert.notEqual(a.kid,b.kid);assert.notEqual(a.x,b.x);assert.equal(signatureValid(first.compactJws,b),false);assert.equal(signatureValid(card.compactJws,a),false)
 const rows=await f.vault.query(collection,{});assert.equal(rows.length,2);for(const row of rows){assert.equal('d'in(row.publicJwk??{}),false);assert.equal(JSON.stringify(row).includes('"d":'),false)}
})

test('missing clinical author authority and controller-only or foreign organization bindings deny before key creation',async()=>{
 for(const mutate of [s=>{s.licensedClinicalAuthor=false},s=>{delete s.clinicalCreatorBinding},s=>{s.clinicalCreatorBinding.role=HealthcareActorRoles.Controller},s=>{s.clinicalCreatorBinding.ownerIdentifier='Organization/foreign'}]){
  const f=await fixture();mutate(f.state.current);await assert.rejects(issue(f),code('clinical_document_shc_authorization_denied'));assert.equal((await f.vault.query(collection,{})).length,0)
 }
})

test('clinical revocation during key opening and a changed stored revision prevent release of a credential',async()=>{
 const f=await fixture();f.state.afterRead=async count=>{if(count===1)f.state.current.licensedClinicalAuthor=false}
 await assert.rejects(issue(f),code('clinical_document_shc_authorization_denied'))
 const g=await fixture();g.state.current.revision='8';await assert.rejects(issue(g),code('clinical_document_shc_document_changed'))
 for(const mutate of [s=>{s.authorizationRevision='authorization-4'},s=>{s.clinicalCreatorBinding.actorIdentifier=`urn:uuid:${safe.demoOrganizationUuids.healthCare}`}]){
  const changed=await fixture();changed.state.afterRead=async count=>{if(count===1)mutate(changed.state.current)}
  await assert.rejects(issue(changed),code('clinical_document_shc_authorization_denied'))
 }
})

test('verifies the same signed clinical card from compact JWS, full numeric QR and signed file import',async()=>{
 const f=await fixture(),card=await issue(f),jwks=await f.service.publicJwks(issuer),urls=[]
 const fetchImpl=async(url,options)=>{urls.push(String(url));assert.equal(options.redirect,'error');return Response.json(jwks)}
 for(const credential of [card.compactJws,card.qrValues,JSON.stringify({verifiableCredential:[card.compactJws]})]){
  const result=await f.sdk.verifyClinicalDocumentHealthCard({credential,trustedIssuers:f.issuers,fetchImpl,nowSeconds:nowSeconds()});assert.equal(result.status,'verified');assert.equal(result.issuer,issuer);assert.equal(result.organizationReference,organization)
 }
 assert.deepEqual([...new Set(urls)],[issuer+'/.well-known/jwks.json'])
})

test('payload tamper and same-kid foreign key material never return verified clinical data',async()=>{
 const f=await fixture(),card=await issue(f),jwks=await f.service.publicJwks(issuer),[h,p,s]=card.compactJws.split('.'),changed=s[0]==='A'?'B':'A',tampered=`${h}.${p}.${changed}${s.slice(1)}`
 await assert.rejects(f.sdk.verifyClinicalDocumentHealthCard({credential:tampered,trustedIssuers:f.issuers,fetchImpl:async()=>Response.json(jwks),nowSeconds:nowSeconds()}),code('clinical_document_shc_signature_invalid'))
 const foreign=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'})
 await assert.rejects(f.sdk.verifyClinicalDocumentHealthCard({credential:card.qrValues,trustedIssuers:f.issuers,fetchImpl:async()=>Response.json({keys:[{...foreign,kid:jwks.keys[0].kid,use:'sig',alg:'ES256'}]}),nowSeconds:nowSeconds()}),code('clinical_document_shc_key_invalid'))
})

test('unconfigured issuer causes no fetch and callers cannot choose issuance issuer, organization or role',async()=>{
 const f=await fixture(),card=await issue(f);let fetches=0
 await assert.rejects(f.sdk.verifyClinicalDocumentHealthCard({credential:card.compactJws,trustedIssuers:[],fetchImpl:async()=>{fetches++;throw Error('must not fetch')},nowSeconds:nowSeconds()}),code('clinical_document_shc_issuer_untrusted'));assert.equal(fetches,0)
 for(const forbidden of [{issuer},{organizationReference:organization},{role:HealthcareActorRoles.Dentist}])await assert.rejects(f.service.issue({...f.command,...forbidden}),code('clinical_document_shc_command_invalid'))
})

test('unsigned, unsupported-algorithm and short numeric lookup labels cannot pass standard SHC verification',async()=>{
 const f=await fixture(),card=await issue(f),[header,payload,signature]=card.compactJws.split('.'),unsupported=Buffer.from(JSON.stringify({...JSON.parse(Buffer.from(header,'base64url').toString()),alg:'ES384'})).toString('base64url')
 for(const credential of [`${header}.${payload}.`,`${unsupported}.${payload}.${signature}`,'12345678901234567890'])await assert.rejects(f.sdk.verifyClinicalDocumentHealthCard({credential,trustedIssuers:f.issuers,fetchImpl:async()=>{throw Error('invalid input must not fetch')},nowSeconds:nowSeconds()}),code('clinical_document_shc_credential_invalid'))
})

test('wrong kid and private JWKS material are rejected rather than selecting an arbitrary verification key',async()=>{
 const f=await fixture(),card=await issue(f),jwks=await f.service.publicJwks(issuer)
 for(const key of [{...jwks.keys[0],kid:'different-key'},{...jwks.keys[0],d:'must-not-be-published'}]){
  await assert.rejects(f.sdk.verifyClinicalDocumentHealthCard({credential:card.compactJws,trustedIssuers:f.issuers,fetchImpl:async()=>Response.json({keys:[key]}),nowSeconds:nowSeconds()}),code('clinical_document_shc_key_invalid'))
 }
})

test('input and inflated payload limits reject oversized credentials before issuer fetch',async()=>{
 const sdk=need();let fetches=0
 const options={trustedIssuers:[{organizationReference:organization,issuer}],nowSeconds:nowSeconds(),fetchImpl:async()=>{fetches++;throw Error('must not fetch')}}
 const header=Buffer.from(JSON.stringify({alg:'ES256',zip:'DEF',kid:'synthetic-limit-key'})).toString('base64url')
 // Fixed defensive limits: 128 KiB encoded input and 1 MiB inflated JSON, not a SHC specification size claim.
 const bomb=deflateRawSync(Buffer.from(JSON.stringify({iss:issuer,padding:'x'.repeat(1024*1024+1)}))).toString('base64url')
 for(const credential of ['x'.repeat(128*1024+1),`${header}.${bomb}.${Buffer.alloc(64).toString('base64url')}`,'{"verifiableCredential":']){
  await assert.rejects(sdk.verifyClinicalDocumentHealthCard({...options,credential}),code('clinical_document_shc_credential_invalid'))
 }
 assert.equal(fetches,0)
})

test('organization-purpose-key custody context is authenticated and private key material never escapes issuance',async()=>{
 const sdk=need(),vault=new api.TransactionalMemoryVaultRepository(),aes=api.createAesGcmProfileSealer(Buffer.alloc(32,31)),contexts=[]
 const sealer={seal:async(clear,aad)=>{contexts.push(aad);return aes.seal(clear,aad)},unseal:(sealed,aad)=>aes.unseal(sealed,aad)}
 const keys=sdk.createOrganizationClinicalDocumentKeyVault({vault,sealer,collection}),service=sdk.createClinicalDocumentHealthCardIssuer({documents:{readAuthorizedDocument:async()=>snapshot()},keys,issuers:[{organizationReference:organization,issuer}],nowSeconds})
 const card=await service.issue({operationId:'synthetic-custody-operation',documentReference,expectedRevision:'7'}),jwks=await service.publicJwks(issuer),kid=jwks.keys[0].kid
 assert.equal(contexts.length,1);assert.ok(contexts[0].includes(organization));assert.ok(contexts[0].includes('clinical-document-shc'));assert.ok(contexts[0].includes(kid))
 const serialized=JSON.stringify({card,jwks});for(const field of ['"d":','privateKey','sealedPrivateKey'])assert.equal(serialized.includes(field),false)
 const rows=await vault.query(collection,{});assert.equal(rows.length,1)
})

test('a stored clinical PractitionerRole author matching the bound assignment can issue without an optional attester',async()=>{
 const f=await fixture(),binding=f.state.current.clinicalCreatorBinding,source=f.state.current.bundle
 source.entry[0].resource.author=[{reference:binding.authorIdentifier}]
 delete source.entry[0].resource.attester
 source.entry.push({fullUrl:binding.authorIdentifier,resource:{resourceType:'PractitionerRole',practitioner:{reference:binding.actorIdentifier},organization:{reference:organization}}})
 source.entry.push({fullUrl:binding.actorIdentifier,resource:{resourceType:'Practitioner'}})
 const before=JSON.stringify(source),card=await issue(f),jwks=await f.service.publicJwks(issuer)
 assert.equal(signatureValid(card.compactJws,jwks.keys[0]),true)
 assert.equal(JSON.stringify(source),before)
 const projected=readPayload(card.compactJws).vc.credentialSubject.fhirBundle
 assert.equal(projected.entry.filter(e=>e.resource.resourceType==='PractitionerRole').length,1)
 assert.equal('attester'in projected.entry[0].resource,false)
})

test('foreign Composition authors and Immunization patient references are denied before organization key creation',async()=>{
 for(const mutate of [
  s=>{s.bundle.entry[0].resource.author=[{reference:'PractitionerRole/foreign-author'}]},
  s=>{s.permittedResourceTypes=['Immunization'];s.bundle.entry[2].resource={resourceType:'Immunization',status:'completed',vaccineCode:{text:'Recorded vaccine'},patient:{reference:'Patient/foreign-subject'},occurrenceDateTime:'2027-01-15T08:00:00.000Z'}},
 ]){
  const f=await fixture();mutate(f.state.current)
  await assert.rejects(issue(f),code('clinical_document_shc_authorization_denied'))
  assert.equal((await f.vault.query(collection,{})).length,0)
 }
})

test('official SMART Health Cards examples 00 and 01 verify with published crlVersion and x5c JWKS extensions',async()=>{
 const sdk=need(),officialIssuer='https://spec.smarthealth.cards/examples/issuer',organizationReference='Organization/official-smart-health-cards-example'
 const base=new URL('./fixtures/smart-health-cards-official/',import.meta.url),jwks=JSON.parse(readFileSync(new URL('jwks.json',base),'utf8'))
 assert.ok(jwks.keys.some(k=>'crlVersion'in k));assert.ok(jwks.keys.some(k=>'x5c'in k))
 for(const name of ['example-00-d-jws.txt','example-01-d-jws.txt']){
  const credential=readFileSync(new URL(name,base),'utf8').trim()
  const result=await sdk.verifyClinicalDocumentHealthCard({credential,trustedIssuers:[{organizationReference,issuer:officialIssuer}],nowSeconds:nowSeconds(),fetchImpl:async(url,options)=>{
   assert.equal(String(url),officialIssuer+'/.well-known/jwks.json');assert.equal(options.redirect,'error');return Response.json(jwks)
  }})
  assert.equal(result.status,'verified');assert.equal(result.issuer,officialIssuer)
  assert.ok(result.payload.vc.credentialSubject.fhirBundle.entry.some(e=>e.resource.resourceType==='Immunization'))
 }
})

test('public JWKS lookup before authorized issuance is read-only and never provisions private custody',async()=>{
 need();const vault=new api.TransactionalMemoryVaultRepository(),aes=api.createAesGcmProfileSealer(Buffer.alloc(32,31));let seals=0
 const sealer={seal:async(clear,aad)=>{seals++;return aes.seal(clear,aad)},unseal:(sealed,aad)=>aes.unseal(sealed,aad)}
 const keys=api.createOrganizationClinicalDocumentKeyVault({vault,sealer,collection}),service=api.createClinicalDocumentHealthCardIssuer({documents:{readAuthorizedDocument:async()=>snapshot()},keys,issuers:[{organizationReference:organization,issuer}],nowSeconds})
 assert.deepEqual(await service.publicJwks(issuer),{keys:[]});assert.equal(seals,0);assert.deepEqual(await vault.query(collection,{}),[])
 const card=await service.issue({operationId:'synthetic-authorized-initialization',documentReference,expectedRevision:'7'})
 const jwks=await service.publicJwks(issuer);assert.equal(jwks.keys.length,1);assert.equal(seals,1);assert.equal(signatureValid(card.compactJws,jwks.keys[0]),true)
})
