// Flow contract: 1) a server-selected verified OIDC bootstrap client crosses real loopback HTTP; 2) dependent and proposed controller remain distinct from the submitting professional; 3) submit/poll retain one thread and exact route; 4) GW admission failures stop before polling. This transport proof does not establish employee/group authorization inside GW or complete controller activation.
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import test from 'node:test'
import {IndividualRegistrationClient} from '../dist/individual-registration-client.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {encodeMultibaseSha3} from 'antifraud-data-utils-ts/encoding'

const route={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'}
const issuerDid=`${safe.didWeb}:employee:synthetic-dentist`
const recipientDid=safe.didWeb
// This is an account transport issuer, not a DCR-enrolled controller actor.
const recipientAccountIssuer=`${safe.didWeb}:account:synthetic-recipient`
const subjectUuidBytes=Uint8Array.from(safe.resourceUuid.replaceAll('-','').match(/../gu),pair=>Number.parseInt(pair,16))
const registeredSubject={organizationId:safe.resourceUuid,publicCardAlias:`${safe.didWeb}:card:synthetic-dependent`,providerDid:recipientDid,canonicalSubjectIdentifier:`${recipientDid}:individual:multibase:${encodeMultibaseSha3(subjectUuidBytes,384)}`}
const claims={
 '@context':'org.schema',
 'Organization.identifier.value':safe.resourceUuid,
 'Organization.alternateName':'Dependent subject',
 'Organization.member.role':'ONESELF',
 'Organization.owner.email':safe.firstContactEmail,
 'Organization.owner.identifier.value':safe.demoOrganizationUuids.healthCare,
 'Service.category':'health-care',
}

async function serve(handler,run){
 let failure
 const server=createServer(async(request,response)=>{
  try{await handler(request,response)}catch(error){failure=error;response.writeHead(500);response.end()}
 })
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{await run(`http://127.0.0.1:${server.address().port}`);assert.equal(failure,undefined)}
 finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
}
async function read(request){const chunks=[];for await(const chunk of request)chunks.push(chunk);return JSON.parse(Buffer.concat(chunks).toString('utf8'))}
const options=(baseUrl,actor='creator')=>({baseUrl,bearerToken:actor==='recipient'?'synthetic-verified-recipient-token':'synthetic-verified-account-token',ctx:route,issuerDid:actor==='recipient'?recipientAccountIssuer:issuerDid,recipientDid,transportProfile:'oidc-bootstrap-json'})

test('preserves a dependent and separately proposed controller across real registration submit and polling',async()=>{
 const seen=[]
 const authoritative={body:{resourceType:'Bundle',type:'collection',data:registrationRows()}}
 await serve(async(request,response)=>{
  assert.equal(request.headers.authorization,'Bearer synthetic-verified-account-token')
  assert.equal(request.headers['content-type'],'application/json')
  const message=await read(request);seen.push({path:request.url,message})
  if(request.url.endsWith('/_transaction')){
   assert.equal(message.iss,issuerDid);assert.equal(message.aud,recipientDid)
   assert.deepEqual(message.body.data[0].resource.meta.claims,claims)
   assert.deepEqual(message.attachments,[{id:'synthetic-signed-evidence',media_type:'application/pdf',data:{base64:'c3ludGhldGlj'}}])
   assert.equal(Object.hasOwn(message.body,'attachments'),false)
   response.writeHead(202,{'Content-Type':'application/json'});response.end(JSON.stringify({thid:message.thid}));return
  }
  assert.equal(message.thid,seen[0].message.thid)
  response.writeHead(200,{'Content-Type':'application/json'});response.end(JSON.stringify(authoritative))
 },async baseUrl=>{
  const client=new IndividualRegistrationClient(options(baseUrl))
  const result=await client.registerIndividualOrganization({claims,attachments:[{id:'synthetic-signed-evidence',media_type:'application/pdf',data:{base64:'c3ludGhldGlj'}}]},{intervalMs:0,timeoutMs:5000})
  assert.deepEqual(result.registration.poll.body,authoritative)
  assert.equal(result.offerId,'synthetic-offer')
  assert.equal(Object.hasOwn(result,'controllerActorDid'),false)
  assert.equal(seen[0].path,`/${route.tenantId}/cds-ES-MD/v1/health-care/individual/org.schema/Organization/_transaction`)
  assert.equal(seen[1].path,`${seen[0].path}-response`)
 })
})

test('preserves GW rejection of an employee without dependant-creation authority instead of treating OIDC bootstrap as permission',async()=>{
 let requests=0
 await serve(async(request,response)=>{
  requests++;await read(request)
  response.writeHead(403,{'Content-Type':'application/json'})
  response.end(JSON.stringify({resourceType:'OperationOutcome',issue:[{severity:'error',code:'forbidden'}]}))
 },async baseUrl=>{
  const client=new IndividualRegistrationClient(options(baseUrl))
  await assert.rejects(client.registerIndividualOrganization({claims},{intervalMs:0,timeoutMs:5000}),error=>error.status===403)
  assert.equal(requests,1)
 })
})

test('confirms only the selected Offer and reads the actual separate RESPRSN assignment from GW',async()=>{
 let thread
 await serve(async(request,response)=>{
  assert.equal(request.headers.authorization,'Bearer synthetic-verified-recipient-token')
  const message=await read(request)
  assert.equal(message.iss,recipientAccountIssuer)
  if(request.url.endsWith('/_batch')){
   thread=message.thid
   assert.equal(message.body.data[0].resource.meta.claims['Order.acceptedOffer.identifier'],'synthetic-offer')
   response.writeHead(202,{'Content-Type':'application/json'});response.end('{}');return
  }
  assert.equal(message.thid,thread)
  response.writeHead(200,{'Content-Type':'application/json'})
  response.end(JSON.stringify({body:{resourceType:'Bundle',type:'collection',data:orderRows()}}))
 },async baseUrl=>{
  const result=await new IndividualRegistrationClient(options(baseUrl,'recipient')).confirmIndividualOrganizationOrder({offerId:'synthetic-offer',registeredSubject},{intervalMs:0,timeoutMs:5000})
  assert.equal(result.activationCode,'synthetic-opaque-activation')
  assert.equal(result.controllerAssignmentIdentifier,safe.demoOrganizationUuids.healthCare)
  assert.equal(Object.hasOwn(result,'controllerActorDid'),false)
 })
})

test('does not turn an activation code without an active RESPRSN assignment into controller authority',async()=>{
 for(const relationship of [undefined,'http://terminology.hl7.org/CodeSystem/v3-RoleCode|ONESELF']){
  await serve(async(request,response)=>{
   await read(request)
   if(request.url.endsWith('/_batch')){response.writeHead(202,{'Content-Type':'application/json'});response.end('{}');return}
   response.writeHead(200,{'Content-Type':'application/json'})
   response.end(JSON.stringify({body:{data:[
    {type:'Family-order-response-v1.0',resource:{resourceType:'Bundle',type:'document',entry:[],meta:{claims:{'org.schema.Order.acceptedOffer.identifier':'synthetic-offer','org.schema.IndividualProduct.serialNumber':'synthetic-opaque-activation'}}},response:{status:'200'}},
    ...(relationship?[{resource:{resourceType:'RelatedPerson',meta:{claims:{'org.hl7.fhir.api.RelatedPerson.identifier':'synthetic-assignment','org.hl7.fhir.api.RelatedPerson.relationship':relationship,'org.hl7.fhir.api.RelatedPerson.active':'true'}}},response:{status:'201'}}]:[]),
   ]}}))
  },async baseUrl=>{
   await assert.rejects(new IndividualRegistrationClient(options(baseUrl,'recipient')).confirmIndividualOrganizationOrder({offerId:'synthetic-offer',registeredSubject},{intervalMs:0,timeoutMs:5000}),/assignment_missing_or_ambiguous/)
  })
 }
})

// Binding fixtures mirror FamilyManager's Organization registration row and
// fresh Invoice-Bundle / replay Organization order row plus RelatedPerson.
// A server-confirmed canonical patient and public card alias are distinct.
function registrationRows(provider=recipientDid){return [{type:'Family-registration-offer-v1.0',resource:{resourceType:'Organization',id:registeredSubject.organizationId,meta:{claims:{'org.schema.Organization.did':registeredSubject.canonicalSubjectIdentifier,'org.schema.Organization.sameAs':registeredSubject.publicCardAlias,'org.schema.Offer.identifier':'synthetic-offer','org.schema.Offer.offeredBy':provider}}},response:{status:'201'}}]}
function orderRows({patient=registeredSubject.canonicalSubjectIdentifier,offer='synthetic-offer',replay=false}={}){return [
 {type:'Family-order-response-v1.0',resource:{resourceType:replay?'Organization':'Bundle',...(replay?{id:registeredSubject.organizationId}:{type:'document',entry:[]}),meta:{claims:{'org.schema.Order.acceptedOffer.identifier':offer,'org.schema.IndividualProduct.serialNumber':'synthetic-opaque-activation'}}},response:{status:replay?'200':'201'}},
 {type:'RelatedPerson',resource:{resourceType:'RelatedPerson',id:safe.demoOrganizationUuids.healthCare,meta:{claims:{'org.hl7.fhir.api.RelatedPerson.identifier':safe.demoOrganizationUuids.healthCare,...(patient?{'org.hl7.fhir.api.RelatedPerson.patient':patient}:{}),'org.hl7.fhir.api.RelatedPerson.relationship':'http://terminology.hl7.org/CodeSystem/v3-RoleCode|RESPRSN','org.hl7.fhir.api.RelatedPerson.active':'true'}}},response:{status:'201'}},
]}
async function withGatewayRows(rows,run,{issuer=recipientDid,actor='creator'}={}){
 await serve(async(request,response)=>{
  const message=await read(request)
  if(request.url.endsWith('/_transaction')||request.url.endsWith('/_batch')){response.writeHead(202,{'Content-Type':'application/json'});response.end('{}');return}
  response.writeHead(200,{'Content-Type':'application/json'})
  response.end(JSON.stringify({iss:issuer,aud:actor==='recipient'?recipientAccountIssuer:issuerDid,thid:message.thid,body:{resourceType:'Bundle',type:'collection',data:rows}}))
 },async baseUrl=>run(new IndividualRegistrationClient(options(baseUrl,actor))))
}
const quick={intervalMs:0,timeoutMs:5000}

test('preserves GW Organization id, public card alias and provider as separate registration fields',async()=>{
 await withGatewayRows(registrationRows(),async client=>{
  const result=await client.registerIndividualOrganization({claims},quick)
  assert.deepEqual(result.identity,registeredSubject)
  assert.equal(Object.hasOwn(result.identity,'controllerActorDid'),false)
 })
})

test('rejects a missing Organization identity, foreign provider or unrelated Offer row',async()=>{
 const missing=registrationRows();delete missing[0].resource.id
 const unrelated=registrationRows();delete unrelated[0].resource.meta.claims['org.schema.Offer.identifier'];unrelated.push({type:'Offer-search-response-v1.0',resource:{meta:{claims:{'org.schema.Offer.identifier':'synthetic-offer'}}},response:{status:'200'}})
 for(const rows of [missing,registrationRows(`${safe.didWeb}:foreign-provider`),unrelated]){
  await withGatewayRows(rows,async client=>assert.rejects(client.registerIndividualOrganization({claims},quick),/binding|identity|offer/))
 }
})

test('accepts actual fresh and replay order shapes without equating public alias with canonical patient',async()=>{
 assert.notEqual(registeredSubject.publicCardAlias,registeredSubject.canonicalSubjectIdentifier)
 for(const replay of [false,true])await withGatewayRows(orderRows({replay}),async client=>{
  const result=await client.confirmIndividualOrganizationOrder({offerId:'synthetic-offer',registeredSubject},quick)
  assert.equal(result.canonicalSubjectIdentifier,registeredSubject.canonicalSubjectIdentifier)
  assert.equal(result.controllerAssignmentIdentifier,safe.demoOrganizationUuids.healthCare)
 },{actor:'recipient'})
})

test('rejects missing or foreign patient, a different accepted Offer and a foreign response issuer',async()=>{
 for(const rows of [orderRows({patient:''}),orderRows({patient:`${safe.didWeb}:individual:foreign-subject`}),orderRows({offer:'synthetic-other-offer'})]){
  await withGatewayRows(rows,async client=>assert.rejects(client.confirmIndividualOrganizationOrder({offerId:'synthetic-offer',registeredSubject},quick),/binding|subject|offer/),{actor:'recipient'})
 }
 await withGatewayRows(orderRows(),async client=>assert.rejects(client.confirmIndividualOrganizationOrder({offerId:'synthetic-offer',registeredSubject},quick),/binding|issuer/),{issuer:`${safe.didWeb}:foreign-provider`,actor:'recipient'})
})

test('cannot confirm the recipient invitation with the original professional creator bearer',async()=>{
 let requests=0
 await serve(async(request,response)=>{
  requests++;assert.equal(request.headers.authorization,'Bearer synthetic-verified-account-token');await read(request)
  response.writeHead(403,{'Content-Type':'application/json'});response.end(JSON.stringify({resourceType:'OperationOutcome',issue:[{severity:'error',code:'forbidden'}]}))
 },async baseUrl=>{
  await assert.rejects(new IndividualRegistrationClient(options(baseUrl)).confirmIndividualOrganizationOrder({offerId:'synthetic-offer',registeredSubject},quick),error=>error.status===403)
  assert.equal(requests,1)
 })
})
