// Flow contract: a registered controller's signed/encrypted administration uses fixed tenant/host bindings, validates typed phone/email inventory and exact installation selectors, preserves explicit Offer/Order payment evidence, and reads authoritative organization counters. A synthetic crypto peer proves transport/wire validation only; actual GW authorization, persistence and online lifecycle have separate gates.
import assert from 'node:assert/strict'
import test from 'node:test'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {buildOrganizationEmployeeDidWeb,buildStableActorIdentifier} from 'antifraud-data-utils-ts/organization-identity'
import {SchemaOrgPersonClaim as Person,SchemaOrgOfferClaim as Offer,SchemaOrgOrganizationClaim as Organization,SchemaOrgIndividualProductClaim as Product,SchemaOrgOrderClaim as Order} from 'antifraud-data-utils-ts/schema-org-claims'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {OrganizationLifecycleClaim} from 'sos-data-utils-ts/organization-lifecycle-contract'
import {buildTestNetworkControllerWorkflowAssignment,OrganizationWorkflowGroupKinds,OrganizationWorkflowCapabilities} from 'sos-data-utils-ts/organization-workflow-access'
import {ClaimConsent,ConsentStatuses} from 'fhir-data-utils-ts'
import {buildResearchStudyReviewTeamGroupSearch} from 'sos-data-utils-ts/research-review-team-identity'
import {buildServiceDirectoryResource,normalizeDirectoryFlatClaimsResource} from 'sos-data-utils-ts/place-service-directory'
import {HealthcareServiceClaim} from 'fhir-data-utils-ts/claims'
import {buildHealthDcatDataset,buildHealthDcatDataService,buildHealthDcatDistribution,ClaimsHealthDcatCatalogRecord} from 'sos-data-utils-ts/health-dcat'
import {buildResearchStudyProvenanceResource} from 'sos-data-utils-ts/provenance'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {createVerifiedGatewaySecureAdapter} from '../dist/registered-gateway-transport.js'
import {WorkforceClient} from '../dist/workforce-client.js'
const need=name=>assert.equal(typeof WorkforceClient.prototype[name],'function','missing owned WorkforceClient.'+name)
const ctx={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'}
const hostDid=safe.didWeb,providerDid=`${hostDid}:${ctx.tenantId}:cds-es-md:v1:${ctx.sector}`
const tenantIssuer=`urn:example:organization:${ctx.tenantId}`,controllerDid=`${providerDid}:controller`
const phone={contactKind:'phone',contact:safe.phoneE164},role=HealthcareActorRoles.Dentist
const employeeDid=buildOrganizationEmployeeDidWeb({...phone,organizationDidWeb:providerDid,role})
const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),randomUUID,
 digestString:async(s,a)=>createHash(a.replaceAll('-','').toLowerCase()).update(s).digest('hex')})
const walletContext=id=>({profile:{profileId:id},runtime:{runtimeId:`${id}:runtime`,runtimeType:'backend-service'}})
const employeeRow=()=>({type:'Employee-search-response-v1.0',response:{status:'200'},resource:{id:safe.resourceUuid,status:'active',claims:{
 [Person.Telephone]:phone.contact,[Person.HasOccupation]:role,[Person.Identifier]:employeeDid,[Person.SameAs]:employeeDid,
},contained:[{id:safe.demoOrganizationUuids.healthCare,type:'Occupation',employeeId:safe.resourceUuid,meta:{claims:{[Person.HasOccupation]:role}}}]}})
const licenseRow=()=>({type:'License-search-response-v1.0',response:{status:'200'},resource:{id:'synthetic-employee-seat',meta:{status:'active',maxDevices:2,subjectId:safe.resourceUuid,
 claims:{[Offer.SerialNumber]:'synthetic-employee-seat',[Product.Category]:'professional',[Product.AdditionalType]:'web',[Person.Telephone]:phone.contact,[Person.OccupationIdentifierValue]:role},
 deviceBindings:[{clientId:'synthetic-employee-client',clientInstanceId:'synthetic-employee-installation',status:'active',deviceInfo:{clientInstanceId:'synthetic-employee-installation',model:'Phone',os:'SyntheticOS',osVersion:'1'},activatedAt:123}]}}})
async function fixture(handler){
 const callerContext=walletContext('synthetic-admin-caller'),tenantContext=walletContext('synthetic-admin-tenant'),hostContext=walletContext('synthetic-admin-host')
 let callerPublic
 const tenant=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>callerPublic.encryption})
 const host=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>callerPublic.encryption})
 await tenant.provisionCommunicationKeys(tenantContext,'synthetic-admin-tenant-seed')
 await host.provisionCommunicationKeys(hostContext,'synthetic-admin-host-seed')
 const tenantPublic=tenant.getPublicJwks(tenantContext),hostPublic=host.getPublicJwks(hostContext)
 const caller=new OrganizationRegistrationWallet({resolveRecipientJwk:async did=>did===hostDid?hostPublic.encryption:tenantPublic.encryption})
 await caller.provisionCommunicationKeys(callerContext,'synthetic-admin-caller-seed');callerPublic=caller.getPublicJwks(callerContext)
 const adapter=(did,key)=>createVerifiedGatewaySecureAdapter({gatewayDid:did,
  pack:message=>caller.packForRecipientWithContext(message,did,{context:callerContext}),
  decrypt:packed=>caller.unpackWithContext(packed,{context:callerContext}),resolveGatewaySigningJwk:async requested=>{assert.equal(requested,did);return key}})
 const messages=[],replies=new Map()
 const fetchImpl=async(url,init)=>{
  const path=new URL(url).pathname,isHost=path.startsWith('/host/'),wallet=isHost?host:tenant,context=isHost?hostContext:tenantContext
  const decoded=await wallet.unpackWithContext(new URLSearchParams(init.body).get('request'),{context})
  const compact=decoded.meta.jws.compact,header=JSON.parse(Buffer.from(compact.split('.')[0],'base64url'))
  assert.equal(Object.hasOwn(header,'jwk'),false);assert.equal(await crypto.verifyJws(compact,callerPublic.signing),true)
  const message=decoded.content
  assert.equal(message.client_id,'synthetic-controller-client');assert.equal(message.iss,controllerDid)
  assert.equal(message.aud,isHost?hostDid:providerDid)
  messages.push({path,message})
  if(!path.endsWith('-response')){
   const response=await handler(path,message)
   if(response?.httpStatus)return new Response('{}',{status:response.httpStatus})
   replies.set(message.thid,{jti:randomUUID(),iss:response.iss,aud:response.aud??controllerDid,thid:response.thid??message.thid,body:response.body})
   return new Response('{}',{status:202})
  }
  const packed=await wallet.packForRecipientWithContext(replies.get(message.thid),controllerDid,{context})
  return new Response(JSON.stringify({response:packed}),{status:200,headers:{'content-type':'application/json'}})
 }
 const options={baseUrl:'https://example.invalid',ctx:{...ctx},providerDid,gatewayDid:providerDid,dcrResponseIssuer:hostDid,tenantIssuer,
  issuerDid:controllerDid,bearerToken:'synthetic-verified-phone-controller-token',clientId:'synthetic-controller-client',transportProfile:'registered-didcomm-encrypted',
  secureTransportAdapter:adapter(providerDid,tenantPublic.signing),fetchImpl,
  hostRegistry:{hostDid,jurisdiction:'ES-MD',hostNetwork:'test-network',responseIssuer:hostDid,secureTransportAdapter:adapter(hostDid,hostPublic.signing)}}
 return {options,messages,client:new WorkforceClient(options)}
}

test('registered controller uses fixed research routes and verifies the correlated signed response',async()=>{
 const body={resourceType:'Bundle',type:'batch',data:[{resource:{resourceType:'Parameters',meta:{claims:{'ResearchStudy.status':['draft']}}}}]}
 const resultBody={resourceType:'Bundle',type:'searchset',data:[]}
 const {client,messages}=await fixture(async(path,message)=>{
  assert.equal(path,`/${ctx.tenantId}/cds-${ctx.jurisdiction}/v1/${ctx.sector}/organization/org.hl7.fhir.r5/ResearchStudy/_search`)
  assert.deepEqual(message.body,body)
  return {iss:providerDid,body:resultBody}
 })
 const result=await client.submitResearchAdministration({resourceType:'ResearchStudy',action:'_search',operationId:'research-study-test',body})
 assert.deepEqual(result.poll.body.body,resultBody)
 await assert.rejects(()=>client.submitResearchAdministration({resourceType:'Patient',action:'_search',operationId:'research-study-test',body}),/workforce_research_route_invalid/u)
 assert.equal(messages.length,2)
})

test('reads research studies through the registered tenant without a caller-built route or Bundle',async()=>{
 const claims={'ResearchStudy.status':['draft']}
 const body={resourceType:'Bundle',type:'searchset',data:[]}
 const {client,messages}=await fixture(async(path,message)=>{
  assert.equal(path,`/${ctx.tenantId}/cds-${ctx.jurisdiction}/v1/${ctx.sector}/organization/org.hl7.fhir.r5/ResearchStudy/_search`)
  assert.deepEqual(message.body,{resourceType:'Bundle',type:'batch',data:[{
   resource:{resourceType:'Parameters',meta:{claims}},
  }]})
  return {iss:providerDid,body}
 })
 const result=await client.searchResearchStudies({operationId:'research-study-list',claims})
 assert.deepEqual(result.poll.body.body,body)
 assert.equal(messages.length,2)
})

test('reads the registered study team and only the consent records matching the study and selected actor',async()=>{
 const studyId=safe.resourceUuid
 const partyReference=`PractitionerRole/${safe.demoOrganizationUuids.healthCare}`
 const requests=[]
 const {client,messages}=await fixture(async(path,message)=>{
  requests.push([path.split('/').slice(-2).join('/'),message.body.data[0].resource.meta.claims])
  return {iss:providerDid,body:{resourceType:'Bundle',type:'searchset',data:[]}}
 })
 await client.searchResearchReviewTeam({studyId,operationId:'research-team-search'})
 await client.searchResearchStudyConsents({studyId,partyReference,operationId:'research-consent-search'})
 assert.deepEqual(requests,[
  ['Group/_search',{'Group.identifier':[buildResearchStudyReviewTeamGroupSearch(studyId).identifier]}],
  ['Consent/_search',{[ClaimConsent.sourceReference]:[`ResearchStudy/${studyId}`],[ClaimConsent.actorIdentifier]:[partyReference]}],
 ])
 await assert.rejects(async()=>client.searchResearchStudyConsents({studyId,partyReference:'Patient/synthetic',operationId:'research-denied'}),/workforce_research_study_party_invalid/u)
 assert.equal(messages.length,4)
})

test('stores internal and public services on their fixed tenant routes and checks the receipt identity',async()=>{
 const id=safe.resourceUuid,department='clinic-department'
 const healthcare={resourceType:'HealthcareService',id,meta:{claims:{
  [HealthcareServiceClaim.Identifier]:id,[HealthcareServiceClaim.Name]:'Consultation',
  [HealthcareServiceClaim.Organization]:`Organization/${department}`,[HealthcareServiceClaim.Active]:'true',
 }}}
 const directory=buildServiceDirectoryResource({id,organizationIdentifier:department,name:'Consultation',
  placeIdentifiers:['clinic-place'],serviceTypes:['consultation'],areaServed:[ctx.jurisdiction]})
 const {client,messages}=await fixture(async(_path,message)=>{
  const resource=message.body.data[0].resource
  return {iss:providerDid,body:{data:[{response:{status:'200'},resource:{...resource,
   id:message.thid==='catalog-mismatched-receipt'?'other-service':resource.id}}]}}
 })
 await client.createHealthcareService({resource:healthcare,operationId:'catalog-healthcare-create'})
 await client.publishDirectoryService({resource:directory,operationId:'catalog-service-publish'})
 const submitted=messages.filter(({path})=>!path.endsWith('-response'))
 assert.deepEqual(submitted.map(({path})=>path.split('/').slice(-4).join('/')),[
  'organization/org.hl7.fhir.r5/HealthcareService/_batch','organization/org.schema/Service/_batch',
 ])
 assert.deepEqual(submitted.map(({message})=>message.body.data[0]),[
  {request:{method:'POST',url:`HealthcareService/${id}`},resource:healthcare},
  {type:'Service-schema.org',request:{method:'PUT',url:`Service/${id}`},resource:normalizeDirectoryFlatClaimsResource(directory)},
 ])
 await assert.rejects(client.publishDirectoryService({resource:directory,operationId:'catalog-mismatched-receipt'}),/workforce_service_receipt_invalid/u)
 await assert.rejects(client.createHealthcareService({resource:{...healthcare,id:'invalid/route'},operationId:'catalog-invalid'}),/workforce_service_resource_invalid/u)
 assert.equal(messages.length,6)
})

test('reads one registered organization catalogue across the governed directory, clinical and DCAT collections',async()=>{
 const resources={HealthcareService:{resourceType:'HealthcareService',id:safe.resourceUuid,meta:{claims:{[HealthcareServiceClaim.Name]:['Consultation']}}},
  Service:normalizeDirectoryFlatClaimsResource(buildServiceDirectoryResource({id:safe.resourceUuid,organizationIdentifier:'clinic-department',
   name:'Consultation',placeIdentifiers:['clinic-place'],serviceTypes:['consultation']}))}
 const requests=[]
 const {client,options}=await fixture(async(path,message)=>{
  const [section,format,type,action]=path.split('/').slice(-4)
  requests.push(`${section}/${format}/${type}/${action}`)
  assert.deepEqual(message.body.data,[{resource:{resourceType:type,id:'search',meta:{claims:{}}}}])
  const resource=resources[type]
  return {iss:providerDid,body:{data:resource?[{response:{status:'200'},resource}]:[]}}
 })
 assert.deepEqual(await client.getOrganizationCatalog({operationId:'catalog-read'}),{
  organizations:[],places:[],healthcareServices:[resources.HealthcareService],services:[resources.Service],products:[],datasets:[],records:[],
 })
 assert.deepEqual(new Set(requests),new Set([
  ...['Organization','Place','Service','Product'].map(type=>`organization/org.schema/${type}/_search`),
  'organization/org.hl7.fhir.r5/HealthcareService/_search',
  ...['Dataset','CatalogRecord'].map(type=>`organization/org.w3.dcat/${type}/_search`),
 ]))
 const foreign=await fixture(async path=>({iss:providerDid,body:{data:path.includes('/HealthcareService/')
  ?[{response:{status:'200'},resource:{...resources.HealthcareService,resourceType:'Patient'}}]:[]}}))
 await assert.rejects(foreign.client.getOrganizationCatalog({operationId:'catalog-foreign'}),/workforce_catalog_resource_invalid/u)
 const offering={id:'published-tracker',type:'Product',name:'Tracker',description:'Tracker',sector:ctx.sector,category:'devices',demo:false,
  publisher:{id:providerDid,name:'Clinic'},offers:[{id:'tracker',seller:{id:providerDid,name:'Clinic'},eligibleRegions:[{country:'ES',regions:[]}],
   deliveryCountries:[],supportCountries:[],operationCountries:[]}]}
 let fetched=0
 const published=new WorkforceClient({...options,fetchImpl:async(url,init)=>{
  fetched++
  assert.match(new URL(url).pathname,new RegExp(`^/${ctx.tenantId}/cds-[^/]+/v1/${ctx.sector}/`))
  assert.equal(init.credentials,'omit')
  assert.equal(init.redirect,'error')
  assert.equal(new Headers(init.headers).has('authorization'),false)
  return Response.json([fetched===1?offering:{...offering,publisher:{id:safe.didWeb,name:'Other publisher'}}])
 }})
 assert.deepEqual((await published.getPublishedOfferings()).map(product=>product.id),[offering.id])
 await assert.rejects(published.getPublishedOfferings(),/public_offering_api_scope_mismatch/u)
})
test('publishes a study dataset with Provenance and archives only its persisted record',async()=>{
 const authority={organizationIdentifier:providerDid,controllerIdentifier:controllerDid,actingControllerIdentifier:controllerDid}
 const study='ResearchStudy/study-one',modifiedAt='2026-09-10T00:00:00.000Z',accessUrl=safe.httpsBaseUrl
 const accessRights='NON_PUBLIC',healthDataAccessBodyIdentifier='Organization/hdab-one'
 const distribution=buildHealthDcatDistribution({...authority,id:'distribution-one',title:'Study data',accessUrl,format:'JSON',accessRights,healthDataAccessBodyIdentifier})
 const dataset=buildHealthDcatDataset({...authority,sector:ctx.sector,id:'dataset-one',title:'Study data',description:'Managed access',
  publisherRole:'data-holder',dataHolderIdentifier:providerDid,sourceKind:'curated-dataset',sourceReference:study,accessRights,
  anonymizationStatus:'pseudonymized',healthCategory:['health'],healthDataAccessBodyIdentifier,structuredData:false,
  distributionIdentifiers:[distribution.id],applicableLegislation:[safe.httpsBaseUrl]})
 const dataService=buildHealthDcatDataService({...authority,id:'api-one',title:'Study data',endpointUrl:accessUrl,
  servesDatasetIdentifiers:[dataset.id],accessRights})
 const provenance=buildResearchStudyProvenanceResource({id:'study-provenance',researchStudyReference:study,recorded:modifiedAt,
  agents:[{type:'author',who:`PractitionerRole/${safe.resourceUuid}`}]})
 const paths=[]; let storedRecord
 const {client}=await fixture(async(path,message)=>{
  paths.push(path.split('/').slice(-3).join('/'))
  const {resource}=message.body.data[0]
  if(path.endsWith('/_search')){
   assert.deepEqual(resource.meta.claims,{[ClaimsHealthDcatCatalogRecord.identifier]:storedRecord.id})
   return {iss:providerDid,body:{data:[{response:{status:'200'},resource:storedRecord}]}}
  }
  if(resource.resourceType==='CatalogRecord')storedRecord=resource
  return {iss:providerDid,body:{data:[{response:{status:'200'},resource}]}}
 })
 const input={distribution,dataService,dataset,provenance,researchStudyIdentifier:study,catalogRecordIdentifier:'record-one',modifiedAt,operationId:'publish-one'}
 await assert.rejects(async()=>client.publishResearchStudyDataset({...input,researchStudyIdentifier:'ResearchStudy/foreign'}),/workforce_dataset_binding_invalid/u)
 assert.equal(paths.length,0)
 const published=await client.publishResearchStudyDataset(input)
 assert.equal(published.record.meta.claims[ClaimsHealthDcatCatalogRecord.status],'published')
 const archived=await client.archiveResearchStudyDataset({recordId:published.record.id,modifiedAt,operationId:'archive-one'})
 assert.equal(archived.meta.claims[ClaimsHealthDcatCatalogRecord.status],'archived')
 assert.deepEqual(paths,['org.w3.dcat/Distribution/_batch','org.w3.dcat/DataService/_batch','org.hl7.fhir.r5/Provenance/_batch',
  'org.w3.dcat/Dataset/_batch','org.w3.dcat/CatalogRecord/_batch','org.w3.dcat/CatalogRecord/_search','org.w3.dcat/CatalogRecord/_batch'])
})

test('projects a real encrypted phone workforce inventory and exact seven-field licence summary without an email placeholder',async()=>{
 need('getAdministration')
 const f=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[employeeRow()]}}:{iss:providerDid,body:{data:[licenseRow()]}})
 const result=await f.client.getAdministration({intervalMs:0})
 assert.equal(result.employees.length,1)
 assert.equal(result.employees[0].contactKind,'phone');assert.equal(result.employees[0].telephone,phone.contact)
 assert.equal(Object.hasOwn(result.employees[0],'email'),false)
 assert.equal(result.employees[0].employeeDid,employeeDid);assert.equal(result.employees[0].license.devices[0].clientId,'synthetic-employee-client')
 assert.equal(result.employees[0].occupationResourceId,safe.demoOrganizationUuids.healthCare)
 assert.deepEqual(result.licenses,{contracted:1,free:0,used:1,available:0,issued:0,active:1,inactive:0})
 assert.equal(f.messages.length,4)
 const email={contactKind:'email',contact:safe.firstContactEmail},emailDid=buildOrganizationEmployeeDidWeb({...email,organizationDidWeb:providerDid,role})
 const employee=employeeRow(),licence=licenseRow()
 delete employee.resource.claims[Person.Telephone];delete employee.resource.claims[Person.HasOccupation]
 employee.resource.claims[Person.Email]=email.contact;employee.resource.claims[Person.OccupationIdentifierValue]=role
 employee.resource.claims[Person.Identifier]=emailDid;employee.resource.claims[Person.SameAs]=emailDid
 delete licence.resource.meta.claims[Person.Telephone];licence.resource.meta.claims[Person.Email]=email.contact
 const retained=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[{type:employee.type,response:{status:'200'},resource:{data:[employee.resource]}}]}}:{iss:providerDid,body:{data:[{type:licence.type,response:{status:'200'},resource:{data:[licence.resource]}}]}})
 const existing=await retained.client.getAdministration({intervalMs:0})
 assert.equal(existing.employees[0].email,email.contact);assert.equal(Object.hasOwn(existing.employees[0],'telephone'),false)
 assert.equal(existing.employees[0].roleCode,role)
})
test('fails closed on foreign seat/contact projection and caller-misbinding instead of returning raw unvalidated inventory',async()=>{
 need('getAdministration')
 const bad=licenseRow();bad.resource.meta.claims[Person.Telephone]='not-a-telephone'
 const f=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[employeeRow()]}}:{iss:providerDid,body:{data:[bad]}})
 await assert.rejects(f.client.getAdministration({intervalMs:0}))
 const conflict=employeeRow();conflict.resource.claims[Person.OccupationIdentifierValue]=HealthcareActorRoles.MedicalDoctors
 const mismatched=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[conflict]}}:{iss:providerDid,body:{data:[licenseRow()]}})
 await assert.rejects(mismatched.client.getAdministration({intervalMs:0}))
 for(const state of ['foreign-occupation','ambiguous-occupation']){
  const employee=employeeRow()
  if(state==='foreign-occupation')employee.resource.contained[0].employeeId=safe.demoOrganizationUuids.publicHealth
  else employee.resource.contained.push({...employee.resource.contained[0],id:safe.demoOrganizationUuids.publicHealth})
  const invalid=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[employee]}}:{iss:providerDid,body:{data:[licenseRow()]}})
  await assert.rejects(invalid.client.getAdministration({intervalMs:0}))
 }
})
test('uses exact employee and device selectors for registered lifecycle without hidden licence release',async()=>{
 need('changeEmployee');need('revokeDevice')
 const f=await fixture(async path=>({iss:path.includes('/Employee/')?tenantIssuer:hostDid,body:{data:[{response:{status:'200'},resource:path.includes('/Device/')?{resourceType:'Device',id:'synthetic-employee-client',status:'revoked'}:{id:safe.resourceUuid}}]}}))
 for(const action of ['disable','reactivate','purge'])await f.client.changeEmployee({action,resourceId:safe.resourceUuid,employeeClaims:{[Person.Identifier]:employeeDid,[Person.Telephone]:phone.contact,[Person.OccupationIdentifierValue]:role,[Person.MemberOfTaxId]:ctx.tenantId}},{intervalMs:0})
 await f.client.revokeDevice({licenseId:'synthetic-employee-seat',clientId:'synthetic-employee-client'},{intervalMs:0})
 const requests=f.messages.filter(row=>!row.path.endsWith('-response'))
 assert.match(requests[0].path,/\/Employee\/_batch$/u);assert.equal(requests[0].message.body.data[0].request.method,'DELETE')
 assert.equal(requests[0].message.body.data[0].type,'Employee-disable-request-v1.0')
 assert.equal(requests[1].message.body.data[0].request.method,'POST');assert.match(requests[2].path,/\/Employee\/_purge$/u)
 assert.equal(requests[1].message.body.data[0].type,'Employee-create-request-v1.0');assert.equal(requests[2].message.body.data[0].type,'Employee-purge-request-v1.0')
 assert.equal(requests[1].message.body.data[0].resource.meta.claims[Person.OccupationIdentifierValue],role)
 assert.equal(requests[1].message.body.data[0].resource.meta.claims[Person.MemberOfTaxId],ctx.tenantId)
 assert.match(requests[3].path,/\/Device\/_revoke$/u)
 await assert.rejects(f.client.changeEmployee({action:'purge',resourceId:'*',employeeClaims:{}},{intervalMs:0}))
 assert.equal(f.messages.length,8)
})
test('keeps Offer then explicit paid Order on the existing host route and never creates free seats implicitly',async()=>{
 need('requestEmployeeLicenseOffer');need('confirmLicenseOrder')
 const f=await fixture(async path=>({iss:hostDid,body:{data:[path.startsWith('/host/')?{type:'Organization-order-response-v1.0',response:{status:'201'},resource:{resourceType:'Bundle',meta:{claims:{[Order.AcceptedOfferIdentifier]:'synthetic-offer'}}}}:{type:'Organization-license-offer-response-v1.0',response:{status:'201'},resource:{id:'synthetic-offer',meta:{claims:{[Offer.Identifier]:'synthetic-offer',[Offer.EligibleQuantityValue]:2,[Offer.Price]:0,[Offer.PriceCurrency]:'CAD'}}}}]}}))
 const offer=await f.client.requestEmployeeLicenseOffer({quantity:2},{intervalMs:0})
 assert.equal(offer.offerId,'synthetic-offer')
 assert.equal(offer.offer.price,0);assert.equal(offer.offer.priceCurrency,'CAD');assert.equal(offer.offer.quantity,2)
 assert.equal(f.messages.length,2,'an Offer does not confirm an Order')
 await f.client.confirmLicenseOrder({offerId:offer.offerId,additionalClaims:{'org.schema.Order.paymentMethod':'synthetic-verified-provider-proof'}},{intervalMs:0})
 const submit=f.messages.filter(row=>!row.path.endsWith('-response'))
 assert.match(submit[0].path,/\/Offer\/_create$/u);assert.match(submit[1].path,/^\/host\/.*\/Order\/_batch$/u)
 assert.ok(submit.every(row=>!row.path.includes('/_add')))
})
test('reads authoritative organization counters through its configured host without replacing tenant provider identity',async()=>{
 need('organizationLifecycle')
 const snapshot={status:'active',descendants:{activeEmployees:1,activeIndividuals:0,unpurgedEmployees:1,unpurgedIndividuals:0},canDisable:false,canPurge:false}
 let state='active',count=1
 const f=await fixture(async path=>{
  if(path.endsWith('/_status'))return {iss:hostDid,body:{data:[{response:{status:'200'},resource:{resourceType:'Organization',id:safe.resourceUuid,lifecycle:{identifierValue:ctx.tenantId,status:state,descendants:{activeEmployees:count,activeIndividuals:0,unpurgedEmployees:count,unpurgedIndividuals:0},canDisable:count===0,canPurge:state==='suspended'&&count===0}}}]}}
  state=path.endsWith('/_disable')?'suspended':path.endsWith('/_enable')?'active':'revoked'
  return {iss:hostDid,body:{data:[{response:{status:'200'},resource:{resourceType:'Organization',id:safe.resourceUuid,meta:{claims:{
   [Organization.IdentifierValue]:ctx.tenantId,[Organization.SameAs]:providerDid,[OrganizationLifecycleClaim.TenantAuthorizationStatus]:state,[OrganizationLifecycleClaim.TenantAuthorizationChangedBy]:controllerDid,
   ...(state==='revoked'?{[OrganizationLifecycleClaim.TenantAuthorizationLifecycleDisposition]:'purged'}:{}),
  }}}}]}}
 })
 const result=await f.client.organizationLifecycle({action:'status'},{intervalMs:0})
 assert.deepEqual(result.snapshot,snapshot)
 const first=f.messages[0];assert.match(first.path,/^\/host\/cds-ES-MD\/v1\/test-network\/registry\/org.schema\/Organization\/_status$/u)
 assert.equal(first.message.body.data[0].resource.meta.claims[Organization.IdentifierValue],ctx.tenantId)
 assert.equal(first.message.body.data[0].resource.meta.claims[Organization.SameAs],providerDid)
 count=0
 for(const action of ['disable','enable','disable']){
  const transitioned=await f.client.organizationLifecycle({action},{intervalMs:0})
  assert.equal(transitioned.snapshot.status,action==='disable'?'suspended':'active')
 }
 const beforePurge=f.messages.length
 const purged=await f.client.organizationLifecycle({action:'purge'},{intervalMs:0})
 assert.equal(purged.purgeReceipt.status,'revoked');assert.equal(purged.purgeReceipt.disposition,'purged')
 assert.equal(Object.hasOwn(purged,'snapshot'),false,'purge has no invented post-delete counter snapshot')
 assert.equal(f.messages.length,beforePurge+2,'a purged registry is not queried for fabricated post-delete counters')
 assert.equal(f.options.providerDid,providerDid)
})
test('pre-DCR possession cannot list or mutate workforce, purchase seats or administer a tenant',async()=>{
 need('getAdministration')
 const f=await fixture(async()=>{throw new Error('unadmitted transport was called')})
 const options={...f.options,transportProfile:'pre-dcr-didcomm-encrypted'}
 delete options.clientId;delete options.tenantIssuer
 const client=new WorkforceClient(options)
 for(const run of [
  ()=>client.getAdministration(),
  ()=>client.changeEmployee({action:'disable',resourceId:safe.resourceUuid,employeeClaims:{}}),
  ()=>client.revokeDevice({licenseId:'synthetic-employee-seat',clientId:'synthetic-employee-client'}),
  ()=>client.requestEmployeeLicenseOffer({quantity:1}),
  ()=>client.confirmLicenseOrder({offerId:'synthetic-offer',additionalClaims:{}}),
  ()=>client.organizationLifecycle({action:'status'}),
 ])await assert.rejects(run)
 assert.equal(f.messages.length,0)
})

function workflowPlan(){
 return buildTestNetworkControllerWorkflowAssignment({networkKind:'test-network',controller:{authorityKind:'organization-controller',organizationReference:`Organization/${safe.resourceUuid}`,accountId:'synthetic-controller-account'},
  member:{accountId:'synthetic-employee-account',practitionerRoleReference:`PractitionerRole/${safe.demoOrganizationUuids.healthCare}`,role},groupKind:OrganizationWorkflowGroupKinds.SchedulingOperations,
  groupReference:`Group/${safe.resourceUuid}`,capabilities:[OrganizationWorkflowCapabilities.ScheduleCruds,OrganizationWorkflowCapabilities.SlotCruds],assignedAt:'2026-11-15T00:00:00.000Z'})
}
function workflowReply(resourceType,message){
 return {iss:providerDid,body:{resourceType:'Bundle',type:'batch-response',data:message.body.data.map((entry,index)=>({
  type:`${resourceType}-v5.0.0`,response:{status:String(resourceType==='Consent'&&(entry.request.method==='PUT'||entry.request.method==='PATCH')?200:index===0?201:200)},resource:{resourceType,id:entry.resource.id,meta:{claims:Object.fromEntries(Object.entries(entry.resource.meta.claims).map(([key,value])=>[key,Array.isArray(value)?value:[value]]))}},
 }))}}
}

test('workflow batches use real encrypted tenant Group/Consent routes, the actual provider issuer and snapshotted owned entries',async()=>{
 need('submitWorkflowAccess')
 const plan=workflowPlan(),entries=structuredClone([plan.group,plan.membership]),before=structuredClone(entries)
 const f=await fixture(async(path,message)=>workflowReply(path.includes('/Group/')?'Group':'Consent',message))
 const operationId=`workflow-group-${safe.resourceUuid}`
 const pending=f.client.submitWorkflowAccess({resourceType:'Group',entries,operationId},{intervalMs:0})
 entries[0].resource.id=safe.demoOrganizationUuids.healthCare
 f.options.ctx.tenantId=safe.demoOrganizationUuids.healthCare;f.options.providerDid=hostDid
 const group=await pending
 assert.equal(group.resourceType,'Group');assert.equal(group.operationId,operationId)
 assert.deepEqual(f.messages[0].message.body,{data:before})
 assert.equal(f.messages[0].message.thid,operationId)
 assert.equal(f.messages[0].path,`/${ctx.tenantId}/cds-${ctx.jurisdiction}/v1/${ctx.sector}/organization/org.hl7.fhir.r5/Group/_batch`)
 assert.equal(f.messages[1].path,f.messages[0].path+'-response')
 const consent=await f.client.submitWorkflowAccess({resourceType:'Consent',entries:[plan.authorization],operationId:`workflow-consent-${safe.resourceUuid}`},{intervalMs:0})
 assert.equal(consent.resourceType,'Consent')
 assert.equal(f.messages[2].message.aud,providerDid)
 assert.deepEqual(f.messages[2].message.body,{data:[plan.authorization]})
 assert.equal(f.messages[2].path,`/${ctx.tenantId}/cds-${ctx.jurisdiction}/v1/${ctx.sector}/organization/org.hl7.fhir.r5/Consent/_batch`)
})

test('workflow batches reject foreign reply bindings, failed entries and substituted Group receipts',async()=>{
 need('submitWorkflowAccess')
 const entries=[workflowPlan().group],input={resourceType:'Group',entries,operationId:`workflow-denial-${safe.resourceUuid}`}
 const changed=[
  reply=>({...reply,iss:tenantIssuer}),
  reply=>({...reply,aud:employeeDid}),
  reply=>({...reply,thid:'synthetic-foreign-thread'}),
  reply=>({...reply,body:{...reply.body,data:[]}}),
  reply=>({...reply,body:{...reply.body,data:reply.body.data.map(row=>({...row,resource:{resourceType:'Group',id:safe.demoOrganizationUuids.healthCare}}))}}),
  reply=>{const changed=structuredClone(reply);const claims=changed.body.data[0].resource.meta.claims;claims[Object.keys(claims)[0]]=['forged-claim'];return changed},
 ]
 for(const change of changed){
  const f=await fixture(async(_path,message)=>change(workflowReply('Group',message)))
  await assert.rejects(f.client.submitWorkflowAccess(input,{intervalMs:0}),/workforce_(response_binding_invalid|workflow_receipt_invalid)/u)
 }
 const denied=await fixture(async(_path,message)=>{const reply=workflowReply('Group',message);reply.body.data[0].response.status='403';return reply})
 await assert.rejects(denied.client.submitWorkflowAccess(input,{intervalMs:0}),error=>error.status===403)
})

test('workflow method accepts no arbitrary resource, URL, method or pre-DCR authority',async()=>{
 need('submitWorkflowAccess')
 const plan=workflowPlan(),f=await fixture(async()=>{throw new Error('invalid workflow reached transport')})
 const input={resourceType:'Group',entries:[plan.group],operationId:`workflow-invalid-${safe.resourceUuid}`}
 const bad=[{...input,resourceType:'Employee'},{...input,entries:[plan.authorization]},
  {...input,entries:[{...plan.group,request:{method:'POST',url:f.options.baseUrl+'/foreign'}}]},
  {...input,entries:[{...plan.group,request:{method:'DELETE',url:`Group/${safe.resourceUuid}`}}]},
  {...input,entries:[{...plan.membership,request:{method:'PATCH',url:'Group/*'}}]},
 ]
 for(const value of bad)await assert.rejects(f.client.submitWorkflowAccess(value,{intervalMs:0}),/workforce_workflow_input_invalid/u)
 const options={...f.options,transportProfile:'pre-dcr-didcomm-encrypted'};delete options.clientId;delete options.tenantIssuer
 await assert.rejects(new WorkforceClient(options).submitWorkflowAccess(input),/workforce_registered_controller_transport_required/u)
 assert.equal(f.messages.length,0)
})

test('actual Consent revocation preserves every original claim and sends inactive PUT rather than a status-only patch',async()=>{
 const original=workflowPlan().authorization
 const resource={...original.resource,meta:{claims:{...original.resource.meta.claims,[ClaimConsent.status]:ConsentStatuses.Inactive}}}
 const entry={...original,resource,request:{method:'PUT',url:`Consent/${resource.id}`}}
 const f=await fixture(async(_path,message)=>workflowReply('Consent',message))
 const result=await f.client.submitWorkflowAccess({resourceType:'Consent',entries:[entry],operationId:`workflow-revoke-${safe.resourceUuid}`},{intervalMs:0})
 assert.equal(result.resourceType,'Consent')
 assert.deepEqual(f.messages[0].message.body.data,[entry])
 const claims=f.messages[0].message.body.data[0].resource.meta.claims
 assert.deepEqual({...claims,[ClaimConsent.status]:ConsentStatuses.Active},original.resource.meta.claims)
})

test('historical routed Consent status-only PATCH returns the stored original inactive resource',async()=>{
 const original=workflowPlan().authorization
 const entry={...original,resource:{...original.resource,meta:{claims:{[ClaimConsent.status]:ConsentStatuses.Inactive}}},request:{method:'PATCH',url:`Consent/${original.resource.id}`}}
 const f=await fixture(async(_path,message)=>{
  const reply=workflowReply('Consent',message)
  reply.body.data[0].resource.meta.claims=Object.fromEntries(Object.entries({...original.resource.meta.claims,[ClaimConsent.status]:ConsentStatuses.Inactive}).map(([key,value])=>[key,[value]]))
  return reply
 })
 const result=await f.client.submitWorkflowAccess({resourceType:'Consent',entries:[entry],operationId:`workflow-patch-${safe.resourceUuid}`},{intervalMs:0})
 assert.equal(result.resourceType,'Consent');assert.deepEqual(f.messages[0].message.body,{data:[entry]})
})

test('generic Consent acknowledgement cannot masquerade as the routed versioned organization receipt',async()=>{
 const entry=workflowPlan().authorization
 const f=await fixture(async()=>({iss:providerDid,body:{resourceType:'Bundle',type:'_batch-response',data:[{type:'Consent',response:{status:'201'}}]}}))
 await assert.rejects(f.client.submitWorkflowAccess({resourceType:'Consent',entries:[entry],operationId:`workflow-wrong-owner-${safe.resourceUuid}`},{intervalMs:0}),/workforce_workflow_receipt_invalid/u)
})

// Current SOS controller writers keep technical responsibility separate from occupational qualifications.
for(const shape of ['bootstrap-occupation','renewed-opaque-contact'])test(`projects signed current controller inventory (${shape}) without treating responsibility as occupation`,async()=>{
 const controllerRole=HealthcareActorRoles.Controller,contact=phone;
 const did=buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role:controllerRole});
 const employee=employeeRow(),licence=licenseRow();
 employee.resource.id=did;employee.resource.claims[Person.Identifier]=did;
 employee.resource.claims[Person.AdditionalType]=controllerRole;
 employee.resource.claims[Person.SameAs]=buildStableActorIdentifier(contact);
 licence.resource.meta.subjectId=did;licence.resource.meta.claims[Person.OccupationIdentifierValue]=controllerRole;
 if(shape==='renewed-opaque-contact'){
  delete employee.resource.claims[Person.Telephone];delete employee.resource.claims[Person.HasOccupation];
  employee.resource.claims[Person.OccupationalCategory]=[role];delete employee.resource.contained;
 }else employee.resource.contained[0].employeeId=did;
 const f=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[employee]}}:{iss:providerDid,body:{data:[licence]}});
 const result=await f.client.getAdministration({intervalMs:0});
 assert.equal(result.employees.length,1);assert.equal(result.employees[0].roleCode,controllerRole);
 assert.equal(result.employees[0].employeeDid,did);assert.equal(result.employees[0].telephone,phone.contact);
 assert.equal(result.employees[0].license.id,licence.resource.id);
 assert.equal(employee.resource.claims[Person.HasOccupation]??employee.resource.claims[Person.OccupationalCategory][0],role);
});

test('opaque controller inventory denies mismatched stable contact and ambiguous linked licences',async()=>{
 const did=buildOrganizationEmployeeDidWeb({...phone,organizationDidWeb:providerDid,role:HealthcareActorRoles.Controller});
 const original=employeeRow(),licence=licenseRow();original.resource.id=did;delete original.resource.contained;
 original.resource.claims={[Person.Identifier]:did,[Person.AdditionalType]:HealthcareActorRoles.Controller,[Person.OccupationalCategory]:[role],[Person.SameAs]:buildStableActorIdentifier(phone)};
 licence.resource.meta.subjectId=did;licence.resource.meta.claims[Person.OccupationIdentifierValue]=HealthcareActorRoles.Controller;
 for(const mode of ['wrong-contact','missing-seat','ambiguous-seat','foreign-did']){
  const employee=structuredClone(original),licenses=[structuredClone(licence)];
  if(mode==='wrong-contact')employee.resource.claims[Person.SameAs]=buildStableActorIdentifier({contactKind:'email',contact:safe.firstContactEmail});
  if(mode==='missing-seat')licenses.length=0;
  if(mode==='ambiguous-seat')licenses.push({...structuredClone(licence),resource:{...structuredClone(licence.resource),id:'synthetic-second-seat'}});
  if(mode==='foreign-did')employee.resource.claims[Person.Identifier]=employeeDid;
  const f=await fixture(async path=>path.includes('/Employee/')?{iss:tenantIssuer,body:{data:[employee]}}:{iss:providerDid,body:{data:licenses}});
  await assert.rejects(f.client.getAdministration({intervalMs:0}),undefined,mode);
 }
});
