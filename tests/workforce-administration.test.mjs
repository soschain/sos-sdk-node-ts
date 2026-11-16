// Flow contract: a registered controller's signed/encrypted administration uses fixed tenant/host bindings, validates typed phone/email inventory and exact installation selectors, preserves explicit Offer/Order payment evidence, and reads authoritative organization counters. A synthetic crypto peer proves transport/wire validation only; actual GW authorization, persistence and online lifecycle have separate gates.
import assert from 'node:assert/strict'
import test from 'node:test'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity'
import {SchemaOrgPersonClaim as Person,SchemaOrgOfferClaim as Offer,SchemaOrgOrganizationClaim as Organization,SchemaOrgIndividualProductClaim as Product,SchemaOrgOrderClaim as Order} from 'antifraud-data-utils-ts/schema-org-claims'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {OrganizationLifecycleClaim} from 'sos-data-utils-ts/organization-lifecycle-contract'
import {buildTestNetworkControllerWorkflowAssignment,OrganizationWorkflowGroupKinds,OrganizationWorkflowCapabilities} from 'sos-data-utils-ts/organization-workflow-access'
import {ClaimConsent,ConsentStatuses} from 'fhir-data-utils-ts'
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
