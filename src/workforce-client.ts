import {randomUUID} from 'node:crypto'
import {DeviceEnrollmentClient,DeviceEnrollmentSubmitError} from './device-enrollment-client.js'
import {buildOrganizationEmployeeDidWeb,buildStableActorIdentifier,normalizeActorContact,normalizeUuid,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import {SchemaOrgPersonClaim as Person,SchemaOrgIndividualProductClaim as Product,SchemaOrgOfferClaim as Offer,SchemaOrgOrganizationClaim as Organization,SchemaOrgOrderClaim as Order} from 'antifraud-data-utils-ts/schema-org-claims'
import {getHealthcareRoleByClaim} from 'sos-data-utils-ts/healthcare-roles'
import {readIsco08Code,findIsco08Occupation} from 'antifraud-data-utils-ts'
import {GatewayResponseEntryTypes} from 'sos-data-utils-ts/gateway-response-contract'
import type {AppInfo,PollOptions,RouteContext} from 'sos-data-utils-ts/gateway-transport-contract'
import type {EmployeeActivationGrant} from 'sos-data-utils-ts/employee-routing'
import {employeeActivationGrantMatchesContact} from './employee-activation-grant.js'
import {RegisteredGatewayTransport,gatewayResponseEntries,type VerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import type {ServerProfileKeyDescriptor} from './server-profile-custody-keys.js'
import {IdentityAuthRequestFields} from 'sos-data-utils-ts/identity-auth-wire-contract'
import type {OrganizationPurgeReceipt} from 'sos-data-utils-ts/organization-lifecycle-contract'
import type {OrganizationWorkflowFlatEntry} from 'sos-data-utils-ts/organization-workflow-access'
import {projectWorkforceAdministration,readOrganizationLifecycleSnapshot,readOrganizationPurgeReceipt,requireOrganizationTransition} from './workforce-administration.js'

type Row=Record<string,unknown>
const record=(value:unknown):Row|undefined=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Row:undefined
const text=(value:unknown):string=>typeof value==='string'?value.trim():''
function claims(row:Row):Row{return record(record(record(row.resource)?.meta)?.claims)??{}}
function requireText(value:unknown,error:string):string{const result=text(value);if(!result)throw new TypeError(error);return result}
const workflowInvalid=()=>new TypeError('workforce_workflow_input_invalid')
function workflowArray(value:unknown):asserts value is unknown[]{
 if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype)throw workflowInvalid()
 const descriptors=Object.getOwnPropertyDescriptors(value)
 for(const name of Reflect.ownKeys(descriptors)){
  if(typeof name!=='string'||(name!=='length'&&!/^(?:0|[1-9][0-9]*)$/u.test(name))||!('value'in descriptors[name]!))throw workflowInvalid()
 }
 for(let index=0;index<value.length;index++)if(!descriptors[String(index)])throw workflowInvalid()
}
function workflowObject(value:unknown,keys?:readonly string[]):Row{
 if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw workflowInvalid()
 const output:Row=Object.create(null),descriptors=Object.getOwnPropertyDescriptors(value)
 for(const name of Reflect.ownKeys(descriptors)){
  if(typeof name!=='string'||(keys&&!keys.includes(name)))throw workflowInvalid()
  const descriptor=descriptors[name]!
  if(!('value'in descriptor))throw workflowInvalid()
  output[name]=descriptor.value
 }
 return output
}
function workflowEntries(resourceType:'Group'|'Consent',input:readonly OrganizationWorkflowFlatEntry[]):OrganizationWorkflowFlatEntry[]{
 workflowArray(input)
 if(!input.length)throw workflowInvalid()
 for(const value of input){
  const entry=workflowObject(value,['type','request','resource']),request=workflowObject(entry.request,['method','url']),resource=workflowObject(entry.resource,['resourceType','id','meta'])
  if(entry.type!==`${resourceType}-v5.0.0`||resource.resourceType!==resourceType||typeof resource.id!=='string'||!/^[A-Za-z0-9.-]{1,64}$/u.test(resource.id))throw workflowInvalid()
  const updates=resourceType==='Group'?['PATCH']:['PATCH','PUT']
  if((request.method==='POST'&&request.url!==resourceType)||(updates.includes(String(request.method))&&request.url!==`${resourceType}/${resource.id}`)||(request.method!=='POST'&&!updates.includes(String(request.method))))throw workflowInvalid()
  const metadata=workflowObject(resource.meta,['claims']),values=workflowObject(metadata.claims)
  if(!Object.keys(values).length)throw workflowInvalid()
  for(const [name,value] of Object.entries(values)){
   if(!name||/[\u0000-\u001f]/u.test(name))throw workflowInvalid()
   if(resourceType==='Consent'){if(typeof value!=='string')throw workflowInvalid()}
   else{
    workflowArray(value)
    const items=Object.getOwnPropertyDescriptors(value)
    for(let index=0;index<value.length;index++)if(!items[String(index)]||!('value'in items[String(index)]!)||typeof items[String(index)]!.value!=='string')throw workflowInvalid()
   }
  }
 }
 return input.map(entry=>structuredClone(entry))
}
/** Vocabulary validation only; current controller, sector, licence and access authority remain server-owned. */
function governedWorkforceRole(role:string):boolean{
 return !!getHealthcareRoleByClaim(role)||!!findIsco08Occupation(readIsco08Code(role))
}
function canonicalContact(contact:ActorContactInput):ActorContactInput{return {contactKind:contact.contactKind,contact:normalizeActorContact(contact)}}
function contactClaims(contact:ActorContactInput):Row{return {[contact.contactKind==='phone'?Person.Telephone:Person.Email]:contact.contact}}
function sameContact(row:Row,contact:ActorContactInput):boolean{
 const value=claims(row)[contact.contactKind==='phone'?Person.Telephone:Person.Email]
 try{return typeof value==='string'&&buildStableActorIdentifier({...contact,contact:value})===buildStableActorIdentifier(contact)}catch{return false}
}
function confirmedTarget(value:unknown,id:string,error:string):Row{
 const entries=gatewayResponseEntries(value)
 const entry=entries[0],resource=record(entry?.resource)
 if(entries.length!==1||!resource||resource.id!==id||!['200','201','204'].includes(String(record(entry?.response)?.status)))throw new Error(error)
 return resource
}
export class WorkforceSubmitError extends Error{
 constructor(readonly status:number,readonly body:unknown){super(`workforce_gateway_failed:${status}`)}
}
/** An actual commercial Offer is not a created employee or an issued seat. Payment/Order stays explicit. */
export class WorkforceSeatOfferRequiredError extends Error{
 constructor(readonly offerId:string,readonly receipt:unknown){super('workforce_employee_seat_order_required')}
}
type WorkforceClientBaseOptions=Readonly<{
 baseUrl:string;ctx:RouteContext;providerDid:string;gatewayDid:string;dcrResponseIssuer:string;issuerDid:string
 bearerToken:string;secureTransportAdapter:VerifiedGatewaySecureAdapter
 appInfo?:AppInfo;requestTimeoutMs?:number;fetchImpl?:typeof fetch;allowLoopbackRedirectUris?:boolean
}>
export type WorkforceHostRegistryOptions=Readonly<{
 hostDid:string;jurisdiction:string;hostNetwork:'test'|'local-network'|'test-network'|'network'
 responseIssuer:string;secureTransportAdapter:VerifiedGatewaySecureAdapter
}>
export type WorkforceClientOptions=WorkforceClientBaseOptions&(
 Readonly<{transportProfile:'registered-didcomm-encrypted';clientId:string;tenantIssuer:string;hostRegistry?:WorkforceHostRegistryOptions}>
 |Readonly<{transportProfile:'pre-dcr-didcomm-encrypted';clientId?:never;tenantIssuer?:never}>
)

/**
 * Independent staff/licence and recipient device transport. The BFF supplies
 * already opened wallet custody and server-verified contacts; GW alone checks
 * current controller authority, seat ownership, role/sector and device bounds.
 * This client neither rotates keys nor treats a local grant as employment.
 */
export class WorkforceClient{
 private readonly transport:RegisteredGatewayTransport
 private readonly prefix:string
 private readonly administrationIdentity?:Readonly<{issuerDid:string;providerDid:string;tenantIssuer:string;clientId:string;dcrResponseIssuer:string;ctx:RouteContext}>
 private readonly hostRegistry?:WorkforceHostRegistryOptions
 private readonly hostTransport?:RegisteredGatewayTransport
 constructor(private readonly options:WorkforceClientOptions){
  const url=new URL(options.baseUrl)
  if(url.username||url.password||url.search||url.hash||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname))))throw new TypeError('workforce_gateway_https_required')
  const {tenantId,jurisdiction,sector}=options.ctx
  if(options.transportProfile!=='registered-didcomm-encrypted'&&options.transportProfile!=='pre-dcr-didcomm-encrypted')throw new TypeError('workforce_transport_profile_required')
  if(options.transportProfile==='registered-didcomm-encrypted'&&!text(options.clientId))throw new TypeError('workforce_registered_controller_client_required')
  if(options.transportProfile==='registered-didcomm-encrypted'&&!text(options.tenantIssuer))throw new TypeError('workforce_tenant_issuer_required')
  if(!/^[-a-zA-Z0-9]+$/u.test(tenantId)||tenantId==='host'||!/^\p{L}{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(jurisdiction)||!/^[-a-z0-9]+$/u.test(sector))throw new TypeError('workforce_route_invalid')
  if(!text(options.bearerToken)||!text(options.issuerDid).startsWith('did:')||!text(options.providerDid).startsWith('did:')
   ||!text(options.gatewayDid).startsWith('did:')||!text(options.dcrResponseIssuer).startsWith('did:')
   ||options.secureTransportAdapter?.gatewayDid!==options.gatewayDid)throw new TypeError('workforce_trusted_context_required')
  this.prefix=`/${encodeURIComponent(tenantId)}/cds-${encodeURIComponent(jurisdiction)}/v1/${encodeURIComponent(sector)}`
  this.transport=new RegisteredGatewayTransport({...options,baseUrl:url.href.replace(/\/+$/u,''),errorPrefix:'workforce',submitError:(status,body)=>new WorkforceSubmitError(status,body)})
  if(options.transportProfile==='registered-didcomm-encrypted'){
   this.administrationIdentity=Object.freeze({issuerDid:options.issuerDid,providerDid:options.providerDid,tenantIssuer:options.tenantIssuer,clientId:options.clientId,dcrResponseIssuer:options.dcrResponseIssuer,ctx:Object.freeze({...options.ctx})})
   if(options.hostRegistry){
    const host=options.hostRegistry
    if(!text(host.hostDid).startsWith('did:web:')||!/^\p{L}{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(host.jurisdiction)
     ||!['test','local-network','test-network','network'].includes(host.hostNetwork)||!text(host.responseIssuer)
     ||host.secureTransportAdapter?.gatewayDid!==host.hostDid)throw new TypeError('workforce_host_registry_context_invalid')
    this.hostRegistry=Object.freeze({...host,secureTransportAdapter:Object.freeze({...host.secureTransportAdapter})})
    this.hostTransport=new RegisteredGatewayTransport({...options,secureTransportAdapter:this.hostRegistry.secureTransportAdapter,baseUrl:url.href.replace(/\/+$/u,''),errorPrefix:'workforce',submitError:(status,body)=>new WorkforceSubmitError(status,body)})
   }
  }
 }
 private message(body:unknown,thread:string,registered:boolean,type='application/didcomm-plain+json'):Row{
  return {jti:randomUUID(),thid:thread,iss:this.options.issuerDid,aud:this.options.providerDid,type,body,
   ...(registered?{client_id:requireText(this.options.clientId,'workforce_registered_controller_client_required')}:{})}
 }
 private controller(){
  if(!this.administrationIdentity)throw new Error('workforce_registered_controller_transport_required')
  return this.administrationIdentity
 }
 private administrationMessage(body:unknown,thread:string,audience?:string):Row{
  const identity=this.controller()
  return {jti:randomUUID(),thid:thread,iss:identity.issuerDid,aud:audience??identity.providerDid,client_id:identity.clientId,type:'application/didcomm-plain+json',body}
 }
 private registry(){
  this.controller()
  if(!this.hostRegistry||!this.hostTransport)throw new Error('workforce_host_registry_context_required')
  const prefix='/host/cds-'+encodeURIComponent(this.hostRegistry.jurisdiction)+'/v1/'+encodeURIComponent(this.hostRegistry.hostNetwork)+'/registry/org.schema'
  return {configuration:this.hostRegistry,transport:this.hostTransport,prefix}
 }
 /** Fixed workflow Group/Consent routes; host and GW retain all assignment/admission policy. */
 async submitWorkflowAccess(input:Readonly<{resourceType:'Group'|'Consent';entries:readonly OrganizationWorkflowFlatEntry[];operationId:string}>,pollOptions?:PollOptions){
  const identity=this.controller(),resourceType=input.resourceType,operationId=input.operationId
  if((resourceType!=='Group'&&resourceType!=='Consent')||typeof operationId!=='string'||!/^[A-Za-z0-9:_.-]{1,200}$/u.test(operationId))throw workflowInvalid()
  const entries=workflowEntries(resourceType,input.entries)
  const result=await this.transport.exchange(`${this.prefix}/organization/org.hl7.fhir.r5/${resourceType}/_batch`,this.administrationMessage({data:entries},operationId),identity.providerDid,pollOptions)
  const envelope=record(result.poll.body),body=record(envelope?.body)??envelope,rows=gatewayResponseEntries(result.poll.body)
  if(!body||body.resourceType!=='Bundle'||body.type!=='batch-response'||rows.length!==entries.length)throw new Error('workforce_workflow_receipt_invalid')
  for(let index=0;index<rows.length;index++){
   const row=rows[index]!,response=record(row.response),resource=record(row.resource)
   if(!/^(?:2[0-9]{2})(?: [A-Za-z][A-Za-z -]*)?$/u.test(String(response?.status))||row.type!==`${resourceType}-v5.0.0`||resource?.resourceType!==resourceType||resource.id!==entries[index]!.resource.id)throw new Error('workforce_workflow_receipt_invalid')
   const returned=record(record(resource.meta)?.claims),requested=entries[index]!.resource.meta.claims
   if(!returned)throw new Error('workforce_workflow_receipt_invalid')
   for(const [name,value] of Object.entries(requested)){
    const expected=typeof value==='string'?[value]:value,actual=returned[name]
    if(!Array.isArray(actual)||actual.length!==expected.length||actual.some((item,position)=>item!==expected[position]))throw new Error('workforce_workflow_receipt_invalid')
   }
  }
  return {resourceType,operationId,result}
 }
 /** Submits a server-built research administration Bundle through registered controller custody. */
 async submitResearchAdministration(input:Readonly<{
  resourceType:'ResearchStudy'|'Group'|'Consent'|'Communication'|'SubscriptionTopic'|'Subscription'
  action:'_search'|'_batch';operationId:string;body:Readonly<Row>
 }>,pollOptions?:PollOptions){
  const identity=this.controller(),{resourceType,action,operationId,body}=input
  const researchResource=resourceType==='ResearchStudy'||resourceType==='Group'||resourceType==='Consent'
  const batchOnly=resourceType==='Communication'||resourceType==='SubscriptionTopic'||resourceType==='Subscription'
  if(!(researchResource&&(action==='_search'||action==='_batch'))&&!(batchOnly&&action==='_batch'))throw new TypeError('workforce_research_route_invalid')
  if(typeof operationId!=='string'||!/^[A-Za-z0-9:_.-]{1,200}$/u.test(operationId)||!record(body))throw new TypeError('workforce_research_input_invalid')
  const directory=resourceType==='Communication'?'individual/org.hl7.fhir.api'
   :resourceType==='SubscriptionTopic'||resourceType==='Subscription'?'entity/org.hl7.fhir.r5':'organization/org.hl7.fhir.r5'
  return this.transport.exchange(`${this.prefix}/${directory}/${resourceType}/${action}`,this.administrationMessage(body,operationId),identity.providerDid,pollOptions)
 }
 /** Replaces the catalogue for the registered controller's tenant. GW authorizes the publisher and validates the document. */
 publishOfferingCatalogue(input:Readonly<{document:Readonly<Row>;operationId:string}>,pollOptions?:PollOptions){
  return this.publishCatalogueDocument('_publish',input,pollOptions)
 }
 /** Writes one offering without replacing the tenant's imported catalogue. */
 publishIndividualOffering(input:Readonly<{document:Readonly<Row>;operationId:string}>,pollOptions?:PollOptions){
  return this.publishCatalogueDocument('_upsert',input,pollOptions)
 }
 private async publishCatalogueDocument(action:'_publish'|'_upsert',input:Readonly<{document:Readonly<Row>;operationId:string}>,pollOptions?:PollOptions){
  const identity=this.controller(),{document,operationId}=input
  if(!record(document)||!Object.hasOwn(document,'data')||typeof operationId!=='string'||!/^[A-Za-z0-9:_.-]{1,200}$/u.test(operationId)){
   throw new TypeError('catalog_offering_document_invalid')
  }
  const path=`${this.prefix}/organization/org.schema/Catalog/${action}`
  const result=await this.transport.exchange(path,this.administrationMessage(document,operationId),identity.providerDid,pollOptions)
  const receipt=record(result.poll.body),total=record(receipt?.body)?.total
  if(receipt?.type!=='org.schema.catalog-publication'||typeof total!=='number'||!Number.isSafeInteger(total)||total<1||(action==='_upsert'&&total!==1)){
   throw new WorkforceSubmitError(502,{error:'catalog_offering_publication_receipt_invalid'})
  }
  return {total}
 }
 /** Reads the signed roster without querying or requiring a licence. */
 async getEmployeeDirectory(pollOptions?:PollOptions){
  const identity=this.controller()
  return this.transport.exchange(this.prefix+'/entity/org.schema/Employee/_search',this.administrationMessage({resourceType:'Bundle',type:'batch',entry:[{
   request:{method:'POST',url:'Employee/_search'},resource:{resourceType:'Parameters',parameter:[]},
  }]},'workforce-employees-'+randomUUID()),identity.tenantIssuer,pollOptions)
 }
 /** Authenticated directory envelopes become typed contacts and exact seat/device projections. */
 async getAdministration(pollOptions?:PollOptions){
  const identity=this.controller()
  const employees=await this.getEmployeeDirectory(pollOptions)
  const licenses=await this.transport.exchange(this.prefix+'/entity/org.schema/License/_search',this.administrationMessage({resourceType:'Bundle',type:'batch',entry:[{
   type:'License-search-request-v1.0',request:{method:'POST'},meta:{},resource:{meta:{claims:{'@context':'org.schema','@type':'IndividualProduct:Search'}}},
  }]},'workforce-licenses-'+randomUUID()),identity.providerDid,pollOptions)
  return {...projectWorkforceAdministration(employees.poll.body,licenses.poll.body,identity.providerDid),evidence:{employees,licenses}}
 }
 async changeEmployee(input:Readonly<{action:'disable'|'reactivate'|'purge';resourceId:string;employeeClaims:Readonly<Row>}>,pollOptions?:PollOptions){
  const identity=this.controller(),resourceId=requireText(input.resourceId,'workforce_employee_resource_required')
  if(resourceId==='*'||/[\s/?#*]/u.test(resourceId)||!['disable','reactivate','purge'].includes(input.action))throw new TypeError('workforce_employee_selector_invalid')
  const employeeClaims=record(input.employeeClaims)
  if(!employeeClaims||(employeeClaims[Person.MemberOfTaxId]!==undefined&&employeeClaims[Person.MemberOfTaxId]!==identity.ctx.tenantId))throw new TypeError('workforce_employee_tenant_binding_invalid')
  const type=input.action==='disable'?'Employee-disable-request-v1.0':input.action==='reactivate'?'Employee-create-request-v1.0':'Employee-purge-request-v1.0'
  const result=await this.transport.exchange(this.prefix+'/entity/org.schema/Employee/'+(input.action==='purge'?'_purge':'_batch'),this.administrationMessage({data:[{
   type,request:{method:input.action==='disable'?'DELETE':'POST'},resource:{id:resourceId,type:'Person',meta:{claims:structuredClone(employeeClaims)}},
  }]},'workforce-employee-'+input.action+'-'+randomUUID()),identity.tenantIssuer,pollOptions)
  confirmedTarget(result.poll.body,resourceId,'workforce_employee_receipt_binding_invalid')
  return {action:input.action,resourceId,result}
 }
 async revokeDevice(input:Readonly<{licenseId:string;clientId:string}>,pollOptions?:PollOptions){
  const identity=this.controller(),licenseId=requireText(input.licenseId,'workforce_license_selector_required'),clientId=requireText(input.clientId,'workforce_device_selector_required')
  if([licenseId,clientId].some(value=>value==='*'||/[\s/?#*]/u.test(value)))throw new TypeError('workforce_device_selector_invalid')
  const result=await this.transport.exchange(this.prefix+'/identity/openid/Device/_revoke',this.administrationMessage({
   [IdentityAuthRequestFields.LicenseId]:licenseId,[IdentityAuthRequestFields.ClientId]:clientId,
  },'workforce-device-revoke-'+randomUUID()),identity.dcrResponseIssuer,pollOptions)
  const resource=confirmedTarget(result.poll.body,clientId,'workforce_device_receipt_binding_invalid')
  if(resource.resourceType!=='Device'||resource.status!=='revoked')throw new Error('workforce_device_receipt_binding_invalid')
  return {clientId,status:'revoked' as const,result}
 }
 /** Request only: a commercial Offer never materializes seats until a separate confirmed Order. */
 async requestEmployeeLicenseOffer(input:Readonly<{quantity:number}>,pollOptions?:PollOptions){
  this.controller()
  const host=this.registry()
  if(!Number.isInteger(input.quantity)||input.quantity<1||input.quantity>100)throw new TypeError('workforce_license_quantity_invalid')
  const result=await this.transport.exchange(this.prefix+'/entity/org.schema/Offer/_create',this.administrationMessage({resourceType:'Bundle',type:'batch',data:[{
   type:'License-purchase-request-v1.0',request:{method:'POST'},meta:{},resource:{meta:{claims:{'@context':'org.schema','@type':'IndividualProduct:Purchase',
    [Product.Category]:'professional',[Product.AdditionalType]:'web',[Offer.EligibleQuantityValue]:input.quantity,
   }}},
  }]},'workforce-license-offer-'+randomUUID()),host.configuration.responseIssuer,pollOptions)
  const offers=gatewayResponseEntries(result.poll.body).flatMap(entry=>{
   if(entry.type!==GatewayResponseEntryTypes.OrganizationLicenseOffer)return []
   const resource=record(entry.resource),value=record(record(resource?.meta)?.claims)
   return resource&&value&&text(value[Offer.Identifier])?[{resource,value}]:[]
  })
  if(offers.length!==1)throw new Error('workforce_license_offer_invalid')
  const {resource,value}=offers[0]!,offerId=requireText(value[Offer.Identifier],'workforce_license_offer_invalid')
  if(resource.id!==undefined&&resource.id!==offerId)throw new Error('workforce_license_offer_invalid')
  const price=value[Offer.Price],priceCurrency=value[Offer.PriceCurrency],quantity=value[Offer.EligibleQuantityValue]
  if(price!==undefined&&!((typeof price==='number'&&Number.isFinite(price)&&price>=0)||(typeof price==='string'&&/^[0-9]+(?:\.[0-9]{1,18})?$/u.test(price))))throw new Error('workforce_license_offer_invalid')
  if(price===undefined||typeof priceCurrency!=='string'||!/^[A-Z][A-Z0-9]{2,11}$/u.test(priceCurrency)
   ||typeof quantity!=='number'||!Number.isSafeInteger(quantity)||quantity!==input.quantity)throw new Error('workforce_license_offer_invalid')
  return {offerId,offer:{id:offerId,price,priceCurrency,quantity,claims:Object.freeze(structuredClone(value))},result}
 }
 /** Domain caller supplies verified payment evidence; GW validates it. No _add or automatic payment exists here. */
 async confirmLicenseOrder(input:Readonly<{offerId:string;additionalClaims:Readonly<Row>}>,pollOptions?:PollOptions){
  const identity=this.controller(),host=this.registry(),offerId=requireText(input.offerId,'workforce_license_offer_required')
  const additional=record(input.additionalClaims)
  if(!additional)throw new TypeError('workforce_license_order_claims_invalid')
  const contextualKey=Order.AcceptedOfferIdentifier.slice('org.schema.'.length)
  if((additional[contextualKey]!==undefined&&additional[contextualKey]!==offerId)||(additional[Order.AcceptedOfferIdentifier]!==undefined&&additional[Order.AcceptedOfferIdentifier]!==offerId)
   ||(additional['@context']!==undefined&&additional['@context']!=='org.schema'))throw new TypeError('workforce_license_order_offer_binding_invalid')
  const result=await host.transport.exchange(host.prefix+'/Order/_batch',this.administrationMessage({data:[{type:'Organization-order-request-v1.0',resource:{meta:{claims:{
   ...structuredClone(additional),'@context':'org.schema',[contextualKey]:offerId,
  }}}}]},'workforce-license-order-'+randomUUID(),host.configuration.hostDid),host.configuration.responseIssuer,pollOptions)
  const entries=gatewayResponseEntries(result.poll.body).filter(entry=>entry.type===GatewayResponseEntryTypes.OrganizationOrder)
  if(entries.length!==1)throw new Error('workforce_license_order_receipt_invalid')
  const value=claims(entries[0]!)
  if(value[Order.AcceptedOfferIdentifier]!==offerId&&value[contextualKey]!==offerId)throw new Error('workforce_license_order_receipt_invalid')
  return {offerId,receipt:{type:GatewayResponseEntryTypes.OrganizationOrder,claims:Object.freeze(structuredClone(value))},result}
 }
 /** Host registry target is explicit and separate from the immutable tenant provider. */
 async organizationLifecycle(input:Readonly<{action:'status'|'disable'|'enable'|'purge'}>,pollOptions?:PollOptions){
  const identity=this.controller(),host=this.registry()
  if(!['status','disable','enable','purge'].includes(input.action))throw new TypeError('workforce_organization_action_invalid')
  const action=input.action,requestType=action==='status'?'Organization-lifecycle-status-request-v1.0':action==='disable'?'Organization-disable-request-v1.0':action==='enable'?'Organization-enable-request-v1.0':'Organization-purge-request-v1.0'
  const thread='workforce-organization-'+action+'-'+randomUUID()
  const result=await host.transport.exchange(host.prefix+'/Organization/_'+action,this.administrationMessage({data:[{type:requestType,request:{method:'POST'},resource:{type:'Organization',meta:{claims:{
   [Organization.IdentifierValue]:identity.ctx.tenantId,[Organization.SameAs]:identity.providerDid,
  }}}}]},thread,host.configuration.hostDid),host.configuration.responseIssuer,pollOptions)
  if(action==='purge'){
   const purgeReceipt:OrganizationPurgeReceipt=readOrganizationPurgeReceipt(result.poll.body,{organizationIdentifier:identity.ctx.tenantId,providerDid:identity.providerDid,actorDid:identity.issuerDid,operationReference:thread})
   return {action:'purge' as const,purgeReceipt,result}
  }
  if(action!=='status')requireOrganizationTransition(result.poll.body,{organizationIdentifier:identity.ctx.tenantId,providerDid:identity.providerDid,actorDid:identity.issuerDid,status:action==='disable'?'suspended':'active'})
  const confirmed=action==='status'?result:await host.transport.exchange(host.prefix+'/Organization/_status',this.administrationMessage({data:[{type:'Organization-lifecycle-status-request-v1.0',request:{method:'POST'},resource:{type:'Organization',meta:{claims:{
   [Organization.IdentifierValue]:identity.ctx.tenantId,[Organization.SameAs]:identity.providerDid,
  }}}}]},'workforce-organization-status-'+randomUUID(),host.configuration.hostDid),host.configuration.responseIssuer,pollOptions)
  const snapshot=readOrganizationLifecycleSnapshot(confirmed.poll.body,identity.ctx.tenantId)
  if(action!=='status'&&snapshot.status!==(action==='disable'?'suspended':'active'))throw new Error('workforce_organization_readback_invalid')
  return {action,snapshot,result,confirmed,operationReference:action==='status'?undefined:thread}
 }
 async provisionEmployee(input:Readonly<{operationId:string;contact:ActorContactInput;role:string}>,pollOptions?:PollOptions){
  if(this.options.transportProfile!=='registered-didcomm-encrypted')throw new Error('workforce_registered_controller_transport_required')
  const operationId=requireText(input.operationId,'workforce_operation_id_required')
  if(!normalizeUuid(operationId))throw new TypeError('workforce_operation_uuid_required')
  const contact=canonicalContact(input.contact),role=requireText(input.role,'workforce_role_required')
  if(!governedWorkforceRole(role))throw new TypeError('workforce_role_invalid')
  const employeeDid=buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:this.options.providerDid,role})
  const requestedClaims={...contactClaims(contact),[Person.Identifier]:employeeDid,[Person.SameAs]:employeeDid,[Person.HasOccupation]:role}
  const employee=await this.transport.exchange(`${this.prefix}/entity/org.schema/Employee/_batch`,this.message({resourceType:'Bundle',type:'batch',data:[{
   type:'Employee-form-v1.0',request:{method:'POST'},resource:{resourceType:'Employee',id:operationId,meta:{claims:requestedClaims}},
  }]},`workforce-employee-${operationId}`,true),this.options.tenantIssuer,pollOptions)
  const rows=gatewayResponseEntries(employee.poll.body)
  const offers=rows.filter(row=>row.type===GatewayResponseEntryTypes.EmployeeLicenseOffer)
  if(offers.length){
   const offerId=text(claims(offers[0]!)[Offer.Identifier])
   if(offers.length!==1||!offerId)throw new Error('workforce_employee_offer_binding_invalid')
   throw new WorkforceSeatOfferRequiredError(offerId,employee)
  }
  const created=rows.filter(row=>row.type==='Employee-form-v1.0'&&['200','201'].includes(String(record(row.response)?.status)))
  const row=created[0],resource=record(row?.resource),returnedClaims=row?claims(row):undefined
  const employeeResourceId=text(resource?.id)
  if(created.length!==1||!row||!normalizeUuid(employeeResourceId)||!sameContact(row,contact)||returnedClaims?.[Person.HasOccupation]!==role
   ||!(returnedClaims?.[Person.Identifier]===employeeDid||String(returnedClaims?.[Person.SameAs]??'').split(',').map(value=>value.trim()).includes(employeeDid)))throw new Error('workforce_employee_receipt_binding_invalid')
  const license=await this.transport.exchange(`${this.prefix}/identity/openid/License/_issue`,this.message({resourceType:'Bundle',type:'batch',data:[{
   type:'License-issue-request-v1.0',request:{method:'POST'},meta:{subjectId:employeeResourceId,subjectDid:employeeDid},resource:{resourceType:'License',meta:{claims:{
    ...contactClaims(contact),[Person.HasOccupation]:role,[Product.Category]:'professional',[Product.AdditionalType]:'web',
   }}},
  }]},`workforce-license-${operationId}`,true),this.options.providerDid,pollOptions)
  const issued=gatewayResponseEntries(license.poll.body).filter(entry=>entry.type===GatewayResponseEntryTypes.LicenseIssued&&['200','201'].includes(String(record(entry.response)?.status)))
  const seat=issued[0],metadata=record(seat?.meta),activationCode=seat?text(claims(seat)[Product.SerialNumber]):''
  if(issued.length!==1||!seat||!activationCode||metadata?.subjectId!==employeeResourceId||metadata?.subjectDid!==employeeDid||!sameContact(seat,contact)
   ||claims(seat)[Person.HasOccupation]!==role||!text(metadata.licenseId)||!Number.isInteger(metadata.maxDevices)||Number(metadata.maxDevices)<1)throw new Error('workforce_license_receipt_binding_invalid')
  return {employee,license,employeeResourceId,employeeDid,role,contact,activationCode,licenseId:text(metadata.licenseId),maxDevices:Number(metadata.maxDevices)}
 }
 async enrollEmployeeDevice(input:Readonly<{
  grant:EmployeeActivationGrant;verifiedContact:ActorContactInput;activationCode:string;clientInstanceId:string
  publicJwks:readonly Readonly<Record<string,unknown>>[];redirectUris:readonly string[]
  enrollmentKeyDescriptors?:readonly ServerProfileKeyDescriptor[]
 }>,pollOptions?:PollOptions){
  if(this.options.transportProfile!=='pre-dcr-didcomm-encrypted')throw new Error('workforce_explicit_pre_dcr_transport_required')
  const grant=input.grant
  if(!employeeActivationGrantMatchesContact(grant,input.verifiedContact))throw new Error('workforce_recipient_contact_binding_invalid')
  if(grant.providerDid!==this.options.providerDid||grant.employeeDid!==this.options.issuerDid
   ||(['tenantId','jurisdiction','sector'] as const).some(key=>grant.routeContext[key]!==this.options.ctx[key]))throw new Error('workforce_recipient_route_binding_invalid')
  if(!governedWorkforceRole(grant.employeeRoleCode)||!Number.isFinite(Date.parse(grant.expiresAt))||Date.parse(grant.expiresAt)<=Date.now())throw new Error('workforce_recipient_grant_invalid')
  if(buildOrganizationEmployeeDidWeb({...input.verifiedContact,organizationDidWeb:grant.providerDid,role:grant.employeeRoleCode})!==grant.employeeDid)throw new Error('workforce_recipient_role_binding_invalid')
  try{
   const result=await new DeviceEnrollmentClient({...this.options,transportProfile:'pre-dcr-didcomm-encrypted',
    expectedProfile:{actorDid:grant.employeeDid,profileDid:grant.employeeDid,contact:input.verifiedContact},errorPrefix:'workforce',
   }).enroll(input,pollOptions)
   return {...result,employeeDid:grant.employeeDid,role:grant.employeeRoleCode,routeContext:grant.routeContext}
  }catch(error){if(error instanceof DeviceEnrollmentSubmitError)throw new WorkforceSubmitError(error.status,error.body);throw error}
 }
}
