import {randomUUID} from 'node:crypto'
import {DeviceEnrollmentClient,DeviceEnrollmentSubmitError} from './device-enrollment-client.js'
import {buildOrganizationEmployeeDidWeb,buildStableActorIdentifier,normalizeActorContact,normalizeUuid,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import {SchemaOrgPersonClaim as Person,SchemaOrgIndividualProductClaim as Product,SchemaOrgOfferClaim as Offer} from 'antifraud-data-utils-ts/schema-org-claims'
import {getHealthcareRoleByClaim} from 'sos-data-utils-ts/healthcare-roles'
import {GatewayResponseEntryTypes} from 'sos-data-utils-ts/gateway-response-contract'
import type {AppInfo,PollOptions,RouteContext} from 'sos-data-utils-ts/gateway-transport-contract'
import type {EmployeeActivationGrant} from 'sos-data-utils-ts/employee-routing'
import {employeeActivationGrantMatchesContact} from './employee-activation-grant.js'
import {RegisteredGatewayTransport,gatewayResponseEntries,type VerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import type {ServerProfileKeyDescriptor} from './server-profile-custody-keys.js'

type Row=Record<string,unknown>
const record=(value:unknown):Row|undefined=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Row:undefined
const text=(value:unknown):string=>typeof value==='string'?value.trim():''
function claims(row:Row):Row{return record(record(record(row.resource)?.meta)?.claims)??{}}
function requireText(value:unknown,error:string):string{const result=text(value);if(!result)throw new TypeError(error);return result}
function canonicalContact(contact:ActorContactInput):ActorContactInput{return {contactKind:contact.contactKind,contact:normalizeActorContact(contact)}}
function contactClaims(contact:ActorContactInput):Row{return {[contact.contactKind==='phone'?Person.Telephone:Person.Email]:contact.contact}}
function sameContact(row:Row,contact:ActorContactInput):boolean{
 const value=claims(row)[contact.contactKind==='phone'?Person.Telephone:Person.Email]
 try{return typeof value==='string'&&buildStableActorIdentifier({...contact,contact:value})===buildStableActorIdentifier(contact)}catch{return false}
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
export type WorkforceClientOptions=WorkforceClientBaseOptions&(
 Readonly<{transportProfile:'registered-didcomm-encrypted';clientId:string;tenantIssuer:string}>
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
 }
 private message(body:unknown,thread:string,registered:boolean,type='application/didcomm-plain+json'):Row{
  return {jti:randomUUID(),thid:thread,iss:this.options.issuerDid,aud:this.options.providerDid,type,body,
   ...(registered?{client_id:requireText(this.options.clientId,'workforce_registered_controller_client_required')}:{})}
 }
 async provisionEmployee(input:Readonly<{operationId:string;contact:ActorContactInput;role:string}>,pollOptions?:PollOptions){
  if(this.options.transportProfile!=='registered-didcomm-encrypted')throw new Error('workforce_registered_controller_transport_required')
  const operationId=requireText(input.operationId,'workforce_operation_id_required')
  if(!normalizeUuid(operationId))throw new TypeError('workforce_operation_uuid_required')
  const contact=canonicalContact(input.contact),role=requireText(input.role,'workforce_role_required')
  if(!getHealthcareRoleByClaim(role))throw new TypeError('workforce_role_invalid')
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
  if(!getHealthcareRoleByClaim(grant.employeeRoleCode)||!Number.isFinite(Date.parse(grant.expiresAt))||Date.parse(grant.expiresAt)<=Date.now())throw new Error('workforce_recipient_grant_invalid')
  if(buildOrganizationEmployeeDidWeb({...input.verifiedContact,organizationDidWeb:grant.providerDid,role:grant.employeeRoleCode})!==grant.employeeDid)throw new Error('workforce_recipient_role_binding_invalid')
  try{
   const result=await new DeviceEnrollmentClient({...this.options,transportProfile:'pre-dcr-didcomm-encrypted',
    expectedProfile:{actorDid:grant.employeeDid,profileDid:grant.employeeDid,contact:input.verifiedContact},errorPrefix:'workforce',
   }).enroll(input,pollOptions)
   return {...result,employeeDid:grant.employeeDid,role:grant.employeeRoleCode,routeContext:grant.routeContext}
  }catch(error){if(error instanceof DeviceEnrollmentSubmitError)throw new WorkforceSubmitError(error.status,error.body);throw error}
 }
}
