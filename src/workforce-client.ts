import {randomUUID} from 'node:crypto'
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
function publicKeySnapshot(value:unknown):Row{
 const failure=()=>new TypeError('workforce_device_public_keys_required')
 if(!value||typeof value!=='object'||Array.isArray(value))throw failure()
 const descriptors=Object.getOwnPropertyDescriptors(value)
 if(Object.values(descriptors).some(descriptor=>!Object.hasOwn(descriptor,'value')))throw failure()
 const key:Row=Object.fromEntries(Object.entries(descriptors).map(([name,descriptor])=>[name,descriptor.value]))
 if(['d','dBytes','privBytes','priv','privateKey','secretKeyBytes','k'].some(field=>field in key)
  ||!text(key.kid)||key.kid!==text(key.kid))throw failure()
 // Supported operational JWK metadata is scalar or a string array, such as key_ops.
 if(Object.values(key).some(item=>item!==undefined&&item!==null&&typeof item!=='string'&&typeof item!=='boolean'
  &&!(Array.isArray(item)&&item.every(part=>typeof part==='string'))))throw failure()
 return key
}
const keyMaterial=(key:Row)=>JSON.stringify(Object.keys(key).sort().map(name=>[name,key[name]]))
function devicePublicKeys(input:readonly Readonly<Row>[],descriptors?:readonly ServerProfileKeyDescriptor[]):Row[]{
 const failure=()=>new TypeError('workforce_device_public_keys_required')
 if(!Array.isArray(input)||![2,3,5].includes(input.length))throw failure()
 const keys=input.map(publicKeySnapshot)
 if(new Set(keys.map(key=>key.kid)).size!==keys.length)throw failure()
 const communicationSigning=keys.filter(key=>key.kty==='AKP'&&typeof key.pub==='string'&&!!key.pub)
 const communicationEncryption=keys.filter(key=>key.kty==='OKP'&&typeof key.x==='string'&&!!key.x)
 const profileSigning=keys.filter(key=>key.kty==='EC'&&key.crv==='P-384'&&key.alg==='ES384'
  &&typeof key.x==='string'&&!!key.x&&typeof key.y==='string'&&!!key.y&&(key.use===undefined||key.use==='sig'))
 if(communicationSigning.length!==1||communicationEncryption.length!==1||profileSigning.length!==keys.length-2)throw failure()
 if(!descriptors){if(keys.length===5)throw new Error('workforce_key_purpose_binding_required');return keys}
 const purposeFailure=()=>new Error('workforce_key_purpose_binding_invalid')
 if(!Array.isArray(descriptors)||descriptors.length<keys.length||descriptors.length>keys.length+1)throw purposeFailure()
 const required=new Map<string,readonly [string,string,string]>([
  ['comm-signing',['runtime','ML-DSA-44','sig']],['comm-encryption',['runtime','ML-KEM-768','enc']],
  ...(keys.length>=3?[['actor-signing',['profile','ES384','sig']] as const]:[]),
  ...(keys.length===5?[['openid-id-token-signing',['runtime','ES384','sig']] as const,['vp-token-signing',['runtime','ES384','sig']] as const]:[]),
 ])
 const seen=new Set<string>(),descriptorKids=new Set<string>()
 for(const descriptor of descriptors){
  if(!descriptor||typeof descriptor!=='object')throw purposeFailure()
  const key=publicKeySnapshot(descriptor.publicJwk)
  if(descriptorKids.has(descriptor.kid)||descriptor.kid!==key.kid
   ||(key.alg??key.crv)!==descriptor.alg||(key.use!==undefined&&key.use!==descriptor.use))throw purposeFailure()
  descriptorKids.add(descriptor.kid)
  if(descriptor.purpose==='document-at-rest'){
   if(descriptor.ownerScope!=='profile'||descriptor.alg!=='ML-KEM-768'||descriptor.use!=='enc'
    ||key.kty!=='OKP'||key.crv!=='ML-KEM-768'||typeof key.x!=='string'||keys.some(candidate=>candidate.kid===key.kid))throw purposeFailure()
   continue
  }
  const expected=required.get(descriptor.purpose),candidate=keys.find(item=>item.kid===descriptor.kid)
  if(!expected||seen.has(descriptor.purpose)||descriptor.ownerScope!==expected[0]||descriptor.alg!==expected[1]||descriptor.use!==expected[2]
   ||!candidate||keyMaterial(candidate)!==keyMaterial(key))throw purposeFailure()
  seen.add(descriptor.purpose)
 }
 if(seen.size!==required.size)throw purposeFailure()
 return keys
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
  const activationCode=requireText(input.activationCode,'workforce_activation_code_required'),clientInstanceId=requireText(input.clientInstanceId,'workforce_installation_required')
  const publicJwks=devicePublicKeys(input.publicJwks,input.enrollmentKeyDescriptors)
  if(!Array.isArray(input.redirectUris)||!input.redirectUris.length||input.redirectUris.some(uri=>{try{
   const parsed=new URL(uri)
   const allowed=parsed.protocol==='https:'||(this.options.allowLoopbackRedirectUris===true&&parsed.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(parsed.hostname))
   return !allowed||!!parsed.username||!!parsed.password||!!parsed.hash
  }catch{return true}}))throw new TypeError('workforce_device_redirects_invalid')
  const token=await this.transport.exchange(`${this.prefix}/identity/openid/Token/_exchange`,this.message({
   grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token:activationCode,client_instance_id:clientInstanceId,
  },`workforce-token-${randomUUID()}`,false),this.options.providerDid,pollOptions)
  const tokenBody=record(record(token.poll.body)?.body),initialAccessToken=text(tokenBody?.initial_access_token)
  if(!initialAccessToken||tokenBody?.token_type!=='Bearer'||tokenBody.scope!=='dcr:register'||!Number.isFinite(tokenBody.expires_in)||Number(tokenBody.expires_in)<=0)throw new Error('workforce_initial_access_token_invalid')
  const registration=await this.transport.exchange(`${this.prefix}/identity/openid/Device/_dcr`,this.message({
   code:activationCode,redirect_uris:[...input.redirectUris],jwks:{keys:structuredClone(publicJwks)},application_type:'web',
   token_endpoint_auth_method:'private_key_jwt',actor_did:grant.employeeDid,profile_did:grant.employeeDid,
   ext_device_info:{device_id:clientInstanceId},
  },`workforce-dcr-${randomUUID()}`,false,'openid-dcr-request'),this.options.dcrResponseIssuer,pollOptions,initialAccessToken)
  const rows=gatewayResponseEntries(registration.poll.body),devices=rows.filter(row=>record(row.resource)?.resourceType==='Device'&&['200','201'].includes(String(record(row.response)?.status)))
  const device=record(devices[0]?.resource),clientId=text(device?.client_id)
  if(devices.length!==1||!device||!clientId||device.id!==clientId||!text(device.registration_access_token)||!text(device.registration_client_uri))throw new Error('workforce_device_registration_binding_invalid')
  return {token,registration,clientId,employeeDid:grant.employeeDid,role:grant.employeeRoleCode,routeContext:grant.routeContext}
 }
}
