import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {RegisteredGatewayTransport,type VerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import type {AppInfo,PollOptions,RouteContext,SubmitAndPollResult} from 'sos-data-utils-ts/gateway-transport-contract'
import {HL7_CODING_SYSTEM_V3_ROLE_CODE} from 'fhir-data-utils-ts'
import {HealthcareActorRoleCodes} from 'sos-data-utils-ts/healthcare-roles'
import {readIndividualOrganizationBootstrapReceipt,type IndividualOrganizationBootstrapIdentity} from 'sos-data-utils-ts/individual-registration-contract'
import {GatewayResponseEntryTypes} from 'sos-data-utils-ts/gateway-response-contract'
import {CryptographyService,type PublicJwk} from 'antifraud-data-utils-ts/cryptography'

type BaseOptions=Readonly<{
 baseUrl:string;bearerToken:string;ctx:RouteContext;issuerDid:string;recipientDid:string
 appInfo?:AppInfo;requestTimeoutMs?:number;fetchImpl?:typeof fetch
}>
type VerifiedSecureAdapter=VerifiedGatewaySecureAdapter
type Options=BaseOptions&(
 Readonly<{transportProfile:'oidc-bootstrap-json';clientId?:never;secureTransportAdapter?:never}>
 |Readonly<{transportProfile:'registered-didcomm-encrypted';clientId:string;secureTransportAdapter:VerifiedSecureAdapter}>
)
type RegistrationInput=Readonly<{claims:Readonly<Record<string,unknown>>;attachments?:readonly unknown[]}>
type Row=Record<string,unknown>
function record(value:unknown):Row|undefined{return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Row:undefined}
function text(value:unknown):string|undefined{return typeof value==='string'&&value.trim()?value.trim():undefined}
function entries(value:unknown):Row[]{const root=record(value),body=record(root?.body)??root;return Array.isArray(body?.data)?body.data.map(record).filter((row):row is Row=>!!row):[]}
function claims(row:Row):Row{return record(record(record(row.resource)?.meta)?.claims)??{}}
function claim(row:Row,key:string):unknown{const values=claims(row);return values[key]??values[key.replace(/^org\.schema\./u,'')]??values[key.replace(/^org\.hl7\.fhir\.api\./u,'')]}

/** Reuses opened-wallet custody and verifies the decrypted JWS with the configured GW's public key. */
export function createIndividualRegistrationSecureAdapter(options:Readonly<{
 gatewayDid:string
 pack:(message:Record<string,unknown>)=>Promise<string>
 decrypt:(packed:string)=>Promise<Readonly<{content:unknown;meta:Record<string,unknown>}>>
 resolveGatewaySigningJwk:(gatewayDid:string)=>Promise<PublicJwk>
}>):VerifiedSecureAdapter{
 if(!text(options.gatewayDid)?.startsWith('did:web:'))throw new TypeError('individual_registration_gateway_identity_required')
 const {gatewayDid,pack,decrypt,resolveGatewaySigningJwk}=options
 const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),digestString:async(data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data).digest('hex'),randomUUID})
 return Object.freeze({gatewayDid,pack,unpackVerified:async(packed:string)=>{
  const decrypted=await decrypt(packed)
  const compact=record(decrypted.meta.jws)?.compact
  if(typeof compact!=='string')throw new Error('individual_registration_signed_response_required')
  const parts=compact.split('.')
  if(parts.length!==3||parts.some(part=>!part||!/^[A-Za-z0-9_-]+$/u.test(part)))throw new Error('individual_registration_signed_response_required')
  const header=record(JSON.parse(Buffer.from(parts[0]!,'base64url').toString('utf8')))
  // The untrusted header never selects a key URI, identity, or resolver target.
  const key=await resolveGatewaySigningJwk(gatewayDid)
  if(key.kty!=='AKP'||!['ML-DSA-44','ML-DSA-65','ML-DSA-87'].includes(key.alg)||typeof key.pub!=='string'||'d'in key||'dBytes'in key||'privBytes'in key
   ||!text(key.kid)||header?.kid!==key.kid||header?.alg!==key.alg||!await crypto.verifyJws(compact,key))throw new Error('individual_registration_response_signature_invalid')
  const content:unknown=JSON.parse(Buffer.from(parts[1]!,'base64url').toString('utf8'))
  if(!record(content))throw new Error('individual_registration_response_payload_invalid')
  return content
 }})
}

/** A terminal GW rejection retains its status and body and never starts another poll. */
export class IndividualRegistrationSubmitError extends Error{
 constructor(readonly status:number,readonly body:unknown){super(`individual_registration_gateway_failed:${status}`)}
}

/**
 * Transport for GW's explicit verified-OIDC bootstrap exception or registered
 * signed/encrypted exchange. The host selects the profile from actual opened
 * credentials; the proposed controller contact never selects that authority.
 * This client grants no employee/group permission and does not activate a
 * controller, register device keys, or infer a controller actor from contact.
 * An Order's issued seat/active assignment is invitation metadata. It does
 * not prove recipient acceptance, device registration, or controller access;
 * the creator must not consume the recipient's activation credential.
 * Employee admission is rechecked by GW against its current registered keys,
 * DCR profile, licence and workflow-group records.
 */
export class IndividualRegistrationClient{
 private readonly baseUrl:string
 private readonly prefix:string
 private readonly transport:RegisteredGatewayTransport
 constructor(private readonly options:Options){
  const url=new URL(options.baseUrl)
  if(url.username||url.password||url.search||url.hash||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname))))throw new TypeError('individual_registration_gateway_https_required')
  if(options.transportProfile!=='oidc-bootstrap-json'&&options.transportProfile!=='registered-didcomm-encrypted')throw new TypeError('individual_registration_transport_profile_required')
  if(options.transportProfile==='registered-didcomm-encrypted'&&(!text(options.clientId)||options.secureTransportAdapter?.gatewayDid!==options.recipientDid))throw new TypeError('individual_registration_registered_profile_required')
  if(!text(options.bearerToken)||!text(options.issuerDid)?.startsWith('did:')||!text(options.recipientDid)?.startsWith('did:'))throw new TypeError('individual_registration_trusted_context_required')
  const {tenantId,jurisdiction,sector}=options.ctx
  if(!text(tenantId)||tenantId==='host'||!/^[-a-zA-Z0-9]+$/u.test(tenantId)||!/^\p{L}{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(jurisdiction)||!/^[-a-z0-9]+$/u.test(sector))throw new TypeError('individual_registration_route_invalid')
  this.baseUrl=url.href.replace(/\/+$/u,'')
  this.prefix=`/${encodeURIComponent(tenantId)}/cds-${encodeURIComponent(jurisdiction)}/v1/${encodeURIComponent(sector)}/individual/org.schema`
  this.transport=new RegisteredGatewayTransport({...options,baseUrl:this.baseUrl,errorPrefix:'individual_registration',
   submitError:(status,body)=>new IndividualRegistrationSubmitError(status,body),
   secureTransportAdapter:options.transportProfile==='registered-didcomm-encrypted'?options.secureTransportAdapter:undefined})
 }
 async registerIndividualOrganization(input:RegistrationInput,pollOptions?:PollOptions){
  const payload=this.message('Family-registration-form-v1.0',input.claims)
  if(input.attachments?.length)payload.attachments=structuredClone([...input.attachments])
  const registration=await this.exchange('Organization','_transaction',payload,pollOptions)
  const requestedOrganizationId=text(input.claims['org.schema.Organization.identifier.value']??input.claims['Organization.identifier.value'])
  if(!requestedOrganizationId)throw new TypeError('individual_registration_identity_binding_required')
  const receipt=readIndividualOrganizationBootstrapReceipt(registration.poll.body,{requestedOrganizationId,expectedProviderDid:this.options.recipientDid})
  return {registration,...receipt}
 }
 /** The registered subject is resolved by the host from its validated receipt, never a browser authority claim. */
 async confirmIndividualOrganizationOrder(input:Readonly<{offerId:string;registeredSubject:IndividualOrganizationBootstrapIdentity}>,pollOptions?:PollOptions){
  if(!text(input.offerId))throw new TypeError('individual_registration_offer_required')
  const subject=input.registeredSubject
  if(!subject||subject.providerDid!==this.options.recipientDid||!text(subject.organizationId)||!text(subject.publicCardAlias)||!text(subject.canonicalSubjectIdentifier)?.startsWith(`${subject.providerDid}:individual:multibase:`))throw new TypeError('individual_registration_subject_binding_required')
  const order=await this.exchange('Order','_batch',this.message('Family-order-request-v1.0',{'@context':'org.schema','Order.acceptedOffer.identifier':input.offerId}),pollOptions)
  const rows=entries(order.poll.body)
  const orderRows=rows.filter(row=>row.type===GatewayResponseEntryTypes.FamilyOrder)
  const orderRow=orderRows[0],orderResource=record(orderRow?.resource)
  if(orderRows.length!==1||!orderRow||!orderResource||!['200','201'].includes(String(record(orderRow.response)?.status))||!['Bundle','Organization'].includes(String(orderResource.resourceType))
   ||claim(orderRow,'org.schema.Order.acceptedOffer.identifier')!==input.offerId
   ||(orderResource.resourceType==='Organization'&&orderResource.id!==subject.organizationId))throw new Error('individual_registration_order_offer_binding_invalid')
  const activationCode=text(claim(orderRow,'org.schema.IndividualProduct.serialNumber'))
  const assignments=rows.filter(row=>record(row.resource)?.resourceType==='RelatedPerson'
   &&['200','201'].includes(String(record(row.response)?.status))
   &&claim(row,'org.hl7.fhir.api.RelatedPerson.relationship')===`${HL7_CODING_SYSTEM_V3_ROLE_CODE}|${HealthcareActorRoleCodes.Controller}`
   &&['true',true].includes(claim(row,'org.hl7.fhir.api.RelatedPerson.active') as string|boolean))
  if(!activationCode||assignments.length!==1)throw new Error('individual_registration_controller_activation_or_assignment_missing_or_ambiguous')
  const assignment=assignments[0]!,assignmentIdentifier=text(claim(assignment,'org.hl7.fhir.api.RelatedPerson.identifier'))
  if(!assignmentIdentifier||record(assignment.resource)?.id!==assignmentIdentifier||claim(assignment,'org.hl7.fhir.api.RelatedPerson.patient')!==subject.canonicalSubjectIdentifier)throw new Error('individual_registration_controller_subject_binding_invalid')
  return {...order,activationCode,controllerAssignmentIdentifier:assignmentIdentifier,canonicalSubjectIdentifier:subject.canonicalSubjectIdentifier}
 }
 private message(type:string,values:Readonly<Record<string,unknown>>):Row{
  return {jti:randomUUID(),thid:randomUUID(),iss:this.options.issuerDid,aud:this.options.recipientDid,...(this.options.transportProfile==='registered-didcomm-encrypted'?{client_id:this.options.clientId}:{}),type:'application/didcomm-plain+json',body:{data:[{type,resource:{meta:{claims:structuredClone(values)}}}]}}
 }
 private async exchange(resource:string,action:string,payload:Row,options:PollOptions={}):Promise<SubmitAndPollResult>{
  return this.transport.exchange(`${this.prefix}/${resource}/${action}`,payload,this.options.recipientDid,options)
 }
}
