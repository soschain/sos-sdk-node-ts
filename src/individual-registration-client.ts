import {randomUUID} from 'node:crypto'
import {RegisteredGatewayTransport,createVerifiedGatewaySecureAdapter,type VerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import type {AppInfo,PollOptions,RouteContext,SubmitAndPollResult} from 'sos-data-utils-ts/gateway-transport-contract'
import {HL7_CODING_SYSTEM_V3_ROLE_CODE} from 'fhir-data-utils-ts'
import {HealthcareActorRoleCodes} from 'sos-data-utils-ts/healthcare-roles'
import {readIndividualOrganizationBootstrapReceipt,type IndividualOrganizationBootstrapIdentity} from 'sos-data-utils-ts/individual-registration-contract'
import {GatewayResponseEntryTypes} from 'sos-data-utils-ts/gateway-response-contract'
import {type PublicJwk} from 'antifraud-data-utils-ts/cryptography'
import {normalizeActorContact,normalizeUuid,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import {SchemaOrgOrganizationClaim as Organization} from 'antifraud-data-utils-ts/schema-org-claims'

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

function personalRegistrationClaim(values:Readonly<Row>,key:string):string|undefined {
 const full = values[key]
 const compact = values['@context'] === 'org.schema' ? values[key.replace(/^org\.schema\./u,'')] : undefined
 if (full !== undefined && compact !== undefined && full !== compact) {
  throw new TypeError('personal_registration_claim_conflict')
 }
 return text(full ?? compact)
}

/** Reuses opened-wallet custody and verifies the decrypted JWS with the configured GW's public key. */
export function createIndividualRegistrationSecureAdapter(options:Readonly<{
 gatewayDid:string
 pack:(message:Record<string,unknown>)=>Promise<string>
 decrypt:(packed:string)=>Promise<Readonly<{content:unknown;meta:Record<string,unknown>}>>
 resolveGatewaySigningJwk:(gatewayDid:string)=>Promise<PublicJwk>
}>):VerifiedSecureAdapter{
 return createVerifiedGatewaySecureAdapter(options)
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
 private submitRegistration(input:RegistrationInput,pollOptions?:PollOptions){
  const payload=this.message('Family-registration-form-v1.0',input.claims)
  if(input.attachments?.length)payload.attachments=structuredClone([...input.attachments])
  return this.exchange('Organization','_transaction',payload,pollOptions)
 }
 async registerIndividualOrganization(input:RegistrationInput,pollOptions?:PollOptions){
  const requestedOrganizationId=text(input.claims['org.schema.Organization.identifier.value']??input.claims['Organization.identifier.value'])
  if(!requestedOrganizationId)throw new TypeError('individual_registration_identity_binding_required')
  const registration=await this.submitRegistration(input,pollOptions)
  const receipt=readIndividualOrganizationBootstrapReceipt(registration.poll.body,{requestedOrganizationId,expectedProviderDid:this.options.recipientDid})
  return {registration,...receipt}
 }

 /** Personal OIDC creation may receive a previously registered Organization owned by the same account. */
 async registerPersonalOrganization(
  input: RegistrationInput & Readonly<{ verifiedContact: ActorContactInput }>,
  pollOptions?: PollOptions,
 ) {
  if (this.options.transportProfile !== 'oidc-bootstrap-json') throw new TypeError('personal_registration_oidc_required')
  const { claims: proposed, verifiedContact } = input
  const proposedId = normalizeUuid(personalRegistrationClaim(proposed, Organization.IdentifierValue))
  const alternateName = personalRegistrationClaim(proposed, Organization.AlternateName)
  const contactKind = verifiedContact.contactKind
  const accountContact = normalizeActorContact(verifiedContact)
  const contactClaim = contactKind === 'email' ? Organization.OwnerEmail : Organization.OwnerTelephone
  const matchesContact = (value: string | undefined) => Boolean(value
    && normalizeActorContact({ contactKind, contact: value }) === accountContact)
  if (!proposedId || !alternateName || !matchesContact(personalRegistrationClaim(proposed, contactClaim))) {
   throw new TypeError('personal_registration_request_binding_invalid')
  }

  const registration = await this.submitRegistration(input, pollOptions)
  const rows = entries(registration.poll.body).filter(row => row.type === GatewayResponseEntryTypes.FamilyRegistrationOffer)
  const row = rows[0]
  if (rows.length !== 1 || !row) throw new TypeError('individual_registration_receipt_invalid')
  const returned = claims(row)
  const status = personalRegistrationClaim(returned, 'org.schema.FamilyRegistration.status')
  const responseStatus = record(row.response)?.status
  const replay = status === 'already_exists' || status === 'resume_required'
  if ((replay && responseStatus !== '200') || (!replay && (status !== 'new_created' || responseStatus !== '201'))) {
   throw new TypeError('personal_registration_status_invalid')
  }
  const actualId = text(record(row.resource)?.id)
  if (!actualId || !normalizeUuid(actualId)) throw new TypeError('personal_registration_receipt_binding_invalid')
  if (normalizeUuid(actualId) !== proposedId && (!replay
    || personalRegistrationClaim(returned, Organization.AlternateName) !== alternateName
    || !matchesContact(personalRegistrationClaim(returned, contactClaim)))) {
   throw new TypeError('personal_registration_replay_binding_invalid')
  }
  const receipt = readIndividualOrganizationBootstrapReceipt(registration.poll.body, {
   requestedOrganizationId: actualId,
   expectedProviderDid: this.options.recipientDid,
  })
  return { registration, ...receipt, orderConfirmationRequired: status !== 'already_exists' }
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
