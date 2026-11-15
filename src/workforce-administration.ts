import {buildOrganizationEmployeeDidWeb,normalizeActorContact,normalizeUuid,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import {readIsco08Code} from 'antifraud-data-utils-ts/isco-08'
import {normalizePublicAliasList} from 'antifraud-data-utils-ts/public-aliases'
import {SchemaOrgPersonClaim as Person,SchemaOrgIndividualProductClaim as Product,SchemaOrgOrganizationClaim as Organization} from 'antifraud-data-utils-ts/schema-org-claims'
import type {OrganizationEmployeeLifecycleRecord,OrganizationEmployeeLicenseRecord,LicenseListSummary} from 'sos-data-utils-ts/employee-routing'
import {OrganizationLifecycleClaim,type OrganizationLifecycleSnapshot,type OrganizationPurgeReceipt} from 'sos-data-utils-ts/organization-lifecycle-contract'

type Row=Record<string,unknown>
function row(value:unknown):value is Row{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
const invalid=()=>new Error('workforce_inventory_invalid')
function object(value:unknown):Row{if(!row(value))throw invalid();return value}
function optionalText(value:unknown):string|undefined{if(value===undefined||value===null)return undefined;if(typeof value!=='string')throw invalid();return value.trim()||undefined}
function text(value:unknown):string{const result=optionalText(value);if(!result)throw invalid();return result}
function claims(value:Row):Row{
 const meta=value.meta===undefined?{}:object(value.meta)
 return {...(meta.claims===undefined?{}:object(meta.claims)),...(value.claims===undefined?{}:object(value.claims))}
}
function resources(value:unknown):Row[]{
 const root=object(value),body=root.body===undefined?root:object(root.body)
 const entries=body.data??body.entry
 if(!Array.isArray(entries))throw invalid()
 const result:Row[]=[]
 for(const entry of entries){
  const current=object(entry)
  if(current.response!==undefined){
   const status=object(current.response).status
   if(!/^[23][0-9]{2}(?: [A-Za-z][A-Za-z -]*)?$/u.test(String(status)))throw invalid()
  }
  const resource=current.resource===undefined?current:object(current.resource)
  if(resource.data!==undefined){if(!Array.isArray(resource.data))throw invalid();for(const nested of resource.data)result.push(object(nested))}
  else result.push(resource)
 }
 return result
}
function contact(value:Row):ActorContactInput{
 const email=optionalText(value[Person.Email])
 const input:ActorContactInput=email?{contactKind:'email',contact:email}:{contactKind:'phone',contact:text(value[Person.Telephone])}
 return {...input,contact:normalizeActorContact(input)}
}
function sameRole(left:string,right:string):boolean{
 const first=readIsco08Code(left),second=readIsco08Code(right)
 return first!==undefined&&second!==undefined?first===second:left===right
}
function role(value:Row):string{
 const direct=optionalText(value[Person.HasOccupation]),identifier=optionalText(value[Person.OccupationIdentifierValue])
 if(direct&&identifier&&!sameRole(direct,identifier))throw invalid()
 return text(identifier??direct)
}
function sameId(left:string,right:string):boolean{
 const first=normalizeUuid(left),second=normalizeUuid(right)
 return first&&second?first===second:left===right
}
function occupationId(resource:Row,id:string):string|undefined{
 if(resource.contained===undefined)return undefined
 if(!Array.isArray(resource.contained))throw invalid()
 const matches:string[]=[]
 for(const value of resource.contained){
  const item=object(value)
  if((item.type??item.resourceType)!=='Occupation')continue
  if(!sameId(text(item.employeeId),id))throw invalid()
  matches.push(text(item.id))
 }
 if(matches.length>1)throw invalid()
 return matches[0]
}
function deviceList(meta:Row,owner:ActorContactInput):OrganizationEmployeeLicenseRecord['devices']{
 const input=meta.deviceBindings??[]
 if(!Array.isArray(input))throw invalid()
 const seen=new Set<string>()
 return input.map((value):OrganizationEmployeeLicenseRecord['devices'][number]=>{
  const binding=object(value),clientId=text(binding.clientId),status=text(binding.status)
  if(seen.has(clientId)||(status!=='active'&&status!=='revoked'))throw invalid()
  seen.add(clientId)
  const info=binding.deviceInfo===undefined?{}:object(binding.deviceInfo)
  const name=[optionalText(info.model),optionalText(info.os),optionalText(info.osVersion)].filter(Boolean).join(' ')||clientId
  const activatedAt=binding.activatedAt
  if(activatedAt!==undefined&&(typeof activatedAt!=='number'||!Number.isFinite(activatedAt)||activatedAt<0))throw invalid()
  return {clientId,name,status,ownerContact:owner.contact,ownerContactKind:owner.contactKind,...(activatedAt===undefined?{}:{activatedAt})}
 })
}

/** Decode only the two authenticated directory responses; this does not authorize administration. */
export function projectWorkforceAdministration(employeeResponse:unknown,licenseResponse:unknown,providerDid:string):{
 employees:OrganizationEmployeeLifecycleRecord[];licenses:LicenseListSummary
}{
 const people=resources(employeeResponse).map(resource=>{
  const id=text(resource.id),value=claims(resource),owner=contact(value),roleCode=role(value)
  const employeeDid=buildOrganizationEmployeeDidWeb({...owner,organizationDidWeb:providerDid,role:roleCode})
  const identifier=optionalText(value[Person.Identifier])
  if(identifier!==employeeDid&&!normalizePublicAliasList(value[Person.SameAs]).includes(employeeDid))throw invalid()
  const state=optionalText(resource.status)??optionalText(row(resource.meta)?resource.meta.status:undefined)
  const status:OrganizationEmployeeLifecycleRecord['status']=state==='active'||state==='inactive'||state==='purged'?state:'unknown'
  return {id,owner,roleCode,employeeDid,status,occupationResourceId:occupationId(resource,id)}
 })
 if(new Set(people.map(person=>person.id)).size!==people.length)throw invalid()
 const summary={contracted:0,free:0,used:0,available:0,issued:0,active:0,inactive:0}
 const linked=new Map<string,OrganizationEmployeeLicenseRecord>()
 const licenseIds=new Set<string>()
 for(const resource of resources(licenseResponse)){
  const id=text(resource.id),meta=object(resource.meta),value=claims(resource),status=text(meta.status??resource.status)
  if(licenseIds.has(id))throw invalid();licenseIds.add(id)
  summary.contracted++
  if(status==='available')summary.available++
  if(status==='issued')summary.issued++
  if(status==='active')summary.active++
  if(status==='inactive')summary.inactive++
  const subject=optionalText(meta.subjectId)
  if(!subject)continue
  const person=people.find(candidate=>sameId(candidate.id,subject))
  if(!person){if(value[Product.Category]==='professional')throw invalid();continue}
  const licenseContact=contact(value)
  if(licenseContact.contactKind!==person.owner.contactKind||licenseContact.contact!==person.owner.contact||!sameRole(role(value),person.roleCode)||linked.has(person.id))throw invalid()
  const maxDevices=meta.maxDevices
  if(typeof maxDevices!=='number'||!Number.isInteger(maxDevices)||maxDevices<1)throw invalid()
  const devices=deviceList(meta,person.owner)
  linked.set(person.id,{id,status,maxDevices,activeDevices:devices.filter(device=>device.status==='active').length,devices})
 }
 summary.free=summary.available;summary.used=summary.issued+summary.active+summary.inactive
 const employees:OrganizationEmployeeLifecycleRecord[]=people.map((person):OrganizationEmployeeLifecycleRecord=>{
  const base={resourceId:person.id,roleCode:person.roleCode,employeeDid:person.employeeDid,status:person.status,
   ...(linked.has(person.id)?{license:linked.get(person.id)}:{}),
   ...(person.occupationResourceId?{occupationResourceId:person.occupationResourceId}:{})}
  return person.owner.contactKind==='email'?{...base,email:person.owner.contact,contactKind:'email'}:{...base,telephone:person.owner.contact,contactKind:'phone'}
 })
 return {employees,licenses:summary}
}

/** Only the host-authored lifecycle record supplies descendant counts. */
export function readOrganizationLifecycleSnapshot(value:unknown,organizationIdentifier:string):OrganizationLifecycleSnapshot{
 const matches=resources(value).filter(resource=>resource.lifecycle!==undefined)
 if(matches.length!==1)throw new Error('workforce_organization_lifecycle_invalid')
 const lifecycle=object(matches[0]!.lifecycle),status=text(lifecycle.status)
 if(text(lifecycle.identifierValue)!==organizationIdentifier||(status!=='active'&&status!=='suspended'&&status!=='revoked'))throw invalid()
 const source=object(lifecycle.descendants)
 const count=(name:string):number=>{const value=source[name];if(typeof value!=='number'||!Number.isSafeInteger(value)||value<0)throw invalid();return value}
 const descendants={activeEmployees:count('activeEmployees'),activeIndividuals:count('activeIndividuals'),unpurgedEmployees:count('unpurgedEmployees'),unpurgedIndividuals:count('unpurgedIndividuals')}
 if(typeof lifecycle.canDisable!=='boolean'||typeof lifecycle.canPurge!=='boolean'
  ||(lifecycle.canDisable&&(descendants.activeEmployees!==0||descendants.activeIndividuals!==0))
  ||(lifecycle.canPurge&&(status!=='suspended'||descendants.unpurgedEmployees!==0||descendants.unpurgedIndividuals!==0)))throw invalid()
 return {status,descendants,canDisable:lifecycle.canDisable,canPurge:lifecycle.canPurge}
}

/** A confirmed purge is an operation receipt, never a fabricated post-purge counter snapshot. */
export function readOrganizationPurgeReceipt(value:unknown,expected:Readonly<{organizationIdentifier:string;providerDid:string;actorDid:string;operationReference:string}>):OrganizationPurgeReceipt{
 const matches=resources(value)
 if(matches.length!==1)throw invalid()
 const valueClaims=claims(matches[0]!)
 if(valueClaims[Organization.IdentifierValue]!==expected.organizationIdentifier||valueClaims[Organization.SameAs]!==expected.providerDid
  ||valueClaims[OrganizationLifecycleClaim.TenantAuthorizationStatus]!=='revoked'
  ||valueClaims[OrganizationLifecycleClaim.TenantAuthorizationLifecycleDisposition]!=='purged'
  ||valueClaims[OrganizationLifecycleClaim.TenantAuthorizationChangedBy]!==expected.actorDid)throw invalid()
 return {status:'revoked',disposition:'purged',organizationIdentifier:expected.organizationIdentifier,providerDid:expected.providerDid,changedBy:expected.actorDid,operationReference:expected.operationReference}
}

export function requireOrganizationTransition(value:unknown,expected:Readonly<{organizationIdentifier:string;providerDid:string;actorDid:string;status:'active'|'suspended'}>):void{
 const matches=resources(value)
 if(matches.length!==1)throw invalid()
 const valueClaims=claims(matches[0]!)
 if(valueClaims[Organization.IdentifierValue]!==expected.organizationIdentifier||valueClaims[Organization.SameAs]!==expected.providerDid
  ||valueClaims[OrganizationLifecycleClaim.TenantAuthorizationStatus]!==expected.status
  ||valueClaims[OrganizationLifecycleClaim.TenantAuthorizationChangedBy]!==expected.actorDid)throw invalid()
}
