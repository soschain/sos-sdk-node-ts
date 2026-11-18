// Flow contract: the controller-owned invitation producer persists a clinical assignment UUID independently of seat hashes, actors and devices; activation/reissue/readback retain it. Legacy rows preserve their activation ciphertext and ordinary workforce access but cannot acquire clinical authority through a read.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationWorkforceVaultProvider} from '../dist/organization-workforce-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const organization=`Organization/${safe.demoOrganizationUuids.healthCare}`,collection='synthetic-clinical-assignments',group='clinical-document-authoring'
const contact={contactKind:'email',contact:safe.individualEmail},installation={clientInstanceId:'synthetic-assignment-browser',name:'Synthetic assignment browser'}
const input={organizationReference:organization,sector:'health-care',profileId:'synthetic-dentist',role:HealthcareActorRoles.Dentist,roleCode:HealthcareActorRoles.Dentist,employeeDid:safe.didWeb,expiresAt:1_800_000_060_000,organizationName:'Synthetic clinic',roleName:'Dentist',groups:[group],email:safe.individualEmail}
const admission={verifiedContact:contact,organizationReference:organization,sector:input.sector,profileId:input.profileId,clientInstanceId:installation.clientInstanceId,requiredGroup:group}
const uuid=/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
function fixture(){
 const store=new TransactionalMemoryVaultRepository(),sealer=createAesGcmProfileSealer(Buffer.alloc(32,41))
 const options={store,collection,assertManage:async ref=>assert.equal(ref,organization),now:()=>1_800_000_000_000,requireLicenseCapacity:true,requireInstallation:true,maxDevicesPerLicense:1,invitationDeliveryPolicy:'notification-only',sealer}
 const provider=new OrganizationWorkforceVaultProvider(options)
 return{store,sealer,options,provider}
}
async function invited(){const f=fixture();await f.provider.addLicenseCapacity({organizationReference:organization,quantity:1,operationId:'synthetic-capacity'});let message;await f.provider.invite(input,async value=>{message=value});return{...f,message}}
const denied=error=>error?.status===403

test('invitation persists a distinct assignment UUID and activation, reload and clinical admission retain it',async()=>{
 const f=await invited(),[pending]=await f.store.query(collection,{})
 assert.match(pending.assignmentIdentifier,uuid);assert.notEqual(pending.assignmentIdentifier,pending.id);assert.notEqual(pending.assignmentIdentifier,installation.clientInstanceId)
 let callbackAssignment
 await f.provider.activate(contact,f.message.activationCode,async seat=>{callbackAssignment=seat.assignmentIdentifier;return true},installation)
 const reloaded=new OrganizationWorkforceVaultProvider(f.options),admitted=await reloaded.requireClinicalAuthor(admission)
 assert.equal(callbackAssignment,pending.assignmentIdentifier);assert.equal(admitted.assignmentIdentifier,pending.assignmentIdentifier);assert.equal(admitted.seat.assignmentIdentifier,pending.assignmentIdentifier)
 assert.equal((await f.store.query(collection,{}))[0].id,pending.id)
})

test('controller reissue retains an existing assignment while replacing the one-use activation code',async()=>{
 const f=await invited(),[first]=await f.store.query(collection,{})
 assert.match(first.assignmentIdentifier,uuid)
 let replacement;await f.provider.invite(input,async value=>{replacement=value})
 const [second]=await f.store.query(collection,{})
 assert.equal(second.assignmentIdentifier,first.assignmentIdentifier);assert.equal(second.id,first.id)
 await assert.rejects(f.provider.activate(contact,f.message.activationCode,async()=>true,installation),denied)
 await f.provider.activate(contact,replacement.activationCode,async()=>true,installation)
 assert.equal((await f.provider.requireClinicalAuthor(admission)).assignmentIdentifier,first.assignmentIdentifier)
})

test('legacy active seats keep ordinary access but require a real controller reissue to obtain a clinical assignment',async()=>{
 const f=await invited();await f.provider.activate(contact,f.message.activationCode,async()=>true,installation)
 const [legacy]=await f.store.query(collection,{});delete legacy.assignmentIdentifier;await f.store.put(collection,legacy)
 assert.equal((await f.provider.requireActive(contact,input.sector,input.profileId)).status,'active')
 await assert.rejects(f.provider.requireClinicalAuthor(admission),denied)
 assert.equal('assignmentIdentifier'in(await f.store.get(collection,legacy.id)),false)
 await f.provider.change(organization,legacy.id,'disable')
 let replacement;await f.provider.invite(input,async value=>{replacement=value})
 await f.provider.activate(contact,replacement.activationCode,async()=>true,installation)
 assert.match((await f.provider.requireClinicalAuthor(admission)).assignmentIdentifier,uuid)
})

test('a pre-assignment pending credential retains its original sealed v1 AAD and never silently gains clinical signing authority',async()=>{
 const f=await invited(),[legacy]=await f.store.query(collection,{})
 delete legacy.assignmentIdentifier
 // Recorded existing email-v1 AAD layout, kept as an explicit compatibility fixture.
 const oldAad=JSON.stringify(['sos-workforce-invitation-v1',collection,legacy.id,legacy.organizationReference,legacy.email,legacy.profileId,legacy.sector,legacy.role,legacy.employee.roleCode,legacy.employee.employeeDid,legacy.expiresAt,legacy.credentialHash])
 legacy.protectedActivationCode=await f.sealer.seal(f.message.activationCode,oldAad)
 await f.store.put(collection,legacy)
 const reloaded=new OrganizationWorkforceVaultProvider(f.options),[visible]=await reloaded.list(organization)
 assert.equal(visible.activationCode,f.message.activationCode)
 await reloaded.activate(contact,visible.activationCode,async()=>true,installation)
 assert.equal((await reloaded.requireActive(contact,input.sector,input.profileId)).status,'active')
 await assert.rejects(reloaded.requireClinicalAuthor(admission),denied)
})
