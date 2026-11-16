// Flow contract: the existing vault workforce provider persists an explicit browser-installation policy and registers a real scoped installation during one-use activation. This unit does not claim GW DCR or physical-device attestation; host PIN/session proof has a separate BFF gate.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationWorkforceVaultProvider} from '../dist/organization-workforce-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
const org=`Organization/${safe.demoOrganizationUuids.healthCare}`
const input={organizationReference:org,sector:'health-care',profileId:'dentist',role:'dentist',email:safe.individualEmail,roleCode:HealthcareActorRoles.Dentist,employeeDid:`urn:uuid:${safe.resourceUuid}`,expiresAt:Date.now()+60000,organizationName:'Synthetic clinic',roleName:'Dentist'}
const policy={requireLicenseCapacity:true,requireInstallation:true,maxDevicesPerLicense:1}
const provider=store=>new OrganizationWorkforceVaultProvider({store,collection:'registered-demo-installations',...policy,assertManage:async reference=>assert.equal(reference,org)})
test('new managed invitations persist their actual installation limit without fabricating registered devices',async()=>{
 const p=provider(new TransactionalMemoryVaultRepository())
 await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 await p.invite(input,async()=>{})
 const [seat]=await p.list(org)
 assert.equal(seat.employee.license?.maxDevices,policy.maxDevicesPerLicense)
 assert.equal(seat.employee.license?.activeDevices,0)
 assert.deepEqual(seat.employee.license?.devices,[])
})
test('valid one-use activation materializes its stored browser registration and supplies that exact ID to the host callback',async()=>{
 const p=provider(new TransactionalMemoryVaultRepository())
 await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 let code='',registration
 await p.invite(input,async message=>{code=message.activationCode})
 await p.activate(input.email,code,async(_seat,_tx,actual)=>{registration=actual;return true},{clientInstanceId:safe.resourceUuid,name:'Synthetic browser'})
 const seat=await p.requireActive(input.email,input.sector,input.profileId)
 assert.equal(seat.employee.license?.activeDevices,1)
 assert.equal(seat.employee.license?.devices.length,1)
 const device=seat.employee.license.devices[0]
 assert.equal(device.clientId,registration.registrationId)
 assert.equal(device.name,'Synthetic browser')
 assert.equal(device.status,'active')
 assert.equal(typeof device.activatedAt,'number')
 assert.notEqual(device.clientId,code)
})


test('installation policy rejects malformed settings and missing registration without consuming the invitation',async()=>{
 const store=new TransactionalMemoryVaultRepository()
 for(const maxDevicesPerLicense of [0,-1,1.5,NaN])assert.throws(()=>new OrganizationWorkforceVaultProvider({store,collection:'invalid-policy',assertManage:async()=>{},requireInstallation:true,maxDevicesPerLicense}),/installation_policy_invalid/)
 assert.throws(()=>new OrganizationWorkforceVaultProvider({store,collection:'invalid-policy',assertManage:async()=>{},requireInstallation:'yes',maxDevicesPerLicense:1}),/installation_policy_invalid/)
 const p=provider(store);await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 let code='';await p.invite(input,async message=>{code=message.activationCode})
 await assert.rejects(p.activate(input.email,code,async()=>true),/installation_required/)
 assert.equal((await p.list(org))[0].status,'pending')
 let called=false
 await assert.rejects(p.activate(safe.firstContactEmail,code,async()=>{called=true},{clientInstanceId:safe.resourceUuid,name:'Synthetic browser'}),/invitation_invalid/)
 assert.equal(called,false)
 await assert.rejects(p.activate(input.email,code,async()=>{throw new Error('profile_commit_failed')},{clientInstanceId:safe.resourceUuid,name:'Synthetic browser'}),/profile_commit_failed/)
 assert.equal((await p.list(org))[0].status,'pending')
 await p.activate(input.email,code,async()=>true,{clientInstanceId:safe.resourceUuid,name:'Synthetic browser'})
 await assert.rejects(p.activate(input.email,code,async()=>true,{clientInstanceId:safe.resourceUuid,name:'Synthetic browser'}),/invitation_invalid/)
})


test('recreated legacy options cannot bypass the installation policy already stored in an invitation',async()=>{
 const store=new TransactionalMemoryVaultRepository(),p=provider(store)
 await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 let code='';await p.invite(input,async message=>{code=message.activationCode})
 const legacy=new OrganizationWorkforceVaultProvider({store,collection:'registered-demo-installations',assertManage:async()=>{}})
 await assert.rejects(legacy.activate(input.email,code,async()=>true),/installation_required/)
 assert.equal((await p.list(org))[0].status,'pending')
})


test('revocation targets the exact stored registration and disabling a role invalidates only its bindings',async()=>{
 const store=new TransactionalMemoryVaultRepository(),p=provider(store)
 await p.addLicenseCapacity({organizationReference:org,quantity:2,operationId:safe.resourceUuid})
 const roles=[input,{...input,profileId:'second-role'}],registrations=[]
 for(const role of roles){let code='';await p.invite(role,async message=>{code=message.activationCode});await p.activate(role.email,code,async(_seat,_tx,registration)=>{registrations.push(registration);return true},{clientInstanceId:role.profileId,name:'Synthetic browser'})}
 const [first,second]=await p.list(org)
 await assert.rejects(p.revokeDevice(org,first.id,first.employee.license.id,registrations[1].registrationId),/device_not_found/)
 assert.equal((await p.requireActiveInstallation(input.email,input.sector,input.profileId,input.profileId)).registrationId,registrations[0].registrationId)
 await assert.rejects(p.requireActiveInstallation(input.email,input.sector,input.profileId,'foreign-browser'),/installation_required/)
 await p.revokeDevice(org,first.id,first.employee.license.id,registrations[0].registrationId)
 let seats=await p.list(org)
 await assert.rejects(p.requireActiveInstallation(input.email,input.sector,input.profileId,input.profileId),/installation_required/)
 assert.equal(seats.find(row=>row.id===first.id).employee.license.activeDevices,0)
 assert.equal(seats.find(row=>row.id===first.id).employee.license.devices[0].status,'revoked')
 assert.equal(seats.find(row=>row.id===second.id).employee.license.activeDevices,1)
 await p.change(org,second.id,'disable')
 seats=await p.list(org)
 assert.equal(seats.find(row=>row.id===second.id).employee.license.activeDevices,0)
 assert.equal(seats.find(row=>row.id===second.id).employee.license.devices[0].status,'revoked')
})


test('role reactivation requires a fresh session generation and never restores an explicitly revoked browser',async()=>{
 const store=new TransactionalMemoryVaultRepository(),p=provider(store)
 await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 let code='',original;await p.invite(input,async message=>{code=message.activationCode})
 await p.activate(input.email,code,async(_seat,_tx,registration)=>{original=registration;return true},{clientInstanceId:safe.resourceUuid,name:'Synthetic browser'})
 const [seat]=await p.list(org)
 await p.change(org,seat.id,'disable');await p.change(org,seat.id,'reactivate')
 const resumed=await p.requireActiveInstallation(input.email,input.sector,input.profileId,safe.resourceUuid)
 assert.equal(resumed.registrationId,original.registrationId)
 assert.ok(resumed.generation>original.generation)
 await p.revokeDevice(org,seat.id,seat.employee.license.id,resumed.registrationId)
 await p.change(org,seat.id,'disable');await p.change(org,seat.id,'reactivate')
 await assert.rejects(p.requireActiveInstallation(input.email,input.sector,input.profileId,safe.resourceUuid),/installation_required/)
})
