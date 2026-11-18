// Flow contract: verified EMAIL or PHONE workforce invitations use the same real capacity/activation/installation lifecycle; clinical admission requires current organization, licence, device and explicit group authority, with no legacy fallback. Contact possession and current PIN/subject permissions remain the authenticated host's responsibility.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationWorkforceVaultProvider} from '../dist/organization-workforce-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const organization=`Organization/${safe.demoOrganizationUuids.healthCare}`,group='clinical-document-authoring',collection='synthetic-clinical-workforce'
const phone={contactKind:'phone',contact:safe.phoneE164},email={contactKind:'email',contact:safe.individualEmail}
const installation={clientInstanceId:'synthetic-clinical-browser',name:'Synthetic clinical browser'}
const base={organizationReference:organization,sector:'health-care',profileId:'synthetic-dentist',role:HealthcareActorRoles.Dentist,roleCode:HealthcareActorRoles.Dentist,employeeDid:safe.didWeb,expiresAt:1_800_000_060_000,organizationName:'Synthetic clinic',roleName:'Dentist',groups:[group]}
function setup(options={}){
 const store=new TransactionalMemoryVaultRepository(),state={now:1_800_000_000_000}
 const provider=new OrganizationWorkforceVaultProvider({store,collection,assertManage:async ref=>{assert.equal(ref,organization)},now:()=>state.now,requireLicenseCapacity:true,requireInstallation:true,maxDevicesPerLicense:1,...options})
 return{store,state,provider}
}
async function activateContact(contact=phone){
 const f=setup();await f.provider.addLicenseCapacity({organizationReference:organization,quantity:1,operationId:'synthetic-capacity'})
 let message;await f.provider.invite({...base,contact},async value=>{message=value})
 assert.ok(message?.activationCode)
 const result=await f.provider.activate(contact,message.activationCode,async(seat,tx,registration)=>{await tx.put('synthetic-profiles',{id:seat.profileId,employeeDid:seat.employee.employeeDid});return{seat,registration}},installation)
 return{...f,message,result,admission:{verifiedContact:contact,organizationReference:organization,sector:base.sector,profileId:base.profileId,clientInstanceId:installation.clientInstanceId,requiredGroup:group}}
}
const denied=error=>error?.status===403

test('retained legacy email invitation and installation methods keep exact email-backed licence behavior',async()=>{
 const f=setup();await f.provider.addLicenseCapacity({organizationReference:organization,quantity:1,operationId:'synthetic-capacity'})
 let message;await f.provider.invite({...base,email:safe.individualEmail},async value=>{message=value})
 assert.equal(message.email,safe.individualEmail)
 await f.provider.activate(safe.individualEmail,message.activationCode,async()=>true,installation)
 const seat=await f.provider.requireActive(safe.individualEmail,base.sector,base.profileId),registration=await f.provider.requireActiveInstallation(safe.individualEmail,base.sector,base.profileId,installation.clientInstanceId)
 assert.equal(seat.email,safe.individualEmail);assert.equal(seat.employee.email,safe.individualEmail)
 assert.equal(seat.employee.license.devices[0].ownerContactKind,'email');assert.ok(registration.registrationId)
})

test('phone-only invitation, delivery and single-use activation persist actual phone identity without fabricated email',async()=>{
 const f=await activateContact(),rows=await f.store.query(collection,{})
 assert.deepEqual(f.message.contact,phone);assert.equal('email'in f.message,false)
 assert.equal(rows.length,1);const seat=rows[0]
 assert.equal(seat.contactKind,'phone');assert.equal(seat.telephone,safe.phoneE164);assert.equal('email'in seat,false)
 assert.equal(seat.employee.contactKind,'phone');assert.equal(seat.employee.telephone,safe.phoneE164);assert.equal('email'in seat.employee,false)
 assert.equal(seat.employee.license.devices[0].ownerContact,safe.phoneE164);assert.equal(seat.employee.license.devices[0].ownerContactKind,'phone')
 await assert.rejects(f.provider.activate(phone,f.message.activationCode,async()=>true,installation),denied)
 assert.equal((await f.provider.readLicenseInventory(organization)).active,1)
})

test('strict clinical admission accepts real activated phone and email contact overloads with current licence and explicit group',async()=>{
 for(const contact of [phone,email]){
  const f=await activateContact(contact),result=await f.provider.requireClinicalAuthor(f.admission)
  assert.equal(result.seat.organizationReference,organization);assert.equal(result.seat.employee.roleCode,HealthcareActorRoles.Dentist)
  assert.equal(result.seat.employee.license.status,'active');assert.equal(result.registration.clientInstanceId,installation.clientInstanceId)
  assert.ok(result.seat.groups.includes(group))
 }
})

test('clinical admission denies foreign contact, organization, sector, profile, installation and absent group',async()=>{
 const f=await activateContact()
 for(const change of [{verifiedContact:{contactKind:'phone',contact:safe.firstContactPhoneE164}},{organizationReference:'Organization/foreign'},{sector:'foreign-sector'},{profileId:'foreign-profile'},{clientInstanceId:'foreign-browser'},{requiredGroup:'foreign-group'}])await assert.rejects(f.provider.requireClinicalAuthor({...f.admission,...change}),denied)
})

test('clinical admission never inherits legacy missing licence, revoked devices, inactive employee or absent-group fallback',async()=>{
 const f=await activateContact(),[original]=await f.store.query(collection,{})
 for(const mutate of [s=>{delete s.employee.license},s=>{s.employee.license.status='inactive'},s=>{s.employee.license.devices[0].status='revoked'},s=>{s.employee.status='inactive'},s=>{delete s.groups},s=>{s.employee.roleCode=HealthcareActorRoles.Controller},s=>{s.employee.employeeDid=''},s=>{s.expiresAt=f.state.now}]){
  const changed=structuredClone(original);mutate(changed);await f.store.put(collection,changed)
  await assert.rejects(f.provider.requireClinicalAuthor(f.admission),denied)
 }
})

test('phone activation preserves wrong-contact denial, profile rollback and shared capacity accounting',async()=>{
 const f=setup();await f.provider.addLicenseCapacity({organizationReference:organization,quantity:1,operationId:'synthetic-capacity'})
 let message;await f.provider.invite({...base,contact:phone},async value=>{message=value})
 await assert.rejects(f.provider.activate({contactKind:'phone',contact:safe.firstContactPhoneE164},message.activationCode,async()=>true,installation),denied)
 await assert.rejects(f.provider.activate(phone,message.activationCode,async()=>{throw Error('synthetic-profile-write-failed')},installation),/synthetic-profile-write-failed/u)
 assert.equal((await f.store.query(collection,{}))[0].status,'pending')
 await assert.rejects(f.provider.invite({...base,profileId:'second-profile',contact:email},async()=>{}),/capacity_exhausted/u)
 await f.provider.activate(phone,message.activationCode,async()=>true,installation)
 assert.equal((await f.provider.requireClinicalAuthor({verifiedContact:phone,organizationReference:organization,sector:base.sector,profileId:base.profileId,clientInstanceId:installation.clientInstanceId,requiredGroup:group})).registration.generation,1)
})

test('disable, reactivate and device revocation reuse existing generation and licence lifecycle for phone admission',async()=>{
 const f=await activateContact(),first=await f.provider.requireClinicalAuthor(f.admission)
 await f.provider.change(organization,first.seat.id,'disable');await assert.rejects(f.provider.requireClinicalAuthor(f.admission),denied)
 await f.provider.change(organization,first.seat.id,'reactivate')
 const restored=await f.provider.requireClinicalAuthor(f.admission);assert.ok(restored.registration.generation>first.registration.generation)
 await f.provider.revokeDevice(organization,restored.seat.id,restored.seat.employee.license.id,restored.registration.registrationId)
 await assert.rejects(f.provider.requireClinicalAuthor(f.admission),denied)
})

test('notification-only phone credentials remain sealed and bound to stored contact before controller readback',async()=>{
 const f=setup({invitationDeliveryPolicy:'notification-only',sealer:createAesGcmProfileSealer(Buffer.alloc(32,37))})
 await f.provider.addLicenseCapacity({organizationReference:organization,quantity:1,operationId:'synthetic-capacity'})
 await f.provider.invite({...base,contact:phone},async()=>{throw Error('synthetic-notification-unavailable')})
 const [row]=await f.store.query(collection,{}),[listed]=await f.provider.list(organization)
 assert.ok(listed.activationCode);assert.equal(JSON.stringify(row).includes(listed.activationCode),false)
 await f.store.put(collection,{...row,telephone:safe.firstContactPhoneE164})
 await assert.rejects(f.provider.list(organization))
})

test('clinical author admission rejects nonclinical occupations despite an active licence, installation and explicit clinical group',async()=>{
 for(const role of [HealthcareActorRoles.Receptionist,HealthcareActorRoles.MedicalSecretary,HealthcareActorRoles.Controller]){
  const f=await activateContact(),[seat]=await f.store.query(collection,{})
  await f.store.put(collection,{...seat,role,employee:{...seat.employee,roleCode:role}})
  // A nonclinical role still has a valid workforce seat; it has no clinical-author scope.
  assert.equal((await f.provider.requireActive(phone,base.sector,base.profileId)).status,'active')
  await assert.rejects(f.provider.requireClinicalAuthor(f.admission),denied)
 }
})

test('supported doctor, nurse, dentist and veterinarian occupations retain current licensed clinical-author admission',async()=>{
 for(const role of [HealthcareActorRoles.GeneralistMedicalPractitioner,HealthcareActorRoles.NursingProfessional,HealthcareActorRoles.Dentist,HealthcareActorRoles.Veterinarian]){
  const f=await activateContact(),[seat]=await f.store.query(collection,{})
  await f.store.put(collection,{...seat,role,employee:{...seat.employee,roleCode:role}})
  const admitted=await f.provider.requireClinicalAuthor(f.admission)
  assert.equal(admitted.seat.employee.roleCode,role);assert.equal(admitted.seat.employee.license.status,'active')
 }
})

test('the actual generic MedicalDoctors profile retains licensed clinical admission without widening all ISCO occupations',async()=>{
 const f=await activateContact(email),[seat]=await f.store.query(collection,{})
 await f.store.put(collection,{...seat,role:HealthcareActorRoles.MedicalDoctors,employee:{...seat.employee,roleCode:HealthcareActorRoles.MedicalDoctors}})
 const admitted=await f.provider.requireClinicalAuthor(f.admission)
 assert.equal(admitted.seat.employee.roleCode,HealthcareActorRoles.MedicalDoctors)
 assert.equal(admitted.seat.employee.license.status,'active')
 assert.ok(admitted.seat.groups.includes(group))
})

function forbidIndependentAuthorityReads(f){
 let independentCalls=0
 const store=new Proxy(f.store,{get(target,property){
  if(['runTransaction','query','get'].includes(String(property)))return()=>{independentCalls++;throw Error('nested_or_outside_authority_read_forbidden')}
  const value=Reflect.get(target,property);return typeof value==='function'?value.bind(target):value
 }})
 const provider=new OrganizationWorkforceVaultProvider({store,collection,assertManage:async ref=>assert.equal(ref,organization),now:()=>f.state.now})
 return{provider,calls:()=>independentCalls}
}

test('clinical authorization composes inside the supplied vault transaction without nesting or independent reads',async()=>{
 const f=await activateContact(),guarded=forbidIndependentAuthorityReads(f)
 const admitted=await f.store.runTransaction(tx=>guarded.provider.requireClinicalAuthor(f.admission,tx))
 assert.equal(admitted.registration.clientInstanceId,installation.clientInstanceId)
 assert.equal(admitted.seat.organizationReference,organization);assert.equal(guarded.calls(),0)
})

test('supplied-transaction clinical authorization reads current licence, group and device revocation rather than a prior admission',async()=>{
 const f=await activateContact(),[original]=await f.store.query(collection,{})
 await f.provider.requireClinicalAuthor(f.admission)
 const guarded=forbidIndependentAuthorityReads(f)
 for(const mutate of [s=>{s.employee.license.status='inactive'},s=>{s.groups=[]},s=>{s.employee.license.devices[0].status='revoked'}]){
  const changed=structuredClone(original);mutate(changed);await f.store.put(collection,changed)
  await assert.rejects(f.store.runTransaction(tx=>guarded.provider.requireClinicalAuthor(f.admission,tx)),denied)
 }
 assert.equal(guarded.calls(),0)
})
