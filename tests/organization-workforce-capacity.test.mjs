// Flow contract: controller capacity is persisted, operation-bound and enforced atomically against real vault seats; UI counters cannot grant capacity.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationWorkforceVaultProvider} from '../dist/organization-workforce-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
const org=`Organization/${safe.demoOrganizationUuids.healthCare}`
const make=(store,allowed=org)=>new OrganizationWorkforceVaultProvider({store,collection:'controller-capacity-test',assertManage:async value=>{if(value!==allowed)throw new Error('controller_forbidden')}})
const invitation=profileId=>({organizationReference:org,sector:'health-care',profileId,role:'dentist',email:safe.individualEmail,roleCode:'ISCO-08|2261',employeeDid:`urn:uuid:${safe.resourceUuid}`,expiresAt:Date.now()+60000,organizationName:'Synthetic clinic',roleName:'Dentist'})
test('capacity survives provider recreation and an exact retry adds no duplicate seats',async()=>{
 const store=new TransactionalMemoryVaultRepository(),p=make(store)
 const command={organizationReference:org,quantity:2,operationId:safe.resourceUuid}
 await p.addLicenseCapacity(command)
 await make(store).addLicenseCapacity(command)
 const inventory=await make(store).readLicenseInventory(org)
 assert.equal(inventory.contracted,2)
 assert.equal(inventory.free,2)
 await assert.rejects(make(store).addLicenseCapacity({...command,quantity:3}),/conflict/)
 assert.equal((await make(store).readLicenseInventory(org)).contracted,2)
 await assert.rejects(make(store,'Organization/foreign').addLicenseCapacity(command),/controller_forbidden/)
 await assert.rejects(make(store,'Organization/foreign').readLicenseInventory(org),/controller_forbidden/)
 const anotherHost=new OrganizationWorkforceVaultProvider({store,collection:'another-host-capacity',assertManage:async reference=>assert.equal(reference,org)})
 assert.equal((await anotherHost.readLicenseInventory(org)).contracted,0)
})
test('two concurrent invitations cannot spend a single persisted seat twice',async()=>{
 const store=new TransactionalMemoryVaultRepository(),p=make(store)
 await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 const attempts=await Promise.allSettled(['dentist-a','dentist-b'].map(id=>make(store).invite(invitation(id),async()=>{})))
 assert.equal(attempts.filter(item=>item.status==='fulfilled').length,1)
 const denied=attempts.find(item=>item.status==='rejected')
 assert.match(String(denied?.reason),/capacity_exhausted/)
 assert.equal((await p.list(org)).length,1)
 const inventory=await make(store).readLicenseInventory(org)
 assert.equal(inventory.contracted,1)
 assert.equal(inventory.used,1)
 assert.equal(inventory.free,0)
})

test('failed capacity transaction rolls back the first write and allows a clean retry',async()=>{
 const store=new TransactionalMemoryVaultRepository()
 let fail=true,writes=0
 const faulting=new Proxy(store,{get(target,key){
  if(key==='runTransaction')return work=>target.runTransaction(tx=>work(new Proxy(tx,{get(port,method){
   if(method==='put')return async(...args)=>{await port.put(...args);writes++;if(fail)throw new Error('after_first_write')}
   const value=Reflect.get(port,method);return typeof value==='function'?value.bind(port):value
  }})))
  const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value
 }})
 const command={organizationReference:org,quantity:2,operationId:safe.resourceUuid}
 await assert.rejects(make(faulting).addLicenseCapacity(command),/after_first_write/)
 assert.equal(writes,1)
 assert.equal((await make(store).readLicenseInventory(org)).contracted,0)
 fail=false
 await make(faulting).addLicenseCapacity(command)
 assert.equal((await make(store).readLicenseInventory(org)).contracted,2)
})

test('invalid capacity is rejected without persisting an operation or allocation',async()=>{
 const store=new TransactionalMemoryVaultRepository(),p=make(store)
 for(const quantity of [0,-1,1.5,Number.NaN,Number.POSITIVE_INFINITY]){
  await assert.rejects(p.addLicenseCapacity({organizationReference:org,quantity,operationId:safe.resourceUuid}),/quantity_invalid/)
 }
 assert.equal((await p.readLicenseInventory(org)).contracted,0)
 assert.deepEqual(await store.query('controller-capacity-test',{}),[])
})

test('managed host admission requires a persisted allocation before creating a seat',async()=>{
 const store=new TransactionalMemoryVaultRepository()
 const options={store,collection:'managed-capacity-test',requireLicenseCapacity:true,assertManage:async reference=>assert.equal(reference,org)}
 const p=new OrganizationWorkforceVaultProvider(options)
 options.requireLicenseCapacity=false
 await assert.rejects(p.invite(invitation('dentist'),async()=>{}),/capacity_exhausted/)
 assert.deepEqual(await p.list(org),[])
 await p.addLicenseCapacity({organizationReference:org,quantity:1,operationId:safe.resourceUuid})
 await p.invite(invitation('dentist'),async()=>{})
 assert.equal((await p.readLicenseInventory(org)).used,1)
})
test('managed-capacity constructor policy cannot be enabled by an ambiguous value',()=>{
 for(const value of ['true',1,{}])assert.throws(()=>new OrganizationWorkforceVaultProvider({store:new TransactionalMemoryVaultRepository(),collection:'managed-capacity-test',requireLicenseCapacity:value,assertManage:async()=>{}}),/capacity_policy_invalid/)
})
