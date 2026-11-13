// Flow contract: both portal hosts reuse the vault workforce provider with injected authorization and delivery; invitation credentials are single-use, scope-bound, and activation rolls back with the protected profile callback.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationWorkforceVaultProvider} from '../dist/organization-workforce-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const organization=`Organization/${safe.demoOrganizationUuids.healthCare}`
const input={organizationReference:organization,sector:'health-care',profileId:'dentist',role:'dentist',email:safe.individualEmail,roleCode:'ISCO-08|2261',employeeDid:`urn:uuid:${safe.resourceUuid}`,expiresAt:Date.now()+60_000,organizationName:'Synthetic clinic',roleName:'Dentist',groups:['encounter-operations']}
const provider=(store,collection='workforce-test')=>new OrganizationWorkforceVaultProvider({store,collection,assertManage:async ref=>{if(ref!==organization)throw new Error('controller_forbidden')}})
test('delivers, activates once and retains canonical licence state',async()=>{
  const store=new TransactionalMemoryVaultRepository(),p=provider(store)
  let credential=''
  await p.invite(input,async message=>{credential=message.activationCode})
  const rows=await p.list(organization)
  assert.equal(rows[0].status,'pending')
  assert.ok(!JSON.stringify(await store.query('workforce-test',{})).includes(credential))
  await assert.rejects(p.activate(safe.firstContactEmail,credential,async()=>true),/invitation_invalid/)
  await assert.rejects(provider(store,'another-workspace').activate(input.email,credential,async()=>true),/invitation_invalid/)
  await assert.rejects(p.activate(input.email,credential,async()=>{throw new Error('profile_failed')}),/profile_failed/)
  const winners=await Promise.allSettled([p.activate(input.email,credential,async()=>true),p.activate(input.email,credential,async()=>true)])
  assert.equal(winners.filter(r=>r.status==='fulfilled').length,1)
  const active=await p.requireActive(input.email,input.sector,input.profileId)
  assert.equal(active.status,'active')
  assert.deepEqual(active.groups,input.groups)
  await p.change(organization,active.id,'disable')
  await assert.rejects(p.requireActive(input.email,input.sector,input.profileId),/activation_required/)
  await assert.rejects(p.change('Organization/foreign',active.id,'reactivate'),/controller_forbidden/)
})
test('never reports a failed delivery as sent or active',async()=>{
  const p=provider(new TransactionalMemoryVaultRepository())
  await assert.rejects(p.invite(input,async()=>{throw new Error('mail_failed')}),/delivery_failed/)
  assert.equal((await p.list(organization))[0].delivery,'failed')
  await assert.rejects(p.requireActive(input.email,input.sector,input.profileId),/activation_required/)
})
