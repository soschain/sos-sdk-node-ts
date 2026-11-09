// Flow contract: the active SOS factory retains the existing V1 routing-grant shape and opaque actor identity for one explicit phone/email contact; the owning BFF still proves contact possession, owner binding, expiry and GW activation.
import assert from 'node:assert/strict'
import test from 'node:test'
import { EmployeeActivationGrantVersions } from 'gdc-common-utils-ts'
import { HealthcareActorRoles } from 'gdc-common-utils-ts/constants/healthcare'
import { buildStableActorIdentifier as legacyActorIdentifier } from 'gdc-common-utils-ts/utils/actor-identifier'
import { createEmployeeActivationGrant as legacyEmailGrant, employeeActivationGrantMatchesEmail } from 'gdc-sdk-node-ts'
import { REPOSITORY_SAFE_EXAMPLES as safe } from 'sos-data-utils-ts/repository-privacy'
import { createEmployeeActivationGrant, employeeActivationGrantMatchesContact } from '../dist/index.js'

const routing = Object.freeze({ employeeDid: `${safe.didWeb}:employee`, employeeRoleCode: HealthcareActorRoles.Veterinarian,
  providerDid: safe.didWeb, routeContext: Object.freeze({tenantId:safe.tenantId,jurisdiction:'CA-BC',sector:safe.sector}),
  createdAt:new Date('2026-11-08T12:00:00.000Z'),expiresAt:new Date('2026-11-08T12:10:00.000Z') })
const phone={contactKind:'phone',contact:safe.phoneE164}
const email={contactKind:'email',contact:safe.individualEmail}

test('phone factory emits exactly the existing V1 model with no clear-contact or new wire fields',()=>{
  const grant=createEmployeeActivationGrant({...routing,...phone})
  assert.deepEqual(grant,{version:EmployeeActivationGrantVersions.V1,employeeDid:routing.employeeDid,employeeRoleCode:routing.employeeRoleCode,
    employeeActorIdentifier:legacyActorIdentifier(phone),providerDid:routing.providerDid,routeContext:routing.routeContext,
    createdAt:routing.createdAt.toISOString(),expiresAt:routing.expiresAt.toISOString()})
  assert.equal(Object.hasOwn(grant,'contact'),false);assert.equal(Object.hasOwn(grant,'email'),false);assert.equal(Object.hasOwn(grant,'phone'),false)
  assert.equal(JSON.stringify(grant).includes(safe.phoneE164),false)
})

test('normalizes explicitly selected telephone formats and rejects another contact identity',()=>{
  const selected={contactKind:'phone',contact:`tel:${safe.firstContactPhoneDisplay}`}
  const grant=createEmployeeActivationGrant({...routing,...selected})
  assert.equal(employeeActivationGrantMatchesContact(grant,{contactKind:'phone',contact:safe.firstContactPhoneE164}),true)
  assert.equal(employeeActivationGrantMatchesContact(grant,phone),false)
  assert.equal(employeeActivationGrantMatchesContact(grant,email),false)
})

for(const [index,selected] of [safe.individualEmail,` ${safe.individualEmail.toUpperCase()} `,`mailto:${safe.individualEmail}`].entries()){
  test(`retains the frozen email factory and matcher wire contract for normalized variant ${index+1}`,()=>{
    const grant=createEmployeeActivationGrant({...routing,contactKind:'email',contact:selected})
    const previous=legacyEmailGrant({...routing,email:selected})
    assert.deepEqual(grant,previous)
    assert.equal(employeeActivationGrantMatchesContact(grant,email),employeeActivationGrantMatchesEmail(previous,safe.individualEmail))
    assert.equal(employeeActivationGrantMatchesContact(grant,{contactKind:'email',contact:safe.firstContactEmail}),false)
  })
}

for(const selected of [{contactKind:'phone',contact:'12345'},{contactKind:'email',contact:'invalid'},{contactKind:'sms',contact:safe.phoneE164},{contactKind:'phone',contact:''}]){
  test(`denies malformed explicit ${selected.contactKind} input without fallback`,()=>{
    assert.throws(()=>createEmployeeActivationGrant({...routing,...selected,email:safe.individualEmail}),TypeError)
    assert.throws(()=>employeeActivationGrantMatchesContact({employeeActorIdentifier:legacyActorIdentifier(phone)},selected),TypeError)
  })
}

test('does not infer the selected contact from a legacy email-only argument',()=>{
  assert.throws(()=>createEmployeeActivationGrant({...routing,email:safe.individualEmail}),TypeError)
  assert.throws(()=>employeeActivationGrantMatchesContact({employeeActorIdentifier:legacyActorIdentifier(email)},{email:safe.individualEmail}),TypeError)
})

test('preserves caller-owned routing and dates without mutating contact input',()=>{
  const input={...routing,contactKind:'phone',contact:`tel:${safe.firstContactPhoneDisplay}`},snapshot=structuredClone(input)
  const grant=createEmployeeActivationGrant(input)
  assert.deepEqual(input,snapshot);assert.equal(grant.routeContext,routing.routeContext)
  assert.equal(grant.employeeRoleCode,routing.employeeRoleCode)
})

test('a contact match is not a TTL or verified-identity decision',()=>{
  const expired={...routing,createdAt:new Date('2020-01-01T00:00:00.000Z'),expiresAt:new Date('2020-01-01T00:01:00.000Z')}
  const grant=createEmployeeActivationGrant({...expired,...phone})
  assert.equal(grant.expiresAt,expired.expiresAt.toISOString())
  assert.equal(employeeActivationGrantMatchesContact(grant,phone),true)
  assert.equal(Object.hasOwn(grant,'verifiedContact'),false);assert.equal(Object.hasOwn(grant,'ownerId'),false)
})
