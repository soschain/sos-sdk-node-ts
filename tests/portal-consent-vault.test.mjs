// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Flow contract: one subject/generation-scoped Consent collection in the injected transactional vault serves both portals; only controllers edit, every read uses current active rules, and stale, foreign, revoked or failed changes never broaden access.
import test from 'node:test'
import assert from 'node:assert/strict'
import {PortalConsentVaultProvider} from '../dist/portal-consent-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {ClaimConsent as C} from 'fhir-data-utils-ts'
import {buildConsentClaimsSimple} from 'sos-data-utils-ts/consent-coverage'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {HealthcareConsentPurposes} from 'fhir-data-utils-ts'
import {IndividualLogicalSections} from 'sos-data-utils-ts/individual-sections'
const section=IndividualLogicalSections.Encounters.attributeValue
const rule=(actor=examples.firstContactEmail)=>buildConsentClaimsSimple({subjectDid:examples.didWeb,actor,actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,actions:[section],consentIdentifier:examples.resourceUuid}).consentClaims
function fixture(){
 const store=new TransactionalMemoryVaultRepository();let write=true
 const provider=new PortalConsentVaultProvider({store,scopeKey:examples.tenantId,generationId:examples.resourceUuid,subjectIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,assertAccess:async(_transaction,action)=>{if(action==='write'&&!write)throw new Error('forbidden')}})
 return {store,provider,revokeWrite:()=>{write=false}}
}
test('one collection persists and re-evaluates professional email, organization and country rules with roles',async()=>{
 const f=fixture()
 for(const [target,actor] of [[examples.firstContactEmail,{email:examples.firstContactEmail}],[examples.didWeb,{organizationDid:examples.didWeb}],[examples.countryIso2,{jurisdiction:examples.countryIso2}]]){
  const snapshot=await f.provider.read()
  await f.provider.replace([rule(target)],snapshot.revision)
  assert.equal((await f.provider.evaluate({actor:{actorKind:'professional',...actor},actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,sections:[section]})).allowed,true)
  assert.equal((await f.provider.evaluate({actor:{actorKind:'professional',...actor},actorRole:HealthcareActorRoles.NursingProfessional,purpose:HealthcareConsentPurposes.Treatment,sections:[section]})).allowed,false)
 }
})
test('inactive rules and foreign subjects fail closed; stale writes and non-controllers cannot replace rules',async()=>{
 const f=fixture();await f.provider.replace([rule()],0)
 await assert.rejects(f.provider.replace([rule()],0),/revision/)
 await assert.rejects(f.provider.replace([{...rule(),[C.subject]:examples.didWeb+':other'}],1),/subject/)
 await f.provider.replace([{...rule(),[C.status]:'inactive'}],1)
 assert.equal((await f.provider.evaluate({actor:{email:examples.firstContactEmail},actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,sections:[section]})).allowed,false)
 f.revokeWrite();await assert.rejects(f.provider.replace([],2),/forbidden/)
})

test('concurrent replacements have one winner and another generation cannot see its rules',async()=>{
 const f=fixture()
 const results=await Promise.allSettled([f.provider.replace([rule()],0),f.provider.replace([rule(examples.individualEmail)],0)])
 assert.equal(results.filter(result=>result.status==='fulfilled').length,1)
 const other=new PortalConsentVaultProvider({store:f.store,scopeKey:examples.tenantId,generationId:examples.resourceUuid+'-new',subjectIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,assertAccess:async()=>{}})
 assert.deepEqual(await other.read(),{revision:0,claims:[]})
})

test('a professional can append only a draft request and cannot approve it',async()=>{
 const f=fixture()
 const professional=new PortalConsentVaultProvider({store:f.store,scopeKey:examples.tenantId,generationId:examples.resourceUuid,subjectIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,assertAccess:async(_transaction,action)=>{if(action==='write')throw new Error('controller_required')}})
 await assert.rejects(professional.requestDraft(rule()),/draft/)
 await professional.requestDraft({...rule(),[C.status]:'draft'})
 await professional.requestDraft({...rule(),[C.status]:'draft'})
 const replay=await professional.requestDraft({...rule(),[C.status]:'draft',[C.date]:new Date(Date.now()+1_000).toISOString()})
 assert.equal(replay.revision,1)
 assert.equal((await f.provider.read()).claims.length,1)
 assert.equal((await professional.evaluate({actor:{email:examples.firstContactEmail},actorRole:HealthcareActorRoles.MedicalDoctors,purpose:HealthcareConsentPurposes.Treatment,sections:[section]})).allowed,false)
 await assert.rejects(professional.replace([rule()],1),/controller_required/)
})

test('controller replacement commits related vault writes atomically and rolls back a failed callback',async()=>{
 const f=fixture(),collection='contract-side-effect' // Literal is a deliberately neutral test collection, not an operational resource.
 await assert.rejects(f.provider.replace([rule()],0,async transaction=>{await transaction.put(collection,{id:examples.resourceUuid});throw new Error('injected-after-related-write')}),/injected/)
 assert.deepEqual(await f.provider.read(),{revision:0,claims:[]})
 assert.equal(await f.store.get(collection,examples.resourceUuid),undefined)
 const commit=async transaction=>{await transaction.put(collection,{id:examples.resourceUuid})}
 await f.provider.replace([rule()],0,commit)
 assert.equal((await f.provider.read()).claims.length,1)
 assert.equal((await f.store.get(collection,examples.resourceUuid)).id,examples.resourceUuid)
 let invoked=false
 f.revokeWrite()
 await assert.rejects(f.provider.replace([],1,async()=>{invoked=true}),/forbidden/)
 assert.equal(invoked,false)
})
