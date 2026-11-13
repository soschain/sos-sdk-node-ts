// Flow contract: related-person encounter grants use the controller's canonical Consent resource/code constraints; emergency-only never becomes all-history access without trusted resource context, and the existing actor, purpose, section, lifecycle and deny precedence remain effective.
import test from 'node:test'
import assert from 'node:assert/strict'
import {PortalConsentVaultProvider} from '../dist/portal-consent-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {DemoMemberConsentRoleClaims} from 'sos-data-utils-ts/demo-member-lifecycle'
import {FHIR_ENCOUNTER_TRANSFER_TEST_DATA as encounter,FHIR_CLINICAL_DOCUMENT_ENCOUNTER_JOURNEY_TEST_DATA as inpatient} from 'fhir-data-utils-ts/data'
import {ClaimConsent as C,ConsentDecisions} from 'fhir-data-utils-ts'
import {buildConsentClaimsSimple} from 'sos-data-utils-ts/consent-coverage'
import {HealthcareConsentPurposes} from 'fhir-data-utils-ts'
import {IndividualLogicalSections} from 'sos-data-utils-ts/individual-sections'

const section=IndividualLogicalSections.Encounters.attributeValue
const emergencyClass=`${encounter.class.system}|${encounter.class.code}`
const nonEmergencyClass=`${encounter.class.system}|${inpatient.encounters[0].class.code}`
const coverage={actor:{actorKind:'related-person',email:examples.firstContactEmail},actorRole:DemoMemberConsentRoleClaims.Caregiver,purpose:HealthcareConsentPurposes.Treatment,sections:[section]}
const context=(resourceType,provisionCodes)=>({resourceType,provisionCodes})

function rule({constrained=true,decision=ConsentDecisions.Permit,purpose=coverage.purpose,id=examples.resourceUuid}={}){
 const claims=buildConsentClaimsSimple({subjectDid:examples.didWeb,actor:examples.firstContactEmail,actorRole:coverage.actorRole,purpose,actions:[section],consentIdentifier:id,decision}).consentClaims
 return {...claims,[C.resourceType]:'Encounter,EncounterHistory',...(constrained?{[C.provisionCode]:emergencyClass}:{})}
}
function fixture(){
 return new PortalConsentVaultProvider({store:new TransactionalMemoryVaultRepository(),scopeKey:examples.tenantId,generationId:examples.resourceUuid,subjectIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,assertAccess:async()=>{}})
}

test('an emergency-only permit cannot authorize an unbounded or unclassified encounter request',async()=>{
 const provider=fixture();await provider.replace([rule()],0)
 for(const resourceContext of [undefined,context('Encounter',[]),context('Encounter',[nonEmergencyClass]),context('Encounter',[`${emergencyClass}-unknown`])]){
  assert.equal((await provider.evaluate(coverage,resourceContext)).allowed,false)
 }
})

test('the exact emergency class permits only eligible Encounter and EncounterHistory resource contexts',async()=>{
 const provider=fixture();await provider.replace([rule()],0)
 for(const resourceType of ['Encounter','EncounterHistory'])assert.equal((await provider.evaluate(coverage,context(resourceType,[emergencyClass]))).allowed,true)
 assert.equal((await provider.evaluate(coverage,context('Appointment',[emergencyClass]))).allowed,false)
})

test('an unconstrained encounter grant retains existing all-history coverage',async()=>{
 const provider=fixture();await provider.replace([rule({constrained:false})],0)
 assert.equal((await provider.evaluate(coverage)).allowed,true)
 assert.equal((await provider.evaluate(coverage,context('Encounter',[nonEmergencyClass]))).allowed,true)
})

test('emergency treatment purpose does not substitute for an emergency resource-class constraint',async()=>{
 const provider=fixture();await provider.replace([rule({purpose:HealthcareConsentPurposes.EmergencyTreatment})],0)
 const request={...coverage,purpose:HealthcareConsentPurposes.EmergencyTreatment}
 assert.equal((await provider.evaluate(request,context('Encounter',[nonEmergencyClass]))).allowed,false)
 assert.equal((await provider.evaluate(request,context('Encounter',[emergencyClass]))).allowed,true)
})

test('matching coded denials retain precedence and missing context cannot discard them',async()=>{
 const provider=fixture()
 await provider.replace([rule({constrained:false}),rule({decision:ConsentDecisions.Deny,id:encounter.communicationIdentifier})],0)
 const denied=await provider.evaluate(coverage,context('Encounter',[emergencyClass]))
 assert.equal(denied.allowed,false);assert.equal(denied.denied,true)
 assert.equal((await provider.evaluate(coverage)).allowed,false)
 assert.equal((await provider.evaluate(coverage,context('Encounter',[nonEmergencyClass]))).allowed,true)
})

test('resource class does not bypass identity, purpose, section, inactivity or explicit revocation',async()=>{
 const provider=fixture();await provider.replace([rule()],0)
 const emergency=context('Encounter',[emergencyClass])
 assert.equal((await provider.evaluate({...coverage,actor:{actorKind:'related-person',email:examples.individualEmail}},emergency)).allowed,false)
 assert.equal((await provider.evaluate({...coverage,purpose:HealthcareConsentPurposes.EmergencyTreatment},emergency)).allowed,false)
 assert.equal((await provider.evaluate({...coverage,sections:[IndividualLogicalSections.Appointments.attributeValue]},emergency)).allowed,false)
 await provider.replace([{...rule(),[C.status]:'inactive'}],1)
 assert.equal((await provider.evaluate(coverage,emergency)).allowed,false)
 await provider.replace([],2)
 assert.equal((await provider.evaluate(coverage,emergency)).allowed,false)
})
