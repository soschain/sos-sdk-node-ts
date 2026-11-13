// Flow contract:
// 1. Two authenticated BFF peers transport a verified raw E164 telephone without synthesizing an email.
// 2. The owning host factory binds that telephone to the canonical Consent actor; the real vault evaluates only the exact actor, role, subject and active rule.
// 3. A telephone-targeted request remains a draft; controller grant, explicit deny and revocation immediately change subsequent authoritative reads.
// 4. Invalid telephone assertions, a forged request target and unauthenticated peers fail closed before gaining access.
import assert from 'node:assert/strict'
import test from 'node:test'
import {PortalDemoExchange,createPortalDemoExchangeHandler,PortalDemoExchangeClient} from '../dist/portal-demo-exchange.js'
import {PortalConsentVaultProvider} from '../dist/portal-consent-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD} from 'sos-data-utils-ts/portal-demo-fixtures'
import {ClaimConsent as C,ConsentStatuses} from 'gdc-common-utils-ts/models/consent-rule'
import {buildConsentClaimsSimple,normalizeConsentTarget} from 'gdc-common-utils-ts/utils/consent'
import {HealthcareActorRoles,HealthcareConsentPurposes} from 'gdc-common-utils-ts/constants/healthcare'
import {IndividualLogicalSections} from 'gdc-common-utils-ts/constants/individual-sections'

const section=IndividualLogicalSections.Encounters.attributeValue
const role=HealthcareActorRoles.MedicalDoctors
const purpose=HealthcareConsentPurposes.Treatment
const phone=examples.phoneE164
const target=normalizeConsentTarget(`tel:${phone}`).canonicalValue
const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:examples.tenantId,tenantId:`demo-${examples.tenantId}`})
const credential='phone-contract-peer-credential-over-32-characters'
function claims({actor=target,decision='permit',status=ConsentStatuses.Active,id=examples.resourceUuid}={}){
  return {...buildConsentClaimsSimple({subjectDid:examples.didWeb,actor,actorRole:role,purpose,actions:[section],consentIdentifier:id,decision}).consentClaims,[C.status]:status}
}
async function fixture(){
  const store=new TransactionalMemoryVaultRepository()
  const exchange=new PortalDemoExchange({store})
  const card={cardNumber:SOSCHAIN_PERSONAL_DEMO_HOUSEHOLD.find(subject=>subject.subjectKind==='human').cardNumber21,generationId:examples.resourceUuid,subjectIdentifier:examples.didWeb,
    displayName:examples.individualGivenName,controllerActorIdentifier:`urn:uuid:${examples.resourceUuid}`,subjectKind:'person',sourceSector:'health-care',expiresAt:Date.now()+60_000}
  await exchange.registerCard(scope,card)
  const provider=new PortalConsentVaultProvider({store,scopeKey:scope.key,generationId:card.generationId,
    subjectIdentifier:card.subjectIdentifier,expiresAt:card.expiresAt,assertAccess:async()=>{}})
  const seen=[]
  const handler=createPortalDemoExchangeHandler({exchange,scope,bearer:credential,
    consentProviderFactory:async({participant})=>{
      seen.push(participant)
      // The BFF already verified the Firebase token and protected profile. This host-owned port translates that contact into the common actor descriptor.
      return {provider,actor:{actorKind:'professional',phone:participant.verifiedPhone},actorRole:role}
    },
  })
  const client=new PortalDemoExchangeClient({baseUrl:examples.httpsBaseUrl,bearer:credential,
    fetchImpl:async(url,init)=>handler(new Request(url,init))})
  const participant={actorIdentifier:`urn:uuid:${examples.resourceUuid}`,verifiedPhone:phone,roleClaim:role}
  const inspect=(who=participant)=>client.consent(scope,card.subjectIdentifier,who,{kind:'inspect',purpose,sections:[section]})
  return {store,exchange,card,provider,client,participant,seen,handler,inspect}
}

test('peer transport retains a raw verified telephone without creating an email and evaluates the exact actor',async()=>{
  const f=await fixture()
  await f.provider.replace([claims()],0)
  assert.equal((await f.inspect()).evaluation.allowed,true)
  assert.equal(f.seen[0].verifiedPhone,phone)
  assert.equal(Object.hasOwn(f.seen[0],'verifiedEmail'),false)
  assert.equal((await f.inspect({...f.participant,verifiedPhone:examples.firstContactPhoneE164})).evaluation.allowed,false)
  assert.equal((await f.inspect({...f.participant,verifiedPhone:undefined})).evaluation.allowed,false)
})

test('a telephone request is only a draft, then controller grant, revoke and explicit deny affect the next read',async()=>{
  const f=await fixture()
  const draft=claims({status:ConsentStatuses.Draft})
  const requested=await f.client.consent(scope,f.card.subjectIdentifier,f.participant,{kind:'request',claims:draft})
  assert.equal(requested.kind,'request')
  assert.equal(requested.claims[C.actorIdentifier],target)
  assert.equal(requested.claims[C.status],ConsentStatuses.Draft)
  assert.equal((await f.inspect()).evaluation.allowed,false)
  let snapshot=await f.provider.read()
  await f.provider.replace([claims()],snapshot.revision)
  assert.equal((await f.inspect()).evaluation.allowed,true)
  snapshot=await f.provider.read()
  await f.provider.replace([claims({status:ConsentStatuses.Inactive})],snapshot.revision)
  assert.equal((await f.inspect()).evaluation.allowed,false)
  snapshot=await f.provider.read()
  await f.provider.replace([claims({decision:'deny'})],snapshot.revision)
  const denied=(await f.inspect()).evaluation
  assert.equal(denied.allowed,false)
  assert.equal(denied.denied,true)
})

test('the same phone never bypasses exact actor role, subject and generation checks',async()=>{
  const f=await fixture()
  await f.provider.replace([claims()],0)
  const request={actor:{actorKind:'professional',phone},actorRole:HealthcareActorRoles.NursingProfessional,purpose,sections:[section]}
  assert.equal((await f.provider.evaluate(request)).allowed,false)
  await assert.rejects(f.provider.replace([{...claims(),[C.subject]:examples.didWeb+':foreign'}],1),/subject/)
  const otherGeneration=new PortalConsentVaultProvider({store:f.store,scopeKey:scope.key,generationId:examples.demoOrganizationUuids.healthCare,
    subjectIdentifier:examples.didWeb,expiresAt:Date.now()+60_000,assertAccess:async()=>{}})
  assert.equal((await otherGeneration.evaluate({...request,actorRole:role})).allowed,false)
})

test('the peer cannot request a different telephone or fabricate an email recipient',async()=>{
  const f=await fixture()
  for(const actor of [normalizeConsentTarget(`tel:${examples.firstContactPhoneE164}`).canonicalValue,examples.firstContactEmail]){
    await assert.rejects(f.client.consent(scope,f.card.subjectIdentifier,f.participant,{kind:'request',claims:claims({actor,status:ConsentStatuses.Draft})}),/actor_forbidden/)
  }
  assert.deepEqual(await f.provider.read(),{revision:0,claims:[]})
})

test('malformed or noncanonical telephone assertions are rejected before the host factory',async()=>{
  for(const verifiedPhone of ['not-a-phone',`tel:${phone}`,examples.firstContactEmail,{},123]){
    const f=await fixture()
    await assert.rejects(f.inspect({...f.participant,verifiedPhone}),/invalid/)
    assert.equal(f.seen.length,0)
  }
})

test('the phone assertion never replaces peer bearer authentication',async()=>{
  const f=await fixture()
  const response=await f.handler(new Request(`${examples.httpsBaseUrl}/api/internal/demo/exchange`,{method:'POST',
    body:JSON.stringify({operation:'consent',scope,subjectIdentifier:f.card.subjectIdentifier,participant:f.participant,
      consent:{kind:'inspect',purpose,sections:[section]}})}))
  assert.equal(response.status,401)
  assert.equal(f.seen.length,0)
})
