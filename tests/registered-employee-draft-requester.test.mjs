// Flow contract: one draft-requester identity comes only from exact completed DCR consumption plus current PIN-sealed registered custody; phone/email, provider/route/role/installation, revision, lock and asynchronous races stay bound, expired invitations do not expire completed enrollment and no seed/token or active permission is returned.
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {createHash} from 'node:crypto'
import {readFileSync} from 'node:fs'
import * as api from '../dist/index.js'
import {ActorKinds} from 'antifraud-data-utils-ts/actor-kinds'
import {buildAuthorityDidWeb,buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
const collections={profiles:'synthetic-draft-profiles',walletSessions:'synthetic-draft-wallet-sessions',enrollmentGrants:'synthetic-draft-enrollment-grants'}
const seed=Buffer.alloc(32,23).toString('base64url'),token=Buffer.alloc(32,37).toString('base64url'),sessionId=createHash('sha256').update(token).digest('hex')
const now=()=>new Date('2026-01-01T00:00:00Z'),hostAuthorityDid=buildAuthorityDidWeb({authority:safe.httpsBaseUrl}),routeContext={tenantId:safe.tenantId,jurisdiction:'CA',sector:safe.sector},role='ISCO-08|2250'
// Pure synthetic wire captured outside SOS; source/module hash stays in the
// ignored oracle receipt. No frozen dependency is loaded by this test.
const providerDid=JSON.parse(readFileSync(new URL('./fixtures/employee-draft-provider-oracle.json',import.meta.url),'utf8')).providerDid
const need=()=>{assert.equal(typeof api.resolveRegisteredEmployeeDraftRequester,'function','missing owned employee draft-requester operation');return api.resolveRegisteredEmployeeDraftRequester}
async function setup(kind='phone'){
 const vault=new api.TransactionalMemoryVaultRepository(),sealer=api.createAesGcmProfileSealer(Buffer.alloc(32,7)),contact={contactKind:kind,contact:kind==='phone'?safe.phoneE164:safe.individualEmail}
 const actorDid=buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role}),profileId=safe.resourceUuid,ownerId='synthetic-employee-owner',clientInstanceId='synthetic-employee-installation',tenantIssuer=`urn:uuid:${safe.demoOrganizationUuids.animalCare}`
 const keys=await api.openServerProfileCustodyKeys({walletKeyDerivationId:'synthetic-draft-employee-keys',unlockedWalletSeed:seed,binding:{kind:'enrollment'}})
 const profile={id:profileId,profileId,ownerId,actorDid,profileDid:actorDid,providerDid,routeContext,actorKind:ActorKinds.OrganizationEmployee,actorMode:'member',clientId:'synthetic-employee-client',clientInstanceId,deviceDid:'synthetic-employee-client',tenantIssuer,allowedSubjectDids:[actorDid],walletKeyDerivationId:'synthetic-draft-employee-keys',publicJwks:keys.publicJwks.map(key=>({...key})),storagePublicJwk:{...keys.storagePublicJwk},confidentialStorageProfile:'confidential-pqc-v1',protectedWalletSeed:await api.protectServerProfileSecret(seed,'fixture-742619',`${profileId}:wallet-seed`,sealer),failedUnlocks:2,createdAt:'2020-01-01T00:00:00Z',updatedAt:'2020-01-01T00:00:00Z'}
 const session={id:sessionId,ownerId,profileId,sealedWalletSeed:await sealer.seal(seed,`${ownerId}:${profileId}:${sessionId}:wallet-session-seed`),expiresAt:'2099-01-01T00:00:00Z'}
 const grant={...api.createEmployeeActivationGrant({...contact,employeeDid:actorDid,employeeRoleCode:role,providerDid,routeContext,createdAt:new Date('2020-01-01T00:00:00Z'),expiresAt:new Date('2020-01-02T00:00:00Z')}),id:'synthetic-consumed-grant',tenantIssuer,accessPath:'test-network',consumedEnrollments:[{ownerId,profileId,clientInstanceId}]}
 await vault.put(collections.profiles,profile);await vault.put(collections.walletSessions,session);await vault.put(collections.enrollmentGrants,grant)
 return {vault,sealer,profile,session,grant,options:{vault,sealer,collections,hostAuthorityDid,gatewayBaseUrl:safe.httpsBaseUrl,now},input:{ownerId,profileId,profileSessionToken:token,verifiedContact:contact}}
}
test('retains the owned historical PIN envelope and public key fixture control',async()=>{
 const s=await setup();assert.equal(await api.openServerProfileSecret(s.profile.protectedWalletSeed,'fixture-742619',`${s.profile.profileId}:wallet-seed`,s.sealer),seed)
 assert.equal(s.profile.publicJwks.length,5)
})
test('projects an actual consumed phone enrollment even after its invitation expired',async()=>{
 const s=await setup(),resolve=need(),result=await resolve(s.options,s.input)
 assert.deepEqual(result,{ownerId:s.profile.ownerId,profileId:s.profile.profileId,actorDid:s.profile.actorDid,providerDid,routeContext,clientId:s.profile.clientId,clientInstanceId:s.profile.clientInstanceId,recordedRole:role})
 for(const secret of[seed,token,s.session.sealedWalletSeed])assert.equal(JSON.stringify(result).includes(secret),false)
 assert.deepEqual(await s.vault.get(collections.profiles,s.profile.id),s.profile)
 assert.deepEqual(await s.vault.get(collections.walletSessions,sessionId),s.session)
 assert.deepEqual(await s.vault.get(collections.enrollmentGrants,s.grant.id),s.grant)
})
test('retains verified-email enrollment compatibility without a synthetic phone/email conversion',async()=>{
 const s=await setup('email'),resolve=need(),result=await resolve(s.options,s.input)
 assert.equal(result.actorDid,s.profile.actorDid);assert.equal(result.recordedRole,role)
})
test('admits the completed organization under its configured enrollment host without a lookup-directory tenant entry',async()=>{
 const s=await setup(),resolve=need()
 const result=await resolve({vault:s.vault,sealer:s.sealer,collections,hostAuthorityDid,gatewayBaseUrl:safe.httpsBaseUrl,now},s.input)
 assert.equal(result.recordedRole,role);assert.equal(result.profileId,s.profile.profileId)
})
test('does not turn an unconsumed invitation into employee authority',async()=>{
 const s=await setup(),resolve=need(),{consumedEnrollments:_consumed,...pending}=s.grant
 await s.vault.put(collections.enrollmentGrants,pending);await assert.rejects(resolve(s.options,s.input))
})
test('rejects wrong owner/contact/host and controller substitution before unsealing',async()=>{
 const s=await setup(),resolve=need();let unseals=0
 const options={...s.options,sealer:{seal:s.sealer.seal,unseal:async(...args)=>{unseals++;return s.sealer.unseal(...args)}}}
 await assert.rejects(resolve(options,{...s.input,ownerId:'synthetic-other-owner'}))
 await assert.rejects(resolve(options,{...s.input,verifiedContact:{contactKind:'phone',contact:safe.firstContactPhoneE164}}))
 await assert.rejects(resolve({...options,hostAuthorityDid:safe.subjectCardProviders.humanIndexDid},s.input))
 await s.vault.put(collections.profiles,{...s.profile,actorKind:ActorKinds.OrganizationController,actorMode:'controller'})
 await assert.rejects(resolve(options,s.input));assert.equal(unseals,0)
})
test('rejects current session expiry, revision mismatch and profile lock independently of invitation dates',async()=>{
 const s=await setup(),resolve=need()
 for(const patch of[{expiresAt:'2025-01-01T00:00:00Z'},{credentialRevision:1}]){await s.vault.put(collections.walletSessions,{...s.session,...patch});await assert.rejects(resolve(s.options,s.input))}
 await s.vault.put(collections.walletSessions,s.session);await s.vault.put(collections.profiles,{...s.profile,lockedUntil:'2099-01-01T00:00:00Z'})
 await assert.rejects(resolve(s.options,s.input))
})
test('requires one exact consumed owner/profile/installation tuple and refuses ambiguous grants',async()=>{
 const s=await setup(),resolve=need()
 for(const field of['ownerId','profileId','clientInstanceId']){await s.vault.put(collections.enrollmentGrants,{...s.grant,consumedEnrollments:[{...s.grant.consumedEnrollments[0],[field]:'synthetic-other'}]});await assert.rejects(resolve(s.options,s.input))}
 await s.vault.put(collections.enrollmentGrants,s.grant);await s.vault.put(collections.enrollmentGrants,{...s.grant,id:'synthetic-duplicate-consumed-grant'})
 await assert.rejects(resolve(s.options,s.input))
})
test('binds recorded role, provider, route and tenant issuer to the actual registered actor',async()=>{
 const s=await setup(),resolve=need()
 for(const patch of[{employeeRoleCode:'ISCO-08|5412'},{providerDid:safe.didWeb},{routeContext:{...routeContext,sector:'public-safety'}},{tenantIssuer:'synthetic-other-issuer'}]){
  await s.vault.put(collections.enrollmentGrants,{...s.grant,...patch});await assert.rejects(resolve(s.options,s.input))
 }
})
test('verifies full registered custody rather than matching only one public kid',async()=>{
 const s=await setup(),resolve=need()
 await s.vault.put(collections.profiles,{...s.profile,publicJwks:s.profile.publicJwks.map(key=>key.alg==='ES384'?{...key,x:'synthetic-changed-public-material'}:key)})
 await assert.rejects(resolve(s.options,s.input))
})
test('rejects profile, session and consumed-evidence races across the real host unseal',async()=>{
 const s=await setup(),resolve=need()
 for(const target of['profile','session','grant']){
  await s.vault.put(collections.profiles,s.profile);await s.vault.put(collections.walletSessions,s.session);await s.vault.put(collections.enrollmentGrants,s.grant)
  const sealer={seal:s.sealer.seal,unseal:async(...args)=>{const clear=await s.sealer.unseal(...args);if(target==='profile')await s.vault.put(collections.profiles,{...s.profile,credentialRevision:1});else if(target==='session')await s.vault.delete(collections.walletSessions,sessionId);else await s.vault.put(collections.enrollmentGrants,{...s.grant,consumedEnrollments:[]});return clear}}
  await assert.rejects(resolve({...s.options,sealer},s.input))
 }
})
test('does not mask a host key outage as a credential denial or reset PIN counters',async()=>{
 const s=await setup(),resolve=need(),outage=new Error('synthetic_host_key_unavailable')
 await assert.rejects(resolve({...s.options,sealer:{seal:s.sealer.seal,unseal:async()=>{throw outage}}},s.input),error=>error===outage)
 assert.equal((await s.vault.get(collections.profiles,s.profile.id)).failedUnlocks,2)
})
test('concurrent identity projections preserve the same durable rows and public result',async()=>{
 const s=await setup(),resolve=need(),results=await Promise.all([resolve(s.options,s.input),resolve(s.options,s.input)])
 assert.deepEqual(results[0],results[1]);assert.deepEqual(await s.vault.get(collections.enrollmentGrants,s.grant.id),s.grant)
})
