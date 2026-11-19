// Flow contract: the registered member signs a pinned-study SMART request and accepts only a verified grant for that member, device and study.
import assert from 'node:assert/strict'
import {createPublicKey,generateKeyPairSync,randomBytes,sign,verify} from 'node:crypto'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {CommunicationCategoryCodes,CommunicationClaim,FhirCodeSystems,HealthcareConsentPurposes} from 'fhir-data-utils-ts'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {createVerifiedGatewaySecureAdapter} from '../dist/registered-gateway-transport.js'
import {openServerProfileCustodyKeys} from '../dist/server-profile-custody-keys.js'
import * as sdk from '../dist/index.js'

test('signs a registered employee presentation and rejects a token for another study',async()=>{
 const providerDid=safe.didWeb,actorDid=`${providerDid}:employee:researcher`,clientId='registered-research-client'
 const ctx={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-research'}
 const studyId=safe.resourceUuid,reference=`ResearchStudy/${studyId}`,scope=`organization/ResearchSubject.crus?study=${reference}`
 const now=1794614400,packets=[],directoryRequests=[]
 const memberContext={profile:{profileId:'research-member'},runtime:{runtimeId:'research-member-runtime',runtimeType:'backend-service'}}
 const gatewayContext={profile:{profileId:'research-gateway'},runtime:{runtimeId:'research-gateway-runtime',runtimeType:'backend-service'}}
 let memberPublicKeys
 const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>memberPublicKeys.encryption})
 await gateway.provisionCommunicationKeys(gatewayContext,randomBytes(32).toString('base64url'))
 const gatewayPublicKeys=gateway.getPublicJwks(gatewayContext)
 const member=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gatewayPublicKeys.encryption})
 await member.provisionCommunicationKeys(memberContext,randomBytes(32).toString('base64url'))
 memberPublicKeys=member.getPublicJwks(memberContext)
 const secureTransportAdapter=createVerifiedGatewaySecureAdapter({gatewayDid:providerDid,
  pack:body=>member.packForRecipientWithContext(body,providerDid,{context:memberContext}),
  decrypt:packed=>member.unpackWithContext(packed,{context:memberContext}),
  resolveGatewaySigningJwk:async()=>gatewayPublicKeys.signing})
 const unlockedWalletSeed=randomBytes(32).toString('base64url'),walletKeyDerivationId='study-member'
 const enrolled=await openServerProfileCustodyKeys({unlockedWalletSeed,walletKeyDerivationId,binding:{kind:'enrollment'}})
 const memberCustody=await openServerProfileCustodyKeys({unlockedWalletSeed,walletKeyDerivationId,
  binding:{kind:'registered',publicJwks:enrolled.publicJwks,storagePublicJwk:enrolled.storagePublicJwk}})
 const keys=generateKeyPairSync('ec',{namedCurve:'P-384'})
 const signingJwk={...keys.publicKey.export({format:'jwk'}),kid:'gateway-signing',alg:'ES384',use:'sig'}
 const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url')
 const signed=claims=>{
  const input=`${encode({alg:'ES384',kid:signingJwk.kid})}.${encode(claims)}`
  return `${input}.${sign('sha384',Buffer.from(input),{key:keys.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')}`
 }
 let foreign=false
 const client=new sdk.RegisteredResearchStudyClient({
  baseUrl:'https://example.invalid',ctx,actorDid,clientId,providerDid,role:HealthcareActorRoles.Dentist,bearerToken:'verified-oidc-token',
  signClientAssertion:memberCustody.signClientAssertion,signIdentityPresentationJws:memberCustody.signIdentityPresentationJws,
  secureTransportAdapter,
  smartTokenVerification:{algorithm:'ES384',resolveSigningJwk:async did=>{assert.equal(did,providerDid);return signingJwk}},now:()=>new Date(now*1000),
  fetchImpl:async (url,init)=>{
   const message=(await gateway.unpackWithContext(new URLSearchParams(init.body).get('request'),{context:gatewayContext})).content
   const path=new URL(url).pathname
   if(path.includes('/_search')){
    if(message.body){directoryRequests.push({path,body:message.body});return new Response('{}',{status:202})}
    const response=await gateway.packForRecipientWithContext({thid:message.thid,iss:providerDid,aud:actorDid,body:{data:[]}},actorDid,{context:gatewayContext})
    return Response.json({response})
   }
   assert.equal(path,`/${ctx.tenantId}/cds-${ctx.jurisdiction}/v1/${ctx.sector}/identity/openid/smart/${message.body?'token':'token-response'}`)
   if(message.body){packets.push(message);return new Response('{}',{status:202})}
   const access_token=signed({iss:providerDid,aud:providerDid,sub:actorDid,client_id:clientId,scope,study:foreign?'ResearchStudy/other':reference,
    purpose:HealthcareConsentPurposes.Research,iat:now,nbf:now,exp:now+300,jti:'study-token'})
   const response=await gateway.packForRecipientWithContext({jti:message.thid,thid:message.thid,iss:providerDid,aud:actorDid,body:{
    access_token,token_type:'Bearer',subject:reference,scope,
   }},actorDid,{context:gatewayContext})
   return Response.json({response})
  },
 })
 const result=await client.requestStudyAccess(studyId)
 assert.equal(result.status,'fetched')
 assert.equal(packets[0].body.scope,scope)
 const [header,payload,signature]=packets[0].body.vp_token.split('.')
 const kid=JSON.parse(Buffer.from(header,'base64url')).kid
 const vpKey=createPublicKey({key:memberCustody.publicJwks.find(key=>key.kid===kid),format:'jwk'})
 assert.ok(verify('sha384',Buffer.from(`${header}.${payload}`),{key:vpKey,dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url')))
 assert.equal(JSON.parse(Buffer.from(payload,'base64url')).vp.holder,clientId)
 foreign=true
 await assert.rejects(client.requestStudyAccess(studyId),/registered_research_study_grant_invalid/u)
 await assert.rejects(client.requestStudyAccess('other?study=foreign'),/research_study_resource_id_invalid/u)
 assert.equal(packets.length,2)
 const party=`PractitionerRole/${safe.resourceUuid}`
 await client.readStudyInvitationCommunications(party)
 await client.readInvitedResearchStudies(party)
 await assert.rejects(client.readInvitedResearchStudies('PractitionerRole/*'),/registered_research_party_invalid/u)
 assert.deepEqual(directoryRequests.map(request=>request.path.split('/').slice(-4).join('/')), [
  'individual/org.hl7.fhir.r4/Communication/_search','organization/org.hl7.fhir.r5/ResearchStudy/_search',
 ])
 assert.deepEqual(directoryRequests[0].body.entry[0].resource.parameter,[
  {name:CommunicationClaim.Category,valueString:CommunicationCategoryCodes.Notification.attributeValue},
  {name:CommunicationClaim.Topic,valueString:`${FhirCodeSystems.ActReason}|${HealthcareConsentPurposes.Research}`},
  {name:'recipient',valueString:party},
 ])
 assert.deepEqual(directoryRequests[1].body.data[0].resource.meta.claims,{'ResearchStudy.party':[party]})
})
