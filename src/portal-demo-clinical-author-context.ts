import {canonicalClinicalSubjectReference} from 'fhir-data-utils-ts'
import {FhirIpsCreatorKinds,type ClinicalCreatorBinding} from 'sos-data-utils-ts/clinical-creator-contract'
import {normalizeClinicalCreatorBinding} from 'sos-sdk-core-ts/clinical-creator'
import type {PortalDemoCareParticipant} from './portal-demo-exchange.js'

/** Short-lived context from an authenticated peer service, not a public licence proof. */
export type PortalDemoClinicalAuthorContext=Readonly<{
 authorizationRevision:string;subjectReference:string;generationId:string;clinicalCreatorBinding:ClinicalCreatorBinding
 installationRegistrationId:string;installationGeneration:number;expiresAt:number
}>
export type PortalDemoClinicalAuthorContextBinding=Readonly<{
 participant:PortalDemoCareParticipant;subjectIdentifier:string;generationId:string;cardExpiresAt:number;now?:()=>number
}>
function fail():never{throw new Error('care_document_authorization_context_forbidden')}
function object(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
function text(value:unknown):value is string{return typeof value==='string'&&value.length>0&&value.length<=2048&&value.trim()===value}
function strings(value:unknown):readonly string[]|undefined{if(value===undefined)return undefined;if(!Array.isArray(value)||value.length>100||!value.every(text))fail();return [...value]}
function creator(value:unknown):ClinicalCreatorBinding{
 if(!object(value)||Object.keys(value).some(key=>!['kind','actorIdentifier','authorIdentifier','ownerIdentifier','role','actorDids','verifiedContactIdentifiers','dcrClientIds','keyIds'].includes(key))||value.kind!==FhirIpsCreatorKinds.Professional||!text(value.actorIdentifier)||!text(value.authorIdentifier)||!text(value.ownerIdentifier)||!text(value.role))fail()
 const actorDids=strings(value.actorDids),verifiedContactIdentifiers=strings(value.verifiedContactIdentifiers),dcrClientIds=strings(value.dcrClientIds),keyIds=strings(value.keyIds)
 try{return normalizeClinicalCreatorBinding({kind:value.kind,actorIdentifier:value.actorIdentifier,authorIdentifier:value.authorIdentifier,ownerIdentifier:value.ownerIdentifier,role:value.role,...(actorDids?{actorDids}:{}),...(verifiedContactIdentifiers?{verifiedContactIdentifiers}:{}),...(dcrClientIds?{dcrClientIds}:{}),...(keyIds?{keyIds}:{})})}catch{return fail()}
}
/**
 * The host supplies the current Personal card/generation/expiry and authenticated
 * Pro participant. Pro admission/revision is rechecked separately before/after
 * peer transport; this parser neither reads Pro storage nor grants authority.
 * The 30-second lease must never become the persisted document's card lifetime.
 */
export function parsePortalDemoClinicalAuthorContext(value:unknown,expected:PortalDemoClinicalAuthorContextBinding):PortalDemoClinicalAuthorContext{
 if(!object(value)||Object.keys(value).some(key=>!['authorizationRevision','subjectReference','generationId','clinicalCreatorBinding','installationRegistrationId','installationGeneration','expiresAt'].includes(key))||typeof value.authorizationRevision!=='string'||!/^[a-f0-9]{64}$/u.test(value.authorizationRevision)||!text(value.subjectReference)||!text(value.generationId)||!text(value.installationRegistrationId)||typeof value.installationGeneration!=='number'||!Number.isSafeInteger(value.installationGeneration)||value.installationGeneration<1||typeof value.expiresAt!=='number'||!Number.isSafeInteger(value.expiresAt))fail()
 const now=(expected.now??Date.now)(),participant=expected.participant
 if(!Number.isFinite(now)||!Number.isFinite(expected.cardExpiresAt)||typeof participant.profileExpiresAt!=='number'||!Number.isFinite(participant.profileExpiresAt)||value.expiresAt<=now||value.expiresAt>now+30_000||value.expiresAt>participant.profileExpiresAt||value.expiresAt>expected.cardExpiresAt||!text(participant.profileId)||!text(expected.subjectIdentifier)||!text(expected.generationId)||value.generationId!==expected.generationId)fail()
 try{if(canonicalClinicalSubjectReference(value.subjectReference)!==canonicalClinicalSubjectReference(expected.subjectIdentifier))fail()}catch{return fail()}
 const binding=creator(value.clinicalCreatorBinding)
 if(binding.actorIdentifier!==participant.actorIdentifier||binding.ownerIdentifier!==participant.organizationReference||!text(participant.roleClaim)||value.installationRegistrationId!==participant.installationRegistrationId||value.installationGeneration!==participant.installationGeneration)fail()
 try{if(normalizeClinicalCreatorBinding({...binding,role:participant.roleClaim}).role!==binding.role)fail()}catch{return fail()}
 return Object.freeze(structuredClone({authorizationRevision:value.authorizationRevision,subjectReference:value.subjectReference,generationId:value.generationId,clinicalCreatorBinding:binding,installationRegistrationId:value.installationRegistrationId,installationGeneration:value.installationGeneration,expiresAt:value.expiresAt}))
}
