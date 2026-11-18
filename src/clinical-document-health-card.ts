import {createHash,createPrivateKey,createPublicKey,generateKeyPairSync,sign,verify,type JsonWebKey} from 'node:crypto'
import {inflateRawSync} from 'node:zlib'
import {validateR4DocumentBundleStructure} from 'fhir-data-utils-ts'
import {prepareSmartHealthCard,assembleSmartHealthCardJws} from 'sos-data-utils-ts'
import {encodeSoschainSmartHealthCardQr} from 'sos-data-utils-ts/clinical-document-shc'
import {clinicalDocumentCompactInput} from './clinical-document-credential-input.js'
import {FhirIpsCreatorKinds,type ClinicalCreatorBinding} from 'sos-data-utils-ts/clinical-creator-contract'
import {HealthcareActorRoles,getHealthcareRoleByClaim} from 'sos-data-utils-ts/healthcare-roles'
import {normalizeClinicalCreatorBinding} from 'sos-sdk-core-ts/clinical-creator'
import type {ServerProfileSealer} from './profile-sealer.js'
import type {TransactionalVaultRepository} from './transactional-vault.js'

const purpose='clinical-document-shc',maxInput=128*1024,maxInflated=1024*1024
type RecordValue=Record<string,unknown>
export class ClinicalDocumentHealthCardError extends Error {
  constructor(readonly code:string){super(code);this.name='ClinicalDocumentHealthCardError'}
}
function fail(suffix:string):never{throw new ClinicalDocumentHealthCardError(`clinical_document_shc_${suffix}`)}
function record(value:unknown):value is RecordValue{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
function text(value:unknown):value is string{return typeof value==='string'&&value.length>0&&value.trim()===value}
function hash(value:string):string{return createHash('sha256').update(value).digest('base64url')}
function canonical(value:unknown):string {
  if(Array.isArray(value))return `[${value.map(canonical).join(',')}]`
  if(record(value))return `{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
  return JSON.stringify(value)??'null'
}
function thumbprint(key:JsonWebKey):string{return hash(JSON.stringify({crv:key.crv,kty:key.kty,x:key.x,y:key.y}))}
function validIssuer(value:string):boolean {
  try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash&&!value.endsWith('/')&&u.href===value}catch{return false}
}
export type ClinicalDocumentIssuer=Readonly<{organizationReference:string;issuer:string}>
function issuerList(values:readonly ClinicalDocumentIssuer[]):readonly ClinicalDocumentIssuer[]{
  if(!Array.isArray(values))fail('issuer_untrusted')
  const result=values.map(v=>{
    if(!v||!text(v.organizationReference)||!validIssuer(v.issuer))fail('issuer_untrusted')
    return Object.freeze({organizationReference:v.organizationReference,issuer:v.issuer})
  })
  if(new Set(result.map(v=>v.issuer)).size!==result.length||new Set(result.map(v=>v.organizationReference)).size!==result.length)fail('issuer_untrusted')
  return Object.freeze(result)
}
type PublicKey=Readonly<{kty:'EC';crv:'P-256';x:string;y:string;kid:string;alg:'ES256';use:'sig'}>
type KeyRow={id:string;organizationReference:string;purpose:string;publicJwk:PublicKey;sealed:string}
/** Opaque custody capability. Only this module can use it, and only for its fixed SHC signing purpose. */
export interface OrganizationClinicalDocumentKeyVault {readonly purpose:'clinical-document-shc'}
type KeyCustody={lookup:(organization:string)=>Promise<KeyRow|undefined>;load:(organization:string)=>Promise<KeyRow>;sign:(row:KeyRow,bytes:Uint8Array)=>Promise<string>}
const custody=new WeakMap<OrganizationClinicalDocumentKeyVault,KeyCustody>()
function aad(row:KeyRow):string{return canonical({organizationReference:row.organizationReference,purpose,kid:row.publicJwk.kid})}

/** Host supplies its established vault/sealer; issuer keys are independent random P-256 keys, never profile/communication seed derivatives. */
export function createOrganizationClinicalDocumentKeyVault(options:Readonly<{vault:TransactionalVaultRepository;sealer:ServerProfileSealer;collection:string}>):OrganizationClinicalDocumentKeyVault {
  if(!text(options.collection))fail('key_invalid')
  const {vault,sealer,collection}=options,token=Object.freeze({purpose})
  function checked(value:unknown,organization:string):KeyRow {
    if(!record(value)||value.organizationReference!==organization||value.purpose!==purpose||!text(value.sealed)||!record(value.publicJwk))fail('key_invalid')
    const publicJwk=validateKey(value.publicJwk)
    if(value.id!==hash(`${purpose}:${organization}`))fail('key_invalid')
    return{id:value.id,organizationReference:organization,purpose,publicJwk,sealed:value.sealed}
  }
  custody.set(token,{
    async lookup(organization){
      const stored=await vault.get(collection,hash(`${purpose}:${organization}`))
      return stored?checked(stored,organization):undefined
    },
    async load(organization){
      return vault.runTransaction(async tx=>{
        const id=hash(`${purpose}:${organization}`),stored=await tx.get(collection,id)
        if(stored)return checked(stored,organization)
        const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),privateJwk=pair.privateKey.export({format:'jwk'}),jwk=pair.publicKey.export({format:'jwk'})
        const publicJwk:PublicKey={kty:'EC',crv:'P-256',x:jwk.x!,y:jwk.y!,kid:thumbprint(jwk),alg:'ES256',use:'sig'}
        const row:KeyRow={id,organizationReference:organization,purpose,publicJwk,sealed:''}
        row.sealed=await sealer.seal(JSON.stringify(privateJwk),aad(row))
        await tx.put(collection,row)
        return row
      })
    },
    async sign(row,bytes){
      const clear=await sealer.unseal(row.sealed,aad(row))
      let key:JsonWebKey
      try{key=JSON.parse(clear);if(!record(key)||!text(key.d)||key.crv!=='P-256'||key.kty!=='EC'||thumbprint(key)!==row.publicJwk.kid)fail('key_invalid')}catch(error){if(error instanceof ClinicalDocumentHealthCardError)throw error;fail('key_invalid')}
      return sign('sha256',bytes,{key:createPrivateKey({key,format:'jwk'}),dsaEncoding:'ieee-p1363'}).toString('base64url')
    },
  })
  return token
}

/** A server-owned port must read the actual stored revision and current authenticated clinical permission/licence. It must never project authority from a browser role. */
export type AuthorizedClinicalDocument=Readonly<{
  documentReference:string;revision:string;authorizationRevision:string;organizationReference:string;subjectReference:string
  licensedClinicalAuthor:boolean;permittedResourceTypes:readonly string[];fhirVersion:string;clinicalCreatorBinding:ClinicalCreatorBinding;bundle:RecordValue
}>
export interface AuthorizedClinicalDocumentPort {readAuthorizedDocument(input:Readonly<{documentReference:string}>):Promise<AuthorizedClinicalDocument|undefined>}
export type ClinicalDocumentHealthCardCommand=Readonly<{operationId:string;documentReference:string;expectedRevision:string}>
export type IssuedClinicalDocumentHealthCard=Readonly<{issuer:string;documentReference:string;documentRevision:string;compactJws:string;qrValues:readonly string[]}>
export interface ClinicalDocumentHealthCardIssuer {
  issue(command:ClinicalDocumentHealthCardCommand):Promise<IssuedClinicalDocumentHealthCard>
  publicJwks(issuer:string):Promise<Readonly<{keys:readonly PublicKey[]}>>
}
function authorized(value:AuthorizedClinicalDocument|undefined,reference:string,revision:string):AuthorizedClinicalDocument {
  if(!value||value.documentReference!==reference||!text(value.revision))fail('authorization_denied')
  if(value.revision!==revision)fail('document_changed')
  if(value.licensedClinicalAuthor!==true||!text(value.authorizationRevision)||!text(value.organizationReference)||!text(value.subjectReference)||value.fhirVersion!=='4.0.1')fail('authorization_denied')
  let binding:ClinicalCreatorBinding
  try{binding=normalizeClinicalCreatorBinding(value.clinicalCreatorBinding)}catch{fail('authorization_denied')}
  if(binding.kind!==FhirIpsCreatorKinds.Professional||binding.ownerIdentifier!==value.organizationReference||value.clinicalCreatorBinding.role===HealthcareActorRoles.Controller||binding.role===HealthcareActorRoles.Controller||!getHealthcareRoleByClaim(binding.role))fail('authorization_denied')
  const bundle=value.bundle
  if(!validateR4DocumentBundleStructure(bundle).ok||!Array.isArray(bundle.entry)||!Array.isArray(value.permittedResourceTypes))fail('authorization_denied')
  const entries=bundle.entry
  const first=entries[0],composition=record(first)&&record(first.resource)?first.resource:undefined
  if(!composition||composition.status!=='final'||!record(composition.subject)||composition.subject.reference!==value.subjectReference||!Array.isArray(composition.author)||!composition.author.length||!composition.author.every(a=>record(a)&&(a.reference===value.organizationReference||a.reference===binding.authorIdentifier)))fail('authorization_denied')
  // The authenticated assignment may itself author a document; attestation is optional in FHIR.
  if(composition.attester!==undefined&&(!Array.isArray(composition.attester)||!composition.attester.every(a=>record(a)&&a.mode==='professional'&&record(a.party)&&a.party.reference===binding.authorIdentifier)))fail('authorization_denied')
  for(const entry of entries){
    if(!record(entry)||!record(entry.resource)||!text(entry.resource.resourceType))fail('authorization_denied')
    const resource=entry.resource
    if(!text(resource.resourceType))fail('authorization_denied')
    const type=resource.resourceType
    if(!['Composition','Patient','Organization','Practitioner','PractitionerRole','RelatedPerson'].includes(type)&&!value.permittedResourceTypes.includes(type))fail('authorization_denied')
    for(const field of ['subject','patient'])if(resource[field]!==undefined&&(!record(resource[field])||resource[field].reference!==value.subjectReference))fail('authorization_denied')
    if(type==='PractitionerRole'&&entry.fullUrl===binding.authorIdentifier&&(!record(resource.practitioner)||resource.practitioner.reference!==binding.actorIdentifier||!record(resource.organization)||resource.organization.reference!==value.organizationReference))fail('authorization_denied')
  }
  return structuredClone(value)
}
/** Issues only a caller-independent authorized stored document. Standard minimization operates on a copy; native clinical source remains intact. */
export function createClinicalDocumentHealthCardIssuer(options:Readonly<{documents:AuthorizedClinicalDocumentPort;keys:OrganizationClinicalDocumentKeyVault;issuers:readonly ClinicalDocumentIssuer[];nowSeconds?:()=>number}>):ClinicalDocumentHealthCardIssuer {
  const issuers=issuerList(options.issuers),keys=custody.get(options.keys),clock=options.nowSeconds??(()=>Math.floor(Date.now()/1000))
  if(!keys)fail('key_invalid')
  return Object.freeze({
    async issue(command:ClinicalDocumentHealthCardCommand){
      if(!record(command)||Object.keys(command).some(k=>!['operationId','documentReference','expectedRevision'].includes(k))||!text(command.operationId)||!text(command.documentReference)||!text(command.expectedRevision))fail('command_invalid')
      const read=async()=>authorized(await options.documents.readAuthorizedDocument({documentReference:command.documentReference}),command.documentReference,command.expectedRevision)
      const source=await read(),config=issuers.find(i=>i.organizationReference===source.organizationReference)
      if(!config)fail('issuer_untrusted')
      const row=await keys.load(source.organizationReference)
      if(canonical(await read())!==canonical(source))fail('authorization_denied')
      const prepared=prepareSmartHealthCard({issuer:config.issuer,notBefore:clock(),kid:row.publicJwk.kid,fhirVersion:source.fhirVersion,fhirBundle:source.bundle})
      const compactJws=assembleSmartHealthCardJws(prepared,await keys.sign(row,prepared.signingBytes))
      if(canonical(await read())!==canonical(source))fail('authorization_denied')
      return Object.freeze({issuer:config.issuer,documentReference:source.documentReference,documentRevision:source.revision,compactJws,qrValues:encodeSoschainSmartHealthCardQr(compactJws)})
    },
    async publicJwks(issuer:string){
      const config=issuers.find(i=>i.issuer===issuer);if(!config)fail('issuer_untrusted')
      const row=await keys.lookup(config.organizationReference)
      return Object.freeze({keys:Object.freeze(row?[Object.freeze({...row.publicJwk})]:[])})
    },
  })
}

function base64(value:string):Buffer {
  if(!/^[A-Za-z0-9_-]+$/u.test(value))fail('credential_invalid')
  const bytes=Buffer.from(value,'base64url');if(bytes.toString('base64url')!==value)fail('credential_invalid');return bytes
}
function validateKey(value:RecordValue):PublicKey {
  if(Object.keys(value).some(k=>!['kty','crv','x','y','kid','alg','use','crlVersion','x5c'].includes(k))||value.kty!=='EC'||value.crv!=='P-256'||value.alg!=='ES256'||value.use!=='sig'||!text(value.x)||!text(value.y)||!text(value.kid))fail('key_invalid')
  // Public specification metadata is compatible, but is not certificate-chain or revocation evidence.
  if(value.crlVersion!==undefined&&(typeof value.crlVersion!=='number'||!Number.isSafeInteger(value.crlVersion)||value.crlVersion<0))fail('key_invalid')
  if(value.x5c!==undefined&&(!Array.isArray(value.x5c)||!value.x5c.length||value.x5c.some(v=>!text(v)||!/^[A-Za-z0-9+/]+={0,2}$/u.test(v))))fail('key_invalid')
  try{if(base64(value.x).length!==32||base64(value.y).length!==32||thumbprint(value)!==value.kid)fail('key_invalid');createPublicKey({key:value,format:'jwk'})}catch{fail('key_invalid')}
  return{kty:'EC',crv:'P-256',x:value.x,y:value.y,kid:value.kid,alg:'ES256',use:'sig'}
}
function parseCredential(input:string|readonly string[]):Readonly<{parts:readonly string[];header:RecordValue;payload:RecordValue;signature:Buffer}>{
  const compact=clinicalDocumentCompactInput(input,()=>fail('credential_invalid'))
  if(Buffer.byteLength(compact)>maxInput)fail('credential_invalid')
  const parts=compact.split('.');if(parts.length!==3)fail('credential_invalid')
  let header:RecordValue,payload:RecordValue,signature:Buffer
  try{
    const h:unknown=JSON.parse(base64(parts[0]).toString('utf8'));if(!record(h)||h.alg!=='ES256'||h.zip!=='DEF'||!text(h.kid)||Object.keys(h).some(k=>!['alg','zip','kid'].includes(k)))fail('credential_invalid');header=h
    signature=base64(parts[2]);if(signature.length!==64)fail('credential_invalid')
    const p:unknown=JSON.parse(inflateRawSync(base64(parts[1]),{maxOutputLength:maxInflated}).toString('utf8'));if(!record(p))fail('credential_invalid');payload=p
  }catch{fail('credential_invalid')}
  return{parts,header,payload,signature}
}
export type UnverifiedClinicalDocumentIssuer=Readonly<{issuer:string;signatureVerified:false}>
/** Bounded locator only: no clinical payload, signature verification, authority or network discovery. The host must independently select a configured known issuer before verification. */
export function inspectClinicalDocumentHealthCardIssuer(input:string|readonly string[]):UnverifiedClinicalDocumentIssuer{
  const{payload}=parseCredential(input)
  if(!text(payload.iss)||!validIssuer(payload.iss))fail('credential_invalid')
  return Object.freeze({issuer:payload.iss,signatureVerified:false})
}
export type VerifiedClinicalDocumentHealthCard=Readonly<{status:'verified';issuer:string;organizationReference:string;payload:Readonly<RecordValue>}>
/** Trusted issuer configuration, not credential content, determines the sole HTTPS JWKS endpoint. No redirects or arbitrary issuer discovery. */
export async function verifyClinicalDocumentHealthCard(options:Readonly<{credential:string|readonly string[];trustedIssuers:readonly ClinicalDocumentIssuer[];fetchImpl?:typeof fetch;nowSeconds?:number}>):Promise<VerifiedClinicalDocumentHealthCard>{
  const issuers=issuerList(options.trustedIssuers),{parts,header,payload,signature}=parseCredential(options.credential)
  const clock=options.nowSeconds??Math.floor(Date.now()/1000)
  // JWT NumericDate permits fractional seconds; official SHC examples use them.
  if(!Number.isFinite(clock)||clock<0||typeof payload.nbf!=='number'||!Number.isFinite(payload.nbf)||payload.nbf<0||payload.nbf>clock||!text(payload.iss)||!record(payload.vc)||!Array.isArray(payload.vc.type)||!payload.vc.type.includes('https://smarthealth.cards#health-card')||!record(payload.vc.credentialSubject)||payload.vc.credentialSubject.fhirVersion!=='4.0.1'||!record(payload.vc.credentialSubject.fhirBundle))fail('credential_invalid')
  if(payload.exp!==undefined&&(typeof payload.exp!=='number'||!Number.isFinite(payload.exp)||payload.exp<0||payload.exp<=clock))fail('credential_invalid')
  const config=issuers.find(v=>v.issuer===payload.iss);if(!config)fail('issuer_untrusted')
  const response=await(options.fetchImpl??fetch)(`${config.issuer}/.well-known/jwks.json`,{redirect:'error',signal:AbortSignal.timeout(15000),headers:{accept:'application/json'}})
  if(!response.ok)fail('key_invalid')
  const declared=Number(response.headers.get('content-length'));if(declared>maxInput)fail('key_invalid')
  // Bound actual response bytes too; Content-Length is optional and cannot be trusted.
  if(!response.body)fail('key_invalid')
  const reader=response.body.getReader(),chunks:Uint8Array[]=[];let length=0
  try{while(true){const next=await reader.read();if(next.done)break;length+=next.value.length;if(length>maxInput){await reader.cancel();fail('key_invalid')}chunks.push(next.value)}}finally{reader.releaseLock()}
  let jwks:unknown;try{jwks=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{fail('key_invalid')}
  if(!record(jwks)||!Array.isArray(jwks.keys)||jwks.keys.length>100)fail('key_invalid')
  const matching=jwks.keys.filter(k=>record(k)&&k.kid===header.kid);if(matching.length!==1||!record(matching[0]))fail('key_invalid')
  const key=validateKey(matching[0]);let valid=false
  try{valid=verify('sha256',Buffer.from(`${parts[0]}.${parts[1]}`),{key:createPublicKey({key,format:'jwk'}),dsaEncoding:'ieee-p1363'},signature)}catch{fail('key_invalid')}
  if(!valid)fail('signature_invalid')
  return Object.freeze({status:'verified',issuer:config.issuer,organizationReference:config.organizationReference,payload:Object.freeze(payload)})
}
