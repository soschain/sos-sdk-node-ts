import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {CryptographyService,encodePostQuantumDetachedProofQr,decodePostQuantumDetachedProofQr,decodePostQuantumDetachedProofUri,type MldsaPublicJwk} from 'antifraud-data-utils-ts/cryptography'
import {ClinicalDocumentHealthCardError,createClinicalDocumentHealthCardIssuer,createDemoClinicalDocumentHealthCardIssuer,verifyClinicalDocumentHealthCard,type AuthorizedClinicalDocument,type AuthorizedClinicalDocumentPort,type ClinicalDocumentHealthCardCommand,type ClinicalDocumentIssuer,type IssuedClinicalDocumentHealthCard,type OrganizationClinicalDocumentKeyVault,type VerifiedClinicalDocumentHealthCard} from './clinical-document-health-card.js'
import type {TransactionalVaultRepository} from './transactional-vault.js'
import type {ServerProfileSealer} from './profile-sealer.js'
import {clinicalDocumentCompactInput} from './clinical-document-credential-input.js'

const purpose='clinical-document-pq-proof',algorithm='ML-DSA-65',maxBytes=128*1024
type Json=Record<string,unknown>
function record(value:unknown):value is Json{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
function text(value:unknown):value is string{return typeof value==='string'&&!!value&&value.trim()===value}
function fail(code:string):never{throw new ClinicalDocumentHealthCardError(`clinical_document_pq_${code}`)}
function sha(value:string):string{return createHash('sha256').update(value,'utf8').digest('base64url')}
function snapshot(value:unknown):string{
 if(Array.isArray(value))return`[${value.map(snapshot).join(',')}]`
 if(record(value))return`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${snapshot(value[k])}`).join(',')}}`
 return JSON.stringify(value)??'null'
}
function crypto():CryptographyService{return new CryptographyService({getRandomBytes:async n=>randomBytes(n),digestString:async(value,alg)=>createHash(alg.replaceAll('-','').toLowerCase()).update(value,'utf8').digest('hex'),randomUUID})}
function thumbprint(value:MldsaPublicJwk):string{return sha(JSON.stringify({alg:value.alg,kty:value.kty,pub:value.pub}))}
type PublicProofKey=Readonly<MldsaPublicJwk&{kid:string;alg:'ML-DSA-65';use:'sig'}>
type Row={id:string;organizationReference:string;purpose:string;algorithm:string;publicJwk:PublicProofKey;sealed:string}
export interface OrganizationClinicalDocumentProofKeyVault{readonly purpose:'clinical-document-pq-proof'}
type Custody={lookup:(org:string)=>Promise<Row|undefined>;ensure:(org:string)=>Promise<Row>;sign:(row:Row,bytes:Uint8Array)=>Promise<string>}
const vaults=new WeakMap<OrganizationClinicalDocumentProofKeyVault,Custody>()
const rowId=(org:string)=>sha(`${purpose}:${org}`)
const aad=(row:Row)=>snapshot({organizationReference:row.organizationReference,purpose,alg:algorithm,kid:row.publicJwk.kid})
function base64(value:unknown,length?:number):Buffer{
 if(!text(value)||!/^[A-Za-z0-9_-]+$/u.test(value))fail('key_invalid')
 const bytes=Buffer.from(value,'base64url');if(bytes.toString('base64url')!==value||length!==undefined&&bytes.length!==length)fail('key_invalid');return bytes
}
function publicKey(value:unknown):PublicProofKey{
 if(!record(value)||Object.keys(value).some(k=>!['kty','alg','pub','kid','use'].includes(k))||value.kty!=='AKP'||value.alg!==algorithm||value.use!=='sig'||!text(value.pub)||!text(value.kid))fail('key_invalid')
 base64(value.pub,1952)
 const key:PublicProofKey={kty:'AKP',alg:algorithm,pub:value.pub,kid:value.kid,use:'sig'}
 if(thumbprint(key)!==key.kid)fail('key_invalid')
 return Object.freeze(key)
}
/** Opaque organization clinical-proof custody; neither seeds nor expanded private keys leave the fixed-purpose operation. */
export function createOrganizationClinicalDocumentProofKeyVault(options:Readonly<{vault:TransactionalVaultRepository;sealer:ServerProfileSealer;collection:string}>):OrganizationClinicalDocumentProofKeyVault{
 if(!text(options.collection))fail('key_invalid')
 const{vault,sealer,collection}=options,token=Object.freeze({purpose})
 function checked(value:unknown,org:string):Row{
  if(!record(value)||value.id!==rowId(org)||value.organizationReference!==org||value.purpose!==purpose||value.algorithm!==algorithm||!text(value.sealed))fail('key_invalid')
  return{id:rowId(org),organizationReference:org,purpose,algorithm,publicJwk:publicKey(value.publicJwk),sealed:value.sealed}
 }
 vaults.set(token,{
  async lookup(org){const stored=await vault.get(collection,rowId(org));return stored?checked(stored,org):undefined},
  async ensure(org){return vault.runTransaction(async tx=>{
   const stored=await tx.get(collection,rowId(org));if(stored)return checked(stored,org)
   const seed=randomBytes(32);let pair:Awaited<ReturnType<CryptographyService['generateKeyPairMlDsa']>>|undefined
   try{
    pair=await crypto().generateKeyPairMlDsa(seed,algorithm)
    const publicJwk=publicKey({...pair.publicJWKey,use:'sig'}),row:Row={id:rowId(org),organizationReference:org,purpose,algorithm,publicJwk,sealed:''}
    row.sealed=await sealer.seal(seed.toString('base64url'),aad(row));await tx.put(collection,row);return row
   }finally{seed.fill(0);pair?.secretKeyBytes.fill(0)}
  })},
  async sign(row,bytes){
   const clear=await sealer.unseal(row.sealed,aad(row));const seed=base64(clear,32);let pair:Awaited<ReturnType<CryptographyService['generateKeyPairMlDsa']>>|undefined
   try{
    const engine=crypto();pair=await engine.generateKeyPairMlDsa(seed,algorithm)
    if(pair.publicJWKey.pub!==row.publicJwk.pub||pair.publicJWKey.kid!==row.publicJwk.kid)fail('key_invalid')
    return Buffer.from(await engine.signBytes(bytes,pair.secretKeyBytes,algorithm)).toString('base64url')
   }finally{seed.fill(0);pair?.secretKeyBytes.fill(0)}
  },
 })
 return token
}
export type ClinicalDocumentCompanion=Readonly<{alg:'ML-DSA-65';kid:string;detachedJws:string;pqcValues:readonly string[]}>
export type IssuedClinicalDocumentWithCompanion=IssuedClinicalDocumentHealthCard&Readonly<{companion:ClinicalDocumentCompanion}>
export interface ClinicalDocumentCompanionIssuer{
 issue(command:ClinicalDocumentHealthCardCommand):Promise<IssuedClinicalDocumentWithCompanion>
 publicJwks(issuer:string):Promise<Readonly<{keys:readonly Readonly<Record<string,unknown>>[]}>>
 publicProofJwks(issuer:string):Promise<Readonly<{keys:readonly PublicProofKey[]}>>
}
/** Standard ES256 SHC plus an explicitly separate signature-covered SOS clinical-proof profile over its exact compact bytes. */
type OrganizationClinicalDocumentCompanionOptions=Readonly<{documents:AuthorizedClinicalDocumentPort;keys:OrganizationClinicalDocumentKeyVault;proofKeys:OrganizationClinicalDocumentProofKeyVault;issuers:readonly ClinicalDocumentIssuer[];nowSeconds?:()=>number}>
export function createClinicalDocumentCompanionIssuer(options:OrganizationClinicalDocumentCompanionOptions):ClinicalDocumentCompanionIssuer{
 return clinicalDocumentCompanionIssuer(options)
}
/** Demo-only persistent signer; clinical ownership and current author checks are
 * unchanged. Hosts keep this realm out of network-mode trust configuration. */
export function createDemoClinicalDocumentCompanionIssuer(options:Omit<OrganizationClinicalDocumentCompanionOptions,'issuers'>&Readonly<{signingRealm:ClinicalDocumentIssuer}>):ClinicalDocumentCompanionIssuer{
 return clinicalDocumentCompanionIssuer({...options,issuers:[options.signingRealm]},options.signingRealm)
}
function clinicalDocumentCompanionIssuer(options:OrganizationClinicalDocumentCompanionOptions,signingRealm?:ClinicalDocumentIssuer):ClinicalDocumentCompanionIssuer{
 const proof=vaults.get(options.proofKeys);if(!proof)fail('key_invalid')
 const issuers=structuredClone(options.issuers),realm=signingRealm?structuredClone(signingRealm):undefined
 const standardFor=(documents:AuthorizedClinicalDocumentPort)=>realm?createDemoClinicalDocumentHealthCardIssuer({...options,documents,signingRealm:realm}):createClinicalDocumentHealthCardIssuer({...options,documents,issuers})
 const standard=standardFor(options.documents)
 return Object.freeze({
  async issue(command:ClinicalDocumentHealthCardCommand):Promise<IssuedClinicalDocumentWithCompanion>{
   // Each issue owns its snapshot; concurrent calls cannot replace one another's authority state.
   const captured:{source?:AuthorizedClinicalDocument}={}
   const issuer=standardFor({async readAuthorizedDocument(input){const source=await options.documents.readAuthorizedDocument(input);captured.source=source?structuredClone(source):undefined;return source}})
   const card=await issuer.issue(command),source=captured.source
   if(!source)throw new ClinicalDocumentHealthCardError('clinical_document_shc_authorization_denied')
   const config=issuers.find(v=>(realm||v.organizationReference===source.organizationReference)&&v.issuer===card.issuer)
   if(!config)fail('key_invalid')
   const recheck=async()=>{const current=await options.documents.readAuthorizedDocument({documentReference:command.documentReference});if(snapshot(current)!==snapshot(source))throw new ClinicalDocumentHealthCardError('clinical_document_shc_authorization_denied')}
   await recheck();const row=await proof.ensure(config.organizationReference);await recheck()
   const header={alg:algorithm,kid:row.publicJwk.kid,b64:false,crit:['b64'],purpose,iss:card.issuer,organizationReference:config.organizationReference}
   const encoded=Buffer.from(JSON.stringify(header),'utf8').toString('base64url'),input=Buffer.concat([Buffer.from(encoded+'.','ascii'),Buffer.from(card.compactJws,'utf8')])
   const detachedJws=`${encoded}..${await proof.sign(row,input)}`
   await recheck()
   return Object.freeze({...card,companion:Object.freeze({alg:algorithm,kid:row.publicJwk.kid,detachedJws,pqcValues:encodePostQuantumDetachedProofQr(detachedJws)})})
  },
  publicJwks:(issuer:string)=>standard.publicJwks(issuer),
  async publicProofJwks(issuer:string):Promise<Readonly<{keys:readonly PublicProofKey[]}>>{const config=issuers.find(v=>v.issuer===issuer);if(!config)fail('key_invalid');const row=await proof.lookup(config.organizationReference);return Object.freeze({keys:Object.freeze(row?[row.publicJwk]:[])})},
 })
}
function proofInput(value:string|readonly string[]):string{
 if(Array.isArray(value)){if(!value.length||value.length>100||value.some(v=>typeof v!=='string')||value.reduce((n,v)=>n+v.length,0)>maxBytes)fail('credential_invalid');try{return decodePostQuantumDetachedProofQr(value)}catch{fail('credential_invalid')}}
 if(typeof value!=='string'||Buffer.byteLength(value)>maxBytes)fail('credential_invalid')
 if(value.startsWith('pqc:/')){try{return /^pqc:\/\d/u.test(value)?decodePostQuantumDetachedProofQr([value]):decodePostQuantumDetachedProofUri(value)}catch{fail('credential_invalid')}}
 return value
}
/** Verifies BOTH signatures. Public AKP keys may be projected beside EC keys at the configured issuer's existing JWKS endpoint. */
export async function verifyClinicalDocumentCompanion(options:Readonly<{credential:string|readonly string[];companion:string|readonly string[];trustedIssuers:readonly ClinicalDocumentIssuer[];fetchImpl?:typeof fetch;nowSeconds?:number}>):Promise<VerifiedClinicalDocumentHealthCard&Readonly<{companion:Readonly<{alg:'ML-DSA-65';kid:string}>}>>{
 const credential=clinicalDocumentCompactInput(options.credential,()=>{throw new ClinicalDocumentHealthCardError('clinical_document_shc_credential_invalid')})
 const verified=await verifyClinicalDocumentHealthCard({...options,credential}),detached=proofInput(options.companion),parts=detached.split('..')
 if(parts.length!==2)fail('credential_invalid')
 let header:unknown
 try{header=JSON.parse(base64(parts[0]).toString('utf8'))}catch{fail('credential_invalid')}
 if(!record(header)||header.alg!==algorithm||header.b64!==false||!Array.isArray(header.crit)||header.crit.length!==1||header.crit[0]!=='b64'||!text(header.kid)||header.purpose!==purpose||Object.keys(header).some(k=>!['alg','kid','b64','crit','purpose','iss','organizationReference'].includes(k)))fail('credential_invalid')
 if(header.iss!==verified.issuer||header.organizationReference!==verified.organizationReference)fail('key_invalid')
 try{base64(parts[1],3309)}catch{fail('signature_invalid')}
 const response=await(options.fetchImpl??fetch)(`${verified.issuer}/.well-known/jwks.json`,{redirect:'error',signal:AbortSignal.timeout(15000),headers:{accept:'application/json'}})
 if(!response.ok||Number(response.headers.get('content-length'))>maxBytes||!response.body)fail('key_invalid')
 const reader=response.body.getReader(),chunks:Uint8Array[]=[];let length=0
 try{while(true){const part=await reader.read();if(part.done)break;length+=part.value.length;if(length>maxBytes){await reader.cancel();fail('key_invalid')}chunks.push(part.value)}}finally{reader.releaseLock()}
 let body:unknown;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{fail('key_invalid')}
 if(!record(body)||!Array.isArray(body.keys)||body.keys.length>100)fail('key_invalid')
 const expectedKid=header.kid,matching=body.keys.filter(v=>record(v)&&v.kid===expectedKid);if(matching.length!==1)fail('key_invalid')
 const key=publicKey(matching[0]);let valid=false
 try{valid=await crypto().verifyDetachedJws(Buffer.from(credential,'utf8'),detached,key)}catch{fail('signature_invalid')}
 if(!valid)fail('signature_invalid')
 return Object.freeze({...verified,companion:Object.freeze({alg:algorithm,kid:key.kid})})
}
