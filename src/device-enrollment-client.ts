import {randomUUID} from 'node:crypto'
import {buildStableActorIdentifier,normalizeActorContact,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity'
import type {AppInfo,PollOptions,RouteContext} from 'sos-data-utils-ts/gateway-transport-contract'
import {RegisteredGatewayTransport,gatewayResponseEntries,type VerifiedGatewaySecureAdapter} from './registered-gateway-transport.js'
import type {ServerProfileKeyDescriptor} from './server-profile-custody-keys.js'
type Row=Record<string,unknown>
const record=(value:unknown):Row|undefined=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Row:undefined
const text=(value:unknown):string=>typeof value==='string'?value.trim():''
function required(value:unknown,error:string):string{const result=text(value);if(!result)throw new TypeError(error);return result}
function publicKeySnapshot(value:unknown,prefix:string):Row{
 const failure=()=>new TypeError(`${prefix}_device_public_keys_required`)
 if(!value||typeof value!=='object'||Array.isArray(value))throw failure()
 const descriptors=Object.getOwnPropertyDescriptors(value)
 if(Object.values(descriptors).some(descriptor=>!Object.hasOwn(descriptor,'value')))throw failure()
 const key:Row=Object.fromEntries(Object.entries(descriptors).map(([name,descriptor])=>[name,Array.isArray(descriptor.value)?[...descriptor.value]:descriptor.value]))
 if(['d','dBytes','privBytes','priv','privateKey','secretKeyBytes','k'].some(field=>field in key)
  ||!text(key.kid)||key.kid!==text(key.kid))throw failure()
 // Supported operational JWK metadata is scalar or a string array, such as key_ops.
 if(Object.values(key).some(item=>item!==undefined&&item!==null&&typeof item!=='string'&&typeof item!=='boolean'
  &&!(Array.isArray(item)&&item.every(part=>typeof part==='string'))))throw failure()
 return key
}
const keyMaterial=(key:Row)=>JSON.stringify(Object.keys(key).sort().map(name=>[name,key[name]]))
function devicePublicKeys(input:readonly Readonly<Row>[],descriptors:readonly ServerProfileKeyDescriptor[]|undefined,prefix:string):Row[]{
 const failure=()=>new TypeError(`${prefix}_device_public_keys_required`)
 if(!Array.isArray(input)||![2,3,5].includes(input.length))throw failure()
 const keys=input.map(value=>publicKeySnapshot(value,prefix))
 if(new Set(keys.map(key=>key.kid)).size!==keys.length)throw failure()
 const communicationSigning=keys.filter(key=>key.kty==='AKP'&&typeof key.pub==='string'&&!!key.pub)
 const communicationEncryption=keys.filter(key=>key.kty==='OKP'&&typeof key.x==='string'&&!!key.x)
 const profileSigning=keys.filter(key=>key.kty==='EC'&&key.crv==='P-384'&&key.alg==='ES384'
  &&typeof key.x==='string'&&!!key.x&&typeof key.y==='string'&&!!key.y&&(key.use===undefined||key.use==='sig'))
 if(communicationSigning.length!==1||communicationEncryption.length!==1||profileSigning.length!==keys.length-2)throw failure()
 if(!descriptors){if(keys.length===5)throw new Error(`${prefix}_key_purpose_binding_required`);return keys}
 const purposeFailure=()=>new Error(`${prefix}_key_purpose_binding_invalid`)
 if(!Array.isArray(descriptors)||descriptors.length<keys.length||descriptors.length>keys.length+1)throw purposeFailure()
 const required=new Map<string,readonly [string,string,string]>([
  ['comm-signing',['runtime','ML-DSA-44','sig']],['comm-encryption',['runtime','ML-KEM-768','enc']],
  ...(keys.length>=3?[['actor-signing',['profile','ES384','sig']] as const]:[]),
  ...(keys.length===5?[['openid-id-token-signing',['runtime','ES384','sig']] as const,['vp-token-signing',['runtime','ES384','sig']] as const]:[]),
 ])
 const seen=new Set<string>(),descriptorKids=new Set<string>()
 for(const descriptor of descriptors){
  if(!descriptor||typeof descriptor!=='object')throw purposeFailure()
  const key=publicKeySnapshot(descriptor.publicJwk,prefix)
  if(descriptorKids.has(descriptor.kid)||descriptor.kid!==key.kid
   ||(key.alg??key.crv)!==descriptor.alg||(key.use!==undefined&&key.use!==descriptor.use))throw purposeFailure()
  descriptorKids.add(descriptor.kid)
  if(descriptor.purpose==='document-at-rest'){
   if(descriptor.ownerScope!=='profile'||descriptor.alg!=='ML-KEM-768'||descriptor.use!=='enc'
    ||key.kty!=='OKP'||key.crv!=='ML-KEM-768'||typeof key.x!=='string'||keys.some(candidate=>candidate.kid===key.kid))throw purposeFailure()
   continue
  }
  const expected=required.get(descriptor.purpose),candidate=keys.find(item=>item.kid===descriptor.kid)
  if(!expected||seen.has(descriptor.purpose)||descriptor.ownerScope!==expected[0]||descriptor.alg!==expected[1]||descriptor.use!==expected[2]
   ||!candidate||keyMaterial(candidate)!==keyMaterial(key))throw purposeFailure()
  seen.add(descriptor.purpose)
 }
 if(seen.size!==required.size)throw purposeFailure()
 return keys
}

export type DeviceEnrollmentClientOptions=Readonly<{
 baseUrl:string;ctx:RouteContext;providerDid:string;gatewayDid:string;dcrResponseIssuer:string
 expectedProfile:Readonly<{actorDid:string;profileDid:string;contact:ActorContactInput}>
 bearerToken:string;transportProfile:'pre-dcr-didcomm-encrypted';secureTransportAdapter:VerifiedGatewaySecureAdapter
 appInfo?:AppInfo;requestTimeoutMs?:number;fetchImpl?:typeof fetch;allowLoopbackRedirectUris?:boolean
 /** Diagnostic compatibility for an existing domain caller; this never changes admission. */
 errorPrefix?:string
}>
export type DeviceEnrollmentInput=Readonly<{
 verifiedContact:ActorContactInput;activationCode:string;clientInstanceId:string
 publicJwks:readonly Readonly<Row>[];redirectUris:readonly string[]
 enrollmentKeyDescriptors?:readonly ServerProfileKeyDescriptor[]
}>
export class DeviceEnrollmentSubmitError extends Error{
 constructor(readonly status:number,readonly body:unknown,prefix='device_enrollment'){super(prefix+'_gateway_failed:'+status)}
}
/** Transport below domain admission. The host supplies reviewed receipt/licence bindings; GW verifies current authority. */
export class DeviceEnrollmentClient{
 private readonly options:DeviceEnrollmentClientOptions
 private readonly transport:RegisteredGatewayTransport
 private readonly prefix:string
 private readonly errorPrefix:string
 constructor(options:DeviceEnrollmentClientOptions){
  const prefix=options.errorPrefix??'device_enrollment'
  const url=new URL(options.baseUrl)
  if(url.username||url.password||url.search||url.hash||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname))))throw new TypeError(prefix+'_gateway_https_required')
  if(options.transportProfile!=='pre-dcr-didcomm-encrypted')throw new TypeError(prefix+'_explicit_pre_dcr_transport_required')
  const {tenantId,jurisdiction,sector}=options.ctx
  if(!/^[-a-zA-Z0-9]+$/u.test(tenantId)||tenantId==='host'||!/^\p{L}{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(jurisdiction)||!/^[-a-z0-9]+$/u.test(sector))throw new TypeError(prefix+'_route_invalid')
  const expected=options.expectedProfile
  if(!text(options.bearerToken)||![options.providerDid,options.gatewayDid,options.dcrResponseIssuer,expected?.actorDid,expected?.profileDid].every(value=>text(value).startsWith('did:'))||options.secureTransportAdapter?.gatewayDid!==options.gatewayDid)throw new TypeError(prefix+'_trusted_context_required')
  const contact:ActorContactInput={contactKind:expected.contact.contactKind,contact:normalizeActorContact(expected.contact)}
  this.options=Object.freeze({...options,ctx:Object.freeze({...options.ctx}),expectedProfile:Object.freeze({...expected,contact:Object.freeze(contact)}),secureTransportAdapter:Object.freeze({...options.secureTransportAdapter})})
  this.errorPrefix=prefix
  this.prefix='/'+encodeURIComponent(tenantId)+'/cds-'+encodeURIComponent(jurisdiction)+'/v1/'+encodeURIComponent(sector)
  this.transport=new RegisteredGatewayTransport({...this.options,baseUrl:url.href.replace(/\/+$/u,''),errorPrefix:prefix,submitError:(status,body)=>new DeviceEnrollmentSubmitError(status,body,prefix)})
 }
 private message(body:unknown,thread:string,type='application/didcomm-plain+json'):Row{
  return {jti:randomUUID(),thid:thread,iss:this.options.expectedProfile.actorDid,aud:this.options.providerDid,type,body}
 }
 async enroll(input:DeviceEnrollmentInput,pollOptions?:PollOptions){
  const prefix=this.errorPrefix
  if(buildStableActorIdentifier(input.verifiedContact)!==buildStableActorIdentifier(this.options.expectedProfile.contact))throw new Error(prefix+'_recipient_contact_binding_invalid')
  const activationCode=required(input.activationCode,prefix+'_activation_code_required'),clientInstanceId=required(input.clientInstanceId,prefix+'_installation_required')
  const publicJwks=devicePublicKeys(input.publicJwks,input.enrollmentKeyDescriptors,prefix)
  if(!Array.isArray(input.redirectUris)||!input.redirectUris.length||input.redirectUris.some(uri=>{try{
   const parsed=new URL(uri)
   const allowed=parsed.protocol==='https:'||(this.options.allowLoopbackRedirectUris===true&&parsed.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(parsed.hostname))
   return !allowed||!!parsed.username||!!parsed.password||!!parsed.hash
  }catch{return true}}))throw new TypeError(prefix+'_device_redirects_invalid')
  const redirectUris=[...input.redirectUris]
  const token=await this.transport.exchange(this.prefix+'/identity/openid/Token/_exchange',this.message({
   grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token:activationCode,client_instance_id:clientInstanceId,
  },'device-token-'+randomUUID()),this.options.providerDid,pollOptions)
  const tokenBody=record(record(token.poll.body)?.body),initialAccessToken=text(tokenBody?.initial_access_token)
  if(!initialAccessToken||tokenBody?.token_type!=='Bearer'||tokenBody.scope!=='dcr:register'||!Number.isFinite(tokenBody.expires_in)||Number(tokenBody.expires_in)<=0)throw new Error(prefix+'_initial_access_token_invalid')
  const registration=await this.transport.exchange(this.prefix+'/identity/openid/Device/_dcr',this.message({
   code:activationCode,redirect_uris:redirectUris,jwks:{keys:publicJwks},application_type:'web',token_endpoint_auth_method:'private_key_jwt',
   actor_did:this.options.expectedProfile.actorDid,profile_did:this.options.expectedProfile.profileDid,ext_device_info:{device_id:clientInstanceId},
  },'device-dcr-'+randomUUID(),'openid-dcr-request'),this.options.dcrResponseIssuer,pollOptions,initialAccessToken)
  const rows=gatewayResponseEntries(registration.poll.body),devices=rows.filter(row=>record(row.resource)?.resourceType==='Device'&&['200','201'].includes(String(record(row.response)?.status)))
  const device=record(devices[0]?.resource),clientId=text(device?.client_id)
  if(devices.length!==1||!device||!clientId||device.id!==clientId||(Object.hasOwn(device,'registration_access_token')&&!text(device.registration_access_token))||!text(device.registration_client_uri))throw new Error(prefix+'_device_registration_binding_invalid')
  return {token,registration,clientId,actorDid:this.options.expectedProfile.actorDid,profileDid:this.options.expectedProfile.profileDid,routeContext:this.options.ctx}
 }
}
