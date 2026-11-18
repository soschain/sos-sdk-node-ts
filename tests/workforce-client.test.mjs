// Flow contract: an already opened controller wallet creates exact contact/role staff and reserves its real GW seat; recipient installation uses only Token exchange and DCR, with contact/route/role binding and authoritative errors. Loopback transport fixtures do not prove GW authorization, signature verification, ledger persistence, or a completed portal enrollment journey.
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {generateKeyPairSync} from 'node:crypto'
import test from 'node:test'
import {WorkforceClient} from '../dist/workforce-client.js'
import {createEmployeeActivationGrant} from '../dist/employee-activation-grant.js'
import {buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity'
import {SchemaOrgPersonClaim as Person,SchemaOrgIndividualProductClaim as Product} from 'antifraud-data-utils-ts/schema-org-claims'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {MultichannelPermissionRoleClaims} from 'sos-data-utils-ts/multichannel-permission-forms'
import {Isco08Occupations} from 'antifraud-data-utils-ts'
import {GatewayResponseEntryTypes} from 'sos-data-utils-ts/gateway-response-contract'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const ctx={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'}
const gatewayDid=safe.didWeb,providerDid=`${gatewayDid}:${ctx.tenantId}:cds-es-md:v1:${ctx.sector}`
const tenantIssuer=`urn:example:organization:${safe.tenantId}`
const controllerDid=`${providerDid}:controller`,role=HealthcareActorRoles.Dentist
const phone={contactKind:'phone',contact:safe.phoneE164},email={contactKind:'email',contact:safe.individualEmail}
// The tenant signs Worker responses, while Device's envelope issuer is the host.
const adapter={gatewayDid:providerDid,pack:async message=>JSON.stringify(message),unpackVerified:async packed=>JSON.parse(packed)}
const options=baseUrl=>({baseUrl,ctx,providerDid,tenantIssuer,gatewayDid:providerDid,dcrResponseIssuer:gatewayDid,issuerDid:controllerDid,
 bearerToken:'synthetic-verified-controller-token',clientId:'registered-controller-client',transportProfile:'registered-didcomm-encrypted',secureTransportAdapter:adapter})
const employeeDid=(contact,selectedRole=role)=>buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role:selectedRole})
const contactClaims=(contact,selectedRole=role)=>({[contact.contactKind==='phone'?Person.Telephone:Person.Email]:contact.contact,[Person.HasOccupation]:selectedRole})
const envelope=(message,iss,rows)=>({iss,aud:message.iss,thid:message.thid,body:{data:rows}})
const employeeRow=(contact,selectedRole=role)=>({type:'Employee-form-v1.0',response:{status:'201'},resource:{id:safe.resourceUuid,type:'Person',
 meta:{claims:{...contactClaims(contact,selectedRole),[Person.Identifier]:employeeDid(contact,selectedRole),[Person.SameAs]:employeeDid(contact,selectedRole)}},
 contained:[{id:safe.demoOrganizationUuids.healthCare,type:'Occupation',meta:{claims:{[Person.HasOccupation]:selectedRole}}}]}})
const licenseRow=(contact,selectedRole=role)=>({type:GatewayResponseEntryTypes.LicenseIssued,response:{status:'201'},meta:{subjectId:safe.resourceUuid,
 subjectDid:employeeDid(contact,selectedRole),licenseId:'synthetic-seat',maxDevices:1},resource:{resourceType:'OperationOutcome',
 meta:{claims:{...contactClaims(contact,selectedRole),[Product.SerialNumber]:'synthetic-activation-code'}}}})
const {publicKey:actorPublicKey}=generateKeyPairSync('ec',{namedCurve:'secp384r1'})
const actorSigningJwk={...actorPublicKey.export({format:'jwk'}),alg:'ES384',kid:'synthetic-actor-signing',use:'sig'}
async function serve(handler,run){
 let failure
 const server=createServer(async(req,res)=>{try{const bytes=[];for await(const chunk of req)bytes.push(chunk)
  const encoded=Buffer.concat(bytes).toString('utf8');const message=JSON.parse(new URLSearchParams(encoded).get('request'))
  await handler(req,res,message)}catch(error){failure=error;res.writeHead(500);res.end()}})
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{await run(`http://127.0.0.1:${server.address().port}`);assert.equal(failure,undefined)}
 finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
}
function reply(res,message){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({response:JSON.stringify(message)}))}

for(const {contact,selectedRole} of [{contact:phone,selectedRole:role},{contact:email,selectedRole:role},{contact:email,selectedRole:MultichannelPermissionRoleClaims.Researcher},{contact:phone,selectedRole:`ISCO-08|${Isco08Occupations.Firefighter.code}`}])test(`provisions canonical ${selectedRole} for exact ${contact.contactKind} employee before its separately bound seat`,async()=>{
 const role=selectedRole,messages=[]
 await serve(async(req,res,message)=>{
  messages.push({path:req.url,message})
  assert.equal(req.headers.authorization,'Bearer synthetic-verified-controller-token')
  assert.equal(message.client_id,'registered-controller-client')
  if(!req.url.endsWith('-response')){
   if(req.url.includes('/Employee/')){
    const entry=message.body.data[0]
    assert.equal(entry.resource.id,safe.resourceUuid)
    assert.equal(entry.resource.meta.claims[Person.HasOccupation],role)
    assert.equal(entry.resource.meta.claims[contact.contactKind==='phone'?Person.Telephone:Person.Email],contact.contact)
    assert.equal(Object.hasOwn(entry.resource.meta.claims,contact.contactKind==='phone'?Person.Email:Person.Telephone),false)
   }else{
    const entry=message.body.data[0]
    assert.equal(entry.meta.subjectId,safe.resourceUuid)
    assert.equal(entry.meta.subjectDid,employeeDid(contact,role))
   }
   res.writeHead(202,{'content-type':'application/json'});res.end('{}');return
  }
  reply(res,envelope(message,req.url.includes('/Employee/')?tenantIssuer:providerDid,[req.url.includes('/Employee/')?employeeRow(contact,role):licenseRow(contact,role)]))
 },async baseUrl=>{
  const result=await new WorkforceClient(options(baseUrl)).provisionEmployee({operationId:safe.resourceUuid,contact,role},{intervalMs:0})
  assert.equal(result.employeeResourceId,safe.resourceUuid)
  assert.equal(result.employeeDid,employeeDid(contact,role))
  assert.equal(result.activationCode,'synthetic-activation-code')
  assert.equal(messages.length,4)
  assert.match(messages[0].path,/\/entity\/org.schema\/Employee\/_batch$/u)
  assert.match(messages[2].path,/\/identity\/openid\/License\/_issue$/u)
 })
})

test('preserves foreign-controller GW denial before licence requests',async()=>{
 let calls=0
 await serve(async(_req,res)=>{calls++;res.writeHead(403,{'content-type':'application/json'});res.end('{"error":"forbidden"}')},async baseUrl=>{
  await assert.rejects(new WorkforceClient(options(baseUrl)).provisionEmployee({operationId:safe.resourceUuid,contact:phone,role}),error=>error.status===403)
  assert.equal(calls,1)
 })
})

test('rejects a different employee contact in the authoritative receipt before reserving a seat',async()=>{
 let calls=0
 await serve(async(req,res,message)=>{calls++;if(!req.url.endsWith('-response')){res.writeHead(202);res.end('{}');return}
  reply(res,envelope(message,tenantIssuer,[employeeRow(email)]))},async baseUrl=>{
  await assert.rejects(new WorkforceClient(options(baseUrl)).provisionEmployee({operationId:safe.resourceUuid,contact:phone,role}),/employee.*binding/iu)
  assert.equal(calls,2)
 })
})

test('rejects recipient contact or route substitution before any transport',async()=>{
 let calls=0
 const grant=createEmployeeActivationGrant({...phone,employeeDid:employeeDid(phone),employeeRoleCode:role,providerDid,routeContext:ctx,
  createdAt:new Date(),expiresAt:new Date(Date.now()+60000)})
 const client=new WorkforceClient({...options('http://127.0.0.1:1'),clientId:undefined,transportProfile:'pre-dcr-didcomm-encrypted',issuerDid:employeeDid(phone),fetchImpl:async()=>{calls++;throw new Error('unexpected request')}})
 const input={grant,verifiedContact:email,activationCode:'synthetic-activation-code',clientInstanceId:'synthetic-installation',publicJwks:[],redirectUris:['https://example.invalid/auth']}
 await assert.rejects(client.enrollEmployeeDevice(input),/contact.*binding/iu)
 await assert.rejects(client.enrollEmployeeDevice({...input,verifiedContact:phone,grant:{...grant,routeContext:{...ctx,sector:'animal-care'}}}),/route.*binding/iu)
 assert.equal(calls,0)
})

test('rejects changing the grant role while retaining the dentist actor before any transport',async()=>{
 let calls=0
 const grant=createEmployeeActivationGrant({...phone,employeeDid:employeeDid(phone),employeeRoleCode:HealthcareActorRoles.MedicalDoctors,providerDid,routeContext:ctx,
  createdAt:new Date(),expiresAt:new Date(Date.now()+60000)})
 const client=new WorkforceClient({...options('http://127.0.0.1:1'),clientId:undefined,transportProfile:'pre-dcr-didcomm-encrypted',issuerDid:employeeDid(phone),fetchImpl:async()=>{calls++;throw new Error('unexpected request')}})
 await assert.rejects(client.enrollEmployeeDevice({grant,verifiedContact:phone,activationCode:'synthetic-activation-code',clientInstanceId:'synthetic-installation',
  publicJwks:[{kty:'AKP',alg:'ML-DSA-44',kid:'synthetic-signing',pub:'synthetic-signing'},
   {kty:'OKP',crv:'ML-KEM-768',kid:'synthetic-encryption',x:'synthetic-encryption'}],redirectUris:['https://example.invalid/auth']}),/role.*binding/iu)
 assert.equal(calls,0)
})

for(const {includeActorSigning,loopback,omitManagementToken=false,registrationManagementToken='synthetic-registration-token',malformed=false,selectedRole=role} of [{includeActorSigning:false,loopback:false},{includeActorSigning:true,loopback:false},{includeActorSigning:true,loopback:true},{includeActorSigning:true,loopback:false,omitManagementToken:true},{includeActorSigning:true,loopback:false,registrationManagementToken:'',malformed:true},{includeActorSigning:true,loopback:false,registrationManagementToken:42,malformed:true},{includeActorSigning:true,loopback:false,selectedRole:MultichannelPermissionRoleClaims.Researcher},{includeActorSigning:true,loopback:false,selectedRole:`ISCO-08|${Isco08Occupations.Firefighter.code}`}])test(`recipient ${selectedRole} registers exact actor/profile keys without Employee mutation; actor-signing=${includeActorSigning}; loopback=${loopback}; optional-RAT-absent=${omitManagementToken}; malformed=${malformed}; token-type=${typeof registrationManagementToken}`,async()=>{
 const role=selectedRole,messages=[]
 const grant=createEmployeeActivationGrant({...phone,employeeDid:employeeDid(phone,role),employeeRoleCode:role,providerDid,routeContext:ctx,
  createdAt:new Date(),expiresAt:new Date(Date.now()+60000)})
 const publicJwks=[{kty:'AKP',alg:'ML-DSA-44',kid:'synthetic-signing',pub:'synthetic-public-signing'},
  {kty:'OKP',crv:'ML-KEM-768',kid:'synthetic-encryption',x:'synthetic-public-encryption'},...(includeActorSigning?[actorSigningJwk]:[])]
 const redirectUris=loopback?['http://localhost:4338/__/auth/handler','http://localhost:4318/__/auth/handler','http://127.0.0.1:4337/__/auth/handler','http://[::1]:4317/__/auth/handler']:['https://example.invalid/auth']
 await serve(async(req,res,message)=>{
  messages.push({path:req.url,message,authorization:req.headers.authorization})
  assert.equal(req.url.includes('/Employee/'),false)
  assert.equal(Object.hasOwn(message,'client_id'),false)
  if(req.url.includes('/Token/')){
   assert.equal(req.headers.authorization,'Bearer synthetic-verified-recipient-token')
   if(req.url.endsWith('-response'))reply(res,{iss:providerDid,aud:message.iss,thid:message.thid,
    body:{initial_access_token:'synthetic-initial-access-token',token_type:'Bearer',expires_in:60,scope:'dcr:register'}})
   else{res.writeHead(202);res.end('{}')}
   return
  }
  assert.equal(req.headers.authorization,'Bearer synthetic-initial-access-token')
  if(req.url.endsWith('-response'))reply(res,envelope(message,gatewayDid,[{type:'openid-dcr-request',response:{status:'201'},resource:{
   resourceType:'Device',id:'synthetic-client',client_id:'synthetic-client',...(omitManagementToken?{}:{registration_access_token:registrationManagementToken}),registration_client_uri:'https://example.invalid/registration'}}]))
  else{
   assert.equal(message.body.actor_did,grant.employeeDid)
   assert.equal(message.body.profile_did,grant.employeeDid)
   assert.equal(message.body.ext_device_info.device_id,'synthetic-installation')
   assert.deepEqual(message.body.jwks.keys,publicJwks)
   assert.deepEqual(message.body.redirect_uris,redirectUris)
   res.writeHead(202);res.end('{}')
  }
 },async baseUrl=>{
  const pending=new WorkforceClient({...options(baseUrl),issuerDid:grant.employeeDid,bearerToken:'synthetic-verified-recipient-token',
   clientId:undefined,tenantIssuer:undefined,transportProfile:'pre-dcr-didcomm-encrypted',secureTransportAdapter:adapter,allowLoopbackRedirectUris:loopback}).enrollEmployeeDevice({grant,verifiedContact:phone,activationCode:'synthetic-activation-code',
    clientInstanceId:'synthetic-installation',publicJwks,redirectUris},{intervalMs:0})
  if(malformed){await assert.rejects(pending,/workforce_device_registration_binding_invalid/u);return}
  const result=await pending
  assert.equal(result.clientId,'synthetic-client')
  assert.equal(result.employeeDid,grant.employeeDid)
  assert.equal(result.role,role)
  assert.deepEqual(result.routeContext,ctx)
  assert.equal(messages.length,4)
 })
})

test('keeps HTTPS default and denies nonloopback HTTP or credential-bearing callbacks despite local opt-in',async()=>{
 const grant=createEmployeeActivationGrant({...phone,employeeDid:employeeDid(phone),employeeRoleCode:role,providerDid,routeContext:ctx,
  createdAt:new Date(),expiresAt:new Date(Date.now()+60000)})
 const publicJwks=[{kty:'AKP',alg:'ML-DSA-44',kid:'synthetic-signing',pub:'synthetic-public-signing'},
  {kty:'OKP',crv:'ML-KEM-768',kid:'synthetic-encryption',x:'synthetic-public-encryption'}]
 const deceptiveCallback=new URL('http://localhost:4338/auth');deceptiveCallback.hostname=`localhost.${safe.domain}`
 const credentialCallback=new URL('http://localhost:4338/auth');credentialCallback.username='synthetic-user';credentialCallback.password='synthetic-secret'
 for(const [allowLoopbackRedirectUris,uri] of [[false,'http://localhost:4338/__/auth/handler'],[true,'http://example.invalid/auth'],
  [true,deceptiveCallback.href],[true,credentialCallback.href],[true,'https://example.invalid/auth#fragment']]){
  let calls=0
  const client=new WorkforceClient({...options('http://127.0.0.1:1'),clientId:undefined,transportProfile:'pre-dcr-didcomm-encrypted',issuerDid:grant.employeeDid,
   allowLoopbackRedirectUris,fetchImpl:async()=>{calls++;throw new Error('unexpected transport')}})
  await assert.rejects(client.enrollEmployeeDevice({grant,verifiedContact:phone,activationCode:'synthetic-activation-code',clientInstanceId:'synthetic-installation',publicJwks,redirectUris:[uri]}),/redirects_invalid/u)
  assert.equal(calls,0)
 }
})

test('rejects duplicate key IDs, private or symmetric material and ungoverned additional keys before transport',async()=>{
 const grant=createEmployeeActivationGrant({...phone,employeeDid:employeeDid(phone),employeeRoleCode:role,providerDid,routeContext:ctx,
  createdAt:new Date(),expiresAt:new Date(Date.now()+60000)})
 const pair=[{kty:'AKP',alg:'ML-DSA-44',kid:'synthetic-signing',pub:'synthetic-public-signing'},
  {kty:'OKP',crv:'ML-KEM-768',kid:'synthetic-encryption',x:'synthetic-public-encryption'}]
 const invalidSets=[
  [{...pair[0],k:'synthetic-secret'},pair[1]],
  [...pair,{...actorSigningJwk,d:'synthetic-private'}],
  [...pair,{...actorSigningJwk,k:'synthetic-secret'}],
  [...pair,{...actorSigningJwk,kid:pair[0].kid}],
  [...pair,{...actorSigningJwk,alg:'ES256'}],
  [...pair,{...actorSigningJwk,crv:'P-256'}],
  [...pair,{...actorSigningJwk,use:'enc'}],
  [...pair,{kty:'oct',kid:'synthetic-symmetric',k:'synthetic-secret'}],
  [...pair,actorSigningJwk,{...actorSigningJwk,kid:'another-actor-key'}],
 ]
 for(const publicJwks of invalidSets){
  let calls=0
  const client=new WorkforceClient({...options('http://127.0.0.1:1'),clientId:undefined,transportProfile:'pre-dcr-didcomm-encrypted',issuerDid:grant.employeeDid,fetchImpl:async()=>{calls++;throw new Error('unexpected transport')}})
  await assert.rejects(client.enrollEmployeeDevice({grant,verifiedContact:phone,activationCode:'synthetic-activation-code',clientInstanceId:'synthetic-installation',publicJwks,redirectUris:['https://example.invalid/auth']}),/public_keys_required/u)
  assert.equal(calls,0)
 }
})

for(const invalidRole of ['ISCO-08|9999','unsupported|2131','ISCO-08|2131|extra','ISCO-08|x2131'])test(`denies ungoverned workforce role ${invalidRole} before transport`,async()=>{
 let calls=0;const client=new WorkforceClient({...options('http://127.0.0.1:1'),fetchImpl:async()=>{calls++;throw new Error('unexpected request')}});
 await assert.rejects(client.provisionEmployee({operationId:safe.resourceUuid,contact:email,role:invalidRole}),/workforce_role_invalid/u);assert.equal(calls,0);
 const grant=createEmployeeActivationGrant({...email,employeeDid:employeeDid(email,invalidRole),employeeRoleCode:invalidRole,providerDid,routeContext:ctx,createdAt:new Date(),expiresAt:new Date(Date.now()+60000)});
 const recipient=new WorkforceClient({...options('http://127.0.0.1:1'),clientId:undefined,tenantIssuer:undefined,transportProfile:'pre-dcr-didcomm-encrypted',issuerDid:grant.employeeDid,fetchImpl:async()=>{calls++;throw new Error('unexpected request')}});
 await assert.rejects(recipient.enrollEmployeeDevice({grant,verifiedContact:email,activationCode:'synthetic-activation-code',clientInstanceId:'synthetic-installation',publicJwks:[],redirectUris:['https://example.invalid/auth']}),/workforce_recipient_grant_invalid/u);assert.equal(calls,0);
});
