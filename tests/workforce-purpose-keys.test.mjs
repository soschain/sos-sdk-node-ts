// Flow contract: the trusted profile helper's six purpose descriptors project exactly five DCR public keys, retaining actor, id-token, VP-token and communication purposes while excluding the document key. Descriptor labels alone grant no authority; actual private custody/oracle/signature and GW persistence have separate gates.
import assert from 'node:assert/strict'
import {generateKeyPairSync,createHash} from 'node:crypto'
import test from 'node:test'
import {WorkforceClient} from '../dist/workforce-client.js'
import {createEmployeeActivationGrant} from '../dist/employee-activation-grant.js'
import {openServerProfileCustodyKeys} from '../dist/server-profile-custody-keys.js'
import {buildAuthorityDidWeb,buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

const contact={contactKind:'phone',contact:safe.phoneE164},role=HealthcareActorRoles.Dentist
const ctx={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-tech'}
const gatewayDid=buildAuthorityDidWeb({authority:safe.domain}),providerDid=`${gatewayDid}:${safe.tenantId}:cds-es-md:v1:health-tech`
const employeeDid=buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role})
const ec=purpose=>{const {publicKey}=generateKeyPairSync('ec',{namedCurve:'secp384r1'});return {...publicKey.export({format:'jwk'}),alg:'ES384',use:'sig',kid:`synthetic-${purpose}`}}
const descriptor=(ownerScope,purpose,publicJwk)=>({ownerScope,purpose,kid:publicJwk.kid,alg:publicJwk.alg??publicJwk.crv,use:publicJwk.use,publicJwk})
const descriptors=[descriptor('profile','actor-signing',ec('actor-signing')),
 descriptor('profile','document-at-rest',{kty:'OKP',crv:'ML-KEM-768',x:'synthetic-document-kem',kid:'synthetic-document-key',use:'enc'}),
 descriptor('runtime','openid-id-token-signing',ec('id-token-signing')),
 descriptor('runtime','vp-token-signing',ec('vp-token-signing')),
 descriptor('runtime','comm-signing',{kty:'AKP',alg:'ML-DSA-44',pub:'synthetic-communication-signing',kid:'synthetic-comm-signing',use:'sig'}),
 descriptor('runtime','comm-encryption',{kty:'OKP',crv:'ML-KEM-768',x:'synthetic-communication-encryption',kid:'synthetic-comm-encryption',use:'enc'})]
const grant=createEmployeeActivationGrant({...contact,employeeDid,employeeRoleCode:role,providerDid,routeContext:ctx,createdAt:new Date(),expiresAt:new Date(Date.now()+60000)})
const input=publicJwks=>({grant,verifiedContact:contact,activationCode:'synthetic-activation',clientInstanceId:'synthetic-installation',publicJwks,
 redirectUris:['https://example.invalid/auth'],enrollmentKeyDescriptors:descriptors})
function harness(){
 const messages=[]
 const client=new WorkforceClient({baseUrl:'http://127.0.0.1:1',ctx,providerDid,gatewayDid:providerDid,dcrResponseIssuer:gatewayDid,issuerDid:employeeDid,
  bearerToken:'synthetic-verified-recipient',transportProfile:'pre-dcr-didcomm-encrypted',
  secureTransportAdapter:{gatewayDid:providerDid,pack:async message=>JSON.stringify(message),unpackVerified:async packed=>JSON.parse(packed)},
  fetchImpl:async(url,init)=>{
   const message=JSON.parse(new URLSearchParams(init.body).get('request'));messages.push({url,message})
   if(!url.endsWith('-response'))return new Response('{}',{status:202})
   const body=url.includes('/Token/')?{initial_access_token:'synthetic-initial-access',token_type:'Bearer',expires_in:60,scope:'dcr:register'}:
    {data:[{type:'openid-dcr-request',response:{status:'201'},resource:{resourceType:'Device',id:'synthetic-registered-client',client_id:'synthetic-registered-client',registration_access_token:'synthetic-client-secret',registration_client_uri:'https://example.invalid/registration'}}]}
   const envelope={iss:url.includes('/Token/')?providerDid:gatewayDid,aud:message.iss,thid:message.thid,body}
   return Response.json({response:JSON.stringify(envelope)})
  }})
 return {client,messages}
}

test('retains the actual five DCR purposes and excludes the sixth document-at-rest key',async()=>{
 const {client,messages}=harness(),publicJwks=descriptors.filter(key=>key.purpose!=='document-at-rest').map(key=>key.publicJwk)
 const result=await client.enrollEmployeeDevice(input(publicJwks),{intervalMs:0})
 assert.equal(result.clientId,'synthetic-registered-client')
 const dcr=messages.find(row=>row.url.endsWith('/Device/_dcr')).message
 assert.deepEqual(dcr.body.jwks.keys,publicJwks)
 assert.equal(dcr.body.jwks.keys.length,5)
 assert.equal(dcr.body.jwks.keys.some(key=>key.kid==='synthetic-document-key'),false)
 assert.equal(result.role,role);assert.deepEqual(result.routeContext,ctx)
})

test('rejects a purpose/scope substitution even when three raw public keys meet the old shape',async()=>{
 const publicJwks=[descriptors[4].publicJwk,descriptors[5].publicJwk,descriptors[0].publicJwk]
 for(const patch of [{purpose:'vp-token-signing',ownerScope:'runtime'},{purpose:'actor-signing',ownerScope:'runtime'}]){
  const {client,messages}=harness()
  const substituted=[descriptors[4],descriptors[5],{...descriptors[0],...patch}]
  await assert.rejects(client.enrollEmployeeDevice({...input(publicJwks),enrollmentKeyDescriptors:substituted},{intervalMs:0}),/purpose.*binding|public_keys_required/u)
  assert.equal(messages.length,0)
 }
})

test('consumes the real custody helper projection without inventing purpose labels or exporting its document key',async()=>{
 const custody=await openServerProfileCustodyKeys({walletKeyDerivationId:'synthetic-workforce-profile',
  unlockedWalletSeed:createHash('sha256').update('synthetic real workforce profile seed').digest('base64url'),binding:{kind:'enrollment'}})
 const {client,messages}=harness()
 const result=await client.enrollEmployeeDevice({...input(custody.publicJwks),enrollmentKeyDescriptors:custody.descriptors},{intervalMs:0})
 assert.equal(result.clientId,'synthetic-registered-client')
 const keys=messages.find(row=>row.url.endsWith('/Device/_dcr')).message.body.jwks.keys
 assert.deepEqual(keys,custody.publicJwks);assert.equal(keys.length,5)
 assert.equal(keys.some(key=>key.kid===custody.storagePublicJwk.kid),false)
})

test('rejects descriptor algorithm/use labels that contradict their matched public material',async()=>{
 for(const [index,patch] of [[4,{alg:'ML-DSA-65'}],[4,{use:'enc'}],[5,{crv:'ML-KEM-512'}]]){
  const changed={...descriptors[index],publicJwk:{...descriptors[index].publicJwk,...patch}}
  const selected=[index===4?changed:descriptors[4],index===5?changed:descriptors[5],descriptors[0]]
  const {client,messages}=harness()
  await assert.rejects(client.enrollEmployeeDevice({...input(selected.map(key=>key.publicJwk)),enrollmentKeyDescriptors:selected},{intervalMs:0}),/purpose.*binding|public_keys_required/u)
  assert.equal(messages.length,0)
 }
})
