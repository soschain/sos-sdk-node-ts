// Flow contract: the normal organization runtime reconstructs its own bootstrap wallet, crosses real HTTP with signed/encrypted packets, and consumes only a configured-GW JWS bound to its caller/thread/issuer. Public encryption keys alone cannot forge a tenant-issuer receipt. This does not establish ICA policy, controller admission or a completed portal onboarding journey.
import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import test from 'node:test'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {SchemaOrgOrganizationClaim as Organization,SchemaOrgServiceClaim as Service} from 'antifraud-data-utils-ts/schema-org-claims'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {SecureOrganizationRegistrationRuntime,buildOrganizationRegistrationWalletContext} from '../dist/secure-organization-registration.js'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'

const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value).digest('hex'),randomUUID})
const walletKeyDerivationId='synthetic-reviewed-controller',walletSeed=createHash('sha256').update('synthetic-reviewed-controller-seed').digest('base64url')
const context=buildOrganizationRegistrationWalletContext(walletKeyDerivationId),gatewayContext=buildOrganizationRegistrationWalletContext('synthetic-configured-host')
const hostDid=safe.didWeb,controllerDid=`${hostDid}:employee:synthetic-controller`,route={tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-tech'}
const tenantIssuer=`urn:example:organization:${safe.tenantId}`

async function run(mode){
 let clientPublic,serverFailure,configuredLookups=0
 const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>clientPublic.encryption})
 await gateway.provisionCommunicationKeys(gatewayContext,'synthetic-host-keys')
 const gatewayPublic=gateway.getPublicJwks(gatewayContext)
 const client=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gatewayPublic.encryption})
 await client.provisionCommunicationKeys(context,walletSeed);clientPublic=client.getPublicJwks(context)
 const rogue=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>clientPublic.encryption})
 const rogueContext=buildOrganizationRegistrationWalletContext('synthetic-rogue-host')
 await rogue.provisionCommunicationKeys(rogueContext,'synthetic-rogue-host-keys')
 const server=createServer(async(req,res)=>{
  try{
   const chunks=[];for await(const chunk of req)chunks.push(chunk)
   const packed=new URLSearchParams(Buffer.concat(chunks).toString('utf8')).get('request')
   const decoded=await gateway.unpackWithContext(packed,{context:gatewayContext}),message=decoded.content
   assert.equal(await crypto.verifyJws(decoded.meta.jws.compact,clientPublic.signing),true)
   assert.equal(message.iss,controllerDid);assert.equal(message.aud,hostDid)
   if(!req.url.endsWith('-response')){res.writeHead(202);res.end('{}');return}
   const payload={iss:mode==='foreign-issuer'?`${hostDid}:foreign`:hostDid,aud:mode==='foreign-audience'?`${controllerDid}:foreign`:controllerDid,
    thid:mode==='foreign-thread'?'synthetic-foreign-thread':message.thid,body:{data:[{type:'Organization-registration-response-v1.0',response:{status:'201'},resource:{resourceType:'Organization',
     id:safe.tenantId,meta:{claims:{[Organization.IdentifierReference]:tenantIssuer,[Organization.SameAs]:`${hostDid}:tenant`}}}}]}}
   let reply=mode==='wrong-signer'?await rogue.packForRecipientWithContext(payload,controllerDid,{context:rogueContext}):await gateway.packForRecipientWithContext(payload,controllerDid,{context:gatewayContext})
   if(mode==='unsigned'){
    const ephemeral=await crypto.generateKeyPairMlKem(randomBytes(64),'ML-KEM-768')
    reply=await crypto.encryptJweToCompact(JSON.stringify(payload),{enc:'A256GCM',skid:ephemeral.publicJWKey.kid,cty:'application/json'},
     {...ephemeral.publicJWKey,dBytes:ephemeral.secretKeyBytes},clientPublic.encryption)
   }
   if(mode==='tampered'){
    const parts=reply.split('.');parts[3]=(parts[3][0]==='A'?'B':'A')+parts[3].slice(1);reply=parts.join('.')
   }
   res.writeHead(200,{'content-type':'application/x-www-form-urlencoded'});res.end(`response=${encodeURIComponent(reply)}`)
  }catch(error){serverFailure=error;res.writeHead(500);res.end()}
 })
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{
  const runtime=new SecureOrganizationRegistrationRuntime({gatewayBaseUrl:`http://127.0.0.1:${server.address().port}`,
   resolveRecipientJwk:async did=>{assert.equal(did,hostDid);return gatewayPublic.encryption},
   resolveGatewaySigningJwk:async did=>{configuredLookups++;assert.equal(did,hostDid);return gatewayPublic.signing}})
  const result=await runtime.submitVerificationWithBootstrapWallet({walletSeed,walletKeyDerivationId,bearerToken:'synthetic-verified-controller',providerDid:hostDid,
   routeContext:route,hostContext:{jurisdiction:'ES-MD',hostNetwork:'test',controllerDid,hostDid},verificationInput:{claims:{[Organization.LegalName]:'Synthetic clinic',[Service.Category]:route.sector},controller:{did:controllerDid}},pollOptions:{intervalMs:0,timeoutMs:5000}})
  assert.equal(serverFailure,undefined)
  return {result,configuredLookups}
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
}

test('accepts a real configured-host signature before exposing canonical tenant issuer claims',async()=>{
 const {result,configuredLookups}=await run('valid')
 assert.equal(result.poll.body.body.data[0].resource.meta.claims[Organization.IdentifierReference],tenantIssuer)
 assert.equal(configuredLookups,1,'the configured signer resolver, never the returned header identity, must establish trust')
})
for(const mode of ['wrong-signer','unsigned','tampered','foreign-issuer','foreign-audience','foreign-thread'])test(`rejects organization receipt mode=${mode} before the caller can persist tenant authority`,async()=>{
 await assert.rejects(run(mode),mode==='tampered'?{name:'OperationError'}:/signature|signed_response|binding/iu)
})
