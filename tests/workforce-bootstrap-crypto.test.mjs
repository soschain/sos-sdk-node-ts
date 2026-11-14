// Flow contract: registered packing keeps keys out of the header; explicit fresh-installation bootstrap packing embeds only its own public signing JWK in a real signed/encrypted message. Key possession is not controller, contact, licence, role or device authority.
import assert from 'node:assert/strict'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import test from 'node:test'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'
import {WorkforceClient} from '../dist/workforce-client.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles'

const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),
 digestString:async(data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data).digest('hex'),randomUUID})
const context=id=>({profile:{profileId:id},runtime:{runtimeId:`${id}:server-runtime`,runtimeType:'backend-service'}})

test('explicit pre-DCR packing embeds and verifies its exact public key without changing registered packing',async()=>{
 const gatewayContext=context('synthetic-workforce-gateway'),recipientContext=context('synthetic-workforce-recipient')
 let publicRecipient
 const gateway=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>publicRecipient.encryption})
 await gateway.provisionCommunicationKeys(gatewayContext,'synthetic-gateway-seed')
 const gatewayPublic=gateway.getPublicJwks(gatewayContext)
 const recipient=new OrganizationRegistrationWallet({resolveRecipientJwk:async()=>gatewayPublic.encryption})
 await recipient.provisionCommunicationKeys(recipientContext,'synthetic-new-recipient-seed')
 publicRecipient=recipient.getPublicJwks(recipientContext)
 const message={iss:`${safe.didWeb}:employee:synthetic-recipient`,aud:safe.didWeb,thid:safe.resourceUuid,
  body:{subject_token:'synthetic-one-installation-credential',client_instance_id:'synthetic-installation'}}
 const registered=await recipient.packForRecipientWithContext(message,safe.didWeb,{context:recipientContext})
 const registeredDecoded=await gateway.unpackWithContext(registered,{context:gatewayContext})
 const registeredHeader=JSON.parse(Buffer.from(registeredDecoded.meta.jws.compact.split('.')[0],'base64url').toString('utf8'))
 assert.equal(Object.hasOwn(registeredHeader,'jwk'),false)
 assert.equal(await crypto.verifyJws(registeredDecoded.meta.jws.compact,publicRecipient.signing),true)
 const bootstrap=await recipient.packBootstrapForRecipientWithContext(message,safe.didWeb,{context:recipientContext})
 const bootstrapDecoded=await gateway.unpackWithContext(bootstrap,{context:gatewayContext})
 const bootstrapHeader=JSON.parse(Buffer.from(bootstrapDecoded.meta.jws.compact.split('.')[0],'base64url').toString('utf8'))
 assert.deepEqual(bootstrapHeader.jwk,publicRecipient.signing)
 assert.equal(bootstrapHeader.kid,publicRecipient.signing.kid)
 assert.equal(await crypto.verifyJws(bootstrapDecoded.meta.jws.compact,bootstrapHeader.jwk),true)
 assert.deepEqual(bootstrapDecoded.content,message)
 for(const field of ['d','dBytes','privBytes','secretKeyBytes'])assert.equal(Object.hasOwn(bootstrapHeader.jwk,field),false)
 assert.deepEqual(recipient.getPublicJwks(recipientContext),publicRecipient,'bootstrap packing must not rotate existing keys')
})

test('a recipient pre-DCR transport profile cannot administer staff',async()=>{
 let calls=0
 const client=new WorkforceClient({baseUrl:'http://127.0.0.1:1',ctx:{tenantId:safe.tenantId,jurisdiction:'ES-MD',sector:'health-care'},
  providerDid:safe.didWeb,tenantIssuer:`urn:example:organization:${safe.tenantId}`,gatewayDid:safe.didWeb,dcrResponseIssuer:safe.didWeb,
  issuerDid:`${safe.didWeb}:employee:synthetic-recipient`,bearerToken:'synthetic-recipient-token',
  transportProfile:'pre-dcr-didcomm-encrypted',clientId:'untrusted-controller-client',secureTransportAdapter:{gatewayDid:safe.didWeb,pack:async()=>{calls++;throw new Error('unexpected pack')},unpackVerified:async()=>{throw new Error('unexpected unpack')}}})
 await assert.rejects(client.provisionEmployee({operationId:safe.resourceUuid,contact:{contactKind:'phone',contact:safe.phoneE164},role:HealthcareActorRoles.Dentist}),/registered_controller_transport_required/u)
 assert.equal(calls,0)
})
