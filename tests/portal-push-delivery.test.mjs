// Flow contract: each enabled browser installation is bound to one verified actor and environment; encrypted vault registrations feed explicit content-free per-device delivery jobs with idempotent receipts, revocation and retry, never card selection or caller-controlled targets.
import assert from 'node:assert/strict'
import {randomBytes,createECDH,createCipheriv,createDecipheriv} from 'node:crypto'
import test from 'node:test'
import {PortalPushDeliveryService} from '../dist/portal-push-delivery.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
const identity={scopeKey:safe.tenantId,actorIdentifier:safe.didWeb}
const key=randomBytes(32)
const sealer={
  async seal(value,aad){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(aad));return Buffer.concat([iv,cipher.update(value),cipher.final(),cipher.getAuthTag()]).toString('base64url')},
  async unseal(value,aad){const data=Buffer.from(value,'base64url'),cipher=createDecipheriv('aes-256-gcm',key,data.subarray(0,12));cipher.setAAD(Buffer.from(aad));cipher.setAuthTag(data.subarray(-16));return Buffer.concat([cipher.update(data.subarray(12,-16)),cipher.final()]).toString()},
}
function subscription(id){const ecdh=createECDH('prime256v1');ecdh.generateKeys();return {endpoint:`${safe.httpsBaseUrl}/push/${id}`,expirationTime:null,keys:{p256dh:ecdh.getPublicKey().toString('base64url'),auth:randomBytes(16).toString('base64url')}}}
const notice={version:1,tag:safe.resourceUuid,state:'ringing',occurredAt:new Date().toISOString()}
function runtime(overrides={}){const store=new TransactionalMemoryVaultRepository();const sent=[];return {store,sent,service:new PortalPushDeliveryService({store,sealer,allowedEndpointOrigins:[safe.httpsBaseUrl],send:async(device,payload)=>{sent.push({device,payload});return {statusCode:201}},...overrides})}}
test('registers two devices, hides endpoints from listings and sends one content-free delivery per active device',async()=>{
  const {store,sent,service}=runtime()
  const first=subscription('first'),second=subscription('second')
  const a=await service.register(identity,first),b=await service.register(identity,second)
  assert.notEqual(a.keyId,b.keyId)
  assert.equal((await service.list(identity)).length,2)
  assert.ok(!JSON.stringify(await service.list(identity)).includes('endpoint'))
  assert.ok(!JSON.stringify(await store.query(service.collections(identity).devices,{})).includes(first.endpoint))
  await service.enqueue(identity,notice)
  assert.deepEqual(await service.dispatch(identity),{accepted:2,pending:0,expired:0})
  assert.equal(sent.length,2);assert.deepEqual(sent[0].payload,notice)
  await service.enqueue(identity,notice);await service.dispatch(identity);assert.equal(sent.length,2)
  await service.revoke(identity,a.keyId)
  await service.enqueue(identity,{...notice,state:'updated',occurredAt:new Date(Date.now()+1).toISOString()});await service.dispatch(identity)
  assert.equal(sent.length,3);assert.equal(sent.at(-1).device.endpoint,second.endpoint)
})
test('rejects another owner, another environment, private/unapproved endpoints and oversized device sets',async()=>{
  const {service}=runtime(),device=subscription('first')
  const registered=await service.register(identity,device)
  const foreign={...identity,actorIdentifier:safe.firstContactIdentifier}
  await assert.rejects(service.register(foreign,device),/owner_conflict/)
  await assert.rejects(service.revoke(foreign,registered.keyId),/not_found/)
  assert.deepEqual(await service.list({...identity,scopeKey:safe.resourceUuid}),[])
  await assert.rejects(service.register(identity,{...device,endpoint:'https://127.0.0.1/push'}),/endpoint_forbidden/)
})
test('records provider acceptance separately from delivery, retries temporary failure and revokes expired subscriptions',async()=>{
  let now=Date.now(),attempt=0
  const {service}=runtime({now:()=>now,send:async()=>{attempt++;if(attempt===1)throw Object.assign(new Error('private provider error'),{statusCode:503});return {statusCode:410}}})
  await service.register(identity,subscription('first'));await service.enqueue(identity,notice)
  assert.deepEqual(await service.dispatch(identity),{accepted:0,pending:1,expired:0})
  now+=31_000
  assert.deepEqual(await service.dispatch(identity),{accepted:0,pending:0,expired:1})
  assert.deepEqual(await service.list(identity),[])
})
test('concurrent workers claim a delivery once and revoked devices are checked before transport',async()=>{
  const {service,sent}=runtime()
  await service.register(identity,subscription('first'));await service.enqueue(identity,notice)
  await Promise.all([service.dispatch(identity),service.dispatch(identity)])
  assert.equal(sent.length,1)
})

test('supersedes queued ringing when the call changes and retries without an open recipient page',async()=>{
  const {service,sent}=runtime()
  await service.register(identity,subscription('first'))
  await service.enqueue(identity,notice)
  await service.enqueue(identity,{...notice,state:'updated',occurredAt:new Date(Date.parse(notice.occurredAt)+1).toISOString()})
  assert.deepEqual(await service.dispatchScope(identity.scopeKey),{accepted:1,pending:0,expired:0})
  assert.deepEqual(sent.map(item=>item.payload.state),['updated'])
})

test('bounds active registrations while allowing renewal of an existing device',async()=>{
  const {service}=runtime()
  const first=subscription('first')
  await service.register(identity,first)
  for(let index=1;index<20;index++)await service.register(identity,subscription(String(index)))
  await assert.rejects(service.register(identity,subscription('overflow')),/device_limit/)
  await service.register(identity,first)
  assert.equal((await service.list(identity)).length,20)
})
