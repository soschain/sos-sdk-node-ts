import {createHash,randomUUID} from 'node:crypto'
import type {ServerProfileSealer} from 'gdc-sdk-node-ts'
import type {IVaultRepository} from 'gdc-common-utils-ts/storage'
import {normalizePortalPushNotice,normalizePortalPushSubscription,type PortalPushNotice,type PortalPushSubscription} from 'sos-data-utils-ts/portal-push'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type PortalPushIdentity=Readonly<{scopeKey:string;actorIdentifier:string}>
type Device={id:string;actorHash:string;sealedSubscription:string;expiresAt:number;revoked:boolean;updatedAt:number}
type Delivery={id:string;actorHash:string;deviceId:string;notice:PortalPushNotice;expiresAt:number;status:'pending'|'sending'|'accepted'|'expired';leaseId?:string;retryAt:number;attempts:number}
type DeviceView=Readonly<{keyId:string;expiresAt:number;updatedAt:number}>

/** One explicit target per job. Provider acceptance is not a device delivery receipt. */
export class PortalPushDeliveryService{
  constructor(private readonly options:Readonly<{
    store:TransactionalVaultRepository
    sealer:ServerProfileSealer
    allowedEndpointOrigins:readonly string[]
    send:(subscription:PortalPushSubscription,notice:PortalPushNotice)=>Promise<{statusCode:number}>
    now?:()=>number
  }>){ }
  private now(){return (this.options.now??Date.now)()}
  collections(identity:PortalPushIdentity){
    if(!identity.scopeKey.trim()||!identity.actorIdentifier.trim())throw new Error('portal_push_identity_required')
    return collectionsForScope(identity.scopeKey)
  }
  private actor(identity:PortalPushIdentity){return hash(`${identity.scopeKey}\0${identity.actorIdentifier}`)}
  async register(identity:PortalPushIdentity,input:unknown):Promise<DeviceView>{
    const subscription=normalizePortalPushSubscription(input),url=new URL(subscription.endpoint)
    if(!this.options.allowedEndpointOrigins.includes(url.origin)||url.port||url.hostname==='localhost'||url.hostname.endsWith('.localhost')||url.hostname.includes(':')||/^\d+(?:\.\d+){3}$/u.test(url.hostname))throw new Error('portal_push_endpoint_forbidden')
    const now=this.now(),expiresAt=Math.min(subscription.expirationTime??Infinity,now+30*24*60*60*1000)
    if(expiresAt<=now)throw new Error('portal_push_subscription_expired')
    const names=this.collections(identity),id=hash(subscription.endpoint),actorHash=this.actor(identity)
    const sealedSubscription=await this.options.sealer.seal(JSON.stringify(subscription),`${names.devices}\0${actorHash}\0${id}`)
    return this.options.store.runTransaction(async store=>{
      const existing=await store.get<Device>(names.devices,id)
      const devices=await store.query<Device>(names.devices,{where:[{attribute:'actorHash',equals:actorHash}]})
      if(existing&&existing.actorHash!==actorHash&&!existing.revoked&&existing.expiresAt>now)throw new Error('portal_push_owner_conflict')
      if(!devices.some(device=>device.id===id)&&devices.filter(device=>!device.revoked&&device.expiresAt>now).length>=20)throw new Error('portal_push_device_limit')
      await store.put(names.devices,{id,actorHash,sealedSubscription,expiresAt,revoked:false,updatedAt:now})
      return {keyId:id,expiresAt,updatedAt:now}
    })
  }
  async list(identity:PortalPushIdentity):Promise<DeviceView[]>{
    const records=await this.options.store.query<Device>(this.collections(identity).devices,{where:[{attribute:'actorHash',equals:this.actor(identity)}]})
    return records.filter(record=>!record.revoked&&record.expiresAt>this.now()).map(record=>({keyId:record.id,expiresAt:record.expiresAt,updatedAt:record.updatedAt}))
  }
  async revoke(identity:PortalPushIdentity,keyId:string):Promise<void>{
    const names=this.collections(identity)
    await this.options.store.runTransaction(async store=>{
      const record=await store.get<Device>(names.devices,keyId)
      if(!record||record.actorHash!==this.actor(identity))throw new Error('portal_push_device_not_found')
      await store.put(names.devices,{...record,revoked:true,updatedAt:this.now()})
    })
  }
  /** The host can use its current transaction to commit a Communication and its delivery jobs atomically. */
  async enqueue(identity:PortalPushIdentity,input:PortalPushNotice,transaction?:IVaultRepository):Promise<void>{
    const notice=normalizePortalPushNotice(input),names=this.collections(identity),actorHash=this.actor(identity),now=this.now()
    const enqueue=async(store:IVaultRepository)=>{
      const devices=(await store.query<Device>(names.devices,{where:[{attribute:'actorHash',equals:actorHash}]})).filter(device=>!device.revoked&&device.expiresAt>now)
      const obsolete=notice.state==='updated'?(await store.query<Delivery>(names.deliveries,{where:[{attribute:'actorHash',equals:actorHash},{attribute:'status',in:['pending','sending']}]}))
        .filter(job=>job.notice.tag===notice.tag&&Date.parse(job.notice.occurredAt)<Date.parse(notice.occurredAt)):[]
      const jobs=await Promise.all(devices.map(async device=>{
        const id=hash(`${device.id}\0${notice.tag}\0${notice.state}\0${notice.occurredAt}`)
        const existing=await store.get<Delivery>(names.deliveries,id)
        return existing?undefined:{id,deviceId:device.id,actorHash,notice,expiresAt:Date.parse(notice.occurredAt)+120_000,status:'pending' as const,retryAt:0,attempts:0}
      }))
      for(const job of obsolete)await store.put(names.deliveries,{...job,status:'expired'})
      for(const job of jobs)if(job&&job.expiresAt>now)await store.put(names.deliveries,job)
    }
    if(transaction)await enqueue(transaction);else await this.options.store.runTransaction(enqueue)
  }
  async dispatch(identity:PortalPushIdentity):Promise<{accepted:number;pending:number;expired:number}>{
    this.collections(identity)
    return this.dispatchJobs(identity.scopeKey,this.actor(identity))
  }
  /** Trusted background worker: retry this configured environment's jobs without an open account page. */
  async dispatchScope(scopeKey:string):Promise<{accepted:number;pending:number;expired:number}>{return this.dispatchJobs(scopeKey)}
  private async dispatchJobs(scopeKey:string,onlyActorHash?:string):Promise<{accepted:number;pending:number;expired:number}>{
    const names=collectionsForScope(scopeKey),result={accepted:0,pending:0,expired:0}
    const jobs=await this.options.store.query<Delivery>(names.deliveries,{where:[{attribute:'status',in:['pending','sending']},...(onlyActorHash?[{attribute:'actorHash',equals:onlyActorHash}]:[])],limit:100})
    for(const job of jobs){
      const actorHash=job.actorHash
      if(job.status==='accepted'||job.status==='expired')continue
      const claim=await this.options.store.runTransaction(async store=>{
        const current=await store.get<Delivery>(names.deliveries,job.id)
        const device=await store.get<Device>(names.devices,job.deviceId)
        const now=this.now()
        if(!current||current.status==='accepted'||current.status==='expired')return undefined
        if(!device||device.actorHash!==actorHash||device.revoked||device.expiresAt<=now||current.expiresAt<=now){await store.put(names.deliveries,{...current,status:'expired'});return 'expired' as const}
        if(current.retryAt>now)return undefined
        const delivery={...current,status:'sending' as const,leaseId:randomUUID(),retryAt:now+30_000,attempts:current.attempts+1}
        await store.put(names.deliveries,delivery)
        return {delivery,device}
      })
      if(claim==='expired'){result.expired++;continue}
      if(!claim){result.pending++;continue}
      let statusCode=0
      try{
        const cleartext=await this.options.sealer.unseal(claim.device.sealedSubscription,`${names.devices}\0${actorHash}\0${claim.device.id}`)
        const subscription=normalizePortalPushSubscription(JSON.parse(cleartext))
        if(!this.options.allowedEndpointOrigins.includes(new URL(subscription.endpoint).origin))throw new Error('portal_push_endpoint_forbidden')
        statusCode=(await this.options.send(subscription,claim.delivery.notice)).statusCode
      }catch(error){statusCode=Number((error as {statusCode?:number})?.statusCode)||0}
      const status=statusCode>=200&&statusCode<300?'accepted':statusCode===404||statusCode===410?'expired':'pending'
      await this.options.store.runTransaction(async store=>{
        const current=await store.get<Delivery>(names.deliveries,job.id)
        const device=await store.get<Device>(names.devices,job.deviceId)
        if(current?.leaseId!==claim.delivery.leaseId||current.status==='expired')return
        await store.put(names.deliveries,{...current,status})
        if(status==='expired'&&device)await store.put(names.devices,{...device,revoked:true,updatedAt:this.now()})
      })
      result[status]++
    }
    return result
  }
}
function hash(value:string){return createHash('sha256').update(value).digest('hex')}
function collectionsForScope(scopeKey:string){
  if(!scopeKey.trim())throw new Error('portal_push_scope_required')
  const namespace=`portal_push_${hash(scopeKey)}`
  return {devices:`${namespace}_devices`,deliveries:`${namespace}_deliveries`}
}
