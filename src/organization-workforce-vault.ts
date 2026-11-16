import {createHash,randomBytes} from 'node:crypto'
import type {ServerProfileSealer} from 'sos-sdk-core-ts/profile-sealer'
import type {IVaultRepository} from 'sos-sdk-core-ts/vault-repository'
import type {LicenseListSummary,OrganizationEmployeeLifecycleRecord} from 'sos-data-utils-ts/employee-routing'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type OrganizationWorkforceSeat=Readonly<{
  id:string;organizationReference:string;sector:string;profileId:string;role:string;email:string
  status:'pending'|'active'|'inactive';expiresAt:number;credentialHash:string;delivery:'pending'|'sent'|'failed'
  employee:OrganizationEmployeeLifecycleRecord;groups?:readonly string[]
}>
type StoredSeat=OrganizationWorkforceSeat & Readonly<{protectedActivationCode?:string;invitationDeliveryPolicy?:'notification-only'}>
type StoredCapacity=Readonly<{id:string;organizationReference:string;contracted:number}>
type StoredCapacityOperation=Readonly<{id:string;organizationReference:string;operationId:string;quantity:number}>
export type OrganizationWorkforceInvitation=OrganizationWorkforceSeat & Readonly<{activationCode?:string;requiresReissue?:boolean}>
export type OrganizationWorkforceVaultOptions=Readonly<{
  store:TransactionalVaultRepository;collection:string;assertManage:(organizationReference:string)=>Promise<void>;now?:()=>number
  invitationDeliveryPolicy?:'required'|'notification-only';sealer?:ServerProfileSealer
  requireLicenseCapacity?:boolean
}>
export type OrganizationWorkforceDelivery=Readonly<{email:string;activationCode:string;organizationName:string;roleName:string}>
export class OrganizationWorkforceError extends Error{
  constructor(message:string,readonly status:number){super(message);this.name='OrganizationWorkforceError'}
}
const hash=(value:string)=>createHash('sha256').update(value).digest('hex')
const email=(value:string)=>String(value||'').trim().toLowerCase()

/** Vault-backed workforce provider. Hosts inject scope, controller policy and delivery; GW providers retain the same use cases. */
export class OrganizationWorkforceVaultProvider{
  private readonly options:OrganizationWorkforceVaultOptions
  constructor(options:OrganizationWorkforceVaultOptions){
    if(!options.collection)throw new TypeError('workforce_collection_required')
    if(options.requireLicenseCapacity!==undefined&&typeof options.requireLicenseCapacity!=='boolean')throw new TypeError('employee_licence_capacity_policy_invalid')
    const policy=options.invitationDeliveryPolicy??'required'
    if(policy!=='required'&&policy!=='notification-only')throw new TypeError('workforce_delivery_policy_invalid')
    if(policy==='notification-only'&&(!options.sealer||typeof options.sealer.seal!=='function'||typeof options.sealer.unseal!=='function'))throw new TypeError('workforce_invitation_sealer_required')
    const sealer=options.sealer
    this.options=Object.freeze({...options,invitationDeliveryPolicy:policy,...(sealer?{sealer:Object.freeze({seal:sealer.seal.bind(sealer),unseal:sealer.unseal.bind(sealer)})}:{})})
  }
  private aad(seat:OrganizationWorkforceSeat){
    return JSON.stringify(['sos-workforce-invitation-v1',this.options.collection,seat.id,seat.organizationReference,seat.email,seat.profileId,seat.sector,seat.role,seat.employee.roleCode,seat.employee.employeeDid,seat.expiresAt,seat.credentialHash])
  }
  private publicSeat(seat:StoredSeat):OrganizationWorkforceSeat{
    const {protectedActivationCode: _protected,invitationDeliveryPolicy: _policy,...visible}=seat
    return visible
  }
  private now(){return (this.options.now??Date.now)()}
  private capacityCollection(){return `${this.options.collection}__license-capacity`}
  private capacityId(organizationReference:string){return hash([this.options.collection,organizationReference].join('\0'))}
  private validateCapacity(capacity:StoredCapacity|undefined,organizationReference:string){
    if(capacity&&(capacity.organizationReference!==organizationReference||!Number.isSafeInteger(capacity.contracted)||capacity.contracted<0))throw new OrganizationWorkforceError('employee_licence_capacity_invalid',409)
  }
  private inventory(capacity:StoredCapacity|undefined,seats:readonly OrganizationWorkforceSeat[]):LicenseListSummary{
    const current=seats.filter(seat=>seat.expiresAt>this.now()),used=current.length,contracted=capacity?.contracted??used
    if(contracted<used)throw new OrganizationWorkforceError('employee_licence_capacity_invalid',409)
    return Object.freeze({contracted,free:contracted-used,used,available:contracted-used,issued:used,active:current.filter(seat=>seat.status==='active').length,inactive:current.filter(seat=>seat.status==='inactive').length})
  }
  async readLicenseInventory(organizationReference:string):Promise<LicenseListSummary>{
    await this.options.assertManage(organizationReference)
    return this.options.store.runTransaction(async tx=>{
      const capacity=await tx.get<StoredCapacity>(this.capacityCollection(),this.capacityId(organizationReference))
      const seats=await tx.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'organizationReference',equals:organizationReference}]})
      this.validateCapacity(capacity,organizationReference)
      return this.inventory(capacity,seats)
    })
  }
  /** Allocate host-authorized vault capacity; payment and governed admission remain with the host/GW provider. */
  async addLicenseCapacity(input:Readonly<{organizationReference:string;quantity:number;operationId:string}>):Promise<LicenseListSummary>{
    const {organizationReference,quantity}=input
    if(!Number.isSafeInteger(quantity)||quantity<=0)throw new OrganizationWorkforceError('employee_licence_quantity_invalid',400)
    if(typeof input.operationId!=='string'||!input.operationId.trim()||input.operationId.length>160)throw new OrganizationWorkforceError('employee_licence_operation_invalid',400)
    const operationId=input.operationId.trim(),id=this.capacityId(organizationReference),operationKey=hash([id,operationId].join('\0')),operations=`${this.capacityCollection()}__operations`
    await this.options.assertManage(organizationReference)
    return this.options.store.runTransaction(async tx=>{
      const operation=await tx.get<StoredCapacityOperation>(operations,operationKey)
      const capacity=await tx.get<StoredCapacity>(this.capacityCollection(),id)
      const seats=await tx.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'organizationReference',equals:organizationReference}]})
      this.validateCapacity(capacity,organizationReference)
      const previous=this.inventory(capacity,seats)
      if(operation){
        if(!capacity||operation.organizationReference!==organizationReference||operation.operationId!==operationId||operation.quantity!==quantity)throw new OrganizationWorkforceError('employee_licence_operation_conflict',409)
        return previous
      }
      const contracted=previous.contracted+quantity
      if(!Number.isSafeInteger(contracted))throw new OrganizationWorkforceError('employee_licence_quantity_invalid',400)
      const updated:StoredCapacity={id,organizationReference,contracted}
      await tx.put(this.capacityCollection(),updated)
      await tx.put(operations,{id:operationKey,organizationReference,operationId,quantity})
      return this.inventory(updated,seats)
    })
  }
  async invite(input:Readonly<{organizationReference:string;sector:string;profileId:string;role:string;email:string;roleCode:string;employeeDid:string;expiresAt:number;organizationName:string;roleName:string;groups?:readonly string[]}>,deliver:(message:OrganizationWorkforceDelivery)=>Promise<void>){
    input=structuredClone(input)
    await this.options.assertManage(input.organizationReference)
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(email(input.email))||!input.roleCode||!input.profileId||!input.sector||!input.employeeDid||!Number.isFinite(input.expiresAt)||input.expiresAt<=this.now())throw new OrganizationWorkforceError('employee_invitation_invalid',400)
    if(input.groups&&(!Array.isArray(input.groups)||input.groups.length>32||input.groups.some(group=>typeof group!=='string'||!group||group.length>160)))throw new OrganizationWorkforceError('employee_group_invalid',400)
    const id=hash([this.options.collection,input.organizationReference,email(input.email),input.profileId].join('\0'))
    const activationCode=randomBytes(32).toString('base64url'),credentialHash=hash(activationCode)
    const base:OrganizationWorkforceSeat={id,organizationReference:input.organizationReference,sector:input.sector,profileId:input.profileId,role:input.role,email:email(input.email),status:'pending',expiresAt:input.expiresAt,credentialHash,delivery:'pending',...(input.groups?{groups:[...new Set(input.groups)]}:{}),employee:{resourceId:id,email:email(input.email),roleCode:input.roleCode,employeeDid:input.employeeDid,status:'inactive'}}
    const protectedActivationCode=this.options.invitationDeliveryPolicy==='notification-only'?await this.options.sealer!.seal(activationCode,this.aad(base)):undefined
    await this.options.assertManage(input.organizationReference)
    const row=await this.options.store.runTransaction(async tx=>{
      const current=await tx.get<StoredSeat>(this.options.collection,id)
      const seats=await tx.query<StoredSeat>(this.options.collection,{where:[{attribute:'organizationReference',equals:input.organizationReference}]})
      const capacity=await tx.get<StoredCapacity>(this.capacityCollection(),this.capacityId(input.organizationReference))
      this.validateCapacity(capacity,input.organizationReference)
      if(current?.status==='active'&&current.expiresAt>this.now())throw new OrganizationWorkforceError('employee_already_active',409)
      const newReservation=(capacity||this.options.requireLicenseCapacity)?(!current||current.expiresAt<=this.now()):!current
      const contracted=capacity?.contracted??(this.options.requireLicenseCapacity?0:32)
      if(newReservation&&seats.filter(seat=>seat.expiresAt>this.now()).length>=contracted)throw new OrganizationWorkforceError('employee_licence_capacity_exhausted',409)
      const seat:StoredSeat={...base,...(protectedActivationCode?{protectedActivationCode,invitationDeliveryPolicy:'notification-only' as const}:{})}
      await tx.put(this.options.collection,seat)
      return seat
    })
    try{await deliver({email:row.email,activationCode,organizationName:input.organizationName,roleName:input.roleName})}
    catch{
      await this.markDelivery(id,credentialHash,'failed')
      if(this.options.invitationDeliveryPolicy!=='notification-only')throw new OrganizationWorkforceError('employee_delivery_failed',503)
      return {invited:true}
    }
    await this.markDelivery(id,credentialHash,'sent')
    return {invited:true}
  }
  private async markDelivery(id:string,credentialHash:string,delivery:OrganizationWorkforceSeat['delivery']){
    await this.options.store.runTransaction(async tx=>{const row=await tx.get<OrganizationWorkforceSeat>(this.options.collection,id);if(row?.credentialHash===credentialHash)await tx.put(this.options.collection,{...row,delivery})})
  }
  async list(organizationReference:string):Promise<OrganizationWorkforceInvitation[]>{
    await this.options.assertManage(organizationReference)
    const seats=await this.options.store.query<StoredSeat>(this.options.collection,{where:[{attribute:'organizationReference',equals:organizationReference}]})
    const result:OrganizationWorkforceInvitation[]=[]
    const released:StoredSeat[]=[]
    for(const row of seats){
      if(row.organizationReference!==organizationReference||row.expiresAt<=this.now())continue
      const visible=this.publicSeat(row)
      if(this.options.invitationDeliveryPolicy!=='notification-only'||row.status!=='pending'){result.push(visible);continue}
      if(row.invitationDeliveryPolicy!=='notification-only'||!row.protectedActivationCode){result.push({...visible,requiresReissue:true});continue}
      const activationCode=await this.options.sealer!.unseal(row.protectedActivationCode,this.aad(row))
      if(!/^[A-Za-z0-9_-]{43}$/u.test(activationCode)||hash(activationCode)!==row.credentialHash)throw new OrganizationWorkforceError('employee_invitation_invalid',403)
      await this.options.assertManage(organizationReference)
      await this.options.store.runTransaction(async tx=>{
        const current=await tx.get<StoredSeat>(this.options.collection,row.id)
        if(!current||current.status!=='pending'||current.expiresAt<=this.now()||this.aad(current)!==this.aad(row)||current.protectedActivationCode!==row.protectedActivationCode||current.invitationDeliveryPolicy!=='notification-only')throw new OrganizationWorkforceError('employee_invitation_changed',409)
      })
      released.push(row)
      result.push({...visible,activationCode})
    }
    await this.options.assertManage(organizationReference)
    await this.options.store.runTransaction(async tx=>{
      for(const row of released){
        const current=await tx.get<StoredSeat>(this.options.collection,row.id)
        if(!current||current.status!=='pending'||current.expiresAt<=this.now()||this.aad(current)!==this.aad(row)||current.protectedActivationCode!==row.protectedActivationCode||current.invitationDeliveryPolicy!=='notification-only')throw new OrganizationWorkforceError('employee_invitation_changed',409)
      }
    })
    return result
  }
  async activate<T>(verifiedEmail:string,activationCode:string,createProfile:(seat:OrganizationWorkforceSeat,transaction:IVaultRepository)=>Promise<T>):Promise<T>{
    if(!/^[A-Za-z0-9_-]{43}$/u.test(activationCode))throw new OrganizationWorkforceError('employee_invitation_invalid',403)
    const matches=await this.options.store.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'credentialHash',equals:hash(activationCode)}]})
    if(matches.length!==1)throw new OrganizationWorkforceError('employee_invitation_invalid',403)
    return this.options.store.runTransaction(async tx=>{
      const seat=await tx.get<StoredSeat>(this.options.collection,matches[0]!.id)
      if(!seat||seat.email!==email(verifiedEmail)||seat.status!=='pending'||(seat.delivery!=='sent'&&!(this.options.invitationDeliveryPolicy==='notification-only'&&seat.invitationDeliveryPolicy==='notification-only'&&seat.protectedActivationCode))||seat.expiresAt<=this.now()||seat.credentialHash!==hash(activationCode))throw new OrganizationWorkforceError('employee_invitation_invalid',403)
      const visible=this.publicSeat(seat)
      const result=await createProfile(visible,tx)
      await tx.put(this.options.collection,{...visible,status:'active',credentialHash:'',employee:{...seat.employee,status:'active'}})
      return result
    })
  }
  async requireActive(verifiedEmail:string,sector:string,profileId:string){
    const seats=(await this.options.store.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'email',equals:email(verifiedEmail)}]})).filter(seat=>seat.sector===sector&&seat.profileId===profileId&&seat.expiresAt>this.now()&&seat.status==='active')
    if(seats.length!==1)throw new OrganizationWorkforceError('employee_activation_required',403)
    return seats[0]!
  }
  async change(organizationReference:string,id:string,action:string){
    await this.options.assertManage(organizationReference)
    await this.options.store.runTransaction(async tx=>{
      const seat=await tx.get<OrganizationWorkforceSeat>(this.options.collection,id)
      if(!seat||seat.organizationReference!==organizationReference||seat.expiresAt<=this.now())throw new OrganizationWorkforceError('employee_not_found',404)
      if(action==='purge'){if(seat.status!=='inactive')throw new OrganizationWorkforceError('employee_must_be_disabled_before_purge',409);await tx.delete(this.options.collection,id);return}
      if(!['disable','reactivate'].includes(action))throw new OrganizationWorkforceError('employee_action_invalid',400)
      if(seat.status==='pending')throw new OrganizationWorkforceError('employee_activation_required',409)
      await tx.put(this.options.collection,{...seat,status:action==='disable'?'inactive':'active'})
    })
  }
  async setGroup(organizationReference:string,id:string,group:string,enabled:boolean){
    await this.options.assertManage(organizationReference)
    if(!group||group.length>160)throw new OrganizationWorkforceError('employee_group_invalid',400)
    await this.options.store.runTransaction(async tx=>{
      const seat=await tx.get<OrganizationWorkforceSeat>(this.options.collection,id)
      if(!seat||seat.organizationReference!==organizationReference||seat.expiresAt<=this.now()||seat.status!=='active')throw new OrganizationWorkforceError('employee_not_found',404)
      const groups=new Set(seat.groups??[]);if(enabled)groups.add(group);else groups.delete(group)
      await tx.put(this.options.collection,{...seat,groups:[...groups]})
    })
  }
}
