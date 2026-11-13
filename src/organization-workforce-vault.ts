import {createHash,randomBytes} from 'node:crypto'
import type {IVaultRepository} from 'gdc-common-utils-ts/storage'
import type {OrganizationEmployeeLifecycleRecord} from 'gdc-common-utils-ts/models/organization-employee-lifecycle'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type OrganizationWorkforceSeat=Readonly<{
  id:string;organizationReference:string;sector:string;profileId:string;role:string;email:string
  status:'pending'|'active'|'inactive';expiresAt:number;credentialHash:string;delivery:'pending'|'sent'|'failed'
  employee:OrganizationEmployeeLifecycleRecord;groups?:readonly string[]
}>
export type OrganizationWorkforceDelivery=Readonly<{email:string;activationCode:string;organizationName:string;roleName:string}>
export class OrganizationWorkforceError extends Error{
  constructor(message:string,readonly status:number){super(message);this.name='OrganizationWorkforceError'}
}
const hash=(value:string)=>createHash('sha256').update(value).digest('hex')
const email=(value:string)=>String(value||'').trim().toLowerCase()

/** Vault-backed workforce provider. Hosts inject scope, controller policy and delivery; GW providers retain the same use cases. */
export class OrganizationWorkforceVaultProvider{
  constructor(private readonly options:Readonly<{store:TransactionalVaultRepository;collection:string;assertManage:(organizationReference:string)=>Promise<void>;now?:()=>number}>){
    if(!options.collection)throw new TypeError('workforce_collection_required')
  }
  private now(){return (this.options.now??Date.now)()}
  async invite(input:Readonly<{organizationReference:string;sector:string;profileId:string;role:string;email:string;roleCode:string;employeeDid:string;expiresAt:number;organizationName:string;roleName:string;groups?:readonly string[]}>,deliver:(message:OrganizationWorkforceDelivery)=>Promise<void>){
    await this.options.assertManage(input.organizationReference)
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(email(input.email))||!input.roleCode||!input.profileId||!input.sector||!input.employeeDid||!Number.isFinite(input.expiresAt)||input.expiresAt<=this.now())throw new OrganizationWorkforceError('employee_invitation_invalid',400)
    if(input.groups&&(!Array.isArray(input.groups)||input.groups.length>32||input.groups.some(group=>typeof group!=='string'||!group||group.length>160)))throw new OrganizationWorkforceError('employee_group_invalid',400)
    const id=hash([this.options.collection,input.organizationReference,email(input.email),input.profileId].join('\0'))
    const activationCode=randomBytes(32).toString('base64url'),credentialHash=hash(activationCode)
    const row=await this.options.store.runTransaction(async tx=>{
      const current=await tx.get<OrganizationWorkforceSeat>(this.options.collection,id)
      const seats=await tx.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'organizationReference',equals:input.organizationReference}]})
      if(current?.status==='active'&&current.expiresAt>this.now())throw new OrganizationWorkforceError('employee_already_active',409)
      if(!current&&seats.filter(seat=>seat.expiresAt>this.now()).length>=32)throw new OrganizationWorkforceError('employee_licence_capacity_exhausted',409)
      const seat:OrganizationWorkforceSeat={id,organizationReference:input.organizationReference,sector:input.sector,profileId:input.profileId,role:input.role,email:email(input.email),status:'pending',expiresAt:input.expiresAt,credentialHash,delivery:'pending',...(input.groups?{groups:[...new Set(input.groups)]}:{}),employee:{resourceId:id,email:email(input.email),roleCode:input.roleCode,employeeDid:input.employeeDid,status:'inactive'}}
      await tx.put(this.options.collection,seat)
      return seat
    })
    try{await deliver({email:row.email,activationCode,organizationName:input.organizationName,roleName:input.roleName})}
    catch{await this.markDelivery(id,credentialHash,'failed');throw new OrganizationWorkforceError('employee_delivery_failed',503)}
    await this.markDelivery(id,credentialHash,'sent')
    return {invited:true}
  }
  private async markDelivery(id:string,credentialHash:string,delivery:OrganizationWorkforceSeat['delivery']){
    await this.options.store.runTransaction(async tx=>{const row=await tx.get<OrganizationWorkforceSeat>(this.options.collection,id);if(row?.credentialHash===credentialHash)await tx.put(this.options.collection,{...row,delivery})})
  }
  async list(organizationReference:string){
    await this.options.assertManage(organizationReference)
    return (await this.options.store.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'organizationReference',equals:organizationReference}]})).filter(row=>row.expiresAt>this.now())
  }
  async activate<T>(verifiedEmail:string,activationCode:string,createProfile:(seat:OrganizationWorkforceSeat,transaction:IVaultRepository)=>Promise<T>):Promise<T>{
    if(!/^[A-Za-z0-9_-]{43}$/u.test(activationCode))throw new OrganizationWorkforceError('employee_invitation_invalid',403)
    const matches=await this.options.store.query<OrganizationWorkforceSeat>(this.options.collection,{where:[{attribute:'credentialHash',equals:hash(activationCode)}]})
    if(matches.length!==1)throw new OrganizationWorkforceError('employee_invitation_invalid',403)
    return this.options.store.runTransaction(async tx=>{
      const seat=await tx.get<OrganizationWorkforceSeat>(this.options.collection,matches[0]!.id)
      if(!seat||seat.email!==email(verifiedEmail)||seat.status!=='pending'||seat.delivery!=='sent'||seat.expiresAt<=this.now()||seat.credentialHash!==hash(activationCode))throw new OrganizationWorkforceError('employee_invitation_invalid',403)
      const result=await createProfile(seat,tx)
      await tx.put(this.options.collection,{...seat,status:'active',credentialHash:'',employee:{...seat.employee,status:'active'}})
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
