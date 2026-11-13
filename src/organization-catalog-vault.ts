import {createHash} from 'node:crypto'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type OrganizationCatalogVaultResource=Readonly<{resourceType:string;id:string;meta:Readonly<{claims:Readonly<Record<string,unknown>>}>}>
export type OrganizationCatalogVaultSnapshot=Readonly<{revision:number;resources:readonly OrganizationCatalogVaultResource[];publicProfile?:Readonly<Record<string,unknown>>}>
export type OrganizationCatalogVaultOperation=Readonly<{kind:'read'}>|Readonly<{kind:'save';expectedRevision:number;resources:readonly OrganizationCatalogVaultResource[];publicProfile?:Readonly<Record<string,unknown>>}>
type RecordValue=OrganizationCatalogVaultSnapshot&Readonly<{id:string;organizationReference:string;expiresAt:number}>
const failure=(code:string,status:number)=>Object.assign(new Error(code),{status})

/** Organization-scoped catalog persistence. The host authenticates the principal and validates governed resource builders before execution. */
export class OrganizationCatalogVaultProvider{
  private readonly id:string
  constructor(private readonly options:Readonly<{store:TransactionalVaultRepository;collection:string;organizationReference:string;expiresAt:number}>){
    if(!options.collection||!/^Organization\/[A-Za-z0-9.-]{1,64}$/u.test(options.organizationReference)||!Number.isFinite(options.expiresAt))throw new TypeError('catalog_scope_invalid')
    this.id=createHash('sha256').update(options.organizationReference).digest('hex')
  }
  async execute(operation:OrganizationCatalogVaultOperation):Promise<OrganizationCatalogVaultSnapshot>{
    if(this.options.expiresAt<=Date.now())throw failure('catalog_expired',403)
    if(operation?.kind==='read')return this.project(await this.options.store.get<RecordValue>(this.options.collection,this.id))
    if(operation?.kind!=='save'||!Number.isSafeInteger(operation.expectedRevision)||operation.expectedRevision<0||!Array.isArray(operation.resources)||operation.resources.length>128)throw new TypeError('catalog_operation_invalid')
    for(const resource of operation.resources){
      if(!resource||!['Organization','Place','Location','HealthcareService','Service','Product'].includes(resource.resourceType)||!/^[A-Za-z0-9.-]{1,64}$/u.test(resource.id)||!resource.meta?.claims||typeof resource.meta.claims!=='object'||Array.isArray(resource.meta.claims))throw new TypeError('catalog_resource_invalid')
    }
    if(Buffer.byteLength(JSON.stringify(operation))>24_000)throw failure('catalog_request_too_large',413)
    return this.options.store.runTransaction(async tx=>{
      const current=this.project(await tx.get<RecordValue>(this.options.collection,this.id))
      if(current.revision!==operation.expectedRevision)throw failure('catalog_revision_conflict',409)
      const resources=new Map(current.resources.map(resource=>[`${resource.resourceType}/${resource.id}`,resource]))
      for(const resource of operation.resources)resources.set(`${resource.resourceType}/${resource.id}`,resource)
      if(resources.size>128)throw failure('catalog_capacity_exceeded',409)
      const value:RecordValue={id:this.id,organizationReference:this.options.organizationReference,expiresAt:this.options.expiresAt,revision:current.revision+1,resources:[...resources.values()],...((operation.publicProfile??current.publicProfile)?{publicProfile:operation.publicProfile??current.publicProfile}:{})}
      await tx.put(this.options.collection,value)
      return this.project(value)
    })
  }
  private project(record:RecordValue|undefined):OrganizationCatalogVaultSnapshot{
    if(!record||record.expiresAt<=Date.now())return {revision:0,resources:[]}
    if(record.organizationReference!==this.options.organizationReference)throw failure('catalog_scope_forbidden',403)
    return {revision:record.revision,resources:record.resources,...(record.publicProfile?{publicProfile:record.publicProfile}:{})}
  }
}
