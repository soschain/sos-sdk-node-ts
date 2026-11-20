import {createHash} from 'node:crypto'
import {publicOfferingResourceKey,readPublicOfferingSubmission,type PublicOffering,type PublicOfferingPublicationScope} from 'antifraud-data-utils-ts/public-offering-catalog'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type OrganizationCatalogVaultResource=Readonly<{resourceType:string;id:string;meta:Readonly<{claims:Readonly<Record<string,unknown>>}>}>
export type OrganizationCatalogVaultSnapshot=Readonly<{
  revision:number
  resources:readonly OrganizationCatalogVaultResource[]
  publicProfile?:Readonly<Record<string,unknown>>
  publishedOfferings?:readonly PublicOffering[]
  reviewedOfferings?:readonly PublicOffering[]
  publicationCount?:number
}>
export type OrganizationCatalogVaultOperation=Readonly<{kind:'read'}>
  |Readonly<{kind:'save';expectedRevision:number;resources:readonly OrganizationCatalogVaultResource[];publicProfile?:Readonly<Record<string,unknown>>}>
  |Readonly<{kind:'replace-offering-catalogue';expectedRevision:number;document:unknown}>
  |Readonly<{kind:'upsert-offering-batch';expectedRevision:number;document:unknown}>
type RecordValue=OrganizationCatalogVaultSnapshot&Readonly<{id:string;organizationReference:string;expiresAt:number}>
const failure=(code:string,status:number)=>Object.assign(new Error(code),{status})

/** Organization-scoped catalog persistence. The host authenticates the principal and validates governed resource builders before execution. */
export class OrganizationCatalogVaultProvider{
  private readonly id:string
  constructor(private readonly options:Readonly<{store:TransactionalVaultRepository;collection:string;organizationReference:string;expiresAt:number;publication?:PublicOfferingPublicationScope}>){
    if(!options.collection||!/^Organization\/[A-Za-z0-9.-]{1,64}$/u.test(options.organizationReference)||!Number.isFinite(options.expiresAt))throw new TypeError('catalog_scope_invalid')
    this.id=createHash('sha256').update(options.organizationReference).digest('hex')
  }
  async execute(operation:OrganizationCatalogVaultOperation):Promise<OrganizationCatalogVaultSnapshot>{
    if(this.options.expiresAt<=Date.now())throw failure('catalog_expired',403)
    if(operation?.kind==='read')return this.project(await this.options.store.get<RecordValue>(this.options.collection,this.id))
    if(operation?.kind!=='save'&&operation?.kind!=='replace-offering-catalogue'&&operation?.kind!=='upsert-offering-batch'){
      throw new TypeError('catalog_operation_invalid')
    }
    if(!Number.isSafeInteger(operation.expectedRevision)||operation.expectedRevision<0)throw new TypeError('catalog_operation_invalid')
    const updates=operation.kind==='save'?operation.resources:[]
    if(!Array.isArray(updates)||updates.length>128)throw new TypeError('catalog_operation_invalid')
    for(const resource of updates){
      if(!resource||!['Organization','Place','Location','HealthcareService','Service','Product'].includes(resource.resourceType)||!/^[A-Za-z0-9.-]{1,64}$/u.test(resource.id)||!resource.meta?.claims||typeof resource.meta.claims!=='object'||Array.isArray(resource.meta.claims))throw new TypeError('catalog_resource_invalid')
    }
    if(Buffer.byteLength(JSON.stringify(operation))>24_000)throw failure('catalog_request_too_large',413)
    const submission=operation.kind==='save'?undefined:this.readPublication(operation.document)
    if(operation.kind==='upsert-offering-batch'){
      const type=submission?.[0]?.type
      if((type!=='Product'&&type!=='Service')||submission?.some(offering=>offering.type!==type)){
        throw new TypeError('catalog_offering_batch_mixed_types')
      }
    }
    return this.options.store.runTransaction(async tx=>{
      const current=this.project(await tx.get<RecordValue>(this.options.collection,this.id))
      if(current.revision!==operation.expectedRevision)throw failure('catalog_revision_conflict',409)
      const resources=new Map(current.resources.map(resource=>[`${resource.resourceType}/${resource.id}`,resource]))
      for(const resource of updates)resources.set(`${resource.resourceType}/${resource.id}`,resource)
      if(resources.size>128)throw failure('catalog_capacity_exceeded',409)
      const publicProfile=(operation.kind==='save'?operation.publicProfile:undefined)??current.publicProfile
      const publishedOfferings=operation.kind==='replace-offering-catalogue'?submission:current.publishedOfferings
      const reviewed=new Map(current.reviewedOfferings?.map(offering=>[publicOfferingResourceKey(offering),offering]))
      for(const resource of updates){
        if(resource.resourceType==='Product'||resource.resourceType==='Service'){
          reviewed.delete(publicOfferingResourceKey({type:resource.resourceType,id:resource.id}))
        }
      }
      if(operation.kind==='upsert-offering-batch'){
        for(const offering of submission??[])reviewed.set(publicOfferingResourceKey(offering),offering)
      }
      const value:RecordValue={id:this.id,organizationReference:this.options.organizationReference,expiresAt:this.options.expiresAt,
        revision:current.revision+1,resources:[...resources.values()],...(publicProfile?{publicProfile}:{}),
        ...(publishedOfferings?{publishedOfferings}:{}),...(reviewed.size?{reviewedOfferings:[...reviewed.values()]}:{})}
      await tx.put(this.options.collection,value)
      return {...this.project(value),...(operation.kind==='upsert-offering-batch'?{publicationCount:submission?.length}:{})}
    })
  }
  private readPublication(document:unknown):readonly PublicOffering[]{
    if(!this.options.publication)throw failure('catalog_publication_scope_required',403)
    return readPublicOfferingSubmission(document,this.options.publication)
  }
  private project(record:RecordValue|undefined):OrganizationCatalogVaultSnapshot{
    if(!record||record.expiresAt<=Date.now())return {revision:0,resources:[]}
    if(record.organizationReference!==this.options.organizationReference)throw failure('catalog_scope_forbidden',403)
    return {revision:record.revision,resources:record.resources,...(record.publicProfile?{publicProfile:record.publicProfile}:{}),
      ...(record.publishedOfferings?{publishedOfferings:record.publishedOfferings}:{}),
      ...(record.reviewedOfferings?{reviewedOfferings:record.reviewedOfferings}:{}),
    }
  }
}
