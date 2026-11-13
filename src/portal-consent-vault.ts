import {evaluateProfessionalConsentCoverage} from 'sos-data-utils-ts/multichannel-permission-forms'
import {createHash} from 'node:crypto'
import type {IVaultRepository} from 'gdc-common-utils-ts/storage'
import {ClaimConsent as C,ConsentStatuses,type ConsentRule} from 'gdc-common-utils-ts/models/consent-rule'
import {buildConsentClaimsSimple,isValidConsentPeriodBoundary} from 'gdc-common-utils-ts/utils/consent'
import type {ConsentCoverageRequest,EffectiveAccessEvaluation} from 'gdc-common-utils-ts/models/consent-access'
import type {TransactionalVaultRepository} from './transactional-vault.js'

export type PortalConsentSnapshot=Readonly<{revision:number;claims:readonly Readonly<Record<string,unknown>>[]}>
export type PortalConsentVaultOptions=Readonly<{
  store:TransactionalVaultRepository;scopeKey:string;generationId:string;subjectIdentifier:string;expiresAt:number
  assertAccess:(transaction:IVaultRepository,action:'read'|'write'|'request')=>Promise<void>;now?:()=>number
}>
type RecordState=PortalConsentSnapshot&{id:string;scopeKey:string;generationId:string;subjectIdentifier:string;expiresAt:number}
/** One scoped Consent collection behind the existing Confidential Storage port; no independent database or browser authority. */
export class PortalConsentVaultProvider{
  readonly collectionName:string
  private readonly id:string
  private readonly now:()=>number
  constructor(private readonly options:PortalConsentVaultOptions){
    if([options.scopeKey,options.generationId,options.subjectIdentifier].some(value=>typeof value!=='string'||!value.trim())||!Number.isFinite(options.expiresAt))throw new TypeError('consent_context_invalid')
    this.collectionName=`portal_consents_${hash(options.scopeKey)}`
    this.id=hash([options.scopeKey,options.generationId,options.subjectIdentifier].join('\0'));this.now=options.now??Date.now
  }
  read():Promise<PortalConsentSnapshot>{return this.options.store.runTransaction(transaction=>this.readInTransaction(transaction))}
  async readInTransaction(transaction:IVaultRepository):Promise<PortalConsentSnapshot>{
    await this.authorize(transaction,'read')
    const record=await transaction.get<RecordState>(this.collectionName,this.id)
    if(!record)return {revision:0,claims:[]}
    if(record.scopeKey!==this.options.scopeKey||record.generationId!==this.options.generationId||record.subjectIdentifier!==this.options.subjectIdentifier||!Number.isFinite(record.expiresAt)||record.expiresAt<=this.now()||!Number.isInteger(record.revision)||record.revision<1)throw new Error('consent_context_forbidden')
    return {revision:record.revision,claims:record.claims.map(claims=>this.normalize(claims))}
  }
  /** The optional host hook couples related vault changes to this authorized revision.
   * It must use only the supplied transaction port, finish reads before writes,
   * and never perform an external side effect. A thrown error rolls everything back.
   */
  async replace(raw:readonly Readonly<Record<string,unknown>>[],expectedRevision:number,commitRelatedChanges?:(transaction:IVaultRepository)=>Promise<void>):Promise<PortalConsentSnapshot>{
    if(!Array.isArray(raw)||raw.length>100||!Number.isInteger(expectedRevision)||expectedRevision<0||JSON.stringify(raw).length>1_000_000)throw new TypeError('consent_snapshot_invalid')
    const claims=raw.map(item=>this.normalize(item))
    if(new Set(claims.map(item=>item[C.identifier])).size!==claims.length)throw new TypeError('consent_identifier_duplicate')
    return this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'write')
      const current=await this.readInTransaction(transaction)
      if(current.revision!==expectedRevision)throw new Error('consent_revision_conflict')
      await commitRelatedChanges?.(transaction)
      const next:RecordState={id:this.id,scopeKey:this.options.scopeKey,generationId:this.options.generationId,subjectIdentifier:this.options.subjectIdentifier,expiresAt:this.options.expiresAt,revision:current.revision+1,claims}
      await transaction.put(this.collectionName,next)
      return {revision:next.revision,claims:next.claims}
    })
  }
  /** Professionals may request a rule; draft status never authorizes access. The BFF binds its target and role. */
  async requestDraft(raw:Readonly<Record<string,unknown>>,recordRequest?:(transaction:IVaultRepository,claims:Readonly<Record<string,unknown>>,replay:boolean)=>Promise<void>):Promise<PortalConsentSnapshot>{
    const claims=this.normalize(raw)
    if(claims[C.status]!==ConsentStatuses.Draft)throw new TypeError('consent_request_requires_draft')
    return this.options.store.runTransaction(async transaction=>{
      await this.authorize(transaction,'request')
      const current=await this.readInTransaction(transaction)
      const existing=current.claims.find(item=>item[C.identifier]===claims[C.identifier])
      if(existing){
        const semantic=(value:Readonly<Record<string,unknown>>)=>JSON.stringify(Object.keys(value).filter(key=>key!==C.date).sort().map(key=>[key,value[key]]))
        // The first receipt owns its date. Retrying a transport request must not edit it or manufacture another draft.
        if(existing[C.status]!==ConsentStatuses.Draft||semantic(existing)!==semantic(claims))throw new Error('consent_request_conflict')
        await recordRequest?.(transaction,existing,true)
        return current
      }
      if(current.claims.length>=100)throw new TypeError('consent_snapshot_invalid')
      const next:RecordState={id:this.id,scopeKey:this.options.scopeKey,generationId:this.options.generationId,subjectIdentifier:this.options.subjectIdentifier,expiresAt:this.options.expiresAt,revision:current.revision+1,claims:[...current.claims,claims]}
      // The audit hook may read its receipt; run it before the first write for durable adapters.
      await recordRequest?.(transaction,claims,false)
      await transaction.put(this.collectionName,next)
      return {revision:next.revision,claims:next.claims}
    })
  }
  evaluate(request:ConsentCoverageRequest):Promise<EffectiveAccessEvaluation>{return this.options.store.runTransaction(transaction=>this.evaluateInTransaction(transaction,request))}
  async evaluateInTransaction(transaction:IVaultRepository,request:ConsentCoverageRequest):Promise<EffectiveAccessEvaluation>{
    if(request.subject&&request.subject!==this.options.subjectIdentifier)throw new TypeError('consent_subject_mismatch')
    const snapshot=await this.readInTransaction(transaction)
    return evaluateProfessionalConsentCoverage(snapshot.claims.map(claims=>({...claims}) as unknown as ConsentRule),{...request,subject:this.options.subjectIdentifier,now:new Date(this.now())})
  }
  private normalize(raw:Readonly<Record<string,unknown>>):Readonly<Record<string,unknown>>{
    if(!raw||typeof raw!=='object'||Array.isArray(raw)||Object.keys(raw).some(key=>key!=='@context'&&!key.startsWith('Consent.'))||Object.values(raw).some(value=>typeof value!=='string')||JSON.stringify(raw).length>64_000)throw new TypeError('consent_claims_invalid')
    if(raw[C.subject]!==this.options.subjectIdentifier)throw new TypeError('consent_subject_mismatch')
    if(!Object.values(ConsentStatuses).includes(raw[C.status] as never)||!['permit','deny'].includes(String(raw[C.decision]))||!String(raw[C.identifier]||'').trim())throw new TypeError('consent_claims_invalid')
    if(!isValidConsentPeriodBoundary(String(raw[C.date]||''))||String(raw[C.identifier]).length>256)throw new TypeError('consent_claims_invalid')
    const canonical=buildConsentClaimsSimple({subjectDid:this.options.subjectIdentifier,actor:String(raw[C.actorIdentifier]||''),actorRole:String(raw[C.actorRole]||''),purpose:String(raw[C.purpose]||''),actions:String(raw[C.action]||'').split(',').filter(Boolean),consentIdentifier:String(raw[C.identifier]),consentDate:String(raw[C.date]||''),decision:raw[C.decision] as 'permit'|'deny'})
    if(raw['@context']!==canonical.consentClaims['@context'])throw new TypeError('consent_context_invalid')
    for(const key of [C.periodStart,C.periodEnd,C.dataPeriodStart,C.dataPeriodEnd])if(raw[key]&&!isValidConsentPeriodBoundary(String(raw[key])))throw new TypeError('consent_period_invalid')
    return Object.freeze({...raw})
  }
  private async authorize(transaction:IVaultRepository,action:'read'|'write'|'request'){
    if(this.options.expiresAt<=this.now())throw new Error('consent_context_expired')
    await this.options.assertAccess(transaction,action)
  }
}
function hash(value:string){return createHash('sha256').update(value).digest('hex')}
