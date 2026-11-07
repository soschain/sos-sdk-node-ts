import {createHash, timingSafeEqual} from 'node:crypto'
import {createCommMsgExtendedDraft} from 'gdc-sdk-node-ts'
import {CommunicationClaim} from 'gdc-common-utils-ts/models/interoperable-claims/communication-claims'
import {CommunicationCategoryCodes} from 'gdc-common-utils-ts/constants/communication'
import {buildDemoWorkspaceScope, demoWorkspaceStorageNamespace, type DemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {normalizePortalRtcCallEvent, PORTAL_RTC_CALL_CONTENT_TYPE, type PortalRtcCallEvent} from 'sos-data-utils-ts/portal-rtc-call'
import {buildSubjectCommunicationGroupReference} from 'sos-data-utils-ts/subject-communication-group'
import type {TransactionalVaultRepository} from './transactional-vault.js'

/** Minimal synthetic directory projection; it does not convey real subject authority. */
export type PortalDemoCard = Readonly<{
  cardNumber:string; generationId:string; subjectIdentifier:string; displayName:string
  controllerActorIdentifier:string; subjectKind:'person'|'animal'; sourceSector:string; expiresAt:number
}>
export type PortalDemoParticipant = Readonly<{actorIdentifier:string; professionalGroupReference?:string}>
type CardRecord = PortalDemoCard & {id:string}
type CommunicationRecord = {id:string;callId:string;subjectIdentifier:string;occurredAt:string;communication:ReturnType<typeof createCommMsgExtendedDraft>['message']}

/** One BFF owns the injected vault; peer BFFs use its authenticated service port. No GW, Chat or second store is involved. */
export class PortalDemoExchange {
  constructor(private readonly options:Readonly<{store:TransactionalVaultRepository;now?:()=>number}>) {}
  private now() {return (this.options.now??Date.now)()}
  async registerCard(scope:DemoWorkspaceScope,card:PortalDemoCard):Promise<void> {
    const collection=collections(scope).cards
    if (!/^\d{21}$/u.test(card.cardNumber)||!card.subjectIdentifier||!card.controllerActorIdentifier||!card.generationId
      ||!['animal','person'].includes(card.subjectKind)||!Number.isFinite(card.expiresAt)||card.expiresAt<=this.now()) throw new Error('demo_card_invalid')
    await this.options.store.runTransaction(async store=>{
      const id=hash(card.cardNumber);const existing=await store.get<CardRecord>(collection,id)
      if (existing&&existing.expiresAt>this.now()&&(existing.generationId!==card.generationId||existing.subjectIdentifier!==card.subjectIdentifier)) throw new Error('demo_card_collision')
      await store.put(collection,{...card,id})
    })
  }
  async resolveCard(scope:DemoWorkspaceScope,cardNumber:string):Promise<PortalDemoCard> {
    const card=await this.options.store.get<CardRecord>(collections(scope).cards,hash(cardNumber))
    if (!card||card.expiresAt<=this.now()) throw new Error('demo_card_not_found')
    const {id:_id,...view}=card;return view
  }
  async revokeGeneration(scope:DemoWorkspaceScope,generationId:string):Promise<void> {
    const collection=collections(scope).cards
    await this.options.store.runTransaction(async store=>{
      const records=await store.query<CardRecord>(collection,{where:[{attribute:'generationId',equals:generationId}]})
      for (const record of records) await store.delete(collection,record.id)
    })
  }
  async listEvents(scope:DemoWorkspaceScope,subjectIdentifier:string,participant:PortalDemoParticipant):Promise<PortalRtcCallEvent[]> {
    const names=collections(scope)
    const cards=await this.options.store.query<CardRecord>(names.cards,{where:[{attribute:'subjectIdentifier',equals:subjectIdentifier}]})
    if (!cards.some(card=>card.expiresAt>this.now())) throw new Error('demo_card_not_found')
    const rows=await this.options.store.query<CommunicationRecord>(names.communications,{where:[{attribute:'subjectIdentifier',equals:subjectIdentifier}]})
    return rows.map(eventFromCommunication).filter(event=>isParticipant(event,participant)).sort((a,b)=>Date.parse(a.occurredAt)-Date.parse(b.occurredAt))
  }
  async submitEvent(scope:DemoWorkspaceScope,raw:PortalRtcCallEvent,participant:PortalDemoParticipant):Promise<void> {
    let event=normalizePortalRtcCallEvent(raw);const names=collections(scope)
    await this.options.store.runTransaction(async store=>{
      const cards=await store.query<CardRecord>(names.cards,{where:[{attribute:'subjectIdentifier',equals:event.subjectIdentifier}]})
      const card=cards.find(card=>card.expiresAt>this.now())
      if (!card) throw new Error('demo_card_not_found')
      const rows=await store.query<CommunicationRecord>(names.communications,{where:[{attribute:'callId',equals:event.callId}]})
      const prior=rows.map(eventFromCommunication).filter(item=>item.callId===event.callId).sort((a,b)=>Date.parse(b.occurredAt)-Date.parse(a.occurredAt))[0]
      if (event.recipientActorIdentifier!==card.controllerActorIdentifier||(prior&&!sameCall(prior,event))) throw new Error('demo_call_identity_mismatch')
      if (!isParticipant(event,participant)) throw new Error('demo_call_participant_forbidden')
      if (!prior) {
        if (event.state!=='ringing'||participant.actorIdentifier!==event.callerActorIdentifier) throw new Error('demo_call_caller_required')
      } else {
        if (prior.state===event.state) return
        if (prior.state==='ringing'&&['received','declined'].includes(event.state)) {
          if (participant.actorIdentifier!==event.recipientActorIdentifier) throw new Error('demo_call_recipient_required')
        } else if (prior.state==='ringing'&&['cancelled','missed'].includes(event.state)) {
          if (participant.actorIdentifier!==event.callerActorIdentifier) throw new Error('demo_call_caller_required')
        } else if (!(prior.state==='received'&&event.state==='completed')) throw new Error('demo_call_transition_invalid')
      }
      event=normalizePortalRtcCallEvent({...event,occurredAt:new Date(Math.max(this.now(),Date.parse(event.occurredAt),prior?Date.parse(prior.occurredAt)+1:0)).toISOString()})
      const id=`${event.callId}-${event.state}`
      const draft=createCommMsgExtendedDraft({messageId:id,thid:`${id}-request`,subject:event.subjectIdentifier,sender:event.callerActorIdentifier,sent:event.occurredAt,status:'completed',category:CommunicationCategoryCodes.Notification.claim,
        claims:{[CommunicationClaim.Identifier]:id,[CommunicationClaim.Recipient]:[buildSubjectCommunicationGroupReference(event.subjectIdentifier),event.professionalGroupReference,event.recipientActorIdentifier].join(','),[CommunicationClaim.PartOf]:event.threadId,[CommunicationClaim.ContentAttachmentType]:PORTAL_RTC_CALL_CONTENT_TYPE,[CommunicationClaim.ContentAttachmentTitle]:'portal-rtc-call.json',[CommunicationClaim.ContentAttachmentData]:Buffer.from(JSON.stringify(event)).toString('base64')}})
      await store.put(names.communications,{id,callId:event.callId,subjectIdentifier:event.subjectIdentifier,occurredAt:event.occurredAt,communication:{...draft.message,pthid:event.threadId}})
    })
  }
}

export function createPortalDemoExchangeHandler(options:Readonly<{exchange:PortalDemoExchange;scope:DemoWorkspaceScope;bearer:string}>) {
  const expected=serviceCredential(options.bearer)
  collections(options.scope)
  return async(request:Request):Promise<Response>=>{
    const actual=Buffer.from(request.headers.get('authorization')||'')
    if (actual.length!==expected.length||!timingSafeEqual(actual,expected)) return Response.json({error:'demo_exchange_unauthorized'},{status:401})
    if (request.method!=='POST') return Response.json({error:'method_not_allowed'},{status:405})
    try {
      const text=await request.text();if(Buffer.byteLength(text)>32_768) return Response.json({error:'demo_exchange_request_too_large'},{status:413})
      const body=JSON.parse(text) as {operation:string;scope:DemoWorkspaceScope;cardNumber:string;subjectIdentifier:string;event:PortalRtcCallEvent;participant:PortalDemoParticipant}
      collections(body.scope)
      if(body.scope.key!==options.scope.key) return Response.json({error:'demo_exchange_scope_forbidden'},{status:403})
      const result=body.operation==='resolveCard'?await options.exchange.resolveCard(body.scope,body.cardNumber)
        :body.operation==='listEvents'?await options.exchange.listEvents(body.scope,body.subjectIdentifier,body.participant)
          :body.operation==='submitEvent'?await options.exchange.submitEvent(body.scope,body.event,body.participant)
            :(()=>{throw new Error('demo_exchange_operation_invalid')})()
      return Response.json({result:result??null})
    } catch(error) {
      const message=error instanceof Error?error.message:''
      const code=/^(?:demo_|portal_rtc_)[a-z0-9_]+$/u.test(message)?message
        :error instanceof SyntaxError||error instanceof TypeError?'demo_exchange_request_invalid':'demo_exchange_failed'
      const status=code==='demo_exchange_failed'?502:code==='demo_card_not_found'?404:/forbidden|required|identity_mismatch/u.test(code)?403:/transition_invalid/u.test(code)?409:400
      return Response.json({error:code},{status})
    }
  }
}

export class PortalDemoExchangeClient {
  private readonly url:string
  constructor(private readonly options:Readonly<{baseUrl:string;bearer:string;fetchImpl?:typeof fetch}>) {
    const url=new URL(options.baseUrl)
    if (url.username||url.password||url.search||url.hash||!(url.protocol==='https:'||(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname)))) throw new Error('demo_exchange_url_invalid')
    serviceCredential(options.bearer);this.url=`${url.origin}/api/internal/demo/exchange`
  }
  resolveCard(scope:DemoWorkspaceScope,cardNumber:string):Promise<PortalDemoCard> {return this.call({operation:'resolveCard',scope,cardNumber})}
  listEvents(scope:DemoWorkspaceScope,subjectIdentifier:string,participant:PortalDemoParticipant):Promise<PortalRtcCallEvent[]> {return this.call({operation:'listEvents',scope,subjectIdentifier,participant})}
  async submitEvent(scope:DemoWorkspaceScope,event:PortalRtcCallEvent,participant:PortalDemoParticipant):Promise<void> {await this.call({operation:'submitEvent',scope,event,participant})}
  private async call<T>(body:object):Promise<T> {
    const response=await (this.options.fetchImpl??fetch)(this.url,{method:'POST',headers:{authorization:`Bearer ${this.options.bearer}`,'content-type':'application/json'},body:JSON.stringify(body),cache:'no-store',signal:AbortSignal.timeout(15_000)})
    const payload=await response.json() as {result:T;error?:string}
    if(!response.ok) throw new Error(payload.error||'demo_exchange_failed')
    return payload.result
  }
}

function collections(scope:DemoWorkspaceScope) {
  const validated=buildDemoWorkspaceScope(scope)
  if (validated.network!=='demo'||scope.key!==validated.key) throw new Error('demo_exchange_scope_invalid')
  const namespace=demoWorkspaceStorageNamespace(validated)
  return {cards:`${namespace}__demo-cards`,communications:`${namespace}__demo-communications`}
}
function hash(value:string) {return createHash('sha256').update(value).digest('hex')}
function serviceCredential(value:string) {if(!value||value.length<32||/^(?:replace-with-|example-|dummy-|<)/iu.test(value))throw new Error('demo_exchange_service_credential_required');return Buffer.from(`Bearer ${value}`)}
function isParticipant(event:PortalRtcCallEvent,participant:PortalDemoParticipant) {return participant.actorIdentifier===event.recipientActorIdentifier||(participant.actorIdentifier===event.callerActorIdentifier&&participant.professionalGroupReference===event.professionalGroupReference)}
function sameCall(a:PortalRtcCallEvent,b:PortalRtcCallEvent) {return ['threadId','subjectIdentifier','professionalGroupReference','callerActorIdentifier','recipientActorIdentifier'].every(key=>a[key as keyof PortalRtcCallEvent]===b[key as keyof PortalRtcCallEvent])&&a.media.join(',')===b.media.join(',')}
function eventFromCommunication(record:CommunicationRecord):PortalRtcCallEvent {
  const message=record.communication as unknown as {body:{data:Array<{resource:{meta:{claims:Record<string,unknown>}}}>}}
  return normalizePortalRtcCallEvent(JSON.parse(Buffer.from(String(message.body.data[0].resource.meta.claims[CommunicationClaim.ContentAttachmentData]),'base64').toString('utf8')))
}
