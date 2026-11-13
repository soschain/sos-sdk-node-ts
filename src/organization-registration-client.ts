import {randomUUID} from 'node:crypto'
import {buildGatewayApplicationHeaders} from 'sos-data-utils-ts/gateway-application-identity'
import {buildLegalOrganizationVerificationTransactionBundle,type AppInfo,type RouteContext,type HostRouteContext,type LegalOrganizationOrderInput,type LegalOrganizationVerificationTransactionInput,type PollOptions,type SubmitAndPollResult} from 'sos-data-utils-ts/gateway-transport-contract'

export type {AppInfo,RouteContext,HostRouteContext,LegalOrganizationOrderInput,PollOptions,SubmitAndPollResult}
export type NodeLegalOrganizationVerificationTransactionInput=LegalOrganizationVerificationTransactionInput
export const TransportProfiles=Object.freeze({DidcommEncryptedForm:'application/x-www-form-urlencoded'} as const)
type SecureAdapter=Readonly<{pack:(message:Record<string,unknown>)=>Promise<string>;unpack:(jwe:string)=>Promise<unknown>}>
type ClientOptions=Readonly<{
  baseUrl:string;bearerToken:string;ctx:RouteContext;appInfo?:AppInfo;fetchImpl?:typeof fetch
  requestTimeoutMs?:number;transportProfile:typeof TransportProfiles.DidcommEncryptedForm;secureTransportAdapter:SecureAdapter
}>
type HttpResult={status:number;body:unknown;location?:string;retryAfterMs?:number}

/** A rejected submit is terminal; its status/body remain available to the owning BFF. */
export class OrganizationRegistrationSubmitError extends Error {
  constructor(readonly status:number,readonly body:unknown){super(`organization_registration_submit_failed:${status}`)}
}

/** Owned encrypted submit/poll runtime for legal-organization verification, reissuance and Order confirmation. */
export class OrganizationRegistrationClient {
  private readonly baseUrl:string
  constructor(private readonly options:ClientOptions){
    const base=new URL(options.baseUrl)
    if(base.username||base.password||base.search||base.hash||(base.protocol!=='https:'&&!(base.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(base.hostname))))throw new TypeError('organization_registration_gateway_https_required')
    if(options.transportProfile!==TransportProfiles.DidcommEncryptedForm)throw new TypeError('organization_registration_encrypted_profile_required')
    if(!options.bearerToken.trim())throw new TypeError('organization_registration_bearer_required')
    this.baseUrl=base.href.replace(/\/+$/u,'')
  }
  submitLegalOrganizationVerificationTransaction(host:HostRouteContext,input:LegalOrganizationVerificationTransactionInput,pollOptions?:PollOptions):Promise<SubmitAndPollResult>{
    return this.verification(host,input,'_transaction','organization-verification-transaction',pollOptions)
  }
  submitLegalOrganizationCredentialReissuance(host:HostRouteContext,input:LegalOrganizationVerificationTransactionInput,pollOptions?:PollOptions):Promise<SubmitAndPollResult>{
    return this.verification(host,input,'_issue','organization-issue',pollOptions)
  }
  private verification(host:HostRouteContext,input:LegalOrganizationVerificationTransactionInput,action:string,prefix:string,pollOptions?:PollOptions):Promise<SubmitAndPollResult>{
    const {attachments,...body}=buildLegalOrganizationVerificationTransactionBundle(input)
    const payload={jti:`${prefix}-jti-${randomUUID()}`,thid:`${prefix}-${randomUUID()}`,iss:host.controllerDid,aud:host.hostDid,type:'application/api+json',body,...(attachments?.length?{attachments}:{})}
    return this.exchange(this.path(host,'Organization',action),this.path(host,'Organization',`${action}-response`),payload,pollOptions)
  }
  confirmLegalOrganizationOrder(host:HostRouteContext,input:LegalOrganizationOrderInput,pollOptions?:PollOptions):Promise<SubmitAndPollResult>{
    if(!input.offerId.trim())throw new TypeError('organization_registration_offer_required')
    const payload={jti:`jti-${randomUUID()}`,thid:`order-${randomUUID()}`,iss:host.controllerDid,aud:host.hostDid,type:'application/didcomm-plain+json',body:{data:[{type:input.dataType??'Organization-order-request-v1.0',resource:{meta:{claims:{'@context':'org.schema','Order.acceptedOffer.identifier':input.offerId,...input.additionalClaims}}}}]}}
    const options=pollOptions??{...(input.timeoutSeconds===undefined?{}:{timeoutMs:input.timeoutSeconds*1000}),...(input.intervalSeconds===undefined?{}:{intervalMs:input.intervalSeconds*1000})}
    return this.exchange(this.path(host,'Order','_batch'),this.path(host,'Order','_batch-response'),payload,options)
  }
  private path(host:HostRouteContext,resource:string,action:string):string{
    const jurisdiction=String(host.jurisdiction||this.options.ctx.jurisdiction).trim()
    const network=String(host.hostNetwork||host.hostNetworkOrTenantSector||'').trim()||(host.sector?'':'test')
    if(!/^[A-Za-z]{2}(?:-[A-Za-z0-9]{1,3})?$/u.test(jurisdiction)||!['test','local-network','test-network','network'].includes(network))throw new TypeError('organization_registration_host_route_invalid')
    return `/host/cds-${encodeURIComponent(jurisdiction)}/v1/${encodeURIComponent(network)}/registry/org.schema/${resource}/${action}`
  }
  private async post(path:string,payload:Record<string,unknown>):Promise<HttpResult>{
    const packed=await this.options.secureTransportAdapter.pack(payload)
    if(!packed.trim())throw new Error('organization_registration_encrypted_request_required')
    const headers:Record<string,string>={Authorization:`Bearer ${this.options.bearerToken}`,Accept:TransportProfiles.DidcommEncryptedForm,'Content-Type':TransportProfiles.DidcommEncryptedForm,...(this.options.appInfo?buildGatewayApplicationHeaders(this.options.appInfo):{})}
    const response=await (this.options.fetchImpl??fetch)(`${this.baseUrl}${path}`,{method:'POST',headers,body:`request=${encodeURIComponent(packed)}`,redirect:'error',signal:AbortSignal.timeout(Math.max(1,Math.floor(this.options.requestTimeoutMs??15000)))})
    const raw=await response.text()
    let body:unknown=raw
    if(raw){try{body=JSON.parse(raw)}catch{}}
    const retry=response.headers.get('retry-after')
    const retryAfterMs=retry===null?undefined:Number.isFinite(Number(retry))?Math.max(0,Number(retry)*1000):Math.max(0,Date.parse(retry)-Date.now())
    return {status:response.status,body,...(response.headers.get('location')?{location:response.headers.get('location')!}:{}),...(retryAfterMs===undefined||!Number.isFinite(retryAfterMs)?{}:{retryAfterMs})}
  }
  private async exchange(submitPath:string,pollPath:string,payload:Record<string,unknown>,options:PollOptions={}):Promise<SubmitAndPollResult>{
    const submit=await this.post(submitPath,payload)
    if(submit.status<200||submit.status>=300)throw new OrganizationRegistrationSubmitError(submit.status,submit.body)
    const started=Date.now(),timeout=options.timeoutMs??60000
    let attempts=0
    for(;;){
      attempts++
      const response=await this.post(pollPath,{thid:payload.thid,...(payload.iss?{iss:payload.iss}:{}),...(payload.aud?{aud:payload.aud}:{})})
      if(response.status!==202){
        let body=response.body
        if(response.status>=200&&response.status<300){
          const packed=typeof body==='string'?new URLSearchParams(body).get('response'):body&&typeof body==='object'?(body as Record<string,unknown>).response:undefined
          if(typeof packed!=='string'||!packed.trim())throw new Error('organization_registration_encrypted_response_required')
          body=await this.options.secureTransportAdapter.unpack(packed)
        }
        return {submit:{status:submit.status,body:submit.body,...(submit.location?{location:submit.location}:{})},poll:{status:response.status,body,attempts}}
      }
      const remaining=timeout-(Date.now()-started)
      if(remaining<=0)throw new Error('organization_registration_poll_timeout')
      const delay=Math.min(remaining,Math.max(0,options.intervalMs??response.retryAfterMs??2000))
      await new Promise(resolve=>setTimeout(resolve,delay))
    }
  }
}
