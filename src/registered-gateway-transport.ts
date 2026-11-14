import {buildGatewayApplicationHeaders} from 'sos-data-utils-ts/gateway-application-identity'
import type {AppInfo,PollOptions,SubmitAndPollResult} from 'sos-data-utils-ts/gateway-transport-contract'

export type VerifiedGatewaySecureAdapter=Readonly<{
 gatewayDid:string
 pack:(message:Record<string,unknown>)=>Promise<string>
 unpackVerified:(packed:string)=>Promise<unknown>
}>
type Row=Record<string,unknown>
const record=(value:unknown):Row|undefined=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Row:undefined
export function gatewayResponseEntries(value:unknown):Row[]{
 const root=record(value),body=record(root?.body)??root
 return Array.isArray(body?.data)?body.data.map(record).filter((row):row is Row=>!!row):[]
}

/** Internal transport: the host supplies trusted signing custody and each operation's expected issuer separately. */
export class RegisteredGatewayTransport{
 constructor(private readonly options:Readonly<{
  baseUrl:string;bearerToken:string;appInfo?:AppInfo;requestTimeoutMs?:number;fetchImpl?:typeof fetch
  secureTransportAdapter?:VerifiedGatewaySecureAdapter;errorPrefix:string
  submitError:(status:number,body:unknown)=>Error
 }>){ }
 private failure(reason:string):Error{return new Error(`${this.options.errorPrefix}_${reason}`)}
 async post(path:string,payload:Row,bearerToken=this.options.bearerToken){
  if(!path.startsWith('/')||path.startsWith('//')||path.includes('://'))throw this.failure('route_invalid')
  const secure=this.options.secureTransportAdapter
  const packed=secure?await secure.pack(payload):undefined
  if(secure&&(typeof packed!=='string'||!packed.trim()))throw this.failure('encrypted_request_required')
  const mediaType=secure?'application/x-www-form-urlencoded':'application/json'
  const response=await(this.options.fetchImpl??fetch)(`${this.options.baseUrl}${path}`,{
   method:'POST',redirect:'error',signal:AbortSignal.timeout(Math.max(1,Math.floor(this.options.requestTimeoutMs??15000))),
   headers:{Authorization:`Bearer ${bearerToken}`,'Content-Type':mediaType,Accept:mediaType,...(this.options.appInfo?buildGatewayApplicationHeaders(this.options.appInfo):{})},
   body:secure?`request=${encodeURIComponent(packed!)}`:JSON.stringify(payload),
  })
  const raw=await response.text();let body:unknown=raw
  if(raw){try{body=JSON.parse(raw)}catch{}}
  if(!response.ok)throw this.options.submitError(response.status,body)
  if(secure&&response.status!==202){
   const responsePacked=typeof body==='string'?new URLSearchParams(body).get('response'):record(body)?.response
   if(typeof responsePacked!=='string'||!responsePacked.trim())throw this.failure('encrypted_response_required')
   body=await secure.unpackVerified(responsePacked)
  }
  return {status:response.status,body,...(response.headers.get('location')?{location:response.headers.get('location')!}:{})}
 }
 async exchange(path:string,payload:Row,expectedResponseIssuer:string,options:PollOptions={},bearerToken=this.options.bearerToken):Promise<SubmitAndPollResult>{
  const submit=await this.post(path,payload,bearerToken)
  const started=Date.now(),timeout=options.timeoutMs??60000
  for(let attempts=1;;attempts++){
   if(Date.now()-started>=timeout)throw this.failure('poll_timeout')
   const poll=await this.post(`${path}-response`,{thid:payload.thid,iss:payload.iss,aud:payload.aud,...(payload.client_id?{client_id:payload.client_id}:{})},bearerToken)
   if(poll.status!==202){
    const envelope=record(poll.body)
    if(this.options.secureTransportAdapter&&(envelope?.iss!==expectedResponseIssuer||envelope?.aud!==payload.iss||envelope?.thid!==payload.thid))throw this.failure('response_binding_invalid')
    if((envelope?.iss!==undefined&&envelope.iss!==expectedResponseIssuer)||(envelope?.aud!==undefined&&envelope.aud!==payload.iss)||(envelope?.thid!==undefined&&envelope.thid!==payload.thid))throw this.failure('response_issuer_binding_invalid')
    for(const row of gatewayResponseEntries(poll.body)){const status=Number(record(row.response)?.status);if(status>=400)throw this.options.submitError(status,poll.body)}
    return {submit,poll:{...poll,attempts}}
   }
   const remaining=timeout-(Date.now()-started)
   if(remaining<=0)throw this.failure('poll_timeout')
   await new Promise(resolve=>setTimeout(resolve,Math.min(remaining,Math.max(0,options.intervalMs??2000))))
  }
 }
}
