import {timingSafeEqual} from 'node:crypto'

/** Exact server-to-server bearer check shared by private BFF backchannels and workers. */
export function createBffServiceBearerVerifier(value:string){
  if(!value||value.length<32||/^(?:replace-with-|example-|dummy-|<)/iu.test(value))throw new Error('bff_service_credential_required')
  const expected=Buffer.from(`Bearer ${value}`)
  return (header:string|null)=>{
    const actual=Buffer.from(header||'')
    return actual.length===expected.length&&timingSafeEqual(actual,expected)
  }
}
