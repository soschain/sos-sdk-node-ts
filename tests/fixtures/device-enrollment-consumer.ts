// Flow contract: typed existing and resumable hosts use the owned enrollment API without implicit custody or fabricated submit acknowledgements.
import {DeviceEnrollmentClient,type DeviceEnrollmentClientOptions,type DeviceEnrollmentInput,type DeviceEnrollmentCheckpoint} from 'sos-sdk-node-ts/device-enrollment-client'
export async function enroll(options: DeviceEnrollmentClientOptions,input: DeviceEnrollmentInput) {
  const receipt=await new DeviceEnrollmentClient(options).enroll(input)
  const clientId:string=receipt.clientId
  const actorDid:string=receipt.actorDid
  const profileDid:string=receipt.profileDid
  return {clientId,actorDid,profileDid,routeContext:receipt.routeContext}
}
declare const options:DeviceEnrollmentClientOptions
// @ts-expect-error Registered administration cannot be substituted for explicit bootstrap transport.
const registered:DeviceEnrollmentClientOptions={...options,transportProfile:'registered-didcomm-encrypted'}
void registered

export async function resumeEnrollment(options:DeviceEnrollmentClientOptions,input:DeviceEnrollmentInput,checkpoint:DeviceEnrollmentCheckpoint|undefined,saveCheckpoint:(checkpoint:DeviceEnrollmentCheckpoint)=>Promise<void>){
  const receipt=await new DeviceEnrollmentClient(options).enroll(input,undefined,{checkpoint,saveCheckpoint})
  const submitStatus:number|undefined=receipt.registration.submit?.status
  const clientId:string=receipt.clientId
  return {clientId,submitStatus}
}
