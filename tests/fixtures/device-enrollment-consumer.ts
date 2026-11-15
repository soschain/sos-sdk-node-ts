import {DeviceEnrollmentClient,type DeviceEnrollmentClientOptions,type DeviceEnrollmentInput} from 'sos-sdk-node-ts/device-enrollment-client'
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
