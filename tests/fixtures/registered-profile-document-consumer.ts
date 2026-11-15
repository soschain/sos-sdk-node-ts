// Flow contract: the real cache adapter port accepts managed custody directly, and document metadata survives typed protect/unprotect calls without consumer casts.
import {openServerProfileCustodyKeys,type ConfidentialChannelStorageAdapter} from 'sos-sdk-node-ts'
declare const custody:Awaited<ReturnType<typeof openServerProfileCustodyKeys>>
const adapter:ConfidentialChannelStorageAdapter=custody.confidentialStorageAdapter
async function use(){
 const stored=await custody.confidentialStorageAdapter.protect({id:'synthetic-row',projection:3,content:{version:1,messages:[]}})
 const jwe:string=stored.jwe,id:string=stored.id,projection:number=stored.projection
 const opened=await custody.confidentialStorageAdapter.unprotect(stored)
 const restoredId:string=opened.id,restoredProjection:number=opened.projection
 void [jwe,id,projection,restoredId,restoredProjection]
}
void [adapter,use]
