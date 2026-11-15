// Flow contract: actual BFF projections need trusted profile/route/role/aliases
// and structural encrypted transport plus metadata-preserving document ports.
import type {RegisteredProfileAccess} from 'sos-sdk-node-ts/registered-profile-access'
import type {RegisteredProfileBinding} from 'sos-data-utils-ts/registered-profile-contract'
async function consume(access:RegisteredProfileAccess,binding:RegisteredProfileBinding,sessionId:string){
 const session=await access.resolveSession({...binding,sessionId})
 const profile={profileId:session.profile.profileId,actorKind:session.profile.actorKind,actorMode:session.profile.actorMode,actorDid:session.profile.actorDid,profileDid:session.profile.profileDid,providerDid:session.profile.providerDid,allowedSubjectDids:session.profile.allowedSubjectDids,deviceDid:session.profile.deviceDid}
 // @ts-expect-error Session-confirmed aliases are a read-only projection.
 session.profile.allowedSubjectDids.push('synthetic-untrusted-subject')
 const gateway={...session.profile.routeContext,requesterId:session.profile.actorDid,actorMode:session.profile.actorMode,secureTransportAdapter:session.secureTransportAdapter}
 const protectedDocument=await session.confidentialStorageAdapter.protect({id:'synthetic-consumer-document',content:{message:'synthetic'},channelId:'synthetic-channel'})
 const channelId:string=protectedDocument.channelId
 const opened=await session.confidentialStorageAdapter.unprotect(protectedDocument)
 const id:string=opened.id
 const actor=await access.resolveActorSession({...binding,sessionId})
 const subjects:readonly string[]=actor.authorizedSubjectDids
 return {profile,gateway,id,channelId,subjects,actorMode:session.actorMode,attester:session.attester}
}
void consume
