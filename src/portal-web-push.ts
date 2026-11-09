import {Agent} from 'node:https'
import {BlockList,isIP} from 'node:net'
import {lookup} from 'node:dns'
import {sendNotification,type RequestOptions} from 'web-push'
import {normalizePortalPushNotice,normalizePortalPushSubscription,type PortalPushNotice,type PortalPushSubscription} from 'sos-data-utils-ts/portal-push'

const blocked=new BlockList()
const blockedV6=new BlockList()
for(const [address,prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.168.0.0',16],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]] as const)blocked.addSubnet(address,prefix,'ipv4')
for(const [address,prefix] of [['::',128],['::1',128],['::ffff:0:0',96],['fc00::',7],['fe80::',10],['ff00::',8]] as const)blockedV6.addSubnet(address,prefix,'ipv6')
export function isPortalPushPublicAddress(address:string){const family=isIP(address);return family===4?!blocked.check(address,'ipv4'):family===6?!blockedV6.check(address,'ipv6'):false}

/** Fresh DNS results are checked at connection time, including IPv4/IPv6 rebinding. */
function publicPushAgent(){
  return new Agent({keepAlive:false,lookup:(hostname,options,callback)=>{
    lookup(hostname,{all:true},(error,addresses)=>{
      if(error)return callback(error,[])
      if(!addresses.length||addresses.some(address=>!isPortalPushPublicAddress(address.address)))return callback(new Error('portal_push_address_forbidden'),[])
      if(options.all)return callback(null,addresses)
      const preferred=addresses.find(address=>!options.family||address.family===options.family)??addresses[0]
      callback(null,preferred.address,preferred.family)
    })
  }})
}

/** No mutable global VAPID config. The host owns configuration and optional test TLS boundary. */
export function createPortalWebPushSender(options:Readonly<{vapidDetails:NonNullable<RequestOptions['vapidDetails']>;agent?:Agent}>){
  const agent=options.agent??publicPushAgent()
  return async(input:PortalPushSubscription,rawNotice:PortalPushNotice)=>{
    const subscription=normalizePortalPushSubscription(input),notice=normalizePortalPushNotice(rawNotice)
    const response=await sendNotification(subscription,JSON.stringify(notice),{
      vapidDetails:options.vapidDetails,agent,contentEncoding:'aes128gcm',timeout:10_000,
      TTL:notice.state==='ringing'?30:60,urgency:'high',topic:notice.tag.slice(0,32),
    })
    return {statusCode:response.statusCode}
  }
}
