// Flow contract: the real Web Push adapter encrypts a content-free payload with RFC 8291 and authenticates with VAPID over HTTPS; the receiving boundary decrypts exactly that notice, and the production resolver rejects private addresses.
import assert from 'node:assert/strict'
import test from 'node:test'
import {createECDH,createPrivateKey,randomBytes} from 'node:crypto'
import {createServer,Agent} from 'node:https'
import {X509CertificateGenerator,SubjectAlternativeNameExtension} from '@peculiar/x509'
import {generateVAPIDKeys} from 'web-push'
import ece from 'http_ece'
import {createPortalWebPushSender,isPortalPushPublicAddress} from '../dist/portal-web-push.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
test('sends an encrypted, authenticated request to a real HTTPS receiver that decrypts the notice',async()=>{
  let server,agent
  try{
    const algorithm={name:'RSASSA-PKCS1-v1_5',hash:'SHA-256',modulusLength:2048,publicExponent:new Uint8Array([1,0,1])}
    const keys=await crypto.subtle.generateKey(algorithm,true,['sign','verify'])
    const certificate=await X509CertificateGenerator.createSelfSigned({serialNumber:safe.resourceUuid.replaceAll('-',''),name:`CN=${safe.domain}`,notBefore:new Date(Date.now()-60_000),notAfter:new Date(Date.now()+86_400_000),signingAlgorithm:algorithm,keys,extensions:[new SubjectAlternativeNameExtension([{type:'dns',value:safe.domain}])]})
    const cert=certificate.toString('pem')
    const key=createPrivateKey({key:Buffer.from(await crypto.subtle.exportKey('pkcs8',keys.privateKey)),format:'der',type:'pkcs8'}).export({format:'pem',type:'pkcs8'})
    const receiverKey=createECDH('prime256v1');receiverKey.generateKeys();const auth=randomBytes(16)
    const notice={version:1,tag:safe.resourceUuid,state:'ringing',occurredAt:new Date().toISOString()}
    let received
    server=createServer({key,cert},async(request,response)=>{
      const chunks=[];for await(const chunk of request)chunks.push(chunk)
      received={headers:request.headers,payload:JSON.parse(ece.decrypt(Buffer.concat(chunks),{version:'aes128gcm',privateKey:receiverKey,authSecret:auth}).toString())}
      response.writeHead(201);response.end()
    })
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
    agent=new Agent({ca:cert,lookup:(_host,options,callback)=>options.all?callback(null,[{address:'127.0.0.1',family:4}]):callback(null,'127.0.0.1',4)})
    const send=createPortalWebPushSender({vapidDetails:{...generateVAPIDKeys(),subject:safe.httpsBaseUrl},agent})
    const subscription={endpoint:`${safe.httpsBaseUrl}:${server.address().port}/push`,expirationTime:null,keys:{p256dh:receiverKey.getPublicKey().toString('base64url'),auth:auth.toString('base64url')}}
    assert.equal((await send(subscription,notice)).statusCode,201)
    assert.deepEqual(received.payload,notice)
    assert.match(received.headers.authorization,/^vapid /)
    assert.equal(received.headers['content-encoding'],'aes128gcm')
    assert.equal(received.headers.urgency,'high')
    assert.equal(received.headers.ttl,'30')
  }finally{agent?.destroy();await new Promise(resolve=>server?server.close(resolve):resolve())}
})
test('blocks loopback, link-local, private, multicast and mapped private push destinations',()=>{
  for(const address of ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','100.64.0.1','0.0.0.0','224.0.0.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1'])assert.equal(isPortalPushPublicAddress(address),false,address)
  assert.equal(isPortalPushPublicAddress('8.8.8.8'),true)
  assert.equal(isPortalPushPublicAddress('2606:4700:4700::1111'),true)
})
