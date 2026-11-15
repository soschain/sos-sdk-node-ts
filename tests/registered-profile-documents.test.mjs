// Flow contract: open static synthetic ciphertext captured from the historical published runtime using exact registered document custody, preserve its compact-JWE profile and derivation-owner binding, and reject an authentically encrypted foreign-owner probe. No historical runtime executes in these tests.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import test from 'node:test'
import ts from 'typescript'
import {fileURLToPath} from 'node:url'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
import {openServerProfileCustodyKeys} from '../dist/server-profile-custody-keys.js'
const fixture=JSON.parse(await readFile(new URL('./fixtures/registered-profile-document.json',import.meta.url)))
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const oracle=JSON.parse(await readFile(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)))
const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),digestString:async(data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data,'utf8').digest('hex'),randomUUID})
const open=()=>openServerProfileCustodyKeys({walletKeyDerivationId:fixture.effectiveDerivationId,unlockedWalletSeed:seed.walletSeed,binding:{kind:'registered',publicJwks:oracle.descriptors.filter(d=>d.purpose!=='document-at-rest').map(d=>d.publicJwk),storagePublicJwk:fixture.publicStorageJwk}})
async function independentOpen(jwe){
 const material=createHash('sha512').update(`${seed.walletSeed}:profile:${fixture.effectiveDerivationId}:default:document-at-rest:0`,'utf8').digest()
 const pair=await crypto.generateKeyPairMlKem(material,'ML-KEM-768');material.fill(0)
 try{assert.deepEqual(pair.publicJWKey,fixture.publicStorageJwk);return await crypto.decryptJwe(jwe,{...pair.publicJWKey,dBytes:pair.secretKeyBytes})}
 finally{pair.secretKeyBytes.fill(0)}
}
test('opens newly captured synthetic historical-runtime ciphertext and independently decodes new ciphertext with the same protected profile',async()=>{
 const custody=await open(),adapter=custody.confidentialStorageAdapter
 assert.notEqual(fixture.logicalProfileId,fixture.effectiveDerivationId)
 assert.deepEqual(await adapter.unprotect(fixture.protectedDocument),fixture.expectedDocument)
 const stored=await adapter.protect(fixture.expectedDocument)
 assert.equal(typeof stored.jwe,'string');assert.equal(stored.jwe.split('.').length,5)
 assert.equal('content' in stored,false);assert.equal(stored.id,fixture.expectedDocument.id)
 const decoded=await independentOpen(stored.jwe)
 assert.deepEqual(decoded.protectedHeader,fixture.protectedHeader)
 assert.deepEqual(JSON.parse(Buffer.from(decoded.decryptedBytes).toString('utf8')),fixture.expectedDocument.content)
 assert.deepEqual(await adapter.unprotect(stored),fixture.expectedDocument)
})
test('rejects the wrong owner even when its ciphertext authenticates with the exact same document key',async()=>{
 const custody=await open(),decoded=await independentOpen(fixture.negativeOwnerDocument.jwe)
 assert.deepEqual(JSON.parse(Buffer.from(decoded.decryptedBytes).toString('utf8')),fixture.expectedDocument.content)
 assert.notEqual(decoded.protectedHeader.gdc_owner_binding,fixture.protectedHeader.gdc_owner_binding)
 await assert.rejects(custody.confidentialStorageAdapter.unprotect(fixture.negativeOwnerDocument),/owner|binding|policy/i)
 const parts=fixture.protectedDocument.jwe.split('.'),tag=Buffer.from(parts[4],'base64url');tag[0]^=1;parts[4]=tag.toString('base64url')
 await assert.rejects(custody.confidentialStorageAdapter.unprotect({...fixture.protectedDocument,jwe:parts.join('.')}))
})

test('snapshots derivation custody before caller mutation and preserves outer metadata without asserting its authenticity',async()=>{
 const options={walletKeyDerivationId:fixture.effectiveDerivationId,unlockedWalletSeed:seed.walletSeed,binding:{kind:'registered',publicJwks:oracle.descriptors.filter(d=>d.purpose!=='document-at-rest').map(d=>d.publicJwk),storagePublicJwk:fixture.publicStorageJwk}}
 const custody=await openServerProfileCustodyKeys(options)
 options.walletKeyDerivationId=fixture.logicalProfileId;options.unlockedWalletSeed=Buffer.alloc(32,8).toString('base64url');options.binding.kind='enrollment'
 assert.deepEqual(await custody.confidentialStorageAdapter.unprotect(fixture.protectedDocument),fixture.expectedDocument)
 await assert.rejects(openServerProfileCustodyKeys({...options,binding:{...options.binding,kind:'registered'}}))
 const changed={...fixture.protectedDocument,id:'synthetic-other-row',projection:'synthetic-index'}
 assert.deepEqual(await custody.confidentialStorageAdapter.unprotect(changed),{...fixture.expectedDocument,id:changed.id,projection:changed.projection})
})

test('rejects executable inputs and noncompact envelopes without invoking getters or coercion while retaining JSON optional fields',async()=>{
 const adapter=(await open()).confidentialStorageAdapter;let calls=0
 const getter={};Object.defineProperty(getter,'content',{enumerable:true,get(){calls++;throw new Error('getter must not execute')}})
 await assert.rejects(adapter.protect(getter))
 const nested=[];Object.defineProperty(nested,'0',{enumerable:true,get(){calls++;throw new Error('nested getter must not execute')}})
 await assert.rejects(adapter.protect({content:{nested}}))
 await assert.rejects(adapter.unprotect({jwe:{toString(){calls++;return fixture.protectedDocument.jwe}}}))
 assert.equal(calls,0)
 for(const content of [false,0,'',null,{optional:undefined,items:[undefined],sent:undefined}]){
  const opened=await adapter.unprotect(await adapter.protect({id:'synthetic-json-value',content}))
  assert.deepEqual(opened.content,JSON.parse(JSON.stringify(content)))
 }
 await assert.rejects(adapter.unprotect({jwe:'synthetic-not-compact'}))
 await assert.rejects(adapter.protect({content:{unsupported:()=>0}}))
 const enrollment=await openServerProfileCustodyKeys({walletKeyDerivationId:fixture.effectiveDerivationId,unlockedWalletSeed:seed.walletSeed,binding:{kind:'enrollment'}})
 await assert.rejects(enrollment.confidentialStorageAdapter.protect(fixture.expectedDocument),/registered_binding_required/)
})

test('assigns the actual CH cache port and preserves outer metadata through public typed calls without casts',()=>{
 const file=fileURLToPath(new URL('./fixtures/registered-profile-document-consumer.ts',import.meta.url))
 const program=ts.createProgram([file],{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.NodeNext,moduleResolution:ts.ModuleResolutionKind.NodeNext,strict:true,noEmit:true,skipLibCheck:true})
 assert.deepEqual(ts.getPreEmitDiagnostics(program).map(d=>ts.flattenDiagnosticMessageText(d.messageText,' ')),[])
})
