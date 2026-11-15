// Flow contract: recover separate controller-governance ML-DSA-65 and runtime access-token ML-DSA-44 public material and wire profiles from static newly generated synthetic historical examples, without altering the normal six-key profile or inventing issuer/role authority. Package tests import no historical runtime.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import test from 'node:test'
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography'
const loadGovernance=()=>import('../dist/controller-governance-signer.js')
const loadIssuer=()=>import('../dist/runtime-access-token-signer.js')
const fixture=JSON.parse(await readFile(new URL('./fixtures/historical-managed-signing-baselines.json',import.meta.url)))
const seed=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)))
const crypto=new CryptographyService({getRandomBytes:async n=>randomBytes(n),digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value,'utf8').digest('hex'),randomUUID})
async function rejectsSignature(operation){try{return await operation()===false}catch{return true}}

test('preserves the governance public key and detached credential profile, independently verified through AF',async()=>{
 assert.equal(await crypto.verifyDetachedJws(Buffer.from(fixture.governance.payload),fixture.governance.detachedJws,fixture.governance.publicJwk),true)
 const {openControllerGovernanceSigner}=await loadGovernance()
 const signer=await openControllerGovernanceSigner({keyDerivationId:fixture.governance.keyDerivationId,unlockedWalletSeed:seed.walletSeed})
 assert.deepEqual(signer.publicJwk,fixture.governance.publicJwk)
 const jws=await signer.signDetachedCredential({payload:fixture.governance.payload})
 assert.deepEqual(JSON.parse(Buffer.from(jws.split('.')[0],'base64url')),fixture.governance.protectedHeader)
 assert.equal(await crypto.verifyDetachedJws(Buffer.from(fixture.governance.payload),jws,fixture.governance.publicJwk),true)
 assert.equal(await rejectsSignature(()=>crypto.verifyDetachedJws(Buffer.from(`${fixture.governance.payload} altered`),jws,fixture.governance.publicJwk)),true)
 assert.equal(await rejectsSignature(()=>crypto.verifyDetachedJws(Buffer.from(fixture.governance.payload),jws,fixture.issuer.publicJwk)),true)
 const bytes=Buffer.from(fixture.governance.payload),pending=signer.signDetachedCredential({payload:bytes});bytes.fill(0)
 assert.equal(await crypto.verifyDetachedJws(Buffer.from(fixture.governance.payload),await pending,fixture.governance.publicJwk),true)
})

test('preserves runtime issuer public key and at+jwt claims without adding or inferring authority',async()=>{
 assert.equal(await crypto.verifyJws(fixture.issuer.compactJws,fixture.issuer.publicJwk),true)
 const {openRuntimeAccessTokenSigner}=await loadIssuer()
 const signer=await openRuntimeAccessTokenSigner({runtimeId:fixture.issuer.runtimeId,seedMaterial:seed.walletSeed})
 assert.deepEqual(signer.publicJwk,fixture.issuer.publicJwk)
 const before=structuredClone(fixture.issuer.claims),compact=await signer.signAccessToken({claims:fixture.issuer.claims}),parts=compact.split('.')
 assert.deepEqual(JSON.parse(Buffer.from(parts[0],'base64url')),fixture.issuer.protectedHeader)
 assert.deepEqual(JSON.parse(Buffer.from(parts[1],'base64url')),before);assert.deepEqual(fixture.issuer.claims,before)
 assert.equal(await crypto.verifyJws(compact,fixture.issuer.publicJwk),true)
 assert.equal(await rejectsSignature(()=>crypto.verifyJws(compact,fixture.governance.publicJwk)),true)
 const changed=Buffer.from(JSON.stringify({...before,aud:'synthetic-foreign-audience'})).toString('base64url')
 assert.equal(await rejectsSignature(()=>crypto.verifyJws(`${parts[0]}.${changed}.${parts[2]}`,fixture.issuer.publicJwk)),true)
 const mutable=structuredClone(before),pending=signer.signAccessToken({claims:mutable});mutable.aud='synthetic-later-audience'
 assert.deepEqual(JSON.parse(Buffer.from((await pending).split('.')[1],'base64url')),before)
})

test('keeps foreign context and seed material separate and returns no private key fields',async()=>{
 const {openControllerGovernanceSigner}=await loadGovernance(),{openRuntimeAccessTokenSigner}=await loadIssuer()
 const governance=await openControllerGovernanceSigner({keyDerivationId:fixture.governance.foreignKeyDerivationId,unlockedWalletSeed:seed.walletSeed})
 const issuer=await openRuntimeAccessTokenSigner({runtimeId:fixture.issuer.foreignRuntimeId,seedMaterial:seed.walletSeed})
 assert.deepEqual(governance.publicJwk,fixture.governance.foreignContextPublicJwk)
 assert.deepEqual(issuer.publicJwk,fixture.issuer.foreignContextPublicJwk)
 const jws=await governance.signDetachedCredential({payload:fixture.governance.payload}),token=await issuer.signAccessToken({claims:fixture.issuer.claims})
 assert.equal(await rejectsSignature(()=>crypto.verifyDetachedJws(Buffer.from(fixture.governance.payload),jws,fixture.governance.publicJwk)),true)
 assert.equal(await rejectsSignature(()=>crypto.verifyJws(token,fixture.issuer.publicJwk)),true)
 const other=await openRuntimeAccessTokenSigner({runtimeId:fixture.issuer.runtimeId,seedMaterial:Buffer.alloc(32,6).toString('base64url')})
 assert.notDeepEqual(other.publicJwk,fixture.issuer.publicJwk)
 const mutable={runtimeId:fixture.issuer.runtimeId,seedMaterial:seed.walletSeed},pending=openRuntimeAccessTokenSigner(mutable)
 mutable.runtimeId=fixture.issuer.foreignRuntimeId;mutable.seedMaterial='synthetic-later-seed'
 assert.deepEqual((await pending).publicJwk,fixture.issuer.publicJwk)
 for(const capability of [governance,issuer,other])for(const key of ['walletSeed','seedMaterial','privateKey','d','dBytes','privBytes','secretKeyBytes']){assert.equal(key in capability,false);assert.equal(key in capability.publicJwk,false)}
})
