// Flow contract: an unverified issuer hint exposes only an HTTPS issuer locator from bounded SHC input; it performs no signature, identity, licence or network verification. Hosts must match their configured known issuer registry before invoking full cryptographic verification.
import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import {inflateRawSync,deflateRawSync} from 'node:zlib'
import * as sdk from '../dist/index.js'
import {encodeSoschainSmartHealthCardQr} from 'sos-data-utils-ts/clinical-document-shc'

const compact=readFileSync(new URL('./fixtures/smart-health-cards-official/example-00-d-jws.txt',import.meta.url),'utf8').trim(),issuer='https://spec.smarthealth.cards/examples/issuer'
function inspect(input){assert.equal(typeof sdk.inspectClinicalDocumentHealthCardIssuer,'function','missing bounded unverified issuer locator');return sdk.inspectClinicalDocumentHealthCardIssuer(input)}
function altered(change){const[h,p,s]=compact.split('.'),payload=JSON.parse(inflateRawSync(Buffer.from(p,'base64url')).toString('utf8'));change(payload);return`${h}.${deflateRawSync(Buffer.from(JSON.stringify(payload))).toString('base64url')}.${s}`}
const invalid=error=>error?.code==='clinical_document_shc_credential_invalid'

test('bounded issuer hint reads official compact, full numeric QR and signed-file input without returning clinical data',()=>{
 for(const input of [compact,encodeSoschainSmartHealthCardQr(compact),JSON.stringify({verifiableCredential:[compact]})]){
  assert.deepEqual(inspect(input),{issuer,signatureVerified:false})
 }
})

test('a syntactically valid but tampered signature still yields explicitly unverified locator only',()=>{
 const[h,p]=compact.split('.'),untrusted=`${h}.${p}.${Buffer.alloc(64,19).toString('base64url')}`
 const hint=inspect(untrusted);assert.equal(hint.signatureVerified,false);assert.deepEqual(Object.keys(hint).sort(),['issuer','signatureVerified'])
})

test('issuer hint rejects malformed, unsigned, unsupported-algorithm and short lookup-label inputs',()=>{
 const[h,p,s]=compact.split('.'),wrongAlgorithm=Buffer.from(JSON.stringify({alg:'ML-DSA-65',zip:'DEF',kid:'synthetic-unsupported'})).toString('base64url')
 for(const input of ['{',`${h}.${p}.`,`${wrongAlgorithm}.${p}.${s}`,'12345678901234567890',JSON.stringify({verifiableCredential:[compact,compact]})])assert.throws(()=>inspect(input),invalid)
})

test('issuer hint bounds encoded input and decompression before exposing any locator',()=>{
 const[h,,s]=compact.split('.'),bomb=deflateRawSync(Buffer.from(JSON.stringify({iss:issuer,padding:'x'.repeat(1024*1024+1)}))).toString('base64url')
 for(const input of ['x'.repeat(128*1024+1),`${h}.${bomb}.${s}`])assert.throws(()=>inspect(input),invalid)
})

test('issuer hint rejects malformed and noncanonical HTTPS issuer locators without discovery',()=>{
 for(const badIssuer of ['http://untrusted.invalid/issuer','https://user:secret@untrusted.invalid/issuer','https://untrusted.invalid/issuer?key=1','https://untrusted.invalid/issuer#key','https://untrusted.invalid/issuer/',null])assert.throws(()=>inspect(altered(p=>{p.iss=badIssuer})),invalid)
})
