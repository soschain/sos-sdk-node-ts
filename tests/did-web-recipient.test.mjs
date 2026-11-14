// Flow contract: key discovery binds a DID document to the requested recipient, resolves explicit key-agreement references and rejects private material or a substituted identity.
import assert from 'node:assert/strict'
import test from 'node:test'
import {resolveDidWebKeyAgreementJwk,buildAuthorityDidWeb} from '../dist/did-web-recipient.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'

test('resolves only the requested DID and its public encryption method',async()=>{
  const did=buildAuthorityDidWeb({authority:safe.httpsBaseUrl})
  const key={kty:'OKP',crv:'ML-KEM-768',x:'synthetic-public-key',use:'enc'}
  const method=`${did}#encryption`
  const document={id:did,verificationMethod:[{id:method,publicKeyJwk:key}],keyAgreement:[method]}
  let requested
  const fetchImpl=async url=>{requested=String(url);return new Response(JSON.stringify(document),{status:200})}
  assert.deepEqual(await resolveDidWebKeyAgreementJwk(did,{fetchImpl}),{...key,kid:'encryption'})
  assert.equal(requested,`${safe.httpsBaseUrl}/.well-known/did.json`)
  document.id=`${did}:other`
  await assert.rejects(resolveDidWebKeyAgreementJwk(did,{fetchImpl}),/did_document_identity_mismatch/)
  document.id=did
  document.verificationMethod[0].publicKeyJwk={...key,d:'synthetic-private-material'}
  await assert.rejects(resolveDidWebKeyAgreementJwk(did,{fetchImpl}),/did_public_encryption_key_missing/)
})
