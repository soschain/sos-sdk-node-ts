// Flow contract: a trusted product-neutral BFF reconstructs the reviewed controller bootstrap wallet, submits encrypted organization verification and Order confirmation, and rejects terminal Gateway failures before activation can advance; wallet seeds, bearer credentials and DIDComm details remain server-only.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import {
  assertSuccessfulOrganizationRegistrationResult,
  buildOrganizationRegistrationWalletContext,
} from '../dist/secure-organization-registration.js'

test('rejects direct and nested failed OperationOutcome responses', () => {
  assert.throws(() => assertSuccessfulOrganizationRegistrationResult({ poll: {
    status: 415,
    body: { resourceType: 'OperationOutcome', issue: [{ severity: 'error', code: 'not-supported' }] },
  } }), /organization_registration_gateway_failed:415:not-supported/)
  assert.throws(() => assertSuccessfulOrganizationRegistrationResult({ poll: {
    status: 200,
    body: { resourceType: 'Bundle', entry: [{ response: { status: '403 Forbidden' }, resource: {
      resourceType: 'OperationOutcome', issue: [{ severity: 'fatal', code: 'security' }],
    } }] },
  } }), /organization_registration_gateway_failed:403:security/)
})

test('reconstructs the same isolated profile and server runtime used by reviewed controller keys', () => {
  assert.deepEqual(buildOrganizationRegistrationWalletContext('organization-controller:synthetic-one'), {
    profile: { profileId: 'organization-controller:synthetic-one' },
    runtime: { runtimeId: 'organization-controller:synthetic-one:server-runtime', runtimeType: 'backend-service' },
  })
  assert.throws(() => buildOrganizationRegistrationWalletContext(''), /organization_registration_wallet_context_required/)
})

test('keeps encrypted verification and Offer-to-Order continuation inside the Node SDK', () => {
  const source = readFileSync('src/secure-organization-registration.ts', 'utf8')
  assert.match(source, /submitLegalOrganizationVerificationTransaction/)
  assert.match(source, /confirmLegalOrganizationOrder/)
  assert.match(source, /TransportProfiles\.DidcommEncryptedForm/)
  assert.match(source, /packForRecipientWithContext/)
  assert.match(source, /unpackWithContext/)
})

test('exports the neutral runtime without product SDK dependencies', () => {
  const packageJson = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.equal(packageJson.dependencies['gdc-sdk-node-ts'], undefined)
  assert.equal(packageJson.dependencies['gdc-common-utils-ts'], undefined)
  assert.equal(packageJson.dependencies['uhc-sdk-node-ts'], undefined)
  assert.equal(packageJson.dependencies['vet-sdk-node-ts'], undefined)
})
