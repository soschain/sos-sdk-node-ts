// Flow contract: only an authoritative review supplies the predicates; the same tenant and authenticated holder can read the current revision, and revocation does not restore it on replay.
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import test from 'node:test'
import {REPOSITORY_SAFE_EXAMPLES as examples} from 'sos-data-utils-ts/repository-privacy'
import {ProofOfAgeMdocType, proofOfAgeAttribute} from 'antifraud-data-utils-ts/identity-assurance'
import {ApprovedProofOfAgeVault} from '../dist/approved-proof-of-age-vault.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'

test('binds the reviewed claim to its tenant, holder and latest revision', async () => {
  const store = new TransactionalMemoryVaultRepository()
  const tenantVaultId = examples.tenantId
  const holderReference = examples.didWeb
  const reviewId = randomUUID()
  let now = Date.now()
  const projection = {docType:ProofOfAgeMdocType,namespaces:{[ProofOfAgeMdocType]:{[proofOfAgeAttribute(18)]:true}}}
  const identity = {tenantVaultId, holderReference}
  const writer = {}
  const reader = {}
  const otherReader = {}
  const otherHolder = {}
  const authority = new Map([
    [reader, identity],
    [otherReader, {...identity, tenantVaultId:examples.demoOrganizationUuids.animalCare}],
    [otherHolder, {...identity, holderReference:examples.resourceUuid}],
  ])
  let review = {...identity, revision:reviewId, expiresAt:now + 60_000, projection}
  const vault = new ApprovedProofOfAgeVault({
    store,
    verifyReview: async (participant, id) => participant === writer && id === review.revision ? review : undefined,
    resolveHolder: async participant => authority.get(participant),
    now: () => now,
  })
  assert.equal(await vault.read(reader), undefined)
  await assert.rejects(vault.record(reader, reviewId), /forbidden/u)
  assert.equal(await vault.record(writer, reviewId), reviewId)
  assert.deepEqual(await vault.read(reader), {revision:reviewId, projection})
  assert.equal(await vault.read(otherReader), undefined)
  assert.equal(await vault.read(otherHolder), undefined)
  assert.equal(await vault.read({}), undefined)
  assert.equal(await vault.record(writer, reviewId), reviewId)

  const revocation = randomUUID()
  review = {...identity, revision:revocation, replaces:reviewId}
  assert.equal(await vault.record(writer, revocation), revocation)
  assert.equal(await vault.read(reader), undefined)
  review = {...identity, revision:reviewId, expiresAt:now + 60_000, projection}
  await assert.rejects(vault.record(writer, reviewId), /conflict/u)
  assert.equal(await vault.read(reader), undefined)

  const renewed = randomUUID()
  review = {...identity, revision:renewed, replaces:revocation, expiresAt:now + 1, projection}
  assert.equal(await vault.record(writer, renewed), renewed)
  now += 1
  assert.equal(await vault.read(reader), undefined)
})
