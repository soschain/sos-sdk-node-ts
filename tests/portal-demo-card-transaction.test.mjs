// Flow contract: a BFF registers a synthetic card and updates its existing workspace in one caller-owned vault transaction; failure after the directory write rolls back both, and retry reuses the same card. Existing standalone registration stays compatible.
import assert from 'node:assert/strict'
import test, {mock} from 'node:test'
import {PortalDemoExchange} from '../dist/portal-demo-exchange.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'

const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:'soschain',tenantId:'demo-soschain'})
const card={cardNumber:'123456789012345678901',generationId:'synthetic-generation',subjectIdentifier:'urn:uuid:synthetic-subject',displayName:'Synthetic subject',controllerActorIdentifier:'urn:uuid:synthetic-controller',subjectKind:'animal',sourceSector:'animal-research',expiresAt:Date.now()+60_000}

test('joins the supplied transaction and rolls back a first-write failure before retry',async()=>{
  const store=new TransactionalMemoryVaultRepository()
  const exchange=new PortalDemoExchange({store})
  const create=async fail=>store.runTransaction(async transaction=>{
    const nested=mock.method(store,'runTransaction',()=>{throw new Error('nested_transaction_forbidden')})
    try{
      await transaction.get('fixture-workspaces','workspace')
      await exchange.registerCard(scope,card,transaction)
      if(fail) throw new Error('injected_after_directory_write')
      await transaction.put('fixture-workspaces',{id:'workspace',cards:[card.subjectIdentifier]})
    }finally{nested.mock.restore()}
  })
  await assert.rejects(create(true),/injected_after_directory_write/)
  await assert.rejects(exchange.resolveCard(scope,card.cardNumber),/demo_card_not_found/)
  assert.equal(await store.get('fixture-workspaces','workspace'),undefined)
  await create(false)
  await create(false)
  assert.equal((await exchange.resolveCard(scope,card.cardNumber)).subjectIdentifier,card.subjectIdentifier)
  assert.deepEqual((await store.get('fixture-workspaces','workspace')).cards,[card.subjectIdentifier])
})

test('retains standalone registration and collision denial',async()=>{
  const exchange=new PortalDemoExchange({store:new TransactionalMemoryVaultRepository()})
  await exchange.registerCard(scope,card)
  assert.deepEqual(await exchange.resolveCard(scope,card.cardNumber),card)
  await assert.rejects(exchange.registerCard(scope,{...card,subjectIdentifier:'urn:uuid:another-subject'}),/demo_card_collision/)
})

test('joins generation revocation to the caller transaction and rolls back a failed reset',async()=>{
  const store=new TransactionalMemoryVaultRepository()
  const exchange=new PortalDemoExchange({store})
  await exchange.registerCard(scope,card)
  await assert.rejects(store.runTransaction(async transaction=>{
    const nested=mock.method(store,'runTransaction',()=>{throw new Error('nested_transaction_forbidden')})
    try{
      await exchange.revokeGeneration(scope,card.generationId,transaction)
      throw new Error('injected_after_directory_delete')
    }finally{nested.mock.restore()}
  }),/injected_after_directory_delete/)
  assert.deepEqual(await exchange.resolveCard(scope,card.cardNumber),card)
  await store.runTransaction(transaction=>exchange.revokeGeneration(scope,card.generationId,transaction))
  await assert.rejects(exchange.resolveCard(scope,card.cardNumber),/demo_card_not_found/)
})
