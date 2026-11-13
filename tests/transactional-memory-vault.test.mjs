// Flow contract: the shared memory vault serializes transactions, commits atomically, rolls back failures and preserves the existing vault interface for every channel.
import assert from 'node:assert/strict'
import test from 'node:test'
import {spawnSync} from 'node:child_process'
import { TransactionalMemoryVaultRepository } from '../dist/transactional-vault.js'

test('loads and executes the SOS memory vault with every GDC module forbidden',()=>{
  const target=new URL('../dist/transactional-vault.js',import.meta.url).href
  const result=spawnSync(process.execPath,['--input-type=module','-e',`
    import {registerHooks} from 'node:module';
    registerHooks({resolve(specifier,context,nextResolve){
      if(specifier.startsWith('gdc-'))throw new Error('forbidden_legacy_dependency');
      return nextResolve(specifier,context);
    }});
    const {TransactionalMemoryVaultRepository}=await import(${JSON.stringify(target)});
    const vault=new TransactionalMemoryVaultRepository();
    await vault.put('records',{id:'isolated',value:1});
    if((await vault.get('records','isolated'))?.value!==1)throw new Error('vault_readback_failed');
  `],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
})

test('commits one competing claim and rolls back every write on failure', async () => {
  const vault = new TransactionalMemoryVaultRepository()
  await vault.put('grants', { id: 'grant', status: 'ready' })
  const claim = () => vault.runTransaction(async transaction => {
    const grant = await transaction.get('grants', 'grant')
    if (grant?.status !== 'ready') throw new Error('already_claimed')
    await transaction.put('grants', { ...grant, status: 'claimed' })
    return grant.id
  })
  const results = await Promise.allSettled([claim(), claim()])
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1)
  assert.equal((await vault.get('grants', 'grant')).status, 'claimed')
  await assert.rejects(vault.runTransaction(async transaction => {
    await transaction.put('grants', { id: 'grant', status: 'consumed' })
    await transaction.put('receipts', { id: 'receipt' })
    throw new Error('injected_failure')
  }), /injected_failure/)
  assert.equal((await vault.get('grants', 'grant')).status, 'claimed')
  assert.equal(await vault.get('receipts', 'receipt'), undefined)
  await vault.put('grants', { id: 'after-failure', status: 'ready' })
  assert.equal((await vault.query('grants', { where: [{ attribute: 'status', equals: 'ready' }] })).length, 1)
})

test('does not expose mutable references outside an atomic transaction', async () => {
  const vault = new TransactionalMemoryVaultRepository()
  const original = { id: 'one', nested: { counter: 1 } }
  await vault.put('records', original)
  original.nested.counter = 2
  const readback = await vault.get('records', 'one')
  readback.nested.counter = 3
  assert.equal((await vault.get('records', 'one')).nested.counter, 1)
})
