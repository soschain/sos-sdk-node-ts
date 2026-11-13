// Flow contract: the Node SDK public surface loads under a resolver that rejects every frozen-project import, including transitive runtime imports.
import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import test from 'node:test'

test('loads all Node SDK public exports with GDC imports forbidden',()=>{
  const target=new URL('../dist/index.js',import.meta.url).href
  const result=spawnSync(process.execPath,['--input-type=module','-e',`
    import {registerHooks} from 'node:module';
    registerHooks({resolve(specifier,context,nextResolve){
      if(specifier.startsWith('gdc-'))throw new Error('forbidden_frozen_dependency');
      return nextResolve(specifier,context);
    }});
    const sdk=await import(${JSON.stringify(target)});
    if(typeof sdk.SecureOrganizationRegistrationRuntime!=='function')throw new Error('registration_runtime_missing');
    if(typeof sdk.TransactionalMemoryVaultRepository!=='function')throw new Error('memory_adapter_missing');
  `],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
})
