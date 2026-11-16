// Flow contract: managed PIN preparation performs no writes or private-key return; the actual host transaction can join exact-owner/profile session revocation to recovery/outbox updates, with rollback and stale-preparation rejection.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy';
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js';
import {RegisteredProfileSessions} from '../dist/registered-profile-sessions.js';
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js';
import {protectServerProfileSecret,openServerProfileSecret} from '../dist/server-profile-protection.js';

const seed=JSON.parse(readFileSync(new URL('./fixtures/registered-communication-wallet.json',import.meta.url)));
const oracle=JSON.parse(readFileSync(new URL('./fixtures/server-profile-custody-keys.json',import.meta.url)));
const pin='synthetic-initial-pin',newPin='synthetic-replacement-pin';
const profileId=seed.walletKeyDerivationId,ownerId='synthetic-recovery-owner';
const binding={profileId,ownerId,actorDid:SAFE.didWeb,providerDid:SAFE.didWeb,routeContext:{tenantId:SAFE.tenantId,jurisdiction:SAFE.countryIso2,sector:'health-tech'}};
async function setup(){
 const vault=new TransactionalMemoryVaultRepository();
 const sealer=createAesGcmProfileSealer(createHash('sha256').update('synthetic recovery transaction host').digest());
 const profile={id:profileId,...binding,walletKeyDerivationId:profileId,actorKind:'organization_controller',actorMode:'controller',profileDid:SAFE.didWeb,allowedSubjectDids:[],clientId:'synthetic-client',deviceDid:SAFE.didWeb,
  publicJwks:oracle.descriptors.filter(value=>value.purpose!=='document-at-rest').map(value=>value.publicJwk),storagePublicJwk:oracle.descriptors.find(value=>value.purpose==='document-at-rest').publicJwk,
  protectedWalletSeed:await protectServerProfileSecret(seed.walletSeed,pin,`${profileId}:wallet-seed`,sealer,{cost:1024}),failedUnlocks:0,createdAt:'2026-11-15T00:00:00.000Z',updatedAt:'2026-11-15T00:00:00.000Z'};
 await vault.put('synthetic_profiles',profile);
 const sessions=new RegisteredProfileSessions({vault,sealer,collections:{profiles:'synthetic_profiles',sessions:'synthetic_sessions'},additionalSessionCollections:['synthetic_wallet_sessions'],protection:{cost:1024}});
 const opened=await sessions.unlock({...binding,pin});
 await vault.put('synthetic_wallet_sessions',{id:'synthetic-owned-wallet-session',profileId,ownerId});
 for(const collection of ['synthetic_sessions','synthetic_wallet_sessions']){
  await vault.put(collection,{id:'synthetic-other-profile',profileId:'synthetic-other-profile',ownerId});
  await vault.put(collection,{id:'synthetic-other-owner',profileId,ownerId:'synthetic-other-owner'});
 }
 await vault.put('synthetic_recovery',{id:profileId,profileId,ownerId,generation:1});
 return {vault,sealer,sessions,profile:await vault.get('synthetic_profiles',profileId),opened};
}

function strictPort(port){
 let writing=false;
 return {
  get(...args){assert.equal(writing,false,'read after write');return port.get(...args);},
  query(...args){assert.equal(writing,false,'query after write');return port.query(...args);},
  put(...args){writing=true;return port.put(...args);},
  delete(...args){writing=true;return port.delete(...args);},
 };
}

test('one real transaction joins profile rewrap, both session families and recovery/outbox; failure rolls everything back',async()=>{
 const f=await setup();
 const input={...binding,routeContext:{...binding.routeContext},authorizedWalletSeed:seed.walletSeed,newPin};
 const prepared=await f.sessions.preparePinReplacement(input);
 input.ownerId='synthetic-other-owner';input.profileId='synthetic-other-profile';input.routeContext.tenantId=SAFE.demoOrganizationUuids.healthCare;
 assert.deepEqual(Object.keys(prepared),['commit']);
 assert.deepEqual(await f.vault.get('synthetic_profiles',profileId),f.profile);
 async function commit(fail){
  return f.vault.runTransaction(async raw=>{
   const port=strictPort(raw),current=await port.get('synthetic_recovery',profileId);
   await port.get('synthetic_outbox','synthetic-event');
   assert.equal(current.generation,1);
   await prepared.commit(port);
   await port.put('synthetic_recovery',{...current,generation:2});
   await port.put('synthetic_outbox',{id:'synthetic-event',profileId,ownerId,generation:2});
   if(fail)throw new Error('synthetic-commit-rejected');
  });
 }
 await assert.rejects(commit(true),/synthetic-commit-rejected/u);
 assert.equal((await f.vault.get('synthetic_recovery',profileId)).generation,1);
 assert.equal(await f.vault.get('synthetic_outbox','synthetic-event'),undefined);
 assert.deepEqual(await f.vault.get('synthetic_profiles',profileId),f.profile);
 await f.sessions.resolve(binding,f.opened.session.sessionId);
 assert.ok(await f.vault.get('synthetic_wallet_sessions','synthetic-owned-wallet-session'));
 await commit(false);
 assert.equal((await f.vault.get('synthetic_recovery',profileId)).generation,2);
 assert.ok(await f.vault.get('synthetic_outbox','synthetic-event'));
 assert.equal(await openServerProfileSecret((await f.vault.get('synthetic_profiles',profileId)).protectedWalletSeed,newPin,`${profileId}:wallet-seed`,f.sealer),seed.walletSeed);
 await assert.rejects(f.sessions.resolve(binding,f.opened.session.sessionId));
 assert.equal(await f.vault.get('synthetic_wallet_sessions','synthetic-owned-wallet-session'),undefined);
 for(const collection of ['synthetic_sessions','synthetic_wallet_sessions']){
  assert.ok(await f.vault.get(collection,'synthetic-other-profile'));
  assert.ok(await f.vault.get(collection,'synthetic-other-owner'));
 }
});

test('a prepared replacement cannot override a newer protected profile or replay its old snapshot',async()=>{
 const f=await setup();
 const prepared=await f.sessions.preparePinReplacement({...binding,authorizedWalletSeed:seed.walletSeed,newPin});
 await f.sessions.replacePin({...binding,authorizedWalletSeed:seed.walletSeed,newPin:'synthetic-newer-pin'});
 const before=await f.vault.get('synthetic_profiles',profileId);
 await assert.rejects(f.vault.runTransaction(port=>prepared.commit(port)),/changed|stale|revoked/iu);
 assert.deepEqual(await f.vault.get('synthetic_profiles',profileId),before);
 assert.equal((await f.vault.get('synthetic_recovery',profileId)).generation,1);
});
