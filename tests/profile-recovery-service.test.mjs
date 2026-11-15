// Flow contract: owned recovery preserves historical email ciphertext/AAD/code bytes, binds phone separately, returns no seed, and reports success only after a one-use generation commit. Host transaction tests separately prove profile/session/outbox atomicity.
// Historical published-module provenance is recorded in the static synthetic fixture; no UHC or GDC runtime is imported here.
import assert from 'node:assert/strict';
import test from 'node:test';
import {createCipheriv,createDecipheriv,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy';

const load=()=>import('../dist/profile-recovery-service.js');
const hash=value=>createHash('sha256').update(value).digest('hex');
const fixture=name=>JSON.parse(readFileSync(new URL('./fixtures/'+name,import.meta.url)));
const seedFixture=fixture('registered-communication-wallet.json');
const seed=()=>Buffer.from(seedFixture.walletSeed,'base64url');
const identity={profileId:seedFixture.walletKeyDerivationId,ownerId:'synthetic-recovery-owner',controllerKind:'organization-controller',contactKind:'email',contact:SAFE.firstContactEmail};

async function setup(overrides={},commitPreparedProfile=async()=>{}){
 const {ProfileRecoveryService}=await load();
 const key=createHash('sha256').update('synthetic-profile-recovery-baseline-kek').digest();
 let encrypted=0,shares=0,current,notice,prepared,failRotate=false,failKms=false,decryptions=0;
 const aadHashes=[];
 const kms={keyName:'synthetic://profile-recovery-key',async encrypt(cleartext,aad){
  if(failKms)throw new Error('synthetic-kms-outage');
  aadHashes.push(hash(aad));
  const iv=Buffer.alloc(12,0x31+encrypted++),cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(aad);
  return Buffer.concat([iv,cipher.update(cleartext),cipher.final(),cipher.getAuthTag()]).toString('base64url');
 },async decrypt(ciphertext,aad){
  decryptions++;
  if(failKms)throw new Error('synthetic-kms-outage');
  const bytes=Buffer.from(ciphertext,'base64url'),decipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));
  decipher.setAAD(aad);decipher.setAuthTag(bytes.subarray(-16));
  return Uint8Array.from(Buffer.concat([decipher.update(bytes.subarray(12,-16)),decipher.final()]));
 }};
 const initialProfile={profileId:identity.profileId,ownerId:identity.ownerId};
 const repository={async get(){return current?structuredClone(current):null;},async put(record,expected){
  assert.equal(expected,null);assert.equal(current,undefined);
  await commitPreparedProfile(initialProfile);
  current=structuredClone(record);prepared=structuredClone(initialProfile);
 },async rotate(record,expected,notification,profile){
  if(failRotate)throw new Error('synthetic-commit-rejected');
  if(current.generation!==expected)throw new Error('synthetic-generation-conflict');
  current=structuredClone(record);notice=structuredClone(notification);prepared=structuredClone(profile);
 }};
 const service=new ProfileRecoveryService({repository,kms,environment:'staging',now:()=>new Date('2026-11-15T00:00:00.000Z'),randomBytes:size=>new Uint8Array(size).fill(0x42+shares++),
  prepareRestoredProfile:async({walletSeed,identity:binding})=>({profileId:binding.profileId,ownerId:binding.ownerId,fingerprint:hash(walletSeed)}),...overrides});
 return {service,aadHashes,record:()=>structuredClone(current),notice:()=>structuredClone(notice),prepared:()=>structuredClone(prepared),decryptions:()=>decryptions,
  failRotate:()=>{failRotate=true;},failKms:()=>{failKms=true;}};
}

test('preserves the exact captured historical email record, AAD and one-use code profiles without returning a seed',async()=>{
 let finalized=0;
 const f=await setup({},async profile=>{assert.deepEqual(profile,{profileId:identity.profileId,ownerId:identity.ownerId});finalized++;}),baseline=fixture('legacy-email-recovery.json');
 const enrolled=await f.service.enroll({...identity,contact:`  ${identity.contact.toUpperCase()}  `},seed());
 assert.equal(finalized,1);
 const record=f.record();
 for(const [name,value] of Object.entries(baseline.record))assert.deepEqual(record[name],value,name);
 assert.equal(record.verifiedEmail,identity.contact);
 assert.equal('verifiedTelephone' in record,false);
 assert.equal(f.aadHashes[0],baseline.aadSha256);
 assert.equal(hash(enrolled.recoveryCode),baseline.recoveryCodeSha256);
 assert.deepEqual(Object.keys(enrolled),['recoveryCode']);
 const recovered=await f.service.recover(identity,enrolled.recoveryCode);
 assert.deepEqual(Object.keys(recovered),['replacementRecoveryCode']);
 assert.equal(hash(recovered.replacementRecoveryCode),baseline.replacementCodeSha256);
 assert.equal(f.prepared().fingerprint,hash(seed()));
 assert.equal(f.record().generation,2);
 await assert.rejects(f.service.recover(identity,enrolled.recoveryCode));
});

test('phone binding is explicit and distinct; foreign account, contact and controller kind deny before KMS',async()=>{
 const f=await setup(),phone={...identity,contactKind:'phone',contact:SAFE.phoneE164};
 const enrolled=await f.service.enroll(phone,seed());
 assert.equal(f.record().version,'sos-profile-recovery-v1');
 assert.equal(f.record().verifiedTelephone,SAFE.phoneE164);
 assert.equal('verifiedEmail' in f.record(),false);
 const calls=f.decryptions();
 for(const change of [{ownerId:'synthetic-foreign-owner'},{profileId:'synthetic-foreign-profile'},{contact:SAFE.secondContactPhoneE164},{contactKind:'email',contact:SAFE.firstContactEmail},{controllerKind:'individual-controller'}]){
  await assert.rejects(f.service.recover({...phone,...change},enrolled.recoveryCode));
 }
 assert.equal(f.decryptions(),calls);
 const recovered=await f.service.recover(phone,enrolled.recoveryCode);
 assert.equal(typeof recovered.replacementRecoveryCode,'string');
 assert.equal(f.notice().verifiedTelephone,SAFE.phoneE164);
 assert.equal('verifiedEmail' in f.notice(),false);
});

test('KMS outage is operational and leaves the persisted generation and prepared profile unchanged',async()=>{
 const f=await setup(),enrolled=await f.service.enroll(identity,seed());
 const before=f.record(),prepared=f.prepared();f.failKms();
 await assert.rejects(f.service.recover(identity,enrolled.recoveryCode),/synthetic-kms-outage/u);
 assert.deepEqual(f.record(),before);assert.deepEqual(f.prepared(),prepared);assert.equal(f.notice(),undefined);
});

test('failed or racing generation commits return no premature success and consume a code at most once',async()=>{
 const failed=await setup(),first=await failed.service.enroll(identity,seed());
 const before=failed.record();failed.failRotate();
 await assert.rejects(failed.service.recover(identity,first.recoveryCode),/synthetic-commit-rejected/u);
 assert.deepEqual(failed.record(),before);assert.equal(failed.notice(),undefined);
 const concurrent=await setup(),enrolled=await concurrent.service.enroll(identity,seed());
 const outcomes=await Promise.allSettled([concurrent.service.recover(identity,enrolled.recoveryCode),concurrent.service.recover(identity,enrolled.recoveryCode)]);
 assert.equal(outcomes.filter(value=>value.status==='fulfilled').length,1);
 assert.equal(outcomes.filter(value=>value.status==='rejected').length,1);
 assert.equal(concurrent.record().generation,2);
});
