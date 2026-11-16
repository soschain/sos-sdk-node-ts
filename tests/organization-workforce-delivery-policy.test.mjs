// Flow contract: an explicit trusted host policy retains failed notification state while sealing a pending invitation code for its authorized controller; recipient/contact/code/capacity checks, single-use activation and default required delivery remain unchanged. Legacy hash-only rows require an explicit reissue, never mutation on GET.
import assert from 'node:assert/strict';
import test from 'node:test';
import {OrganizationWorkforceVaultProvider} from '../dist/organization-workforce-vault.js';
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js';
import {createAesGcmProfileSealer} from '../dist/profile-sealer.js';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';

const organization=`Organization/${safe.demoOrganizationUuids.healthCare}`;
const foreignOrganization=`Organization/${safe.resourceUuid}`;
const collection='synthetic-workforce-notification-policy';
const mailFailure=async()=>{throw new Error('synthetic notification unavailable')};
class AuditVault extends TransactionalMemoryVaultRepository{
 inside=false;
 async runTransaction(operation){return super.runTransaction(async port=>{
  this.inside=true;let writing=false;
  const observed={get:(...args)=>{assert.equal(writing,false);return port.get(...args)},query:(...args)=>{assert.equal(writing,false);return port.query(...args)},put:(...args)=>{writing=true;return port.put(...args)},delete:(...args)=>{writing=true;return port.delete(...args)}};
  try{return await operation(observed)}finally{this.inside=false}
 })}
}
function fixture(){
 const store=new AuditVault(),state={now:Date.parse('2026-11-16T08:00:00Z'),allowed:true,unseals:0,afterSeal:undefined,afterUnseal:undefined};
 const base=createAesGcmProfileSealer(Buffer.alloc(32,31));
 const sealer={async seal(value,aad){assert.equal(store.inside,false);const sealed=await base.seal(value,aad);await state.afterSeal?.();return sealed},async unseal(value,aad){assert.equal(store.inside,false);state.unseals++;const clear=await base.unseal(value,aad);await state.afterUnseal?.();return clear}};
 const options={store,collection,assertManage:async ref=>{if(!state.allowed||ref!==organization)throw new Error('synthetic controller forbidden')},now:()=>state.now};
 const provider=overrides=>new OrganizationWorkforceVaultProvider({...options,...overrides});
 const input={organizationReference:organization,sector:'health-care',profileId:'dentist',role:'dentist',email:safe.firstContactEmail,roleCode:'ISCO-08|2261',employeeDid:`urn:uuid:${safe.resourceUuid}`,expiresAt:state.now+60_000,organizationName:'Synthetic clinic',roleName:'Dentist'};
 return {store,state,sealer,options,provider,input,opt:()=>provider({invitationDeliveryPolicy:'notification-only',sealer})};
}

test('notification-only failure preserves a sealed scoped pending code and exact single-use recipient activation',async()=>{
 const f=fixture(),p=f.opt();assert.deepEqual(await p.invite(f.input,mailFailure),{invited:true});
 const [row]=await p.list(organization),code=row.activationCode;
 assert.match(code,/^[A-Za-z0-9_-]{43}$/u);assert.equal(row.delivery,'failed');assert.equal(row.status,'pending');
 const [stored]=await f.store.query(collection,{});assert.equal(typeof stored.protectedActivationCode,'string');
 assert.equal('protectedActivationCode'in row,false);assert.equal(JSON.stringify(stored).includes(code),false);
 await assert.rejects(p.activate(safe.secondContactEmail,code,async()=>true),/invitation_invalid/u);
 await assert.rejects(p.activate(f.input.email,'A'.repeat(43),async()=>true),/invitation_invalid/u);
 await assert.rejects(f.provider({collection:'synthetic-other-workspace',invitationDeliveryPolicy:'notification-only',sealer:f.sealer}).activate(f.input.email,code,async()=>true),/invitation_invalid/u);
 await assert.rejects(p.activate(f.input.email,code,async(_seat,tx)=>{await tx.put('synthetic-profiles',{id:'synthetic-profile'});throw new Error('synthetic profile failure')}),/profile failure/u);
 assert.equal(await f.store.get('synthetic-profiles','synthetic-profile'),undefined);
 assert.equal((await p.list(organization))[0].activationCode,code);
 const outcomes=await Promise.allSettled([p.activate(f.input.email,code,async()=>true),p.activate(f.input.email,code,async()=>true)]);
 assert.equal(outcomes.filter(outcome=>outcome.status==='fulfilled').length,1);
 const [active]=await p.list(organization);assert.equal(active.status,'active');assert.equal('activationCode'in active,false);
 assert.equal((await f.store.get(collection,stored.id)).protectedActivationCode,undefined);
});

test('legacy hash-only failure requires explicit reissue and repeated reads never change its credential',async()=>{
 const f=fixture();let oldCode;
 await assert.rejects(f.provider().invite(f.input,async message=>{oldCode=message.activationCode;await mailFailure()}),/delivery_failed/u);
 const before=await f.store.query(collection,{}),p=f.opt();
 for(let index=0;index<2;index++){const [legacy]=await p.list(organization);assert.equal(legacy.requiresReissue,true);assert.equal('activationCode'in legacy,false)}
 assert.deepEqual(await f.store.query(collection,{}),before);
 await assert.rejects(p.activate(f.input.email,oldCode,async()=>true),/invitation_invalid/u);
 await p.invite(f.input,mailFailure);const [reissued]=await p.list(organization);
 assert.notEqual(reissued.activationCode,oldCode);assert.equal(reissued.requiresReissue,undefined);
 await assert.rejects(p.activate(f.input.email,oldCode,async()=>true),/invitation_invalid/u);
 assert.equal(await p.activate(f.input.email,reissued.activationCode,async()=>true),true);
});

test('pending code custody rechecks controller authority and authenticates organization and seat metadata',async()=>{
 const f=fixture(),p=f.opt();await p.invite(f.input,mailFailure);
 await assert.rejects(p.list(foreignOrganization),/controller forbidden/u);assert.equal(f.state.unseals,0);
 const [stored]=await f.store.query(collection,{});
 await f.store.put(collection,{...stored,id:'synthetic-foreign-seat',organizationReference:foreignOrganization});
 const multi=f.provider({invitationDeliveryPolicy:'notification-only',sealer:f.sealer,assertManage:async()=>{}});
 await assert.rejects(multi.list(foreignOrganization));
 f.state.afterUnseal=async()=>{f.state.allowed=false};await assert.rejects(p.list(organization),/controller forbidden/u);
 const g=fixture();g.state.afterSeal=async()=>{g.state.allowed=false};
 await assert.rejects(g.opt().invite(g.input,mailFailure),/controller forbidden/u);assert.deepEqual(await g.store.query(collection,{}),[]);
});

test('activation or expiry during unseal cannot release a stale pending credential',async()=>{
 const f=fixture(),p=f.opt();let code;await p.invite(f.input,async message=>{code=message.activationCode;await mailFailure()});
 f.state.afterUnseal=async()=>{f.state.afterUnseal=undefined;await p.activate(f.input.email,code,async()=>true)};
 await assert.rejects(p.list(organization),/changed|invalid/u);
 const g=fixture(),expired=g.opt();await expired.invite(g.input,mailFailure);g.state.afterUnseal=async()=>{g.state.now=g.input.expiresAt};
 await assert.rejects(expired.list(organization),/changed|expired|invalid/u);
 assert.deepEqual(await expired.list(organization),[]);
});

test('default required delivery retains its failure gate and cannot reveal or activate an opt-in failed row',async()=>{
 const f=fixture();let code;
 await assert.rejects(f.provider({sealer:f.sealer}).invite(f.input,async message=>{code=message.activationCode;await mailFailure()}),/delivery_failed/u);
 assert.equal((await f.provider().list(organization))[0].activationCode,undefined);
 await assert.rejects(f.provider().activate(f.input.email,code,async()=>true),/invitation_invalid/u);
 assert.equal((await f.store.query(collection,{}))[0].protectedActivationCode,undefined);
 await f.opt().invite(f.input,mailFailure);
 const [pending]=await f.opt().list(organization);
 assert.equal((await f.provider().list(organization))[0].activationCode,undefined);
 await assert.rejects(f.provider().activate(f.input.email,pending.activationCode,async()=>true),/invitation_invalid/u);
});

test('notification-only is an immutable explicit constructor policy and requires custody',async()=>{
 const f=fixture();assert.throws(()=>f.provider({invitationDeliveryPolicy:'notification-only'}),/sealer|custody/u);
 assert.throws(()=>f.provider({invitationDeliveryPolicy:'unsupported',sealer:f.sealer}),/policy/u);
 const mutable={...f.options,invitationDeliveryPolicy:'required',sealer:f.sealer},required=new OrganizationWorkforceVaultProvider(mutable);
 mutable.invitationDeliveryPolicy='notification-only';
 await assert.rejects(required.invite(f.input,mailFailure),/delivery_failed/u);
});

test('failed notifications under opt-in still consume the existing bounded seat capacity',async()=>{
 const f=fixture(),p=f.opt();
 for(let index=0;index<32;index++)await p.invite({...f.input,profileId:`synthetic-profile-${index}`},mailFailure);
 await assert.rejects(p.invite({...f.input,profileId:'synthetic-over-capacity'},mailFailure),/capacity_exhausted/u);
 assert.equal((await f.store.query(collection,{})).length,32);
});
