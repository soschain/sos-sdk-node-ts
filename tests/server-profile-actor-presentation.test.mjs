// Flow contract: controller presentations retain the actual profile actor key and embedded public JWK, remain bound to a returned client ID, and never substitute the distinct runtime VP purpose. This proves signing semantics, not credential authority or GW admission.
import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {openServerProfileCustodyKeys} from '../dist/server-profile-custody-keys.js';
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy';

const open=()=>openServerProfileCustodyKeys({walletKeyDerivationId:SAFE.tenantId,unlockedWalletSeed:createHash('sha256').update(SAFE.resourceUuid).digest('base64url'),binding:{kind:'enrollment'}});
const header=token=>JSON.parse(Buffer.from(token.split('.')[0],'base64url').toString('utf8'));
function checks(token,jwk){const [protectedHeader,payload,signature]=token.split('.');return verify('sha384',Buffer.from(protectedHeader+'.'+payload,'ascii'),{key:createPublicKey({key:jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url'));}
test('actor presentation embeds its real actor public key and verifies with that purpose only',async()=>{
 const keys=await open(),actor=keys.descriptors.find(key=>key.purpose==='actor-signing'),vp=keys.descriptors.find(key=>key.purpose==='vp-token-signing');
 assert.equal(typeof keys.signActorPresentationJws,'function','missing purpose-fixed actor presentation operation');
 const payload={client_id:SAFE.resourceUuid,iss:actor.kid,sub:SAFE.tenantId,aud:SAFE.httpsBaseUrl,vp:{holder:actor.kid,verifiableCredential:[]}};
 const token=await keys.signActorPresentationJws({clientId:SAFE.resourceUuid,payload});
 assert.deepEqual(header(token),{alg:'ES384',typ:'JWT',kid:actor.kid,jwk:actor.publicJwk});
 assert.deepEqual(JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString('utf8')),payload);
 assert.equal(checks(token,actor.publicJwk),true);assert.equal(checks(token,vp.publicJwk),false);
});
test('requires the actual client binding and preserves existing actor/VP signing profiles',async()=>{
 const keys=await open(),actor=keys.descriptors.find(key=>key.purpose==='actor-signing'),vp=keys.descriptors.find(key=>key.purpose==='vp-token-signing');
 assert.equal(typeof keys.signActorPresentationJws,'function','missing purpose-fixed actor presentation operation');
 await assert.rejects(keys.signActorPresentationJws({clientId:SAFE.resourceUuid,payload:{client_id:'foreign-client'}}),/client_binding_invalid/u);
 await assert.rejects(keys.signActorPresentationJws({clientId:'',payload:{}}),/client_binding_required/u);
 const input={clientId:SAFE.resourceUuid,payload:{client_id:SAFE.resourceUuid}};
 const actorToken=await keys.signActorJws(input),vpToken=await keys.signVpJws(input);
 assert.equal(header(actorToken).kid,actor.kid);assert.equal('jwk'in header(actorToken),false);
 assert.equal(header(vpToken).kid,vp.kid);assert.deepEqual(header(vpToken).jwk,vp.publicJwk);
 assert.equal(checks(actorToken,actor.publicJwk),true);assert.equal(checks(vpToken,vp.publicJwk),true);
});
