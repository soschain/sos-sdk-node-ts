// Flow contract: recover the exact registered communication keys from a synthetic unlocked profile context, compare actual public material and identifiers to an independent JSON compatibility oracle, and reject missing or mismatched registration context without rotation. The oracle generator is external; these tests import no legacy SDK.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {readFile} from 'node:fs/promises'
import test from 'node:test'
import {OrganizationRegistrationWallet} from '../dist/organization-registration-wallet.js'

const fixture=JSON.parse(await readFile(new URL('./fixtures/registered-communication-wallet.json',import.meta.url),'utf8'))
const load=()=>import('../dist/registered-communication-wallet.js')
const publicFields=key=>key.kty==='AKP'?{kty:key.kty,alg:key.alg,pub:key.pub,kid:key.kid}:{kty:key.kty,crv:key.crv,x:key.x,kid:key.kid}
const expected=Object.fromEntries(fixture.publicJwks.map(key=>[key.kty==='AKP'?'signing':'encryption',publicFields(key)]))
const input=()=>({walletKeyDerivationId:fixture.walletKeyDerivationId,unlockedWalletSeed:fixture.walletSeed,registeredPublicJwks:structuredClone(fixture.publicJwks),resolveRecipientJwk:async()=>{throw new Error('must_not_fetch_a_remote_provider_to_recover_keys')}})

test('existing independent wallet reproduces the actual synthetic oracle public material and both key identifiers',async()=>{
 assert.equal(fixture.synthetic,true)
 const wallet=new OrganizationRegistrationWallet()
 await wallet.provisionCommunicationKeys(fixture.context,fixture.walletSeed)
 const actual=wallet.getPublicJwks(fixture.context)
 assert.deepEqual({signing:publicFields(actual.signing),encryption:publicFields(actual.encryption)},expected)
})

test('opens the exact registered communication pair without exposing the unlocked seed or registering replacement keys',async()=>{
 const {openRegisteredCommunicationWallet}=await load()
 const opened=await openRegisteredCommunicationWallet(input())
 assert.deepEqual(opened.context,fixture.context)
 const keys=opened.wallet.getPublicJwks(opened.context)
 assert.deepEqual({signing:publicFields(keys.signing),encryption:publicFields(keys.encryption)},expected)
 assert.equal(Object.hasOwn(opened,'unlockedWalletSeed'),false)
})

test('rejects wrong seed, missing or wrong derivation context, missing keys and foreign material under the same kid',async()=>{
 const {openRegisteredCommunicationWallet}=await load()
 const wrongSeed=createHash('sha256').update(`${fixture.walletSeed}:different`).digest('base64url')
 const foreign=new OrganizationRegistrationWallet()
 await foreign.provisionCommunicationKeys(fixture.context,wrongSeed)
 const foreignSigning=foreign.getPublicJwks(fixture.context).signing
 const forged=input();forged.registeredPublicJwks=forged.registeredPublicJwks.map(key=>key.kty==='AKP'?{...key,pub:foreignSigning.pub}:key)
 for(const candidate of [
  {...input(),unlockedWalletSeed:wrongSeed},
  {...input(),walletKeyDerivationId:''},
  {...input(),walletKeyDerivationId:`${fixture.walletKeyDerivationId}:different`},
  {...input(),registeredPublicJwks:[]},
  forged,
 ])await assert.rejects(openRegisteredCommunicationWallet(candidate),/registered_communication_wallet/)
})
