// Flow contract: actual registered BFF clients consume the existing frozen transport constant through the public SDK API, preserving its exact form media value and owning implementation identity.
import assert from 'node:assert/strict'
import test from 'node:test'
import * as sdk from '../dist/index.js'
import {TransportProfiles} from '../dist/organization-registration-client.js'
test('public transport profile is the existing frozen registered client configuration',()=>{
 assert.equal(sdk.TransportProfiles,TransportProfiles)
 assert.equal(Object.isFrozen(sdk.TransportProfiles),true)
 assert.equal(sdk.TransportProfiles.DidcommEncryptedForm,'application/x-www-form-urlencoded')
})
