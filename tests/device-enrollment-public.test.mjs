// Flow contract: the public root/subpath expose one owned pre-DCR client, and a real typed host can consume bound enrollment receipts without an employee grant or an implicit registered-transport fallback.
import assert from 'node:assert/strict'
import test from 'node:test'
import {execFileSync} from 'node:child_process'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import * as root from '../dist/index.js'
import * as leaf from 'sos-sdk-node-ts/device-enrollment-client'
const require=createRequire(import.meta.url)
test('public root/subpath share the device client and support an actual typed host',()=>{
 assert.equal(root.DeviceEnrollmentClient,leaf.DeviceEnrollmentClient)
 execFileSync(process.execPath,[require.resolve('typescript/bin/tsc'),'--noEmit','--strict','--skipLibCheck','--target','ES2023','--module','NodeNext','--moduleResolution','NodeNext',fileURLToPath(new URL('./fixtures/device-enrollment-consumer.ts',import.meta.url))],{stdio:'pipe'})
})
