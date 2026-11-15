// Flow contract: actual public hosts receive validated Data-owned phone/email inventory, seven numeric licence totals, explicit quote amounts and distinct status/purge evidence without casting unknown replies into authority.
import test from 'node:test'
import {execFileSync} from 'node:child_process'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
const require=createRequire(import.meta.url)
test('public administration consumers compile through precise Data-owned outputs',()=>{
 execFileSync(process.execPath,[require.resolve('typescript/bin/tsc'),'--noEmit','--strict','--skipLibCheck','--target','ES2023','--module','NodeNext','--moduleResolution','NodeNext',fileURLToPath(new URL('./fixtures/workforce-administration-consumer.ts',import.meta.url))],{stdio:'pipe'})
})
